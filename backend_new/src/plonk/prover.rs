//! PLONK Prover
//!
//! Implements the 5-round PLONK prover following Section 8.3 of the paper.
//!
//! Round 1: Compute wire polynomial commitments [a], [b], [c]
//! Round 2: Compute permutation polynomial commitment [z]
//! Round 3: Compute quotient polynomial commitment [t]
//! Round 4: Compute evaluations at challenge ζ
//! Round 5: Compute opening proofs [W_ζ], [W_{ζω}]

use crate::circuit::ConstraintSystem;
use crate::curve::G1Affine;
use crate::fft::Domain;
use crate::field::Fr;
use crate::kzg::{Commitment, OpeningProof, Srs};
use crate::plonk::permutation::Permutation;
use crate::plonk::types::*;
use crate::polynomial::Polynomial;
use crate::transcript::Transcript;
use rand::Rng;
use serde::{Deserialize, Serialize};

/// The PLONK prover
pub struct Prover<'a> {
    /// The constraint system
    pub cs: &'a ConstraintSystem,
    /// The proving key
    pub pk: &'a ProvingKey,
    /// The permutation data
    pub permutation: &'a Permutation,
    /// The domain
    pub domain: &'a Domain,
    /// The SRS
    pub srs: &'a Srs,
}

impl<'a> Prover<'a> {
    /// Create a new prover
    pub fn new(
        cs: &'a ConstraintSystem,
        pk: &'a ProvingKey,
        permutation: &'a Permutation,
        domain: &'a Domain,
        srs: &'a Srs,
    ) -> Self {
        Prover {
            cs,
            pk,
            permutation,
            domain,
            srs,
        }
    }

    /// Generate a proof for the witness in the constraint system
    pub fn prove(&self, public_inputs: &[Fr]) -> Proof {
        let (proof, _trace) = self.prove_with_trace(public_inputs);
        proof
    }

    /// Generate a proof with detailed trace for visualization
    pub fn prove_with_trace(&self, public_inputs: &[Fr]) -> (Proof, ProverTrace) {
        let mut rng = rand::thread_rng();
        let mut transcript = Transcript::new(b"PLONK-v1");

        let n = self.pk.n;

        // Absorb public inputs
        for (i, pi) in public_inputs.iter().enumerate() {
            transcript.absorb_fr(&format!("pi_{}", i), pi);
        }

        // ==========================================
        // Round 1: Wire polynomials
        // ==========================================
        let round1 = self.round1(&mut transcript, &mut rng);

        // Get challenges β, γ
        let beta = transcript.squeeze_challenge("beta");
        let gamma = transcript.squeeze_challenge("gamma");

        // ==========================================
        // Round 2: Permutation polynomial z(X)
        // ==========================================
        let round2 = self.round2(&round1, beta, gamma, &mut transcript, &mut rng);

        // Get challenge α
        let alpha = transcript.squeeze_challenge("alpha");

        // ==========================================
        // Round 3: Quotient polynomial t(X)
        // ==========================================
        let round3 = self.round3(
            &round1,
            &round2,
            public_inputs,
            beta,
            gamma,
            alpha,
            &mut transcript,
            &mut rng,
        );

        // Get challenge ζ
        let zeta = transcript.squeeze_challenge("zeta");

        // ==========================================
        // Round 4: Evaluations
        // ==========================================
        let round4 = self.round4(&round1, &round2, &round3, zeta, &mut transcript);

        // Get challenge v
        let v = transcript.squeeze_challenge("v");

        // ==========================================
        // Round 5: Opening proofs
        // ==========================================
        let round5 = self.round5(
            &round1,
            &round2,
            &round3,
            &round4,
            zeta,
            v,
            alpha,
            beta,
            gamma,
            public_inputs,
            &mut transcript,
        );

        // Build proof (paper-aligned: only 3 quotient commitments)
        let proof = Proof {
            a_comm: round1.a_comm,
            b_comm: round1.b_comm,
            c_comm: round1.c_comm,
            z_comm: round2.z_comm,
            t_lo_comm: round3.t_lo_comm,
            t_mid_comm: round3.t_mid_comm,
            t_hi_comm: round3.t_hi_comm,
            a_eval: round4.evaluations.a_zeta,
            b_eval: round4.evaluations.b_zeta,
            c_eval: round4.evaluations.c_zeta,
            s_sigma1_eval: round4.evaluations.s_sigma1_zeta,
            s_sigma2_eval: round4.evaluations.s_sigma2_zeta,
            z_omega_eval: round4.evaluations.z_zeta_omega,
            w_zeta_comm: round5.w_zeta_comm,
            w_zeta_omega_comm: round5.w_zeta_omega_comm,
        };

        // Build trace
        let circuit_trace = self.build_circuit_trace(public_inputs);

        let mut round1_trace = round1;
        round1_trace.beta = beta;
        round1_trace.gamma = gamma;

        let mut round2_trace = round2;
        round2_trace.alpha = alpha;

        let mut round3_trace = round3;
        round3_trace.zeta = zeta;

        let mut round4_trace = round4;
        round4_trace.v = v;

        let trace = ProverTrace {
            circuit: circuit_trace,
            round1: round1_trace,
            round2: round2_trace,
            round3: round3_trace,
            round4: round4_trace,
            round5,
            proof: proof.clone(),
        };

        (proof, trace)
    }

    /// Round 1: Compute blinded wire polynomials and commitments
    fn round1<R: Rng>(&self, transcript: &mut Transcript, rng: &mut R) -> Round1Trace {
        let n = self.pk.n;

        // Get wire values from the constraint system
        let (a_evals, b_evals, c_evals) = self.cs.get_wire_values().expect("Wire values not set");

        // Generate random blinding factors for zero-knowledge
        // Paper-aligned: a, b, c all get degree-1 blinding × Z_H
        let b1 = Fr::random(rng);
        let b2 = Fr::random(rng);
        let b3 = Fr::random(rng);
        let b4 = Fr::random(rng);
        let b5 = Fr::random(rng);
        let b6 = Fr::random(rng);

        // Convert evaluations to polynomials via IFFT
        let a_poly_unblinded = Polynomial::from_evaluations(&a_evals, self.domain);
        let b_poly_unblinded = Polynomial::from_evaluations(&b_evals, self.domain);
        let c_poly_unblinded = Polynomial::from_evaluations(&c_evals, self.domain);

        // Add blinding: a(X) = a_unblinded(X) + (b1*X + b2)*Z_H(X)
        // where Z_H(X) = X^n - 1
        let z_h = Polynomial::vanishing(n);

        let blind_a = Polynomial::from_coeffs(vec![b2, b1]);
        let blind_b = Polynomial::from_coeffs(vec![b4, b3]);
        let blind_c = Polynomial::from_coeffs(vec![b6, b5]);

        let a_poly = &a_poly_unblinded + &(&blind_a * &z_h);
        let b_poly = &b_poly_unblinded + &(&blind_b * &z_h);
        let c_poly = &c_poly_unblinded + &(&blind_c * &z_h);

        // Commit
        let a_comm = Commitment::commit(&a_poly, self.srs).point;
        let b_comm = Commitment::commit(&b_poly, self.srs).point;
        let c_comm = Commitment::commit(&c_poly, self.srs).point;

        // Absorb commitments into transcript
        transcript.absorb_g1("a_comm", &a_comm);
        transcript.absorb_g1("b_comm", &b_comm);
        transcript.absorb_g1("c_comm", &c_comm);

        Round1Trace {
            a_evals,
            b_evals,
            c_evals,
            a_coeffs: a_poly.coeffs.clone(),
            b_coeffs: b_poly.coeffs.clone(),
            c_coeffs: c_poly.coeffs.clone(),
            blinding_factors: BlindingFactorsRound1 {
                b1,
                b2,
                b3,
                b4,
                b5,
                b6,
            },
            a_comm,
            b_comm,
            c_comm,
            beta: Fr::zero(),  // Set later
            gamma: Fr::zero(), // Set later
        }
    }

    /// Round 2: Compute permutation polynomial z(X)
    fn round2<R: Rng>(
        &self,
        round1: &Round1Trace,
        beta: Fr,
        gamma: Fr,
        transcript: &mut Transcript,
        rng: &mut R,
    ) -> Round2Trace {
        let n = self.pk.n;
        let omega = self.pk.omega;
        let k1 = self.pk.k1;
        let k2 = self.pk.k2;

        // Compute the accumulator z(ω^i)
        // z(ω^0) = 1
        // z(ω^{i+1}) = z(ω^i) * [(a_i + β*ω^i + γ)(b_i + β*k1*ω^i + γ)(c_i + β*k2*ω^i + γ)]
        //                      / [(a_i + β*σ_1(ω^i) + γ)(b_i + β*σ_2(ω^i) + γ)(c_i + β*σ_3(ω^i) + γ)]

        let mut z_evals = vec![Fr::zero(); n];
        z_evals[0] = Fr::one();

        let mut accumulator_steps = Vec::new();

        let mut omega_i = Fr::one();
        for i in 0..(n - 1) {
            let a_i = round1.a_evals[i];
            let b_i = round1.b_evals[i];
            let c_i = round1.c_evals[i];

            let s1_i = self.permutation.s_sigma1_evals[i];
            let s2_i = self.permutation.s_sigma2_evals[i];
            let s3_i = self.permutation.s_sigma3_evals[i];

            // Numerator: (a + β*ω^i + γ)(b + β*k1*ω^i + γ)(c + β*k2*ω^i + γ)
            let num = (a_i + beta * omega_i + gamma)
                * (b_i + beta * k1 * omega_i + gamma)
                * (c_i + beta * k2 * omega_i + gamma);

            // Denominator: (a + β*σ_1(ω^i) + γ)(b + β*σ_2(ω^i) + γ)(c + β*σ_3(ω^i) + γ)
            let denom = (a_i + beta * s1_i + gamma)
                * (b_i + beta * s2_i + gamma)
                * (c_i + beta * s3_i + gamma);

            let z_next = z_evals[i] * num * denom.inverse().expect("Denominator is zero");
            z_evals[i + 1] = z_next;

            accumulator_steps.push(AccumulatorStep {
                i,
                omega_i,
                numerator: num,
                denominator: denom,
                z_next,
            });

            omega_i = omega_i * omega;
        }

        // Verify z(ω^{n-1}) = 1 (the permutation is valid)
        // Actually, we need z(ω^n) = z(1) = 1, but we only compute z(ω^0) to z(ω^{n-1})
        // The constraint is enforced via the polynomial identity

        // Generate blinding factors for zero-knowledge
        // Paper-aligned: z gets degree-2 blinding × Z_H
        let b7 = Fr::random(rng);
        let b8 = Fr::random(rng);
        let b9 = Fr::random(rng);

        // Convert to polynomial via IFFT
        let z_poly_unblinded = Polynomial::from_evaluations(&z_evals, self.domain);

        // Add blinding: z(X) = z_unblinded(X) + (b7*X^2 + b8*X + b9)*Z_H(X)
        let z_h = Polynomial::vanishing(n);
        let blind_z = Polynomial::from_coeffs(vec![b9, b8, b7]);
        let z_poly = &z_poly_unblinded + &(&blind_z * &z_h);

        // Commit
        let z_comm = Commitment::commit(&z_poly, self.srs).point;

        // Absorb into transcript
        transcript.absorb_g1("z_comm", &z_comm);

        Round2Trace {
            z_evals,
            accumulator_steps,
            z_coeffs: z_poly.coeffs.clone(),
            blinding_factors: BlindingFactorsRound2 { b7, b8, b9 },
            z_comm,
            alpha: Fr::zero(), // Set later
        }
    }

    /// Round 3: Compute quotient polynomial t(X)
    fn round3<R: Rng>(
        &self,
        round1: &Round1Trace,
        round2: &Round2Trace,
        public_inputs: &[Fr],
        beta: Fr,
        gamma: Fr,
        alpha: Fr,
        transcript: &mut Transcript,
        rng: &mut R,
    ) -> Round3Trace {
        let n = self.pk.n;
        let omega = self.pk.omega;
        let k1 = self.pk.k1;
        let k2 = self.pk.k2;

        // Reconstruct polynomials
        let a_poly = Polynomial::from_coeffs(round1.a_coeffs.clone());
        let b_poly = Polynomial::from_coeffs(round1.b_coeffs.clone());
        let c_poly = Polynomial::from_coeffs(round1.c_coeffs.clone());
        let z_poly = Polynomial::from_coeffs(round2.z_coeffs.clone());

        // We need to compute t(X) such that:
        // t(X) * Z_H(X) = (gate constraint) + α*(permutation constraint) + α²*(L_1 constraint)

        // Compute on a larger domain (4n) to avoid wraparound
        // Without blinding, degree is ~2n so 4n is sufficient
        let large_domain = Domain::new(4 * n).expect("Large domain creation failed");
        let coset_gen = Fr::from_u64(7); // A generator not in H

        // Evaluate all polynomials on coset of large domain
        let a_coset = a_poly.evaluate_coset(&large_domain, coset_gen);
        let b_coset = b_poly.evaluate_coset(&large_domain, coset_gen);
        let c_coset = c_poly.evaluate_coset(&large_domain, coset_gen);
        let z_coset = z_poly.evaluate_coset(&large_domain, coset_gen);

        // z(ωX) - shift z by ω
        let z_omega_poly = z_poly.shift(omega);
        let z_omega_coset = z_omega_poly.evaluate_coset(&large_domain, coset_gen);

        // Selector polynomials
        let q_m_coset = self.pk.q_m.evaluate_coset(&large_domain, coset_gen);
        let q_l_coset = self.pk.q_l.evaluate_coset(&large_domain, coset_gen);
        let q_r_coset = self.pk.q_r.evaluate_coset(&large_domain, coset_gen);
        let q_o_coset = self.pk.q_o.evaluate_coset(&large_domain, coset_gen);
        let q_c_coset = self.pk.q_c.evaluate_coset(&large_domain, coset_gen);

        // Permutation polynomials
        let s1_coset = self.pk.s_sigma1.evaluate_coset(&large_domain, coset_gen);
        let s2_coset = self.pk.s_sigma2.evaluate_coset(&large_domain, coset_gen);
        let s3_coset = self.pk.s_sigma3.evaluate_coset(&large_domain, coset_gen);

        // L_1 polynomial on coset
        let l1_coset = self.pk.l1.evaluate_coset(&large_domain, coset_gen);

        // Public input polynomial PI(X)
        // PI(X) = Σ_{i∈l} -x_i * L_i(X) where l is the set of public input indices
        let pi_poly = self.compute_public_input_polynomial(public_inputs);
        let pi_coset = pi_poly.evaluate_coset(&large_domain, coset_gen);

        // Z_H on coset
        let mut z_h_coset = vec![Fr::zero(); 4 * n];
        let mut x = coset_gen;
        for i in 0..(4 * n) {
            z_h_coset[i] = x.pow(n as u64) - Fr::one();
            x = x * large_domain.omega;
        }

        // Compute quotient polynomial evaluations on coset
        let mut t_coset = vec![Fr::zero(); 4 * n];

        // Sample for trace
        let mut gate_constraint_sample = Vec::new();
        let mut perm_constraint_sample = Vec::new();
        let mut l1_constraint_sample = Vec::new();

        let mut x = coset_gen;
        for i in 0..(4 * n) {
            // Gate constraint: q_M*a*b + q_L*a + q_R*b + q_O*c + q_C + PI
            let gate = q_m_coset[i] * a_coset[i] * b_coset[i]
                + q_l_coset[i] * a_coset[i]
                + q_r_coset[i] * b_coset[i]
                + q_o_coset[i] * c_coset[i]
                + q_c_coset[i]
                + pi_coset[i];

            // Permutation constraint (accumulated product)
            // z(X) * (a + β*X + γ)(b + β*k1*X + γ)(c + β*k2*X + γ)
            // - z(ωX) * (a + β*σ_1 + γ)(b + β*σ_2 + γ)(c + β*σ_3 + γ)
            let perm_num = z_coset[i]
                * (a_coset[i] + beta * x + gamma)
                * (b_coset[i] + beta * k1 * x + gamma)
                * (c_coset[i] + beta * k2 * x + gamma);

            let perm_denom = z_omega_coset[i]
                * (a_coset[i] + beta * s1_coset[i] + gamma)
                * (b_coset[i] + beta * s2_coset[i] + gamma)
                * (c_coset[i] + beta * s3_coset[i] + gamma);

            let perm = perm_num - perm_denom;

            // L_1 constraint: L_1(X) * (z(X) - 1)
            let l1_constraint = l1_coset[i] * (z_coset[i] - Fr::one());

            // Total numerator
            let numerator = gate + alpha * perm + alpha * alpha * l1_constraint;

            // Divide by Z_H(X)
            t_coset[i] = numerator * z_h_coset[i].inverse().expect("Z_H should not be zero on coset");

            // Save samples for trace
            if i < 4 {
                gate_constraint_sample.push(gate);
                perm_constraint_sample.push(perm);
                l1_constraint_sample.push(l1_constraint);
            }

            x = x * large_domain.omega;
        }

        // DEBUG: Check constraint at ALL points in H (should be zero)
        let mut omega_pow = Fr::one();
        let mut any_nonzero = false;
        for i in 0..n {
            let gate_i = self.pk.q_m.evaluate(&omega_pow) * a_poly.evaluate(&omega_pow) * b_poly.evaluate(&omega_pow)
                + self.pk.q_l.evaluate(&omega_pow) * a_poly.evaluate(&omega_pow)
                + self.pk.q_r.evaluate(&omega_pow) * b_poly.evaluate(&omega_pow)
                + self.pk.q_o.evaluate(&omega_pow) * c_poly.evaluate(&omega_pow)
                + self.pk.q_c.evaluate(&omega_pow)
                + pi_poly.evaluate(&omega_pow);
            let perm_i = z_poly.evaluate(&omega_pow)
                * (a_poly.evaluate(&omega_pow) + beta * omega_pow + gamma)
                * (b_poly.evaluate(&omega_pow) + beta * k1 * omega_pow + gamma)
                * (c_poly.evaluate(&omega_pow) + beta * k2 * omega_pow + gamma)
                - z_poly.evaluate(&(omega_pow * omega))
                * (a_poly.evaluate(&omega_pow) + beta * self.pk.s_sigma1.evaluate(&omega_pow) + gamma)
                * (b_poly.evaluate(&omega_pow) + beta * self.pk.s_sigma2.evaluate(&omega_pow) + gamma)
                * (c_poly.evaluate(&omega_pow) + beta * self.pk.s_sigma3.evaluate(&omega_pow) + gamma);
            let l1_i = self.pk.l1.evaluate(&omega_pow) * (z_poly.evaluate(&omega_pow) - Fr::one());
            let constraint_i = gate_i + alpha * perm_i + alpha * alpha * l1_i;
            if constraint_i != Fr::zero() {
                // Extra debug for public input position
                if i == 15 {
                    let gate_no_pi = self.pk.q_m.evaluate(&omega_pow) * a_poly.evaluate(&omega_pow) * b_poly.evaluate(&omega_pow)
                        + self.pk.q_l.evaluate(&omega_pow) * a_poly.evaluate(&omega_pow)
                        + self.pk.q_r.evaluate(&omega_pow) * b_poly.evaluate(&omega_pow)
                        + self.pk.q_o.evaluate(&omega_pow) * c_poly.evaluate(&omega_pow)
                        + self.pk.q_c.evaluate(&omega_pow);
                    let pi_val = pi_poly.evaluate(&omega_pow);
                }
                any_nonzero = true;
            }
            omega_pow = omega_pow * omega;
        }
        if !any_nonzero {
        }

        // IFFT to get t(X) coefficients
        let t_coeffs = large_domain.coset_ifft(&t_coset, coset_gen);
        let t_poly = Polynomial::from_coeffs(t_coeffs);

        // Split t(X) into t_lo, t_mid, t_hi of degree < n
        // t(X) = t_lo(X) + X^n * t_mid(X) + X^{2n} * t_hi(X)
        let t_degree = t_poly.degree().max(0) as usize;

        // Paper-aligned: deg(t) ≤ 3n+5, use 3 parts with quotient blinding
        // Ensure t_poly degree is within paper bound
        assert!(
            t_poly.coeffs.len() <= 3 * n + 6,
            "t_poly degree {} exceeds paper bound 3n+5 = {}",
            t_poly.coeffs.len().saturating_sub(1),
            3 * n + 5
        );

        // Split into 3 parts:
        // t_lo: coeffs [0..n), but needs n+1 length for quotient blinding X^n term
        // t_mid: coeffs [n..2n), but needs n+1 length for quotient blinding X^n term
        // t_hi: coeffs [2n..3n+5], length up to n+6
        let mut t_lo_coeffs = vec![Fr::zero(); n + 1];
        let mut t_mid_coeffs = vec![Fr::zero(); n + 1];
        let mut t_hi_coeffs = vec![Fr::zero(); n + 6];

        for (i, coeff) in t_poly.coeffs.iter().enumerate() {
            if i < n {
                t_lo_coeffs[i] = *coeff;
            } else if i < 2 * n {
                t_mid_coeffs[i - n] = *coeff;
            } else {
                t_hi_coeffs[i - 2 * n] = *coeff;
            }
        }

        // Quotient blinding (b10, b11) - Paper-aligned
        // t(X) = t_lo(X) + X^n·t_mid(X) + X^{2n}·t_hi(X)
        // Add blinding so individual commitments look random but sum reconstructs t:
        // t_lo  += b10·X^n
        // t_mid -= b10 (at X^0) and += b11·X^n
        // t_hi  -= b11 (at X^0)
        let b10 = Fr::random(rng);
        let b11 = Fr::random(rng);

        t_lo_coeffs[n] = t_lo_coeffs[n] + b10;      // + b10·X^n
        t_mid_coeffs[0] = t_mid_coeffs[0] - b10;    // - b10
        t_mid_coeffs[n] = t_mid_coeffs[n] + b11;    // + b11·X^n
        t_hi_coeffs[0] = t_hi_coeffs[0] - b11;      // - b11

        let t_lo = Polynomial::from_coeffs(t_lo_coeffs.clone());
        let t_mid = Polynomial::from_coeffs(t_mid_coeffs.clone());
        let t_hi = Polynomial::from_coeffs(t_hi_coeffs.clone());

        // Commit (only 3 commitments - paper aligned)
        let t_lo_comm = Commitment::commit(&t_lo, self.srs).point;
        let t_mid_comm = Commitment::commit(&t_mid, self.srs).point;
        let t_hi_comm = Commitment::commit(&t_hi, self.srs).point;

        // Absorb into transcript (only 3)
        transcript.absorb_g1("t_lo_comm", &t_lo_comm);
        transcript.absorb_g1("t_mid_comm", &t_mid_comm);
        transcript.absorb_g1("t_hi_comm", &t_hi_comm);

        Round3Trace {
            gate_constraint_sample,
            perm_constraint_sample,
            l1_constraint_sample,
            t_degree,
            t_lo_coeffs,
            t_mid_coeffs,
            t_hi_coeffs,
            t_lo_comm,
            t_mid_comm,
            t_hi_comm,
            b10,
            b11,
            zeta: Fr::zero(), // Set later
        }
    }

    /// Round 4: Compute polynomial evaluations at ζ
    fn round4(
        &self,
        round1: &Round1Trace,
        round2: &Round2Trace,
        _round3: &Round3Trace,
        zeta: Fr,
        transcript: &mut Transcript,
    ) -> Round4Trace {
        let omega = self.pk.omega;
        let zeta_omega = zeta * omega;

        // Reconstruct polynomials
        let a_poly = Polynomial::from_coeffs(round1.a_coeffs.clone());
        let b_poly = Polynomial::from_coeffs(round1.b_coeffs.clone());
        let c_poly = Polynomial::from_coeffs(round1.c_coeffs.clone());
        let z_poly = Polynomial::from_coeffs(round2.z_coeffs.clone());

        // Evaluate at ζ
        let a_zeta = a_poly.evaluate(&zeta);
        let b_zeta = b_poly.evaluate(&zeta);
        let c_zeta = c_poly.evaluate(&zeta);

        // Evaluate permutation polynomials at ζ
        let s_sigma1_zeta = self.pk.s_sigma1.evaluate(&zeta);
        let s_sigma2_zeta = self.pk.s_sigma2.evaluate(&zeta);

        // Evaluate z at ζω
        let z_zeta_omega = z_poly.evaluate(&zeta_omega);

        // Additional evaluations for the linearization polynomial
        let q_m_zeta = self.pk.q_m.evaluate(&zeta);
        let q_l_zeta = self.pk.q_l.evaluate(&zeta);
        let q_r_zeta = self.pk.q_r.evaluate(&zeta);
        let q_o_zeta = self.pk.q_o.evaluate(&zeta);
        let q_c_zeta = self.pk.q_c.evaluate(&zeta);

        let evaluations = EvaluationsTrace {
            a_zeta,
            b_zeta,
            c_zeta,
            s_sigma1_zeta,
            s_sigma2_zeta,
            z_zeta_omega,
            q_m_zeta,
            q_l_zeta,
            q_r_zeta,
            q_o_zeta,
            q_c_zeta,
        };

        // Absorb evaluations into transcript
        transcript.absorb_fr("a_zeta", &a_zeta);
        transcript.absorb_fr("b_zeta", &b_zeta);
        transcript.absorb_fr("c_zeta", &c_zeta);
        transcript.absorb_fr("s_sigma1_zeta", &s_sigma1_zeta);
        transcript.absorb_fr("s_sigma2_zeta", &s_sigma2_zeta);
        transcript.absorb_fr("z_zeta_omega", &z_zeta_omega);

        Round4Trace {
            zeta,
            zeta_omega,
            evaluations,
            v: Fr::zero(), // Set later
        }
    }

    /// Round 5: Compute opening proofs
    fn round5(
        &self,
        round1: &Round1Trace,
        round2: &Round2Trace,
        round3: &Round3Trace,
        round4: &Round4Trace,
        zeta: Fr,
        v: Fr,
        alpha: Fr,
        beta: Fr,
        gamma: Fr,
        public_inputs: &[Fr],
        transcript: &mut Transcript,
    ) -> Round5Trace {
        let n = self.pk.n;
        let omega = self.pk.omega;
        let k1 = self.pk.k1;
        let k2 = self.pk.k2;
        let zeta_omega = zeta * omega;

        // Reconstruct polynomials
        let a_poly = Polynomial::from_coeffs(round1.a_coeffs.clone());
        let b_poly = Polynomial::from_coeffs(round1.b_coeffs.clone());
        let c_poly = Polynomial::from_coeffs(round1.c_coeffs.clone());
        let z_poly = Polynomial::from_coeffs(round2.z_coeffs.clone());
        // Paper-aligned: only 3 quotient parts
        let t_lo = Polynomial::from_coeffs(round3.t_lo_coeffs.clone());
        let t_mid = Polynomial::from_coeffs(round3.t_mid_coeffs.clone());
        let t_hi = Polynomial::from_coeffs(round3.t_hi_coeffs.clone());

        let evals = &round4.evaluations;

        // Compute the linearization polynomial r(X)
        // r(X) is constructed such that r(ζ) can be computed from the proof elements

        // r(X) = a_bar * b_bar * q_M(X)
        //      + a_bar * q_L(X)
        //      + b_bar * q_R(X)
        //      + c_bar * q_O(X)
        //      + q_C(X)
        //      + α * [(a_bar + β*ζ + γ)(b_bar + β*k1*ζ + γ)(c_bar + β*k2*ζ + γ) * z(X)
        //           - (a_bar + β*S_σ1(ζ) + γ)(b_bar + β*S_σ2(ζ) + γ) * β * z_bar_omega * S_σ3(X)]
        //      + α² * L_1(ζ) * z(X)
        //      - Z_H(ζ) * [t_lo(X) + ζ^n * t_mid(X) + ζ^{2n} * t_hi(X)]

        let a_bar = evals.a_zeta;
        let b_bar = evals.b_zeta;
        let c_bar = evals.c_zeta;
        let s1_bar = evals.s_sigma1_zeta;
        let s2_bar = evals.s_sigma2_zeta;
        let z_bar_omega = evals.z_zeta_omega;

        // Z_H(ζ) = ζ^n - 1
        let z_h_zeta = zeta.pow(n as u64) - Fr::one();

        // L_1(ζ) = (ζ^n - 1) / (n * (ζ - 1))
        let l1_zeta = z_h_zeta * (Fr::from_u64(n as u64) * (zeta - Fr::one())).inverse().unwrap();

        // DEBUG: Print intermediate values

        // DEBUG: Verify constraint at zeta
        // constraint = gate + PI + α*perm + α²*L_1*(z-1) should equal t*Z_H
        let gate_at_zeta = a_bar * b_bar * self.pk.q_m.evaluate(&zeta)
            + a_bar * self.pk.q_l.evaluate(&zeta)
            + b_bar * self.pk.q_r.evaluate(&zeta)
            + c_bar * self.pk.q_o.evaluate(&zeta)
            + self.pk.q_c.evaluate(&zeta);

        let z_at_zeta = z_poly.evaluate(&zeta);
        let z_omega_at_zeta = z_poly.evaluate(&(zeta * omega));

        let s3_at_zeta = self.pk.s_sigma3.evaluate(&zeta);

        // Original permutation constraint at zeta
        let prod1 = (a_bar + beta * zeta + gamma)
            * (b_bar + beta * k1 * zeta + gamma)
            * (c_bar + beta * k2 * zeta + gamma);
        let prod2 = (a_bar + beta * s1_bar + gamma)
            * (b_bar + beta * s2_bar + gamma)
            * (c_bar + beta * s3_at_zeta + gamma);
        let perm_at_zeta = z_at_zeta * prod1 - z_bar_omega * prod2;

        // Compute the full constraint LHS: gate + PI + α*perm + α²*L_1*(z-1)
        // Need PI(ζ) - we'll compute it
        let pi_poly = self.compute_public_input_polynomial(public_inputs);
        let pi_at_zeta = pi_poly.evaluate(&zeta);

        let l1_constraint = l1_zeta * (z_at_zeta - Fr::one());
        let constraint_lhs = gate_at_zeta + pi_at_zeta + alpha * perm_at_zeta + alpha * alpha * l1_constraint;

        // Compute constraint RHS from t
        // t(ζ)*Z_H(ζ)

        // DEBUG: Also check constraint at a point in H (should be zero there)
        let omega_1 = omega; // First point in domain: ω^1
        let z_h_at_omega1 = omega_1.pow(n as u64) - Fr::one();

        // Gate contribution
        let mut r_poly = &self.pk.q_m * (a_bar * b_bar);
        r_poly = &r_poly + &(&self.pk.q_l * a_bar);
        r_poly = &r_poly + &(&self.pk.q_r * b_bar);
        r_poly = &r_poly + &(&self.pk.q_o * c_bar);
        r_poly = &r_poly + &self.pk.q_c;

        // Permutation contribution (part with z(X))
        let perm_coeff1 = alpha
            * (a_bar + beta * zeta + gamma)
            * (b_bar + beta * k1 * zeta + gamma)
            * (c_bar + beta * k2 * zeta + gamma);

        // Permutation contribution (part with S_σ3(X))
        let perm_coeff2 = Fr::zero()
            - alpha
                * (a_bar + beta * s1_bar + gamma)
                * (b_bar + beta * s2_bar + gamma)
                * beta
                * z_bar_omega;

        r_poly = &r_poly + &(&z_poly * perm_coeff1);
        r_poly = &r_poly + &(&self.pk.s_sigma3 * perm_coeff2);

        // L_1 constraint contribution
        r_poly = &r_poly + &(&z_poly * (alpha * alpha * l1_zeta));

        // DEBUG: Print r_poly evaluation before quotient term
        let r_before_quotient = r_poly.evaluate(&zeta);

        // Quotient polynomial contribution
        // Paper-aligned: t(X) = t_lo(X) + ζ^n·t_mid(X) + ζ^{2n}·t_hi(X)
        let zeta_n = zeta.pow(n as u64);
        let zeta_2n = zeta_n * zeta_n;

        let t_mid_scaled = &t_mid * zeta_n;
        let t_hi_scaled = &t_hi * zeta_2n;
        let t_combined = (&t_lo + &t_mid_scaled) + t_hi_scaled;

        // DEBUG: Print t(zeta) and quotient contribution
        let t_zeta = t_combined.evaluate(&zeta);
        let z_h_t_zeta = z_h_zeta * t_zeta;

        r_poly = &r_poly - &(&t_combined * z_h_zeta);

        let r_zeta = r_poly.evaluate(&zeta);

        // Debug: commit to r_poly and print it
        let r_comm_prover = Commitment::commit(&r_poly, self.srs).point;

        // Compute W_ζ(X) - opening proof at ζ
        // We open: r, a, b, c, S_σ1, S_σ2 at ζ
        // W_ζ(X) = (r(X) - r(ζ) + v*(a(X) - a(ζ)) + v²*(b(X) - b(ζ)) + ...) / (X - ζ)

        let v2 = v * v;
        let v3 = v2 * v;
        let v4 = v3 * v;
        let v5 = v4 * v;

        let mut w_zeta_num = &r_poly - &Polynomial::from_coeffs(vec![r_zeta]);
        w_zeta_num = &w_zeta_num + &((&a_poly - &Polynomial::from_coeffs(vec![a_bar])) * v);
        w_zeta_num = &w_zeta_num + &((&b_poly - &Polynomial::from_coeffs(vec![b_bar])) * v2);
        w_zeta_num = &w_zeta_num + &((&c_poly - &Polynomial::from_coeffs(vec![c_bar])) * v3);
        w_zeta_num =
            &w_zeta_num + &((&self.pk.s_sigma1 - &Polynomial::from_coeffs(vec![s1_bar])) * v4);
        w_zeta_num =
            &w_zeta_num + &((&self.pk.s_sigma2 - &Polynomial::from_coeffs(vec![s2_bar])) * v5);

        let w_zeta_poly = w_zeta_num.div_by_linear(&zeta);

        // Compute W_{ζω}(X) - opening proof at ζω
        // We open: z at ζω
        // W_{ζω}(X) = (z(X) - z(ζω)) / (X - ζω)

        let w_zeta_omega_num = &z_poly - &Polynomial::from_coeffs(vec![z_bar_omega]);
        let w_zeta_omega_poly = w_zeta_omega_num.div_by_linear(&zeta_omega);

        // Commit to opening polynomials
        let w_zeta_comm = Commitment::commit(&w_zeta_poly, self.srs).point;
        let w_zeta_omega_comm = Commitment::commit(&w_zeta_omega_poly, self.srs).point;

        // Absorb into transcript (for batching challenge u)
        transcript.absorb_g1("w_zeta_comm", &w_zeta_comm);
        transcript.absorb_g1("w_zeta_omega_comm", &w_zeta_omega_comm);

        let u = transcript.squeeze_challenge("u");

        Round5Trace {
            r_coeffs: r_poly.coeffs.clone(),
            r_zeta,
            w_zeta_coeffs: w_zeta_poly.coeffs.clone(),
            w_zeta_comm,
            w_zeta_omega_coeffs: w_zeta_omega_poly.coeffs.clone(),
            w_zeta_omega_comm,
            u,
        }
    }

    /// Compute the public input polynomial
    fn compute_public_input_polynomial(&self, public_inputs: &[Fr]) -> Polynomial {
        let n = self.pk.n;

        // PI(X) = Σ_{i∈l} -x_i * L_i(X)
        // where l are the public input positions

        let mut pi_evals = vec![Fr::zero(); n];

        for (i, &pos) in self.cs.public_input_positions.iter().enumerate() {
            if i < public_inputs.len() {
                // The public input affects the c-wire at position pos
                // In our range proof, the public input is at the final gate
                pi_evals[pos] = Fr::zero() - public_inputs[i];
            }
        }

        Polynomial::from_evaluations(&pi_evals, self.domain)
    }

    /// Build circuit trace for visualization
    fn build_circuit_trace(&self, public_inputs: &[Fr]) -> CircuitTrace {
        let gates: Vec<GateTrace> = self
            .cs
            .gates
            .iter()
            .map(|g| {
                let a = g.a.unwrap_or(Fr::zero());
                let b = g.b.unwrap_or(Fr::zero());
                let c = g.c.unwrap_or(Fr::zero());

                GateTrace {
                    index: g.index,
                    gate_type: g.gate_type.clone(),
                    description: g.description.clone(),
                    selectors: SelectorsTrace {
                        q_m: g.q_m,
                        q_l: g.q_l,
                        q_r: g.q_r,
                        q_o: g.q_o,
                        q_c: g.q_c,
                    },
                    wires: WiresTrace { a, b, c },
                    constraint_check: if g.is_satisfied() {
                        "✓ Satisfied".to_string()
                    } else {
                        "✗ Not satisfied".to_string()
                    },
                }
            })
            .collect();

        let public_input_traces: Vec<PublicInputTrace> = public_inputs
            .iter()
            .enumerate()
            .map(|(i, pi)| PublicInputTrace {
                index: i,
                value: *pi,
                description: format!("Public input {}", i),
            })
            .collect();

        let copy_constraints: Vec<CopyConstraintTrace> = self
            .cs
            .copy_constraints
            .iter()
            .map(|cc| CopyConstraintTrace {
                wire1: format!("{}[{}]", wire_type_char(cc.wire1.wire_type), cc.wire1.gate),
                wire2: format!("{}[{}]", wire_type_char(cc.wire2.wire_type), cc.wire2.gate),
                reason: cc.reason.clone(),
            })
            .collect();

        CircuitTrace {
            num_gates: self.cs.num_gates,
            n: self.cs.n,
            public_inputs: public_input_traces,
            gates,
            copy_constraints,
        }
    }
}

fn wire_type_char(wt: crate::circuit::WireType) -> char {
    match wt {
        crate::circuit::WireType::A => 'a',
        crate::circuit::WireType::B => 'b',
        crate::circuit::WireType::C => 'c',
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::RangeProofCircuit;
    use crate::plonk::preprocess::preprocess;

    #[test]
    fn test_prover_creates_proof() {
        let circuit = RangeProofCircuit::new(8, 42);
        let cs = &circuit.constraint_system;

        // Create SRS
        let srs = Srs::simulate_ceremony(cs.n + 10, 2);

        // Preprocess
        let data = preprocess(cs, &srs);

        // Create prover
        let prover = Prover::new(
            cs,
            &data.proving_key,
            &data.permutation,
            &data.domain,
            &srs,
        );

        // Public input is x = 42
        let public_inputs = vec![Fr::from_u64(42)];

        // Generate proof
        let (proof, trace) = prover.prove_with_trace(&public_inputs);

        // Basic sanity checks
        assert!(!proof.a_comm.is_identity());
        assert!(!proof.z_comm.is_identity());
        assert!(!proof.t_lo_comm.is_identity());
        assert!(!proof.w_zeta_comm.is_identity());

        // Trace should have correct dimensions
        assert_eq!(trace.circuit.n, cs.n);
        assert_eq!(trace.round1.a_evals.len(), cs.n);
        assert_eq!(trace.round2.z_evals.len(), cs.n);
    }
}
