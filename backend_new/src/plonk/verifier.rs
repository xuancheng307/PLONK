//! PLONK Verifier
//!
//! Implements the PLONK verifier following Section 8.4 of the paper.
//!
//! The verifier checks:
//! 1. Reconstructs the transcript to get challenges
//! 2. Evaluates the vanishing polynomial Z_H(ζ)
//! 3. Evaluates L_1(ζ)
//! 4. Computes the public input polynomial evaluation PI(ζ)
//! 5. Computes the linearization commitment
//! 6. Performs the batched pairing check

use crate::curve::{pairing, pairing_check, G1Affine, G1Projective, G2Affine};
use crate::field::Fr;
use crate::kzg::Srs;
use crate::plonk::types::*;
use crate::polynomial::Polynomial;
use crate::transcript::Transcript;
use serde::{Deserialize, Serialize};

/// The PLONK verifier
pub struct Verifier<'a> {
    /// The verification key
    pub vk: &'a VerificationKey,
    /// The SRS (only needs [1]_2 and [τ]_2)
    pub srs: &'a Srs,
}

impl<'a> Verifier<'a> {
    /// Create a new verifier
    pub fn new(vk: &'a VerificationKey, srs: &'a Srs) -> Self {
        Verifier { vk, srs }
    }

    /// Verify a proof
    pub fn verify(&self, proof: &Proof, public_inputs: &[Fr]) -> bool {
        let (result, _trace) = self.verify_with_trace(proof, public_inputs);
        result
    }

    /// Verify a proof with detailed trace for visualization
    pub fn verify_with_trace(&self, proof: &Proof, public_inputs: &[Fr]) -> (bool, VerifierTrace) {
        let n = self.vk.n;
        let omega = self.vk.omega;
        let k1 = self.vk.k1;
        let k2 = self.vk.k2;

        // ==========================================
        // Step 1: Reconstruct the transcript
        // ==========================================
        let mut transcript = Transcript::new(b"PLONK-v1");

        // Absorb public inputs
        for (i, pi) in public_inputs.iter().enumerate() {
            transcript.absorb_fr(&format!("pi_{}", i), pi);
        }

        // Round 1 commitments
        transcript.absorb_g1("a_comm", &proof.a_comm);
        transcript.absorb_g1("b_comm", &proof.b_comm);
        transcript.absorb_g1("c_comm", &proof.c_comm);

        let beta = transcript.squeeze_challenge("beta");
        let gamma = transcript.squeeze_challenge("gamma");

        // Round 2 commitment
        transcript.absorb_g1("z_comm", &proof.z_comm);

        let alpha = transcript.squeeze_challenge("alpha");

        // Round 3 commitments (paper-aligned: only 3)
        transcript.absorb_g1("t_lo_comm", &proof.t_lo_comm);
        transcript.absorb_g1("t_mid_comm", &proof.t_mid_comm);
        transcript.absorb_g1("t_hi_comm", &proof.t_hi_comm);

        let zeta = transcript.squeeze_challenge("zeta");

        // Round 4 evaluations
        transcript.absorb_fr("a_zeta", &proof.a_eval);
        transcript.absorb_fr("b_zeta", &proof.b_eval);
        transcript.absorb_fr("c_zeta", &proof.c_eval);
        transcript.absorb_fr("s_sigma1_zeta", &proof.s_sigma1_eval);
        transcript.absorb_fr("s_sigma2_zeta", &proof.s_sigma2_eval);
        transcript.absorb_fr("z_zeta_omega", &proof.z_omega_eval);

        let v = transcript.squeeze_challenge("v");

        // Round 5 commitments
        transcript.absorb_g1("w_zeta_comm", &proof.w_zeta_comm);
        transcript.absorb_g1("w_zeta_omega_comm", &proof.w_zeta_omega_comm);

        let u = transcript.squeeze_challenge("u");

        let challenges = TranscriptChallengesTrace {
            beta,
            gamma,
            alpha,
            zeta,
            v,
            u,
        };

        // ==========================================
        // Step 2: Evaluate Z_H(ζ)
        // ==========================================
        let z_h_zeta = zeta.pow(n as u64) - Fr::one();

        // ==========================================
        // Step 3: Evaluate L_1(ζ)
        // ==========================================
        // L_1(ζ) = (ζ^n - 1) / (n * (ζ - 1))
        let l1_zeta = if zeta == Fr::one() {
            Fr::one() // L_1(1) = 1
        } else {
            z_h_zeta * (Fr::from_u64(n as u64) * (zeta - Fr::one())).inverse().unwrap()
        };

        // ==========================================
        // Step 4: Compute PI(ζ)
        // ==========================================
        // PI(ζ) = Σ_{i∈l} -x_i * L_i(ζ)
        // For simplicity, we compute L_i(ζ) directly

        let mut pi_zeta = Fr::zero();
        for (i, pi) in public_inputs.iter().enumerate() {
            // Get the actual position from verification key
            let pos = if i < self.vk.public_input_positions.len() {
                self.vk.public_input_positions[i]
            } else {
                continue; // Skip if no position defined
            };

            // L_pos(ζ) = ω^pos * Z_H(ζ) / (n * (ζ - ω^pos))
            let omega_pos = omega.pow(pos as u64);

            if zeta != omega_pos {
                let l_pos_zeta = omega_pos * z_h_zeta
                    * (Fr::from_u64(n as u64) * (zeta - omega_pos))
                        .inverse()
                        .unwrap();
                pi_zeta = pi_zeta - *pi * l_pos_zeta;
            }
        }

        // ==========================================
        // Step 5: Compute linearization commitment [r]_1
        // ==========================================
        let a_bar = proof.a_eval;
        let b_bar = proof.b_eval;
        let c_bar = proof.c_eval;
        let s1_bar = proof.s_sigma1_eval;
        let s2_bar = proof.s_sigma2_eval;
        let z_bar_omega = proof.z_omega_eval;

        // r(ζ) = a_bar * b_bar * q_M(ζ) + a_bar * q_L(ζ) + b_bar * q_R(ζ) + c_bar * q_O(ζ) + q_C(ζ) + PI(ζ)
        //      + α * [(a_bar + β*ζ + γ)(b_bar + β*k1*ζ + γ)(c_bar + β*k2*ζ + γ) * z(ζ)
        //           - (a_bar + β*s1_bar + γ)(b_bar + β*s2_bar + γ) * β * z_bar_omega * S_σ3(ζ)]
        //      + α² * L_1(ζ) * z(ζ)
        //      - Z_H(ζ) * t(ζ)

        // The verifier computes [r]_1 as a linear combination of commitments
        // [r]_1 = a_bar * b_bar * [q_M] + a_bar * [q_L] + b_bar * [q_R] + c_bar * [q_O] + [q_C]
        //       + (α * perm_coeff1 + α² * L_1(ζ)) * [z]
        //       + α * perm_coeff2 * [S_σ3]
        //       - Z_H(ζ) * ([t_lo] + ζ^n * [t_mid] + ζ^{2n} * [t_hi])

        let perm_coeff1 = (a_bar + beta * zeta + gamma)
            * (b_bar + beta * k1 * zeta + gamma)
            * (c_bar + beta * k2 * zeta + gamma);

        let perm_coeff2 = Fr::zero()
            - (a_bar + beta * s1_bar + gamma)
                * (b_bar + beta * s2_bar + gamma)
                * beta
                * z_bar_omega;

        // Paper-aligned: only zeta_n and zeta_2n needed (3 quotient parts)
        let zeta_n = zeta.pow(n as u64);
        let zeta_2n = zeta_n * zeta_n;

        // Compute [r]_1 using MSM
        let mut r_comm = G1Projective::identity();

        // Selector terms
        r_comm = r_comm + G1Projective::from(self.vk.q_m_comm) * (a_bar * b_bar);
        r_comm = r_comm + G1Projective::from(self.vk.q_l_comm) * a_bar;
        r_comm = r_comm + G1Projective::from(self.vk.q_r_comm) * b_bar;
        r_comm = r_comm + G1Projective::from(self.vk.q_o_comm) * c_bar;
        r_comm = r_comm + G1Projective::from(self.vk.q_c_comm);

        // Permutation z term
        let z_coeff = alpha * perm_coeff1 + alpha * alpha * l1_zeta;
        r_comm = r_comm + G1Projective::from(proof.z_comm) * z_coeff;

        // Permutation S_σ3 term
        r_comm = r_comm + G1Projective::from(self.vk.s_sigma3_comm) * (alpha * perm_coeff2);

        // Quotient polynomial terms (paper-aligned: only 3 parts)
        let t_coeff = Fr::zero() - z_h_zeta;
        r_comm = r_comm + G1Projective::from(proof.t_lo_comm) * t_coeff;
        r_comm = r_comm + G1Projective::from(proof.t_mid_comm) * (t_coeff * zeta_n);
        r_comm = r_comm + G1Projective::from(proof.t_hi_comm) * (t_coeff * zeta_2n);

        let r_comm_affine = G1Affine::from(r_comm);

        // Compute r(ζ) - the expected evaluation
        // r(ζ) = r_0 where r_0 is the constant term in the linearization
        // r_0 = PI(ζ) - L_1(ζ) * α²
        //     + α * (a_bar + β*s1_bar + γ)(b_bar + β*s2_bar + γ)(c_bar + β*S_σ3(ζ) + γ) * z_bar_omega
        //     - but this is complex, we use a different approach

        // Actually, we need to compute what r(ζ) should be
        // From the prover's perspective:
        // r(ζ) = (gate constraint at ζ) + α * (perm constraint at ζ) + α² * L_1(ζ) * (z(ζ) - 1) - Z_H(ζ) * t(ζ)
        // Since t(X) = (constraints) / Z_H(X), we have (constraints) = t(X) * Z_H(X)
        // So at ζ: r(ζ) = t(ζ) * Z_H(ζ) + offset terms - Z_H(ζ) * t(ζ) + remaining

        // For verification, we use the identity:
        // The linearization polynomial satisfies: r(ζ) = 0 (when the proof is valid)
        // But with the construction in Round 5, we have:
        // [r]_1 corresponds to r(X) where r(ζ) = r_eval (a specific value)

        // The verifier computes:
        // r_eval = PI(ζ) + l1_zeta * α² * (0 - 1) + ...
        // This is complex - let's use the batched opening approach

        // ==========================================
        // Step 6: Batched pairing check
        // ==========================================

        // The verification equation is:
        // e([W_ζ] + u[W_{ζω}], [τ]_2) = e([F] + ζ[W_ζ] + uζω[W_{ζω}] - [E], [1]_2)
        //
        // where:
        // [F] = [r]_1 + v[a] + v²[b] + v³[c] + v⁴[S_σ1] + v⁵[S_σ2] + u[z]
        // [E] = [1]_1 * (r_eval + v*a_bar + v²*b_bar + v³*c_bar + v⁴*s1_bar + v⁵*s2_bar + u*z_bar_omega)

        let v2 = v * v;
        let v3 = v2 * v;
        let v4 = v3 * v;
        let v5 = v4 * v;

        // Compute [F]
        let mut f_comm = r_comm;
        f_comm = f_comm + G1Projective::from(proof.a_comm) * v;
        f_comm = f_comm + G1Projective::from(proof.b_comm) * v2;
        f_comm = f_comm + G1Projective::from(proof.c_comm) * v3;
        f_comm = f_comm + G1Projective::from(self.vk.s_sigma1_comm) * v4;
        f_comm = f_comm + G1Projective::from(self.vk.s_sigma2_comm) * v5;
        f_comm = f_comm + G1Projective::from(proof.z_comm) * u;

        let f_comm_affine = G1Affine::from(f_comm);

        // Paper-aligned: Compute r₀ (constant term of linearization polynomial)
        //
        // The verifier cannot compute r(ζ) directly because r(X) contains
        // witness polynomials. Instead, we compute r₀ which is the part that
        // the verifier CAN compute from public information.
        //
        // Paper formula:
        // r₀ = PI(ζ) - α²·L₁(ζ) - α·z̄_ω·(ā+β·s̄₁+γ)·(b̄+β·s̄₂+γ)·(c̄+γ)
        //
        // This comes from the permutation argument's partial linearization:
        // The S_σ3 term uses β*S_σ3(X) in r(X), so we need to account for
        // the missing constant (c̄+γ) multiplied by the other factors.
        let perm_term = alpha
            * z_bar_omega
            * (a_bar + beta * s1_bar + gamma)
            * (b_bar + beta * s2_bar + gamma)
            * (c_bar + gamma);

        let r0 = pi_zeta - alpha * alpha * l1_zeta - perm_term;

        // Compute [E] = [1]_1 * e_eval
        // Paper-aligned: e_eval uses -r₀ (note the sign!)
        // e_eval = -r₀ + v·ā + v²·b̄ + v³·c̄ + v⁴·s̄₁ + v⁵·s̄₂ + u·z̄_ω
        let e_eval = Fr::zero() - r0
            + v * a_bar
            + v2 * b_bar
            + v3 * c_bar
            + v4 * s1_bar
            + v5 * s2_bar
            + u * z_bar_omega;


        let e_comm = G1Projective::from(G1Affine::generator()) * e_eval;
        let e_comm_affine = G1Affine::from(e_comm);

        // Left side: [W_ζ] + u[W_{ζω}]
        let w_combined =
            G1Projective::from(proof.w_zeta_comm) + G1Projective::from(proof.w_zeta_omega_comm) * u;
        let w_combined_affine = G1Affine::from(w_combined);

        // Right side: [F] + ζ[W_ζ] + uζω[W_{ζω}] - [E]
        let zeta_omega = zeta * omega;
        let right_inner = f_comm
            + G1Projective::from(proof.w_zeta_comm) * zeta
            + G1Projective::from(proof.w_zeta_omega_comm) * (u * zeta_omega)
            - e_comm;
        let right_inner_affine = G1Affine::from(right_inner);

        // Pairing check: e(w_combined, [τ]_2) = e(right_inner, [1]_2)
        // Equivalently: e(w_combined, [τ]_2) * e(-right_inner, [1]_2) = 1


        // pairing_check checks e(p1, q1) = e(p2, q2), i.e., e(p1, q1) * e(-p2, q2) = 1
        // We want: e(w_combined, [τ]_2) = e(right_inner, [1]_2)
        // So we call pairing_check(w_combined, [τ]_2, right_inner, [1]_2)
        let pairing_result = pairing_check(
            &w_combined_affine,
            &self.srs.g2_tau,
            &right_inner_affine,
            &G2Affine::generator(),
        );

        // Build trace
        let trace = VerifierTrace {
            transcript_challenges: challenges,
            z_h_zeta,
            l1_zeta,
            pi_zeta,
            linearization: LinearizationTrace {
                r_comm: r_comm_affine,
                r_zeta: r0, // This is r₀, the constant term (paper-aligned)
            },
            pairing_check: PairingCheckTrace {
                f_comm: f_comm_affine,
                e_comm: e_comm_affine,
                left_pairing_input: PairingInput {
                    g1: w_combined_affine,
                    g2_description: "[τ]_2".to_string(),
                },
                right_pairing_input: PairingInput {
                    g1: right_inner_affine,
                    g2_description: "[1]_2".to_string(),
                },
                pairing_result,
            },
            is_valid: pairing_result,
        };

        (pairing_result, trace)
    }
}

// Add neg() method for G1Projective
trait Neg {
    fn neg(self) -> Self;
}

impl Neg for G1Projective {
    fn neg(self) -> Self {
        use ark_ec::CurveGroup;
        -self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::RangeProofCircuit;
    use crate::plonk::preprocess::preprocess;
    use crate::plonk::prover::Prover;

    #[test]
    fn test_verify_valid_proof() {
        let circuit = RangeProofCircuit::new(8, 42);

        // First verify the witness is valid
        println!("=== Witness Verification ===");
        let witness_valid = circuit.verify_witness();
        println!("Witness satisfies constraints: {}", witness_valid);
        assert!(witness_valid, "Witness should satisfy all constraints");

        let cs = &circuit.constraint_system;

        // Create SRS
        let srs = Srs::simulate_ceremony(cs.n + 10, 2);

        // Preprocess
        let data = preprocess(cs, &srs);

        // Create prover and generate proof with trace
        let prover = Prover::new(
            cs,
            &data.proving_key,
            &data.permutation,
            &data.domain,
            &srs,
        );

        let public_inputs = vec![Fr::from_u64(42)];
        let (proof, prover_trace) = prover.prove_with_trace(&public_inputs);

        // Debug: print prover's r(ζ) and challenges
        println!("=== Prover Debug ===");
        println!("r_zeta (prover): {:?}", prover_trace.round5.r_zeta);
        println!("Prover challenges:");
        println!("  alpha: {:?}", prover_trace.round2.alpha);
        println!("  beta: {:?}", prover_trace.round1.beta);
        println!("  gamma: {:?}", prover_trace.round1.gamma);
        println!("  zeta: {:?}", prover_trace.round3.zeta);
        println!("  v: {:?}", prover_trace.round4.v);
        println!("  u: {:?}", prover_trace.round5.u);

        // Create verifier
        let verifier = Verifier::new(&data.verification_key, &srs);

        // Verify
        let (is_valid, trace) = verifier.verify_with_trace(&proof, &public_inputs);

        // Print debug info
        println!("\n=== Verifier Debug ===");
        println!("Verification result: {}", is_valid);
        println!("z_h_zeta: {:?}", trace.z_h_zeta);
        println!("l1_zeta: {:?}", trace.l1_zeta);
        println!("pi_zeta: {:?}", trace.pi_zeta);
        println!("r_zeta (verifier): {:?}", trace.linearization.r_zeta);

        // Compute the missing_perm_term for debugging
        let alpha = trace.transcript_challenges.alpha;
        let beta = trace.transcript_challenges.beta;
        let gamma = trace.transcript_challenges.gamma;
        let l1_zeta = trace.l1_zeta;
        let a_bar = proof.a_eval;
        let b_bar = proof.b_eval;
        let c_bar = proof.c_eval;
        let s1_bar = proof.s_sigma1_eval;
        let s2_bar = proof.s_sigma2_eval;
        let z_bar_omega = proof.z_omega_eval;

        let missing = alpha * z_bar_omega
            * (a_bar + beta * s1_bar + gamma)
            * (b_bar + beta * s2_bar + gamma)
            * (c_bar + gamma);
        let r_expected = alpha * alpha * l1_zeta - trace.pi_zeta + missing;
        println!("missing_perm_term: {:?}", missing);
        println!("α²*L_1: {:?}", alpha * alpha * l1_zeta);
        println!("r_expected = α²L_1 - PI + missing: {:?}", r_expected);
        println!("r_diff (prover - verifier): ?");  // We'll check if prover's matches

        println!("Challenges:");
        println!("  alpha: {:?}", trace.transcript_challenges.alpha);
        println!("  beta: {:?}", trace.transcript_challenges.beta);
        println!("  gamma: {:?}", trace.transcript_challenges.gamma);
        println!("  zeta: {:?}", trace.transcript_challenges.zeta);
        println!("  v: {:?}", trace.transcript_challenges.v);
        println!("  u: {:?}", trace.transcript_challenges.u);

        // The proof should be valid
        assert!(is_valid, "Valid proof should verify successfully");
    }

    #[test]
    fn test_verify_invalid_proof() {
        let circuit = RangeProofCircuit::new(8, 42);
        let cs = &circuit.constraint_system;

        let srs = Srs::simulate_ceremony(cs.n + 10, 2);
        let data = preprocess(cs, &srs);

        let prover = Prover::new(
            cs,
            &data.proving_key,
            &data.permutation,
            &data.domain,
            &srs,
        );

        // Prove for x=42
        let public_inputs = vec![Fr::from_u64(42)];
        let proof = prover.prove(&public_inputs);

        // Verify with wrong public input (x=43)
        let verifier = Verifier::new(&data.verification_key, &srs);
        let wrong_inputs = vec![Fr::from_u64(43)];

        let is_valid = verifier.verify(&proof, &wrong_inputs);

        // Should fail with wrong public input
        assert!(!is_valid);
    }
}
