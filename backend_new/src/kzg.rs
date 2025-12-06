//! KZG (Kate-Zaverucha-Goldberg) Polynomial Commitment Scheme
//!
//! This module implements the KZG polynomial commitment scheme with:
//! - Updatable SRS generation (simulating multi-party ceremony)
//! - Polynomial commitment
//! - Opening proofs (single and batch)
//! - Verification
//!
//! Reference: "Constant-Size Commitments to Polynomials and Their Applications"
//! (Kate, Zaverucha, Goldberg, 2010)

use crate::curve::{G1Affine, G1Projective, G2Affine, G2Projective, pairing, pairing_check};
use crate::field::Fr;
use crate::polynomial::Polynomial;
use rand::Rng;
use serde::{Deserialize, Serialize};

/// Structured Reference String (SRS) for KZG
///
/// Contains powers of τ in both G1 and G2:
/// - G1: [1]₁, [τ]₁, [τ²]₁, ..., [τ^d]₁
/// - G2: [1]₂, [τ]₂
///
/// τ is the "toxic waste" that must be destroyed after setup
#[derive(Clone, Debug)]
pub struct Srs {
    /// Maximum polynomial degree supported
    pub max_degree: usize,
    /// Powers of τ in G1: [τ^i]₁ for i = 0, 1, ..., max_degree
    pub g1_powers: Vec<G1Affine>,
    /// [1]₂ - Generator of G2
    pub g2_generator: G2Affine,
    /// [τ]₂ - τ times the G2 generator
    pub g2_tau: G2Affine,
}

/// Transcript of a multi-party ceremony round
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CeremonyRound {
    pub participant_id: usize,
    pub contribution_hash: String,
}

/// Result of the multi-party ceremony
#[derive(Clone, Debug)]
pub struct CeremonyResult {
    pub srs: Srs,
    pub rounds: Vec<CeremonyRound>,
    pub final_hash: String,
}

/// A polynomial commitment (a point in G1)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment {
    pub point: G1Affine,
}

/// An opening proof (a point in G1)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpeningProof(pub G1Affine);

impl Srs {
    /// Generate SRS with a single secret τ (for testing only)
    /// In production, use multi-party ceremony
    pub fn generate_insecure<R: Rng>(rng: &mut R, max_degree: usize) -> Self {
        let tau = Fr::random(rng);
        Self::from_tau(&tau, max_degree)
    }

    /// Generate SRS from a known τ (internal use)
    fn from_tau(tau: &Fr, max_degree: usize) -> Self {
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();

        // Compute [τ^i]₁ for i = 0, 1, ..., max_degree
        let mut g1_powers = Vec::with_capacity(max_degree + 1);
        let mut tau_power = Fr::one();

        for _ in 0..=max_degree {
            let point = g1.to_projective().scalar_mul(&tau_power).to_affine();
            g1_powers.push(point);
            tau_power = tau_power * *tau;
        }

        // Compute [τ]₂
        let g2_tau = g2.to_projective().scalar_mul(tau).to_affine();

        Srs {
            max_degree,
            g1_powers,
            g2_generator: g2,
            g2_tau,
        }
    }

    /// Simulate a multi-party ceremony (convenience wrapper using thread_rng)
    pub fn simulate_ceremony(max_degree: usize, num_participants: usize) -> Srs {
        use rand::thread_rng;
        let mut rng = thread_rng();
        Self::simulate_ceremony_with_rng(&mut rng, max_degree, num_participants).srs
    }

    /// Simulate a multi-party ceremony with k participants
    ///
    /// Each participant contributes a random value r_i, and the final
    /// secret is τ = τ_1 * τ_2 * ... * τ_k (or equivalently, sum)
    ///
    /// As long as one participant is honest and destroys their r_i,
    /// the final τ is unknown to everyone.
    pub fn simulate_ceremony_with_rng<R: Rng>(
        rng: &mut R,
        max_degree: usize,
        num_participants: usize,
    ) -> CeremonyResult {
        use sha2::{Sha256, Digest};

        let mut rounds = Vec::with_capacity(num_participants);

        // Start with the generator
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();

        // Initial SRS (τ = 1)
        let mut current_g1_powers: Vec<G1Projective> = (0..=max_degree)
            .map(|_| g1.to_projective())
            .collect();
        let mut current_g2_tau = g2.to_projective();

        // Each participant updates the SRS
        for i in 0..num_participants {
            // Participant's secret contribution
            let r = Fr::random(rng);

            // Update G1 powers: [τ^j]₁ → [(τ*r)^j]₁ = [τ^j * r^j]₁
            let mut r_power = Fr::one();
            for power in current_g1_powers.iter_mut() {
                *power = power.scalar_mul(&r_power);
                r_power = r_power * r;
            }

            // Update G2: [τ]₂ → [τ*r]₂
            current_g2_tau = current_g2_tau.scalar_mul(&r);

            // Create hash of this round's contribution
            let mut hasher = Sha256::new();
            hasher.update(&i.to_le_bytes());
            // Add first few G1 points to the hash
            for p in current_g1_powers.iter().take(3) {
                hasher.update(&p.to_affine().to_compressed_bytes());
            }
            let hash = hex::encode(hasher.finalize());

            rounds.push(CeremonyRound {
                participant_id: i,
                contribution_hash: hash,
            });

            // r is now "destroyed" (goes out of scope)
        }

        // Convert to affine
        let g1_powers: Vec<G1Affine> = current_g1_powers
            .iter()
            .map(|p| p.to_affine())
            .collect();
        let g2_tau = current_g2_tau.to_affine();

        // Final hash
        let mut hasher = sha2::Sha256::new();
        for p in &g1_powers {
            hasher.update(&p.to_compressed_bytes());
        }
        hasher.update(&g2_tau.to_compressed_bytes());
        let final_hash = hex::encode(hasher.finalize());

        let srs = Srs {
            max_degree,
            g1_powers,
            g2_generator: g2,
            g2_tau,
        };

        CeremonyResult {
            srs,
            rounds,
            final_hash,
        }
    }

    /// Verify that the SRS is well-formed using pairing checks
    /// e([τ^i]₁, [1]₂) = e([τ^{i-1}]₁, [τ]₂)
    pub fn verify(&self) -> bool {
        if self.g1_powers.len() < 2 {
            return true;
        }

        // Check: e([τ]₁, [1]₂) = e([1]₁, [τ]₂)
        let check = pairing_check(
            &self.g1_powers[1],
            &self.g2_generator,
            &self.g1_powers[0],
            &self.g2_tau,
        );

        if !check {
            return false;
        }

        // For efficiency, only check a few more powers
        for i in [2, 5, self.max_degree].iter() {
            if *i >= self.g1_powers.len() {
                continue;
            }
            let check = pairing_check(
                &self.g1_powers[*i],
                &self.g2_generator,
                &self.g1_powers[i - 1],
                &self.g2_tau,
            );
            if !check {
                return false;
            }
        }

        true
    }
}

impl Commitment {
    /// Commit to a polynomial: [f]₁ = Σ f_i * [τ^i]₁
    pub fn commit(poly: &Polynomial, srs: &Srs) -> Self {
        if poly.coeffs.len() > srs.g1_powers.len() {
            panic!(
                "Polynomial degree {} exceeds SRS max degree {}",
                poly.coeffs.len() - 1,
                srs.max_degree
            );
        }

        // Use MSM for efficiency
        let points: Vec<G1Affine> = srs.g1_powers[..poly.coeffs.len()].to_vec();
        let commitment = G1Projective::msm(&points, &poly.coeffs);

        Commitment { point: commitment.to_affine() }
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        self.point.to_hex()
    }

    /// Convert to short hex string
    pub fn to_short_hex(&self) -> String {
        self.point.to_short_hex()
    }
}

impl OpeningProof {
    /// Create an opening proof for f(z) = y
    ///
    /// The proof is [q]₁ where q(X) = (f(X) - y) / (X - z)
    pub fn create(poly: &Polynomial, z: &Fr, srs: &Srs) -> (Fr, Self) {
        let y = poly.evaluate(z);

        // Compute quotient polynomial q(X) = (f(X) - y) / (X - z)
        let mut f_minus_y = poly.clone();
        if !f_minus_y.coeffs.is_empty() {
            f_minus_y.coeffs[0] -= y;
        }
        let quotient = f_minus_y.div_by_linear(z);

        // Commit to the quotient
        let proof = Commitment::commit(&quotient, srs);

        (y, OpeningProof(proof.point))
    }

    /// Verify an opening proof: e([f]₁ - y*[1]₁, [1]₂) = e([π]₁, [τ]₂ - z*[1]₂)
    ///
    /// This checks that [f]₁ - y*[1]₁ = [π]₁ * (τ - z), which is equivalent to
    /// f(τ) - y = π(τ) * (τ - z), i.e., f(z) = y.
    pub fn verify(
        commitment: &Commitment,
        z: &Fr,
        y: &Fr,
        proof: &OpeningProof,
        srs: &Srs,
    ) -> bool {
        // [f]₁ - y*[1]₁
        let g1 = G1Affine::generator();
        let lhs_point = commitment.point.to_projective() - g1.to_projective().scalar_mul(y);

        // [τ]₂ - z*[1]₂
        let rhs_g2 = srs.g2_tau.to_projective() - srs.g2_generator.to_projective().scalar_mul(z);

        // Check: e(lhs_point, [1]₂) = e([π]₁, rhs_g2)
        pairing_check(
            &lhs_point.to_affine(),
            &srs.g2_generator,
            &proof.0,
            &rhs_g2.to_affine(),
        )
    }
}

/// Batch opening for multiple polynomials at the same point
///
/// Given polynomials f_1, ..., f_k and evaluation point z,
/// prove that f_i(z) = y_i for all i.
pub struct BatchOpening {
    /// The combined opening proof
    pub proof: OpeningProof,
    /// Evaluations y_i = f_i(z)
    pub evaluations: Vec<Fr>,
}

impl BatchOpening {
    /// Create a batch opening proof using random linear combination
    ///
    /// Combines polynomials as g(X) = f_1(X) + γ*f_2(X) + γ²*f_3(X) + ...
    /// Then creates a single opening proof for g(z)
    pub fn create(
        polys: &[Polynomial],
        z: &Fr,
        gamma: &Fr,
        srs: &Srs,
    ) -> Self {
        let evaluations: Vec<Fr> = polys.iter().map(|p| p.evaluate(z)).collect();

        // Combine polynomials: g(X) = Σ γ^i * f_i(X)
        let mut combined = Polynomial::zero();
        let mut gamma_power = Fr::one();
        for poly in polys {
            combined = combined + poly.scale(&gamma_power);
            gamma_power = gamma_power * *gamma;
        }

        let (_, proof) = OpeningProof::create(&combined, z, srs);

        BatchOpening { proof, evaluations }
    }

    /// Verify a batch opening
    pub fn verify(
        &self,
        commitments: &[Commitment],
        z: &Fr,
        gamma: &Fr,
        srs: &Srs,
    ) -> bool {
        if commitments.len() != self.evaluations.len() {
            return false;
        }

        // Combine commitments: [g]₁ = Σ γ^i * [f_i]₁
        let mut combined_commit = G1Projective::identity();
        let mut gamma_power = Fr::one();
        for commitment in commitments {
            combined_commit = combined_commit + commitment.point.to_projective().scalar_mul(&gamma_power);
            gamma_power = gamma_power * *gamma;
        }

        // Combined evaluation: g(z) = Σ γ^i * f_i(z)
        let mut combined_eval = Fr::zero();
        gamma_power = Fr::one();
        for eval in &self.evaluations {
            combined_eval += gamma_power * *eval;
            gamma_power = gamma_power * *gamma;
        }

        OpeningProof::verify(
            &Commitment { point: combined_commit.to_affine() },
            z,
            &combined_eval,
            &self.proof,
            srs,
        )
    }
}

/// Opening at two points (for PLONK's z and z*ω openings)
pub struct TwoPointOpening {
    /// Proof for opening at z
    pub proof_z: OpeningProof,
    /// Proof for opening at z*ω
    pub proof_zw: OpeningProof,
}

impl Serialize for Srs {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct SrsJson {
            max_degree: usize,
            num_g1_elements: usize,
            g1_sample: Vec<G1Affine>,
            g2_generator: G2Affine,
            g2_tau: G2Affine,
        }

        // Only include a sample of G1 powers for display
        let sample_indices = [0, 1, 2, self.max_degree.min(10), self.max_degree];
        let g1_sample: Vec<G1Affine> = sample_indices
            .iter()
            .filter_map(|&i| self.g1_powers.get(i).copied())
            .collect();

        let json = SrsJson {
            max_degree: self.max_degree,
            num_g1_elements: self.g1_powers.len(),
            g1_sample,
            g2_generator: self.g2_generator,
            g2_tau: self.g2_tau,
        };
        json.serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_srs_generation() {
        let mut rng = ChaCha20Rng::seed_from_u64(12345);
        let srs = Srs::generate_insecure(&mut rng, 16);

        assert_eq!(srs.g1_powers.len(), 17);
        assert!(srs.verify());
    }

    #[test]
    fn test_ceremony_simulation() {
        let srs = Srs::simulate_ceremony(16, 4);

        assert_eq!(srs.g1_powers.len(), 17);
        assert!(srs.verify());
    }

    #[test]
    fn test_commit_and_open() {
        let mut rng = ChaCha20Rng::seed_from_u64(12345);
        let srs = Srs::generate_insecure(&mut rng, 16);

        // Create a polynomial f(X) = 1 + 2X + 3X^2
        let poly = Polynomial::from_coeffs(vec![
            Fr::from_u64(1),
            Fr::from_u64(2),
            Fr::from_u64(3),
        ]);

        // Commit
        let commitment = Commitment::commit(&poly, &srs);

        // Open at z = 5
        let z = Fr::from_u64(5);
        let (y, proof) = OpeningProof::create(&poly, &z, &srs);

        // Verify: f(5) = 1 + 10 + 75 = 86
        assert_eq!(y, Fr::from_u64(86));

        // Verify the opening proof
        assert!(OpeningProof::verify(&commitment, &z, &y, &proof, &srs));

        // Verify that a wrong evaluation fails
        let wrong_y = Fr::from_u64(87);
        assert!(!OpeningProof::verify(&commitment, &z, &wrong_y, &proof, &srs));
    }

    #[test]
    fn test_batch_opening() {
        let mut rng = ChaCha20Rng::seed_from_u64(12345);
        let srs = Srs::generate_insecure(&mut rng, 16);

        let poly1 = Polynomial::from_coeffs(vec![Fr::from_u64(1), Fr::from_u64(2)]);
        let poly2 = Polynomial::from_coeffs(vec![Fr::from_u64(3), Fr::from_u64(4)]);

        let commit1 = Commitment::commit(&poly1, &srs);
        let commit2 = Commitment::commit(&poly2, &srs);

        let z = Fr::from_u64(5);
        let gamma = Fr::from_u64(7);

        let batch = BatchOpening::create(&[poly1, poly2], &z, &gamma, &srs);

        assert!(batch.verify(&[commit1, commit2], &z, &gamma, &srs));
    }
}
