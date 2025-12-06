//! PLONK Preprocessing
//!
//! This module handles the preprocessing phase (Section 7.2 of the PLONK paper).
//! Preprocessing creates:
//! - Proving key (PK): selector polynomials, permutation polynomials
//! - Verification key (VK): commitments to all preprocessing polynomials
//!
//! The preprocessing is circuit-specific but witness-independent.

use crate::circuit::ConstraintSystem;
use crate::curve::G1Affine;
use crate::fft::Domain;
use crate::field::Fr;
use crate::kzg::{Commitment, Srs};
use crate::polynomial::Polynomial;
use crate::plonk::permutation::Permutation;
use crate::plonk::types::{ProvingKey, VerificationKey};
use serde::{Deserialize, Serialize};

/// Preprocessed data (contains both PK and VK)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreprocessedData {
    pub proving_key: ProvingKey,
    pub verification_key: VerificationKey,
    pub permutation: Permutation,
    pub domain: Domain,
}

/// Trace of the preprocessing phase
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreprocessTrace {
    /// Domain information
    pub domain: DomainTrace,

    /// Selector polynomial traces
    pub selectors: SelectorsPreprocessTrace,

    /// Permutation traces
    pub permutation: PermutationPreprocessTrace,

    /// Commitment traces
    pub commitments: CommitmentsTrace,
}

/// Domain trace
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DomainTrace {
    pub n: usize,
    pub omega: Fr,
    pub omega_inv: Fr,
    pub elements: Vec<Fr>,
}

/// Selector polynomial traces
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SelectorsPreprocessTrace {
    pub q_m_evals: Vec<Fr>,
    pub q_l_evals: Vec<Fr>,
    pub q_r_evals: Vec<Fr>,
    pub q_o_evals: Vec<Fr>,
    pub q_c_evals: Vec<Fr>,

    pub q_m_coeffs: Vec<Fr>,
    pub q_l_coeffs: Vec<Fr>,
    pub q_r_coeffs: Vec<Fr>,
    pub q_o_coeffs: Vec<Fr>,
    pub q_c_coeffs: Vec<Fr>,
}

/// Permutation preprocessing trace
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PermutationPreprocessTrace {
    pub k1: Fr,
    pub k2: Fr,
    pub s_sigma1_evals: Vec<Fr>,
    pub s_sigma2_evals: Vec<Fr>,
    pub s_sigma3_evals: Vec<Fr>,
    pub s_sigma1_coeffs: Vec<Fr>,
    pub s_sigma2_coeffs: Vec<Fr>,
    pub s_sigma3_coeffs: Vec<Fr>,
}

/// Commitment traces
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitmentsTrace {
    pub q_m_comm: G1Affine,
    pub q_l_comm: G1Affine,
    pub q_r_comm: G1Affine,
    pub q_o_comm: G1Affine,
    pub q_c_comm: G1Affine,
    pub s_sigma1_comm: G1Affine,
    pub s_sigma2_comm: G1Affine,
    pub s_sigma3_comm: G1Affine,
}

/// Preprocess a constraint system
///
/// # Arguments
/// * `cs` - The constraint system (must be finalized)
/// * `srs` - The SRS (must have degree >= n+2 for blinding)
///
/// # Returns
/// Preprocessed data including proving key and verification key
pub fn preprocess(cs: &ConstraintSystem, srs: &Srs) -> PreprocessedData {
    let n = cs.n;

    // Create the domain
    let domain = Domain::new(n).expect("Domain creation failed");
    let omega = domain.omega;

    // Extract selector evaluations from gates
    let selectors = cs.get_selectors();

    // Convert selector evaluations to polynomials via IFFT
    let q_m = Polynomial::from_evaluations(&selectors.q_m, &domain);
    let q_l = Polynomial::from_evaluations(&selectors.q_l, &domain);
    let q_r = Polynomial::from_evaluations(&selectors.q_r, &domain);
    let q_o = Polynomial::from_evaluations(&selectors.q_o, &domain);
    let q_c = Polynomial::from_evaluations(&selectors.q_c, &domain);

    // Compute permutation
    let permutation = Permutation::compute(cs, &domain);

    // Convert permutation evaluations to polynomials
    let s_sigma1 = permutation.s_sigma1_poly(&domain);
    let s_sigma2 = permutation.s_sigma2_poly(&domain);
    let s_sigma3 = permutation.s_sigma3_poly(&domain);

    // Commit to all polynomials
    let q_m_comm = Commitment::commit(&q_m, srs).point;
    let q_l_comm = Commitment::commit(&q_l, srs).point;
    let q_r_comm = Commitment::commit(&q_r, srs).point;
    let q_o_comm = Commitment::commit(&q_o, srs).point;
    let q_c_comm = Commitment::commit(&q_c, srs).point;

    let s_sigma1_comm = Commitment::commit(&s_sigma1, srs).point;
    let s_sigma2_comm = Commitment::commit(&s_sigma2, srs).point;
    let s_sigma3_comm = Commitment::commit(&s_sigma3, srs).point;

    // Compute L_1(X) - the first Lagrange basis polynomial
    // L_1(ω^i) = 1 if i=0, 0 otherwise
    let l1 = Polynomial::lagrange_basis(0, n, &domain);

    // Build proving key
    let proving_key = ProvingKey {
        n,
        num_public_inputs: cs.public_input_positions.len(),
        q_m,
        q_l,
        q_r,
        q_o,
        q_c,
        s_sigma1,
        s_sigma2,
        s_sigma3,
        l1,
        omega,
        k1: permutation.k1,
        k2: permutation.k2,
    };

    // Build verification key
    let verification_key = VerificationKey {
        n,
        num_public_inputs: cs.public_input_positions.len(),
        public_input_positions: cs.public_input_positions.clone(),
        q_m_comm,
        q_l_comm,
        q_r_comm,
        q_o_comm,
        q_c_comm,
        s_sigma1_comm,
        s_sigma2_comm,
        s_sigma3_comm,
        omega,
        k1: permutation.k1,
        k2: permutation.k2,
    };

    PreprocessedData {
        proving_key,
        verification_key,
        permutation,
        domain,
    }
}

/// Preprocess with trace for visualization
pub fn preprocess_with_trace(cs: &ConstraintSystem, srs: &Srs) -> (PreprocessedData, PreprocessTrace) {
    let n = cs.n;
    let domain = Domain::new(n).expect("Domain creation failed");

    // Domain elements
    let elements: Vec<Fr> = domain.elements().collect();

    // Selector evaluations
    let selectors = cs.get_selectors();

    // Convert to polynomials
    let q_m = Polynomial::from_evaluations(&selectors.q_m, &domain);
    let q_l = Polynomial::from_evaluations(&selectors.q_l, &domain);
    let q_r = Polynomial::from_evaluations(&selectors.q_r, &domain);
    let q_o = Polynomial::from_evaluations(&selectors.q_o, &domain);
    let q_c = Polynomial::from_evaluations(&selectors.q_c, &domain);

    // Compute permutation
    let permutation = Permutation::compute(cs, &domain);

    // Permutation polynomials
    let s_sigma1 = permutation.s_sigma1_poly(&domain);
    let s_sigma2 = permutation.s_sigma2_poly(&domain);
    let s_sigma3 = permutation.s_sigma3_poly(&domain);

    // Commitments
    let q_m_comm = Commitment::commit(&q_m, srs).point;
    let q_l_comm = Commitment::commit(&q_l, srs).point;
    let q_r_comm = Commitment::commit(&q_r, srs).point;
    let q_o_comm = Commitment::commit(&q_o, srs).point;
    let q_c_comm = Commitment::commit(&q_c, srs).point;
    let s_sigma1_comm = Commitment::commit(&s_sigma1, srs).point;
    let s_sigma2_comm = Commitment::commit(&s_sigma2, srs).point;
    let s_sigma3_comm = Commitment::commit(&s_sigma3, srs).point;

    // Build trace
    let trace = PreprocessTrace {
        domain: DomainTrace {
            n,
            omega: domain.omega,
            omega_inv: domain.omega_inv,
            elements,
        },
        selectors: SelectorsPreprocessTrace {
            q_m_evals: selectors.q_m.clone(),
            q_l_evals: selectors.q_l.clone(),
            q_r_evals: selectors.q_r.clone(),
            q_o_evals: selectors.q_o.clone(),
            q_c_evals: selectors.q_c.clone(),
            q_m_coeffs: q_m.coeffs.clone(),
            q_l_coeffs: q_l.coeffs.clone(),
            q_r_coeffs: q_r.coeffs.clone(),
            q_o_coeffs: q_o.coeffs.clone(),
            q_c_coeffs: q_c.coeffs.clone(),
        },
        permutation: PermutationPreprocessTrace {
            k1: permutation.k1,
            k2: permutation.k2,
            s_sigma1_evals: permutation.s_sigma1_evals.clone(),
            s_sigma2_evals: permutation.s_sigma2_evals.clone(),
            s_sigma3_evals: permutation.s_sigma3_evals.clone(),
            s_sigma1_coeffs: s_sigma1.coeffs.clone(),
            s_sigma2_coeffs: s_sigma2.coeffs.clone(),
            s_sigma3_coeffs: s_sigma3.coeffs.clone(),
        },
        commitments: CommitmentsTrace {
            q_m_comm,
            q_l_comm,
            q_r_comm,
            q_o_comm,
            q_c_comm,
            s_sigma1_comm,
            s_sigma2_comm,
            s_sigma3_comm,
        },
    };

    // Build preprocessed data
    let l1 = Polynomial::lagrange_basis(0, n, &domain);

    let proving_key = ProvingKey {
        n,
        num_public_inputs: cs.public_input_positions.len(),
        q_m,
        q_l,
        q_r,
        q_o,
        q_c,
        s_sigma1,
        s_sigma2,
        s_sigma3,
        l1,
        omega: domain.omega,
        k1: permutation.k1,
        k2: permutation.k2,
    };

    let verification_key = VerificationKey {
        n,
        num_public_inputs: cs.public_input_positions.len(),
        public_input_positions: cs.public_input_positions.clone(),
        q_m_comm,
        q_l_comm,
        q_r_comm,
        q_o_comm,
        q_c_comm,
        s_sigma1_comm,
        s_sigma2_comm,
        s_sigma3_comm,
        omega: domain.omega,
        k1: permutation.k1,
        k2: permutation.k2,
    };

    let data = PreprocessedData {
        proving_key,
        verification_key,
        permutation,
        domain,
    };

    (data, trace)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::RangeProofCircuit;
    use crate::kzg::Srs;

    #[test]
    fn test_preprocess_range_proof() {
        let circuit = RangeProofCircuit::new(8, 42);
        let cs = &circuit.constraint_system;

        // Create SRS (need n+5 for blinding)
        let srs = Srs::simulate_ceremony(cs.n + 5, 2);

        let data = preprocess(cs, &srs);

        // Check dimensions
        assert_eq!(data.proving_key.n, cs.n);
        assert_eq!(data.verification_key.n, cs.n);

        // Check that selector polynomials have correct degree
        assert!(data.proving_key.q_m.degree() < cs.n as isize);
        assert!(data.proving_key.q_l.degree() < cs.n as isize);

        // Check that permutation polynomials have correct degree
        assert!(data.proving_key.s_sigma1.degree() < cs.n as isize);
    }

    #[test]
    fn test_preprocess_with_trace() {
        let circuit = RangeProofCircuit::new(8, 42);
        let cs = &circuit.constraint_system;
        let srs = Srs::simulate_ceremony(cs.n + 5, 2);

        let (data, trace) = preprocess_with_trace(cs, &srs);

        // Verify trace has correct dimensions
        assert_eq!(trace.domain.n, cs.n);
        assert_eq!(trace.domain.elements.len(), cs.n);
        assert_eq!(trace.selectors.q_m_evals.len(), cs.n);
        assert_eq!(trace.permutation.s_sigma1_evals.len(), cs.n);

        // Verify preprocessed data matches trace
        assert_eq!(data.verification_key.q_m_comm, trace.commitments.q_m_comm);
    }
}
