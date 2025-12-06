//! PLONK Type Definitions
//!
//! Contains all the data structures used in the PLONK protocol.

use crate::curve::G1Affine;
use crate::field::Fr;
use crate::polynomial::Polynomial;
use serde::{Deserialize, Serialize};

/// Proving key - contains all preprocessed data needed by the prover
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProvingKey {
    /// Domain size (power of 2)
    pub n: usize,
    /// Number of public inputs
    pub num_public_inputs: usize,

    /// Selector polynomials in coefficient form
    pub q_m: Polynomial,
    pub q_l: Polynomial,
    pub q_r: Polynomial,
    pub q_o: Polynomial,
    pub q_c: Polynomial,

    /// Permutation polynomials S_σ1, S_σ2, S_σ3 in coefficient form
    pub s_sigma1: Polynomial,
    pub s_sigma2: Polynomial,
    pub s_sigma3: Polynomial,

    /// Lagrange basis polynomial L_1(X) for public input check
    pub l1: Polynomial,

    /// Domain generator ω (n-th root of unity)
    pub omega: Fr,

    /// Coset generators k1, k2 for permutation argument
    pub k1: Fr,
    pub k2: Fr,
}

/// Verification key - contains all preprocessed commitments for verifier
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerificationKey {
    /// Domain size (power of 2)
    pub n: usize,
    /// Number of public inputs
    pub num_public_inputs: usize,
    /// Positions of public inputs in the trace
    pub public_input_positions: Vec<usize>,

    /// Commitments to selector polynomials
    pub q_m_comm: G1Affine,
    pub q_l_comm: G1Affine,
    pub q_r_comm: G1Affine,
    pub q_o_comm: G1Affine,
    pub q_c_comm: G1Affine,

    /// Commitments to permutation polynomials
    pub s_sigma1_comm: G1Affine,
    pub s_sigma2_comm: G1Affine,
    pub s_sigma3_comm: G1Affine,

    /// Domain generator ω
    pub omega: Fr,

    /// Coset generators k1, k2
    pub k1: Fr,
    pub k2: Fr,
}

/// PLONK proof structure
/// Contains all commitments and evaluations produced by the prover
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof {
    // Round 1: Wire polynomial commitments
    /// [a(X)]_1
    pub a_comm: G1Affine,
    /// [b(X)]_1
    pub b_comm: G1Affine,
    /// [c(X)]_1
    pub c_comm: G1Affine,

    // Round 2: Permutation polynomial commitment
    /// [z(X)]_1 - grand product polynomial
    pub z_comm: G1Affine,

    // Round 3: Quotient polynomial commitments (paper-aligned: only 3)
    /// [t_lo(X)]_1
    pub t_lo_comm: G1Affine,
    /// [t_mid(X)]_1
    pub t_mid_comm: G1Affine,
    /// [t_hi(X)]_1 - degree ≤ n+5
    pub t_hi_comm: G1Affine,

    // Round 4: Evaluations at challenge ζ
    /// a(ζ)
    pub a_eval: Fr,
    /// b(ζ)
    pub b_eval: Fr,
    /// c(ζ)
    pub c_eval: Fr,
    /// S_σ1(ζ)
    pub s_sigma1_eval: Fr,
    /// S_σ2(ζ)
    pub s_sigma2_eval: Fr,
    /// z(ωζ)
    pub z_omega_eval: Fr,

    // Round 5: Opening proofs
    /// [W_ζ(X)]_1 - opening proof at ζ
    pub w_zeta_comm: G1Affine,
    /// [W_{ζω}(X)]_1 - opening proof at ζω
    pub w_zeta_omega_comm: G1Affine,
}

/// Detailed trace of a PLONK proof generation
/// Used for educational visualization
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProverTrace {
    /// Circuit information
    pub circuit: CircuitTrace,

    /// Round 1 trace
    pub round1: Round1Trace,

    /// Round 2 trace
    pub round2: Round2Trace,

    /// Round 3 trace
    pub round3: Round3Trace,

    /// Round 4 trace
    pub round4: Round4Trace,

    /// Round 5 trace
    pub round5: Round5Trace,

    /// Final proof
    pub proof: Proof,
}

/// Circuit information for trace
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitTrace {
    /// Number of gates
    pub num_gates: usize,
    /// Domain size
    pub n: usize,
    /// Public inputs
    pub public_inputs: Vec<PublicInputTrace>,
    /// Gate constraints
    pub gates: Vec<GateTrace>,
    /// Copy constraints
    pub copy_constraints: Vec<CopyConstraintTrace>,
}

/// Public input trace
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicInputTrace {
    pub index: usize,
    pub value: Fr,
    pub description: String,
}

/// Gate trace
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GateTrace {
    pub index: usize,
    pub gate_type: String,
    pub description: String,
    pub selectors: SelectorsTrace,
    pub wires: WiresTrace,
    pub constraint_check: String,
}

/// Selector values for a gate
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SelectorsTrace {
    pub q_m: Fr,
    pub q_l: Fr,
    pub q_r: Fr,
    pub q_o: Fr,
    pub q_c: Fr,
}

/// Wire values for a gate
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WiresTrace {
    pub a: Fr,
    pub b: Fr,
    pub c: Fr,
}

/// Copy constraint trace
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CopyConstraintTrace {
    pub wire1: String,
    pub wire2: String,
    pub reason: String,
}

/// Round 1 trace: Wire polynomials
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round1Trace {
    /// Wire values (evaluations on H)
    pub a_evals: Vec<Fr>,
    pub b_evals: Vec<Fr>,
    pub c_evals: Vec<Fr>,

    /// Wire polynomial coefficients
    pub a_coeffs: Vec<Fr>,
    pub b_coeffs: Vec<Fr>,
    pub c_coeffs: Vec<Fr>,

    /// Blinding factors
    pub blinding_factors: BlindingFactorsRound1,

    /// Commitments
    pub a_comm: G1Affine,
    pub b_comm: G1Affine,
    pub c_comm: G1Affine,

    /// Challenge β (after Round 1)
    pub beta: Fr,
    /// Challenge γ (after Round 1)
    pub gamma: Fr,
}

/// Blinding factors for Round 1
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlindingFactorsRound1 {
    pub b1: Fr,
    pub b2: Fr,
    pub b3: Fr,
    pub b4: Fr,
    pub b5: Fr,
    pub b6: Fr,
}

/// Round 2 trace: Permutation polynomial
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round2Trace {
    /// Accumulator values z(ω^i)
    pub z_evals: Vec<Fr>,

    /// Accumulator computation steps
    pub accumulator_steps: Vec<AccumulatorStep>,

    /// z(X) polynomial coefficients
    pub z_coeffs: Vec<Fr>,

    /// Blinding factors
    pub blinding_factors: BlindingFactorsRound2,

    /// Commitment [z(X)]_1
    pub z_comm: G1Affine,

    /// Challenge α (after Round 2)
    pub alpha: Fr,
}

/// Single step in accumulator computation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccumulatorStep {
    pub i: usize,
    pub omega_i: Fr,
    /// (a + β*ω^i + γ)(b + β*k1*ω^i + γ)(c + β*k2*ω^i + γ)
    pub numerator: Fr,
    /// (a + β*S_σ1(ω^i) + γ)(b + β*S_σ2(ω^i) + γ)(c + β*S_σ3(ω^i) + γ)
    pub denominator: Fr,
    /// z_{i+1} = z_i * (num/denom)
    pub z_next: Fr,
}

/// Blinding factors for Round 2
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlindingFactorsRound2 {
    pub b7: Fr,
    pub b8: Fr,
    pub b9: Fr,
}

/// Round 3 trace: Quotient polynomial
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round3Trace {
    /// Gate constraint polynomial (before division)
    pub gate_constraint_sample: Vec<Fr>,

    /// Permutation constraint polynomial (before division)
    pub perm_constraint_sample: Vec<Fr>,

    /// L1 constraint polynomial (before division)
    pub l1_constraint_sample: Vec<Fr>,

    /// Full quotient polynomial degree
    pub t_degree: usize,

    /// Split quotient polynomials (paper-aligned: only 3 parts)
    /// t_lo: degree n (with X^n term for blinding)
    /// t_mid: degree n (with X^n term for blinding)
    /// t_hi: degree ≤ n+5
    pub t_lo_coeffs: Vec<Fr>,
    pub t_mid_coeffs: Vec<Fr>,
    pub t_hi_coeffs: Vec<Fr>,

    /// Commitments (only 3 - paper aligned)
    pub t_lo_comm: G1Affine,
    pub t_mid_comm: G1Affine,
    pub t_hi_comm: G1Affine,

    /// Quotient blinding factors (paper-aligned)
    pub b10: Fr,
    pub b11: Fr,

    /// Challenge ζ (after Round 3)
    pub zeta: Fr,
}

/// Round 4 trace: Evaluations
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round4Trace {
    /// Evaluation point ζ
    pub zeta: Fr,
    /// Evaluation point ζω
    pub zeta_omega: Fr,

    /// Polynomial evaluations
    pub evaluations: EvaluationsTrace,

    /// Challenge v (after Round 4)
    pub v: Fr,
}

/// All polynomial evaluations
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvaluationsTrace {
    pub a_zeta: Fr,
    pub b_zeta: Fr,
    pub c_zeta: Fr,
    pub s_sigma1_zeta: Fr,
    pub s_sigma2_zeta: Fr,
    pub z_zeta_omega: Fr,

    /// Additional evaluations for linearization
    pub q_m_zeta: Fr,
    pub q_l_zeta: Fr,
    pub q_r_zeta: Fr,
    pub q_o_zeta: Fr,
    pub q_c_zeta: Fr,
}

/// Round 5 trace: Opening proofs
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round5Trace {
    /// Linearization polynomial r(X)
    pub r_coeffs: Vec<Fr>,
    /// r(ζ)
    pub r_zeta: Fr,

    /// Opening polynomial at ζ
    pub w_zeta_coeffs: Vec<Fr>,
    /// [W_ζ(X)]_1
    pub w_zeta_comm: G1Affine,

    /// Opening polynomial at ζω
    pub w_zeta_omega_coeffs: Vec<Fr>,
    /// [W_{ζω}(X)]_1
    pub w_zeta_omega_comm: G1Affine,

    /// Challenge u (for batching)
    pub u: Fr,
}

/// Verifier trace
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifierTrace {
    /// Step 1: Transcript reconstruction
    pub transcript_challenges: TranscriptChallengesTrace,

    /// Step 2: Evaluate vanishing polynomial
    pub z_h_zeta: Fr,

    /// Step 3: Evaluate L_1(ζ)
    pub l1_zeta: Fr,

    /// Step 4: Compute public input polynomial evaluation
    pub pi_zeta: Fr,

    /// Step 5: Compute linearization commitment
    pub linearization: LinearizationTrace,

    /// Step 6: Pairing check
    pub pairing_check: PairingCheckTrace,

    /// Final result
    pub is_valid: bool,
}

/// Transcript challenges trace
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TranscriptChallengesTrace {
    pub beta: Fr,
    pub gamma: Fr,
    pub alpha: Fr,
    pub zeta: Fr,
    pub v: Fr,
    pub u: Fr,
}

/// Linearization trace
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LinearizationTrace {
    /// [r]_1 = linearization commitment
    pub r_comm: G1Affine,
    /// r(ζ) computed from proof
    pub r_zeta: Fr,
}

/// Pairing check trace
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PairingCheckTrace {
    /// [F]_1 = combined commitment
    pub f_comm: G1Affine,
    /// [E]_1 = evaluation commitment
    pub e_comm: G1Affine,
    /// Left pairing: e([W_ζ] + u[W_{ζω}], [x]_2)
    pub left_pairing_input: PairingInput,
    /// Right pairing: e([F] - [E] + ζ[W_ζ] + uζω[W_{ζω}], [1]_2)
    pub right_pairing_input: PairingInput,
    /// Result of pairing check
    pub pairing_result: bool,
}

/// Pairing input trace
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PairingInput {
    pub g1: G1Affine,
    pub g2_description: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_serialization() {
        // Just test that types can be serialized
        let _proof_json = serde_json::json!({
            "a_comm": G1Affine::generator(),
        });
    }
}
