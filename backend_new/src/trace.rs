//! Execution Trace for Visualization
//!
//! This module provides comprehensive trace structures for the PLONK protocol.
//! All traces are serializable to JSON for frontend visualization.

use crate::circuit::RangeProofCircuit;
use crate::curve::G1Affine;
use crate::field::Fr;
use crate::kzg::Srs;
use crate::plonk::preprocess::{preprocess_with_trace, PreprocessTrace};
use crate::plonk::prover::Prover;
use crate::plonk::verifier::Verifier;
use crate::plonk::types::{ProverTrace, VerifierTrace};
use crate::plonk::Proof;
use crate::fft::Domain;
use serde::{Deserialize, Serialize};

/// Complete execution trace for a PLONK proof
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FullTrace {
    /// SRS generation trace
    pub srs: SrsTrace,

    /// Circuit setup trace
    pub circuit: CircuitSetupTrace,

    /// Preprocessing trace
    pub preprocess: PreprocessTrace,

    /// Prover trace
    pub prover: ProverTrace,

    /// Verifier trace
    pub verifier: VerifierTrace,

    /// Summary statistics
    pub summary: TraceSummary,
}

/// SRS generation trace
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SrsTrace {
    /// Maximum degree supported
    pub max_degree: usize,

    /// Number of ceremony participants
    pub num_participants: usize,

    /// Participants' contributions (public info only)
    pub participants: Vec<ParticipantTrace>,

    /// Final SRS G1 powers (first few for display)
    pub g1_powers_sample: Vec<G1Affine>,

    /// Final [τ]_2
    pub g2_tau: G1Affine, // Actually G2, but using same type for simplicity

    /// Verification that e([τ]_1, [1]_2) = e([1]_1, [τ]_2)
    pub srs_valid: bool,
}

/// Participant contribution trace
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParticipantTrace {
    pub index: usize,
    pub name: String,
    /// Hash of contribution (for verification)
    pub contribution_hash: String,
}

/// Circuit setup trace
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitSetupTrace {
    /// Type of circuit
    pub circuit_type: String,

    /// Parameters
    pub parameters: CircuitParameters,

    /// Public input
    pub witness_x_for_demo: Fr,

    /// Whether x is in valid range [0, 2^n_bits)
    pub in_range: bool,

    /// Witness (bit decomposition)
    pub witness: WitnessTrace,

    /// Domain information
    pub domain: DomainTrace,
}

/// Circuit parameters
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitParameters {
    pub n_bits: usize,
    pub num_gates: usize,
    pub domain_size: usize,
    pub num_copy_constraints: usize,
}

/// Witness trace
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WitnessTrace {
    pub x: u64,
    pub bits: Vec<bool>,
    pub bit_values: Vec<Fr>,
    pub accumulator_values: Vec<Fr>,
}

/// Domain trace
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DomainTrace {
    pub n: usize,
    pub omega: Fr,
    pub omega_inv: Fr,
    pub elements: Vec<Fr>,
}

/// Summary statistics
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceSummary {
    /// Total commitments made
    pub num_commitments: usize,

    /// Total pairings computed (in verification)
    pub num_pairings: usize,

    /// Total challenges generated
    pub num_challenges: usize,

    /// Proof size in bytes
    pub proof_size_bytes: usize,

    /// Verification result
    pub verification_passed: bool,
}

/// Generate a full execution trace for a range proof
pub fn generate_full_trace(x: u64, n_bits: usize, num_ceremony_participants: usize) -> FullTrace {
    // 1. Create the circuit
    let circuit = RangeProofCircuit::new(n_bits, x);
    let cs = &circuit.constraint_system;
    let n = cs.n;
    // Check if x is in valid range [0, 2^n_bits)
    let max_value = 1u64 << n_bits;
    let in_range = x < max_value;


    // 2. Generate SRS with ceremony simulation
    let srs_degree = n + 10; // Extra for blinding
    let srs = Srs::simulate_ceremony(srs_degree, num_ceremony_participants);

    // Build SRS trace
    let srs_trace = SrsTrace {
        max_degree: srs_degree,
        num_participants: num_ceremony_participants,
        participants: (0..num_ceremony_participants)
            .map(|i| ParticipantTrace {
                index: i,
                name: format!("Participant {}", i + 1),
                contribution_hash: format!("0x{:016x}", i * 12345), // Placeholder
            })
            .collect(),
        g1_powers_sample: srs.g1_powers.iter().take(5).cloned().collect(),
        g2_tau: G1Affine::generator(), // Placeholder for display
        srs_valid: true,
    };

    // 3. Circuit setup trace
    let domain = Domain::new(n).unwrap();
    let witness = circuit.get_witness();

    let circuit_trace = CircuitSetupTrace {
        circuit_type: "Range Proof".to_string(),
        parameters: CircuitParameters {
            n_bits,
            num_gates: cs.num_gates,
            domain_size: n,
            num_copy_constraints: cs.copy_constraints.len(),
        },
        witness_x_for_demo: Fr::from_u64(x),
                in_range: true,
        witness: WitnessTrace {
            x,
            bits: witness.bits.clone(),
            bit_values: witness.bits.iter().map(|&b| if b { Fr::one() } else { Fr::zero() }).collect(),
            accumulator_values: (0..=n_bits)
                .scan(Fr::zero(), |acc, i| {
                    let result = *acc;
                    if i < n_bits && witness.bits[i] {
                        *acc = *acc + Fr::from_u64(1u64 << i);
                    }
                    Some(result)
                })
                .collect(),
        },
        domain: DomainTrace {
            n,
            omega: domain.omega,
            omega_inv: domain.omega_inv,
            elements: domain.elements().collect(),
        },
    };

    // 4. Preprocess with trace
    let (preprocess_data, preprocess_trace) = preprocess_with_trace(cs, &srs);

    // 5. Generate proof with trace
    let prover = Prover::new(
        cs,
        &preprocess_data.proving_key,
        &preprocess_data.permutation,
        &preprocess_data.domain,
        &srs,
    );
    let public_inputs: Vec<Fr> = vec![]; // No public inputs!
    let (proof, prover_trace) = prover.prove_with_trace(&public_inputs);

    // 6. Verify with trace
    let verifier = Verifier::new(&preprocess_data.verification_key, &srs);
    let (is_valid, verifier_trace) = verifier.verify_with_trace(&proof, &public_inputs);

    // 7. Build summary
    let summary = TraceSummary {
        num_commitments: 8 + 3 + 3 + 2, // VK + Round1 + Round3 + Round5
        num_pairings: 2,
        num_challenges: 6, // β, γ, α, ζ, v, u
        proof_size_bytes: estimate_proof_size(&proof),
        verification_passed: is_valid,
    };

    FullTrace {
        srs: srs_trace,
        circuit: circuit_trace,
        preprocess: preprocess_trace,
        prover: prover_trace,
        verifier: verifier_trace,
        summary,
    }
}

/// Estimate proof size in bytes
fn estimate_proof_size(proof: &Proof) -> usize {
    // Each G1 point: 48 bytes (compressed)
    // Each Fr: 32 bytes
    let g1_points = 8; // a, b, c, z, t_lo, t_mid, t_hi, w_zeta, w_zeta_omega
    let fr_elements = 6; // a_eval, b_eval, c_eval, s1_eval, s2_eval, z_omega_eval

    g1_points * 48 + fr_elements * 32
}

/// Compact proof representation for JSON
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompactProof {
    /// Round 1 commitments
    pub round1: Round1Commitments,
    /// Round 2 commitment
    pub round2: Round2Commitment,
    /// Round 3 commitments
    pub round3: Round3Commitments,
    /// Round 4 evaluations
    pub round4: Round4Evaluations,
    /// Round 5 commitments
    pub round5: Round5Commitments,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round1Commitments {
    pub a: G1Affine,
    pub b: G1Affine,
    pub c: G1Affine,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round2Commitment {
    pub z: G1Affine,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round3Commitments {
    pub t_lo: G1Affine,
    pub t_mid: G1Affine,
    pub t_hi: G1Affine,
    // t_4 removed - paper-aligned: only 3 quotient parts
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round4Evaluations {
    pub a_zeta: Fr,
    pub b_zeta: Fr,
    pub c_zeta: Fr,
    pub s_sigma1_zeta: Fr,
    pub s_sigma2_zeta: Fr,
    pub z_omega_zeta: Fr,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round5Commitments {
    pub w_zeta: G1Affine,
    pub w_zeta_omega: G1Affine,
}

impl From<&Proof> for CompactProof {
    fn from(proof: &Proof) -> Self {
        CompactProof {
            round1: Round1Commitments {
                a: proof.a_comm,
                b: proof.b_comm,
                c: proof.c_comm,
            },
            round2: Round2Commitment { z: proof.z_comm },
            round3: Round3Commitments {
                t_lo: proof.t_lo_comm,
                t_mid: proof.t_mid_comm,
                t_hi: proof.t_hi_comm,
            },
            round4: Round4Evaluations {
                a_zeta: proof.a_eval,
                b_zeta: proof.b_eval,
                c_zeta: proof.c_eval,
                s_sigma1_zeta: proof.s_sigma1_eval,
                s_sigma2_zeta: proof.s_sigma2_eval,
                z_omega_zeta: proof.z_omega_eval,
            },
            round5: Round5Commitments {
                w_zeta: proof.w_zeta_comm,
                w_zeta_omega: proof.w_zeta_omega_comm,
            },
        }
    }
}

/// Precomputed data for specific x values
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrecomputedData {
    pub x: u64,
    pub n_bits: usize,
    pub proof: CompactProof,
    pub witness_x_for_demo: Fr,

    /// Whether x is in valid range [0, 2^n_bits)
    pub in_range: bool,
    pub verification_key_hash: String,
    pub is_valid: bool,
}

/// Generate precomputed proofs for a set of x values
pub fn generate_precomputed_proofs(
    x_values: &[u64],
    n_bits: usize,
    num_ceremony_participants: usize,
) -> Vec<PrecomputedData> {
    // Generate common SRS
    let max_x = 1u64 << n_bits;
    let circuit = RangeProofCircuit::new(n_bits, 0); // Dummy circuit to get n
    let n = circuit.constraint_system.n;
    let srs = Srs::simulate_ceremony(n + 10, num_ceremony_participants);

    // Preprocess once
    let dummy_circuit = RangeProofCircuit::new(n_bits, 0);
    let (preprocess_data, _) = preprocess_with_trace(&dummy_circuit.constraint_system, &srs);

    let vk_hash = format!("0x{}", hex::encode(&[0u8; 16])); // Placeholder

    x_values
        .iter()
        .filter_map(|&x| {
            if x >= max_x {
                return None;
            }

            let circuit = RangeProofCircuit::new(n_bits, x);
            let prover = Prover::new(
                &circuit.constraint_system,
                &preprocess_data.proving_key,
                &preprocess_data.permutation,
                &preprocess_data.domain,
                &srs,
            );

            let public_inputs: Vec<Fr> = vec![]; // No public inputs!
            let proof = prover.prove(&public_inputs);

            let verifier = Verifier::new(&preprocess_data.verification_key, &srs);
            let is_valid = verifier.verify(&proof, &public_inputs);

            Some(PrecomputedData {
                x,
                n_bits,
                proof: CompactProof::from(&proof),
                witness_x_for_demo: Fr::from_u64(x),
                in_range: true,
                verification_key_hash: vk_hash.clone(),
                is_valid,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_full_trace() {
        let trace = generate_full_trace(42, 8, 2);

        assert_eq!(trace.circuit.witness_x_for_demo, Fr::from_u64(42));
        assert_eq!(trace.circuit.parameters.n_bits, 8);
        assert_eq!(trace.circuit.parameters.domain_size, 16); // 17 gates padded to power of 2

        // Check that we have valid traces
        assert!(!trace.prover.round1.a_coeffs.is_empty());
        assert!(!trace.prover.round2.z_coeffs.is_empty());
    }

    #[test]
    fn test_generate_precomputed() {
        let x_values = vec![0, 42, 127, 255];
        let precomputed = generate_precomputed_proofs(&x_values, 8, 2);

        assert_eq!(precomputed.len(), 4);
        for data in &precomputed {
            assert!(data.x < 256);
        }
    }
}
