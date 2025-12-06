//! HTTP API Handlers
//!
//! Implements the REST API endpoints:
//! - POST /api/prove - Generate a zero-knowledge proof for a given x (x is witness, NOT public input)
//! - POST /api/verify - Verify a proof (verifier does NOT know x)
//! - GET /api/precomputed - Get precomputed proofs
//! - GET /api/circuit - Get circuit information
//! - GET /api/srs_meta - Get SRS metadata
//!
//! **Zero-Knowledge Design**: x is a private witness, not a public input.
//! The verifier only learns that the prover knows some x in [0, 2^n_bits).

use crate::api::state::AppState;
use crate::circuit::RangeProofCircuit;
use crate::field::Fr;
use crate::plonk::prover::Prover;
use crate::plonk::verifier::Verifier;
use crate::plonk::Proof;
use crate::trace::{generate_full_trace, CompactProof, FullTrace, PrecomputedData};
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Request for proof generation
#[derive(Debug, Deserialize)]
pub struct ProveRequest {
    /// The private witness x to prove is in range [0, 2^n_bits)
    /// Note: x is NOT revealed to the verifier - it's a private witness!
    pub x: u64,
    /// Whether to include full trace (default: false)
    #[serde(default)]
    pub include_trace: bool,
}

/// Response for proof generation
#[derive(Debug, Serialize)]
pub struct ProveResponse {
    pub success: bool,
    /// The witness x (included for demo visualization, NOT sent to verifier in real ZK)
    pub x: u64,
    /// Whether x is within the valid range [0, 2^n_bits)
    pub in_range: bool,
    pub proof: CompactProof,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace: Option<FullTrace>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// POST /api/prove - Generate a zero-knowledge proof
///
/// In this ZK design, x is a **witness** (private input), NOT a public input.
/// The verifier will NOT know x - only that the prover knows some x in [0, 2^n_bits).
pub async fn prove(
    State(state): State<AppState>,
    Json(req): Json<ProveRequest>,
) -> impl IntoResponse {
    let config = &state.inner.config;
    let max_value = 1u64 << config.n_bits;
    let in_range = req.x < max_value;

    // Note: x is a witness, not public input.
    // The circuit will always generate a valid proof for x mod 2^n_bits.
    // Whether the original x was in range is tracked separately for demo purposes.

    // Check if we have a precomputed proof
    {
        let precomputed = state.inner.precomputed.read().await;
        if let Some(data) = precomputed.get(&req.x) {
            if !req.include_trace {
                return (
                    StatusCode::OK,
                    Json(ProveResponse {
                        success: true,
                        x: req.x,
                        in_range,
                        proof: data.proof.clone(),
                        trace: None,
                        error: None,
                    }),
                );
            }
        }
    }

    // Generate proof
    if req.include_trace {
        let trace = generate_full_trace(req.x, config.n_bits, config.num_ceremony_participants);
        let proof = CompactProof::from(&trace.prover.proof);

        return (
            StatusCode::OK,
            Json(ProveResponse {
                success: true,
                x: req.x,
                in_range,
                proof,
                trace: Some(trace),
                error: None,
            }),
        );
    }

    // Generate proof without trace
    let circuit = RangeProofCircuit::new(config.n_bits, req.x);
    let prover = Prover::new(
        &circuit.constraint_system,
        &state.inner.preprocess.proving_key,
        &state.inner.preprocess.permutation,
        &state.inner.preprocess.domain,
        &state.inner.srs,
    );

    // No public inputs! x is entirely a witness.
    let public_inputs: Vec<Fr> = vec![];
    let proof = prover.prove(&public_inputs);
    let compact = CompactProof::from(&proof);

    // Cache the result
    {
        let mut precomputed = state.inner.precomputed.write().await;
        precomputed.insert(
            req.x,
            PrecomputedData {
                x: req.x,
                n_bits: config.n_bits,
                proof: compact.clone(),
                witness_x_for_demo: Fr::from_u64(req.x),
                in_range,
                verification_key_hash: "0x...".to_string(),
                is_valid: true,
            },
        );
    }

    (
        StatusCode::OK,
        Json(ProveResponse {
            success: true,
            x: req.x,
            in_range,
            proof: compact,
            trace: None,
            error: None,
        }),
    )
}

/// Request for verification
///
/// Note: In true ZK, the verifier does NOT know x.
/// The proof alone is sufficient to verify that the prover knows some x in [0, 2^n_bits).
#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    /// The proof to verify (no x needed - it's hidden in the witness!)
    pub proof: CompactProof,
}

/// Response for verification
#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    pub success: bool,
    /// Whether the proof is valid (prover knows some x in range)
    pub valid: bool,
    /// Description of what was verified
    pub verified_statement: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// POST /api/verify - Verify a zero-knowledge proof
///
/// The verifier does NOT know x. It only verifies that:
/// "The prover knows some x such that x is in [0, 2^n_bits)"
///
/// This is true zero-knowledge: the value x is never revealed.
pub async fn verify(
    State(state): State<AppState>,
    Json(req): Json<VerifyRequest>,
) -> impl IntoResponse {
    let config = &state.inner.config;

    // Convert compact proof back to full proof
    let proof = Proof {
        a_comm: req.proof.round1.a,
        b_comm: req.proof.round1.b,
        c_comm: req.proof.round1.c,
        z_comm: req.proof.round2.z,
        t_lo_comm: req.proof.round3.t_lo,
        t_mid_comm: req.proof.round3.t_mid,
        t_hi_comm: req.proof.round3.t_hi,
        a_eval: req.proof.round4.a_zeta,
        b_eval: req.proof.round4.b_zeta,
        c_eval: req.proof.round4.c_zeta,
        s_sigma1_eval: req.proof.round4.s_sigma1_zeta,
        s_sigma2_eval: req.proof.round4.s_sigma2_zeta,
        z_omega_eval: req.proof.round4.z_omega_zeta,
        w_zeta_comm: req.proof.round5.w_zeta,
        w_zeta_omega_comm: req.proof.round5.w_zeta_omega,
    };

    // Verify with NO public inputs (x is hidden in witness)
    let verifier = Verifier::new(&state.inner.preprocess.verification_key, &state.inner.srs);
    let public_inputs: Vec<Fr> = vec![]; // No public inputs!
    let valid = verifier.verify(&proof, &public_inputs);

    let max_value = 1u64 << config.n_bits;
    let verified_statement = format!(
        "Prover knows some x in [0, {})",
        max_value
    );

    (
        StatusCode::OK,
        Json(VerifyResponse {
            success: true,
            valid,
            verified_statement,
            error: None,
        }),
    )
}

/// Query parameters for precomputed endpoint
#[derive(Debug, Deserialize)]
pub struct PrecomputedQuery {
    /// Filter by specific x value
    pub x: Option<u64>,
}

/// Response for precomputed proofs
#[derive(Debug, Serialize)]
pub struct PrecomputedResponse {
    pub success: bool,
    pub n_bits: usize,
    pub proofs: Vec<PrecomputedData>,
}

/// GET /api/precomputed - Get precomputed proofs
pub async fn get_precomputed(
    State(state): State<AppState>,
    Query(query): Query<PrecomputedQuery>,
) -> impl IntoResponse {
    let precomputed = state.inner.precomputed.read().await;

    let proofs: Vec<PrecomputedData> = if let Some(x) = query.x {
        precomputed.get(&x).cloned().into_iter().collect()
    } else {
        precomputed.values().cloned().collect()
    };

    (
        StatusCode::OK,
        Json(PrecomputedResponse {
            success: true,
            n_bits: state.inner.config.n_bits,
            proofs,
        }),
    )
}

/// Response for circuit info
#[derive(Debug, Serialize)]
pub struct CircuitInfoResponse {
    pub circuit_type: String,
    pub n_bits: usize,
    pub num_gates: usize,
    pub domain_size: usize,
    pub num_copy_constraints: usize,
    pub num_public_inputs: usize,
    pub gate_types: GateTypeCounts,
}

#[derive(Debug, Serialize)]
pub struct GateTypeCounts {
    pub booleanity: usize,
    pub accumulator: usize,
    pub padding: usize,
}

/// GET /api/circuit - Get circuit information
pub async fn get_circuit_info(State(state): State<AppState>) -> impl IntoResponse {
    let config = &state.inner.config;
    let pk = &state.inner.preprocess.proving_key;

    (
        StatusCode::OK,
        Json(CircuitInfoResponse {
            circuit_type: "Range Proof".to_string(),
            n_bits: config.n_bits,
            num_gates: config.n_bits * 2, // booleanity + accumulator
            domain_size: pk.n,
            num_copy_constraints: config.n_bits * 3, // Approximate
            num_public_inputs: pk.num_public_inputs,
            gate_types: GateTypeCounts {
                booleanity: config.n_bits,
                accumulator: config.n_bits,
                padding: pk.n - config.n_bits * 2,
            },
        }),
    )
}

/// Response for SRS metadata
#[derive(Debug, Serialize)]
pub struct SrsMetaResponse {
    pub max_degree: usize,
    pub num_ceremony_participants: usize,
    pub g1_generator: String,
    pub g2_generator: String,
    pub g1_tau_sample: Vec<String>,
}

/// GET /api/srs_meta - Get SRS metadata
pub async fn get_srs_meta(State(state): State<AppState>) -> impl IntoResponse {
    use crate::curve::{G1Affine, G2Affine};

    let srs = &state.inner.srs;

    (
        StatusCode::OK,
        Json(SrsMetaResponse {
            max_degree: srs.g1_powers.len() - 1,
            num_ceremony_participants: state.inner.config.num_ceremony_participants,
            g1_generator: G1Affine::generator().to_hex(),
            g2_generator: G2Affine::generator().to_hex(),
            g1_tau_sample: srs
                .g1_powers
                .iter()
                .take(5)
                .map(|p| p.to_hex())
                .collect(),
        }),
    )
}

/// Health check endpoint
pub async fn health() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

/// Create a dummy proof for error responses
fn dummy_proof() -> CompactProof {
    use crate::curve::G1Affine;

    CompactProof {
        round1: crate::trace::Round1Commitments {
            a: G1Affine::identity(),
            b: G1Affine::identity(),
            c: G1Affine::identity(),
        },
        round2: crate::trace::Round2Commitment {
            z: G1Affine::identity(),
        },
        round3: crate::trace::Round3Commitments {
            t_lo: G1Affine::identity(),
            t_mid: G1Affine::identity(),
            t_hi: G1Affine::identity(),
        },
        round4: crate::trace::Round4Evaluations {
            a_zeta: Fr::zero(),
            b_zeta: Fr::zero(),
            c_zeta: Fr::zero(),
            s_sigma1_zeta: Fr::zero(),
            s_sigma2_zeta: Fr::zero(),
            z_omega_zeta: Fr::zero(),
        },
        round5: crate::trace::Round5Commitments {
            w_zeta: G1Affine::identity(),
            w_zeta_omega: G1Affine::identity(),
        },
    }
}
