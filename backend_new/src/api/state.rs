//! Application State
//!
//! Holds the precomputed data and shared state for the API.

use crate::kzg::Srs;
use crate::plonk::preprocess::PreprocessedData;
use crate::trace::PrecomputedData;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    pub inner: Arc<AppStateInner>,
}

pub struct AppStateInner {
    /// SRS for the circuit
    pub srs: Srs,

    /// Preprocessed circuit data
    pub preprocess: PreprocessedData,

    /// Precomputed proofs for specific x values
    pub precomputed: RwLock<HashMap<u64, PrecomputedData>>,

    /// Configuration
    pub config: ApiConfig,
}

/// API configuration
#[derive(Clone, Debug)]
pub struct ApiConfig {
    /// Number of bits in range proof
    pub n_bits: usize,

    /// Number of ceremony participants
    pub num_ceremony_participants: usize,

    /// Default x values to precompute
    pub precomputed_x_values: Vec<u64>,
}

impl Default for ApiConfig {
    fn default() -> Self {
        ApiConfig {
            n_bits: 8,
            num_ceremony_participants: 4,
            precomputed_x_values: vec![0, 1, 2, 42, 100, 127, 128, 254, 255],
        }
    }
}

impl AppState {
    /// Create a new application state with the given configuration
    pub async fn new(config: ApiConfig) -> Self {
        use crate::circuit::RangeProofCircuit;
        use crate::plonk::preprocess::preprocess;
        use crate::plonk::prover::Prover;
        use crate::plonk::verifier::Verifier;
        use crate::trace::CompactProof;

        println!("Initializing application state...");

        // Create a dummy circuit to determine domain size
        let dummy_circuit = RangeProofCircuit::new(config.n_bits, 0);
        let n = dummy_circuit.constraint_system.n;

        println!("  Domain size: {}", n);
        println!("  Generating SRS...");

        // Generate SRS
        let srs = Srs::simulate_ceremony(n + 10, config.num_ceremony_participants);

        println!("  Preprocessing circuit...");

        // Preprocess
        let preprocess_data = preprocess(&dummy_circuit.constraint_system, &srs);

        println!("  Precomputing proofs for {:?}...", config.precomputed_x_values);

        // Precompute proofs
        let mut precomputed = HashMap::new();
        for &x in &config.precomputed_x_values {
            if x >= (1u64 << config.n_bits) {
                continue;
            }

            let circuit = RangeProofCircuit::new(config.n_bits, x);
            let prover = Prover::new(
                &circuit.constraint_system,
                &preprocess_data.proving_key,
                &preprocess_data.permutation,
                &preprocess_data.domain,
                &srs,
            );

            let public_inputs = vec![crate::field::Fr::from_u64(x)];
            let proof = prover.prove(&public_inputs);

            let verifier = Verifier::new(&preprocess_data.verification_key, &srs);
            let is_valid = verifier.verify(&proof, &public_inputs);

            precomputed.insert(
                x,
                PrecomputedData {
                    x,
                    n_bits: config.n_bits,
                    proof: CompactProof::from(&proof),
                    witness_x_for_demo: crate::field::Fr::from_u64(x),
                    in_range: true,
                    verification_key_hash: "0x...".to_string(),
                    is_valid,
                },
            );

            println!("    x={}: valid={}", x, is_valid);
        }

        println!("Application state initialized.");

        AppState {
            inner: Arc::new(AppStateInner {
                srs,
                preprocess: preprocess_data,
                precomputed: RwLock::new(precomputed),
                config,
            }),
        }
    }
}
