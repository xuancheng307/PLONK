//! PLONK ZK-SNARK Implementation
//!
//! This is an educational implementation of the PLONK protocol following
//! the paper "PLONK: Permutations over Lagrange-bases for Oecumenical
//! Noninteractive arguments of Knowledge" (Gabizon, Williamson, Ciobotaru, 2019).
//!
//! # Modules
//! - `field`: BLS12-381 scalar field operations
//! - `curve`: Elliptic curve group operations (G1, G2, GT, pairing)
//! - `polynomial`: Polynomial arithmetic and evaluation
//! - `fft`: Fast Fourier Transform over multiplicative subgroups
//! - `kzg`: Kate-Zaverucha-Goldberg polynomial commitment scheme
//! - `transcript`: Fiat-Shamir transcript for non-interactive proofs
//! - `circuit`: Arithmetic circuit definitions (range proof)
//! - `plonk`: PLONK prover and verifier
//! - `trace`: Execution trace for detailed JSON output
//! - `api`: HTTP API handlers

pub mod field;
pub mod curve;
pub mod polynomial;
pub mod fft;
pub mod kzg;
pub mod transcript;
pub mod circuit;
pub mod plonk;
pub mod trace;
pub mod api;
pub mod poseidon_constants;

/// Re-export commonly used types
pub use field::Fr;
pub use curve::{G1Affine, G1Projective, G2Affine, G2Projective};
pub use polynomial::Polynomial;
pub use kzg::{Srs, Commitment};
pub use plonk::{Proof, VerificationKey, ProvingKey};
