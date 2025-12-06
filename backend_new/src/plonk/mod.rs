//! PLONK Protocol Implementation
//!
//! This module implements the PLONK proving system following the paper:
//! "PLONK: Permutations over Lagrange-bases for Oecumenical Noninteractive
//!  arguments of Knowledge" by Gabizon, Williamson, and Ciobotaru.
//!
//! The implementation follows Sections 6-8 of the paper exactly.

pub mod types;
pub mod permutation;
pub mod preprocess;
pub mod prover;
pub mod verifier;

pub use types::*;
pub use permutation::*;
pub use preprocess::*;
pub use prover::*;
pub use verifier::*;
