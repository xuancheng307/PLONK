//! Arithmetic Circuit Module
//!
//! This module defines the constraint system for PLONK circuits.
//! A circuit is composed of gates with the standard PLONK constraint:
//!
//!   q_M * a * b + q_L * a + q_R * b + q_O * c + q_C = 0
//!
//! where:
//! - a, b, c are wire values
//! - q_M, q_L, q_R, q_O, q_C are selector values

pub mod constraint;
pub mod range_proof;
pub mod poseidon;

pub use constraint::{Gate, ConstraintSystem, Wire, WireType};
pub use range_proof::{RangeProofCircuit, RangeProofWithHashCircuit};
pub use poseidon::PoseidonGadget;
