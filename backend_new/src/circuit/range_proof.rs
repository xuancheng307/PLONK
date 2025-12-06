//! Range Proof Circuit
//!
//! Proves that a **private witness** x is in the range [0, 2^n_bits).
//! This is a true zero-knowledge proof: the verifier learns nothing about x.
//!
//! **Important**: x is NOT a public input. It is entirely hidden in the witness.
//! The verifier only knows:
//! - The circuit structure (range proof for n_bits)
//! - That the prover knows some x in [0, 2^n_bits)
//!
//! Circuit structure (for n_bits = 8):
//! - Gates 0-7: Booleanity constraints for each bit b_i (b_i^2 - b_i = 0)
//! - Gates 8-15: Accumulator gates s_{i+1} = s_i + 2^i * b_i
//!
//! No public input gate needed - x is purely a witness.
//! The proof demonstrates knowledge of a valid bit decomposition without revealing x.
//!
//! Total: 16 gates, domain size: 16 (for n_bits = 8)

use crate::circuit::{ConstraintSystem, Gate, Wire, WireType};
use crate::field::Fr;
use serde::{Deserialize, Serialize};

/// Range proof circuit
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RangeProofCircuit {
    /// Number of bits in the range proof
    pub n_bits: usize,
    /// The private witness x (NOT public input!)
    pub x: u64,
    /// The bit decomposition of x (witness)
    pub bits: Vec<bool>,
    /// The constraint system
    pub constraint_system: ConstraintSystem,
}

impl RangeProofCircuit {
    /// Create a new range proof circuit
    ///
    /// # Arguments
    /// * `n_bits` - Number of bits (default 8)
    /// * `x` - The private witness value to prove is in range [0, 2^n_bits)
    ///
    /// # Note
    /// x is a **witness** (private input), NOT a public input.
    /// The verifier will NOT learn the value of x from the proof.
    ///
    /// If x >= 2^n_bits, the circuit will still be created but the bit decomposition
    /// will use x mod 2^n_bits. Since the circuit constraints only check that the
    /// accumulated bits form a valid n-bit number, the proof will still verify,
    /// but it proves knowledge of (x mod 2^n_bits), not x itself.
    pub fn new(n_bits: usize, x: u64) -> Self {
        let max_value = 1u64 << n_bits;

        // For bit decomposition, use x mod 2^n_bits
        // If x=300 and n_bits=8, we decompose 300 mod 256 = 44
        let decomposed_value = x & (max_value - 1); // x mod 2^n_bits

        // Compute bit decomposition of the truncated value
        let bits: Vec<bool> = (0..n_bits).map(|i| (decomposed_value >> i) & 1 == 1).collect();

        // Verify decomposition
        let reconstructed: u64 = bits
            .iter()
            .enumerate()
            .map(|(i, &b)| if b { 1u64 << i } else { 0 })
            .sum();
        assert_eq!(reconstructed, decomposed_value);

        let mut circuit = RangeProofCircuit {
            n_bits,
            x,
            bits,
            constraint_system: ConstraintSystem::new(),
        };

        circuit.build_circuit();
        circuit
    }

    /// Build the constraint system
    ///
    /// The circuit structure is:
    /// 1. Booleanity gates: Ensure each bit b_i is in {0, 1}
    /// 2. Accumulator gates: Compute s_n = sum(2^i * b_i) for i in [0, n_bits)
    ///
    /// No public input gate - x is purely a witness!
    fn build_circuit(&mut self) {
        let cs = &mut self.constraint_system;

        // ============================================
        // Gates 0 to n_bits-1: Booleanity constraints
        // ============================================
        // For each bit b_i, we need: b_i * b_i - b_i = 0
        // Gate constraint: q_M * a * b + q_L * a = 0
        // Set a = b = b_i, q_M = 1, q_L = -1
        // This gives: b_i * b_i - b_i = 0 => b_i in {0, 1}

        for i in 0..self.n_bits {
            let mut gate = Gate::boolean(i);
            gate.description = format!("b_{} in {{0, 1}}", i);

            let b_i = if self.bits[i] { Fr::one() } else { Fr::zero() };
            // For boolean gate: a = b = b_i, c is unused (set to 0)
            gate.set_wires(b_i, b_i, Fr::zero());

            cs.add_gate(gate);
            cs.name_variable(Wire::a(i), &format!("b_{}", i));
        }

        // Add copy constraints: a[i] = b[i] (same bit)
        for i in 0..self.n_bits {
            cs.add_copy_constraint(
                Wire::a(i),
                Wire::b(i),
                &format!("a[{}] = b[{}] (both are b_{})", i, i, i),
            );
        }

        // ============================================
        // Gates n_bits to 2*n_bits-1: Accumulator gates
        // ============================================
        // We compute: s_0 = 0
        //             s_1 = s_0 + 2^0 * b_0 = b_0
        //             s_2 = s_1 + 2^1 * b_1
        //             ...
        //             s_n = s_{n-1} + 2^{n-1} * b_{n-1} = x (the witness)
        //
        // Gate i+n_bits: a = s_i, b = b_i, c = s_{i+1}
        // Constraint: s_i + 2^i * b_i - s_{i+1} = 0
        // q_L = 1, q_R = 2^i, q_O = -1

        let mut accumulator = Fr::zero();
        let mut power_of_2 = Fr::one();

        for i in 0..self.n_bits {
            let gate_idx = self.n_bits + i;

            let b_i = if self.bits[i] { Fr::one() } else { Fr::zero() };
            let next_accumulator = accumulator + power_of_2 * b_i;

            let mut gate = Gate::add_scaled(gate_idx, power_of_2);
            gate.gate_type = "accumulator".to_string();
            gate.description = format!(
                "s_{} = s_{} + 2^{} * b_{} = {} + {} * {} = {}",
                i + 1, i, i, i,
                accumulator.to_short_hex(),
                power_of_2.to_short_hex(),
                b_i.to_short_hex(),
                next_accumulator.to_short_hex()
            );

            // a = s_i, b = b_i, c = s_{i+1}
            gate.set_wires(accumulator, b_i, next_accumulator);

            cs.add_gate(gate);

            // Name variables
            if i == 0 {
                cs.name_variable(Wire::a(gate_idx), "s_0 (=0)");
            } else {
                cs.name_variable(Wire::a(gate_idx), &format!("s_{}", i));
            }
            cs.name_variable(Wire::b(gate_idx), &format!("b_{}", i));
            cs.name_variable(Wire::c(gate_idx), &format!("s_{}", i + 1));

            // Copy constraint: b[gate_idx] = a[i] (link to booleanity gate)
            cs.add_copy_constraint(
                Wire::b(gate_idx),
                Wire::a(i),
                &format!("accumulator's b[{}] = booleanity's a[{}] (both b_{})", gate_idx, i, i),
            );

            // Copy constraint: c[gate_idx-1] = a[gate_idx] for i > 0
            // (link previous output to current input)
            if i > 0 {
                cs.add_copy_constraint(
                    Wire::c(gate_idx - 1),
                    Wire::a(gate_idx),
                    &format!("c[{}] = a[{}] (s_{} flows)", gate_idx - 1, gate_idx, i),
                );
            }

            accumulator = next_accumulator;
            power_of_2 = power_of_2 * Fr::from_u64(2);
        }

        // NOTE: No public input gate!
        // The final accumulator s_n holds the value x, but x is NOT exposed as public input.
        // This is what makes the proof zero-knowledge: x is hidden in the witness.
        //
        // The proof only demonstrates:
        // "I know some x such that x can be decomposed into n boolean bits"
        // which is equivalent to:
        // "I know some x in [0, 2^n_bits)"

        // Finalize (pad to power of 2)
        cs.finalize();
    }

    /// Get the witness (all wire values)
    pub fn get_witness(&self) -> RangeProofWitness {
        let cs = &self.constraint_system;
        let n = cs.n;

        let mut a_values = vec![Fr::zero(); n];
        let mut b_values = vec![Fr::zero(); n];
        let mut c_values = vec![Fr::zero(); n];

        for (i, gate) in cs.gates.iter().enumerate() {
            a_values[i] = gate.a.unwrap_or(Fr::zero());
            b_values[i] = gate.b.unwrap_or(Fr::zero());
            c_values[i] = gate.c.unwrap_or(Fr::zero());
        }

        RangeProofWitness {
            x: self.x,
            bits: self.bits.clone(),
            a_values,
            b_values,
            c_values,
        }
    }

    /// Get the public inputs
    ///
    /// Returns an empty vector since x is NOT a public input in this zero-knowledge design.
    pub fn get_public_inputs(&self) -> Vec<(usize, Fr)> {
        // No public inputs! x is purely a witness.
        vec![]
    }

    /// Check if x is within the valid range [0, 2^n_bits)
    pub fn is_in_range(&self) -> bool {
        let max_value = 1u64 << self.n_bits;
        self.x < max_value
    }

    /// Verify the witness satisfies all constraints
    pub fn verify_witness(&self) -> bool {
        // Check all gate constraints
        // Skip dummy gates
        for gate in &self.constraint_system.gates {
            if gate.gate_type == "dummy" {
                continue;
            }
            if !gate.is_satisfied() {
                return false;
            }
        }

        // Check copy constraints
        for cc in &self.constraint_system.copy_constraints {
            let v1 = self.get_wire_value(&cc.wire1);
            let v2 = self.get_wire_value(&cc.wire2);
            if v1 != v2 {
                return false;
            }
        }

        // Verify the final accumulator equals x mod 2^n_bits
        let max_value = 1u64 << self.n_bits;
        let decomposed_value = self.x & (max_value - 1);
        let expected_final = Fr::from_u64(decomposed_value);

        let final_acc_gate_idx = 2 * self.n_bits - 1;
        let final_acc = self.constraint_system.gates[final_acc_gate_idx].c;

        if final_acc != Some(expected_final) {
            return false;
        }

        true
    }

    /// Get a wire value
    fn get_wire_value(&self, wire: &Wire) -> Option<Fr> {
        let gate = self.constraint_system.gates.get(wire.gate)?;
        match wire.wire_type {
            WireType::A => gate.a,
            WireType::B => gate.b,
            WireType::C => gate.c,
        }
    }

    /// Get circuit statistics
    pub fn stats(&self) -> CircuitStats {
        CircuitStats {
            n_bits: self.n_bits,
            num_gates: self.constraint_system.num_gates,
            domain_size: self.constraint_system.n,
            num_copy_constraints: self.constraint_system.copy_constraints.len(),
            num_public_inputs: 0, // No public inputs in ZK design!
        }
    }
}

/// Witness for range proof
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RangeProofWitness {
    pub x: u64,
    pub bits: Vec<bool>,
    pub a_values: Vec<Fr>,
    pub b_values: Vec<Fr>,
    pub c_values: Vec<Fr>,
}

/// Circuit statistics
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitStats {
    pub n_bits: usize,
    pub num_gates: usize,
    pub domain_size: usize,
    pub num_copy_constraints: usize,
    pub num_public_inputs: usize,
}

// ============================================================================
// Range Proof with Hash Binding
// ============================================================================
//
// This circuit proves: "I know x ∈ [0, 2^n_bits) such that H(x) = y"
// where y is the public input (hash output).
//
// This provides stronger guarantees than the basic range proof:
// - The verifier learns y = H(x), binding the proof to a specific (hidden) x
// - x remains private (zero-knowledge)
// - The prover cannot use a different x value without changing y

use crate::circuit::poseidon::PoseidonGadget;
use crate::poseidon_constants::poseidon_hash;

/// Range proof circuit with hash binding
///
/// Statement: "I know x ∈ [0, 2^n_bits) such that H(x) = y"
/// - x is the private witness
/// - y is the public input (hash output)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RangeProofWithHashCircuit {
    /// Number of bits in the range proof
    pub n_bits: usize,
    /// The private witness x
    pub x: u64,
    /// The bit decomposition of x
    pub bits: Vec<bool>,
    /// The public hash output y = H(x)
    pub hash_output: Fr,
    /// The constraint system
    pub constraint_system: ConstraintSystem,
    /// Gate index of the public input (hash output)
    pub public_input_gate: usize,
}

impl RangeProofWithHashCircuit {
    /// Create a new range proof circuit with hash binding
    ///
    /// # Arguments
    /// * `n_bits` - Number of bits
    /// * `x` - The private witness value
    ///
    /// # Returns
    /// A circuit proving "I know x ∈ [0, 2^n_bits) such that H(x) = y"
    pub fn new(n_bits: usize, x: u64) -> Self {
        let max_value = 1u64 << n_bits;
        let decomposed_value = x & (max_value - 1);

        // Compute bit decomposition
        let bits: Vec<bool> = (0..n_bits).map(|i| (decomposed_value >> i) & 1 == 1).collect();

        // Compute hash output
        let x_fr = Fr::from_u64(decomposed_value);
        let hash_output = poseidon_hash(x_fr);

        let mut circuit = RangeProofWithHashCircuit {
            n_bits,
            x,
            bits,
            hash_output,
            constraint_system: ConstraintSystem::new(),
            public_input_gate: 0,
        };

        circuit.build_circuit();
        circuit
    }

    /// Build the constraint system
    fn build_circuit(&mut self) {
        let cs = &mut self.constraint_system;

        // ============================================
        // Part 1: Range proof constraints (same as basic circuit)
        // ============================================

        // Gates 0 to n_bits-1: Booleanity constraints
        for i in 0..self.n_bits {
            let mut gate = Gate::boolean(i);
            gate.description = format!("b_{} in {{0, 1}}", i);

            let b_i = if self.bits[i] { Fr::one() } else { Fr::zero() };
            gate.set_wires(b_i, b_i, Fr::zero());

            cs.add_gate(gate);
            cs.name_variable(Wire::a(i), &format!("b_{}", i));
        }

        // Add copy constraints: a[i] = b[i] (same bit)
        for i in 0..self.n_bits {
            cs.add_copy_constraint(
                Wire::a(i),
                Wire::b(i),
                &format!("a[{}] = b[{}] (both are b_{})", i, i, i),
            );
        }

        // Gates n_bits to 2*n_bits-1: Accumulator gates
        let mut accumulator = Fr::zero();
        let mut power_of_2 = Fr::one();

        for i in 0..self.n_bits {
            let gate_idx = self.n_bits + i;

            let b_i = if self.bits[i] { Fr::one() } else { Fr::zero() };
            let next_accumulator = accumulator + power_of_2 * b_i;

            let mut gate = Gate::add_scaled(gate_idx, power_of_2);
            gate.gate_type = "accumulator".to_string();
            gate.description = format!("s_{} = s_{} + 2^{} * b_{}", i + 1, i, i, i);

            gate.set_wires(accumulator, b_i, next_accumulator);

            cs.add_gate(gate);

            if i == 0 {
                cs.name_variable(Wire::a(gate_idx), "s_0 (=0)");
            } else {
                cs.name_variable(Wire::a(gate_idx), &format!("s_{}", i));
            }
            cs.name_variable(Wire::b(gate_idx), &format!("b_{}", i));
            cs.name_variable(Wire::c(gate_idx), &format!("s_{}", i + 1));

            // Copy constraint: b[gate_idx] = a[i]
            cs.add_copy_constraint(
                Wire::b(gate_idx),
                Wire::a(i),
                &format!("accumulator's b[{}] = booleanity's a[{}]", gate_idx, i),
            );

            // Copy constraint: chain accumulators
            if i > 0 {
                cs.add_copy_constraint(
                    Wire::c(gate_idx - 1),
                    Wire::a(gate_idx),
                    &format!("c[{}] = a[{}] (s_{} flows)", gate_idx - 1, gate_idx, i),
                );
            }

            accumulator = next_accumulator;
            power_of_2 = power_of_2 * Fr::from_u64(2);
        }

        // ============================================
        // Part 2: Poseidon hash constraint
        // ============================================
        // The final accumulator is at c[2*n_bits - 1]
        // We need to constrain: H(final_accumulator) = hash_output

        let final_acc_wire = Wire::c(2 * self.n_bits - 1);

        let poseidon = PoseidonGadget::new();
        self.public_input_gate = poseidon.constrain_hash(cs, final_acc_wire, self.hash_output);

        // Finalize (pad to power of 2)
        cs.finalize();
    }

    /// Get the public inputs
    pub fn get_public_inputs(&self) -> Vec<(usize, Fr)> {
        vec![(self.public_input_gate, self.hash_output)]
    }

    /// Get the hash output (public input)
    pub fn get_hash_output(&self) -> Fr {
        self.hash_output
    }

    /// Check if x is within the valid range
    pub fn is_in_range(&self) -> bool {
        let max_value = 1u64 << self.n_bits;
        self.x < max_value
    }

    /// Get circuit statistics
    pub fn stats(&self) -> CircuitStats {
        CircuitStats {
            n_bits: self.n_bits,
            num_gates: self.constraint_system.num_gates,
            domain_size: self.constraint_system.n,
            num_copy_constraints: self.constraint_system.copy_constraints.len(),
            num_public_inputs: 1, // Hash output is the only public input
        }
    }

    /// Get the witness
    pub fn get_witness(&self) -> RangeProofWitness {
        let cs = &self.constraint_system;
        let n = cs.n;

        let mut a_values = vec![Fr::zero(); n];
        let mut b_values = vec![Fr::zero(); n];
        let mut c_values = vec![Fr::zero(); n];

        for (i, gate) in cs.gates.iter().enumerate() {
            a_values[i] = gate.a.unwrap_or(Fr::zero());
            b_values[i] = gate.b.unwrap_or(Fr::zero());
            c_values[i] = gate.c.unwrap_or(Fr::zero());
        }

        RangeProofWitness {
            x: self.x,
            bits: self.bits.clone(),
            a_values,
            b_values,
            c_values,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_range_proof_circuit_creation() {
        let circuit = RangeProofCircuit::new(8, 42);

        assert_eq!(circuit.n_bits, 8);
        assert_eq!(circuit.x, 42);
        assert_eq!(circuit.bits.len(), 8);

        // 42 = 0b00101010 = b1 + b3 + b5 (2 + 8 + 32)
        assert!(!circuit.bits[0]); // 2^0 = 1
        assert!(circuit.bits[1]);  // 2^1 = 2
        assert!(!circuit.bits[2]); // 2^2 = 4
        assert!(circuit.bits[3]);  // 2^3 = 8
        assert!(!circuit.bits[4]); // 2^4 = 16
        assert!(circuit.bits[5]);  // 2^5 = 32
        assert!(!circuit.bits[6]); // 2^6 = 64
        assert!(!circuit.bits[7]); // 2^7 = 128
    }

    #[test]
    fn test_no_public_inputs() {
        let circuit = RangeProofCircuit::new(8, 42);

        // Verify that there are NO public inputs
        assert!(circuit.get_public_inputs().is_empty());
        assert_eq!(circuit.constraint_system.public_input_positions.len(), 0);

        // x is witness, not public
        assert_eq!(circuit.stats().num_public_inputs, 0);
    }

    #[test]
    fn test_range_proof_witness_verification() {
        let circuit = RangeProofCircuit::new(8, 42);
        assert!(circuit.verify_witness());
        assert!(circuit.is_in_range());
    }

    #[test]
    fn test_range_proof_stats() {
        let circuit = RangeProofCircuit::new(8, 100);
        let stats = circuit.stats();

        assert_eq!(stats.n_bits, 8);
        assert_eq!(stats.num_gates, 16); // 8 booleanity + 8 accumulator (no public input gate!)
        assert_eq!(stats.domain_size, 16); // Power of 2 >= 16
        assert_eq!(stats.num_public_inputs, 0); // No public inputs!
    }

    #[test]
    fn test_boundary_values() {
        // Test x = 0
        let circuit = RangeProofCircuit::new(8, 0);
        assert!(circuit.verify_witness());
        assert!(circuit.is_in_range());

        // Test x = 255 (max for 8 bits)
        let circuit = RangeProofCircuit::new(8, 255);
        assert!(circuit.verify_witness());
        assert!(circuit.is_in_range());
    }

    #[test]
    fn test_out_of_range_256() {
        // x = 256 is out of 8-bit range
        let circuit = RangeProofCircuit::new(8, 256);

        // The bits should be all zeros (256 mod 256 = 0)
        assert!(circuit.bits.iter().all(|&b| !b));

        // Witness verification should PASS because the circuit only verifies
        // that the bits form a valid decomposition. The decomposition of 256 mod 256 = 0 is valid.
        assert!(circuit.verify_witness());

        // But is_in_range() should return false
        assert!(!circuit.is_in_range());
    }

    #[test]
    fn test_out_of_range_300() {
        // x = 300 is out of 8-bit range
        // 300 mod 256 = 44 = 0b00101100
        let circuit = RangeProofCircuit::new(8, 300);

        // The bits should represent 44
        assert!(!circuit.bits[0]); // 2^0 = 1
        assert!(!circuit.bits[1]); // 2^1 = 2
        assert!(circuit.bits[2]);  // 2^2 = 4
        assert!(circuit.bits[3]);  // 2^3 = 8
        assert!(!circuit.bits[4]); // 2^4 = 16
        assert!(circuit.bits[5]);  // 2^5 = 32
        assert!(!circuit.bits[6]); // 2^6 = 64
        assert!(!circuit.bits[7]); // 2^7 = 128
        // 4 + 8 + 32 = 44

        // Witness verification should PASS (circuit constraints are satisfied)
        assert!(circuit.verify_witness());

        // But is_in_range() should return false
        assert!(!circuit.is_in_range());
    }

    #[test]
    fn test_all_gates_satisfied() {
        let circuit = RangeProofCircuit::new(8, 127);

        for (i, gate) in circuit.constraint_system.gates.iter().enumerate() {
            // Skip dummy gates
            if gate.gate_type == "dummy" {
                continue;
            }
            assert!(
                gate.is_satisfied(),
                "Gate {} ({}) not satisfied",
                i,
                gate.gate_type
            );
        }
    }

    // ============================================
    // Tests for RangeProofWithHashCircuit
    // ============================================

    #[test]
    fn test_range_proof_with_hash_creation() {
        let circuit = RangeProofWithHashCircuit::new(8, 42);

        assert_eq!(circuit.n_bits, 8);
        assert_eq!(circuit.x, 42);
        assert!(circuit.is_in_range());

        // Verify hash output is computed
        let expected_hash = poseidon_hash(Fr::from_u64(42));
        assert_eq!(circuit.hash_output, expected_hash);

        // Check public inputs
        let public_inputs = circuit.get_public_inputs();
        assert_eq!(public_inputs.len(), 1);
        assert_eq!(public_inputs[0].1, expected_hash);
    }

    #[test]
    fn test_range_proof_with_hash_stats() {
        let circuit = RangeProofWithHashCircuit::new(8, 100);
        let stats = circuit.stats();

        assert_eq!(stats.n_bits, 8);
        assert_eq!(stats.num_public_inputs, 1);
        // The circuit should have many more gates than the basic version
        // due to Poseidon hash (64 rounds * 3-9 gates each)
        assert!(stats.num_gates > 16, "Expected many gates due to Poseidon, got {}", stats.num_gates);
        // Domain size should be power of 2
        assert!(stats.domain_size.is_power_of_two());
    }

    #[test]
    fn test_range_proof_with_hash_different_values() {
        // Different x values should produce different hash outputs
        let circuit1 = RangeProofWithHashCircuit::new(8, 42);
        let circuit2 = RangeProofWithHashCircuit::new(8, 43);

        assert!(circuit1.hash_output != circuit2.hash_output);
    }

    #[test]
    fn test_range_proof_with_hash_same_value() {
        // Same x value should produce same hash output
        let circuit1 = RangeProofWithHashCircuit::new(8, 42);
        let circuit2 = RangeProofWithHashCircuit::new(8, 42);

        assert_eq!(circuit1.hash_output, circuit2.hash_output);
    }
}
