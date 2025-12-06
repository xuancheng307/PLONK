//! Poseidon Hash Gadget for PLONK Circuit
//!
//! This module implements the Poseidon hash function as a PLONK circuit gadget.
//! It can be used to constrain that a hash output equals a specific value,
//! enabling statements like "I know x such that H(x) = y" where y is public.
//!
//! Circuit Structure:
//! - S-box (x^5): Requires 2 multiplication gates
//!   - t1 = x * x
//!   - t2 = t1 * t1
//!   - out = t2 * x  (we use t1 for the last step since t2 = x^4)
//! - MDS layer: Uses linear combination gates
//! - Full rounds: 3 S-boxes + MDS per round
//! - Partial rounds: 1 S-box + MDS per round

use crate::circuit::{ConstraintSystem, Gate, Wire};
use crate::field::Fr;
use crate::poseidon_constants::{
    get_mds_matrix, get_round_constants, poseidon_hash, FULL_ROUNDS, PARTIAL_ROUNDS, STATE_SIZE,
};

/// Poseidon gadget for creating hash constraints in a circuit
pub struct PoseidonGadget {
    /// MDS matrix
    mds: [[Fr; STATE_SIZE]; STATE_SIZE],
    /// Round constants
    round_constants: Vec<[Fr; STATE_SIZE]>,
}

impl PoseidonGadget {
    /// Create a new Poseidon gadget
    pub fn new() -> Self {
        PoseidonGadget {
            mds: get_mds_matrix(),
            round_constants: get_round_constants(),
        }
    }

    /// Constrain that hash(input) = expected_output in the circuit
    ///
    /// # Arguments
    /// * `cs` - The constraint system to add gates to
    /// * `input_wire` - Wire holding the input value
    /// * `expected_output` - The expected hash output (public input)
    ///
    /// # Returns
    /// The gate index of the output gate (which can be marked as public input)
    pub fn constrain_hash(
        &self,
        cs: &mut ConstraintSystem,
        input_wire: Wire,
        expected_output: Fr,
    ) -> usize {
        // Get the input value from the wire
        let input_value = cs.gates[input_wire.gate].get_wire_value(&input_wire.wire_type)
            .expect("Input wire must have a value");

        // Compute the full hash to get intermediate values
        let trace = self.compute_hash_trace(input_value);

        // Initial state: [input, 0, 0]
        // We need wires for all state elements at each step
        let mut state_wires = [input_wire, Wire::a(0), Wire::a(0)]; // Will be updated

        // Create gates for initial state (state[1] and state[2] are 0)
        let start_gate = cs.gates.len();

        // Allocate initial zero values for state[1] and state[2]
        let zero_gate1 = self.add_constant_gate(cs, Fr::zero());
        let zero_gate2 = self.add_constant_gate(cs, Fr::zero());
        state_wires[1] = Wire::c(zero_gate1);
        state_wires[2] = Wire::c(zero_gate2);

        let mut round_idx = 0;
        let r_f_half = FULL_ROUNDS / 2;

        // Process all rounds using the pre-computed trace
        // First half of full rounds
        for round in 0..r_f_half {
            state_wires = self.add_full_round(cs, state_wires, round_idx, &trace);
            round_idx += 1;
        }

        // Partial rounds
        for round in 0..PARTIAL_ROUNDS {
            state_wires = self.add_partial_round(cs, state_wires, round_idx, &trace);
            round_idx += 1;
        }

        // Second half of full rounds
        for round in 0..r_f_half {
            state_wires = self.add_full_round(cs, state_wires, round_idx, &trace);
            round_idx += 1;
        }

        // Add public input constraint: state[0] = expected_output
        let output_gate = self.add_public_input_gate(cs, state_wires[0], expected_output);

        output_gate
    }

    /// Compute the full hash trace (all intermediate values)
    fn compute_hash_trace(&self, input: Fr) -> PoseidonTrace {
        let mut state = [input, Fr::zero(), Fr::zero()];
        let mut trace = PoseidonTrace {
            initial_state: state,
            round_states: Vec::new(),
        };

        let r_f_half = FULL_ROUNDS / 2;
        let mut round_idx = 0;

        // First half of full rounds
        for _ in 0..r_f_half {
            let round_state = self.apply_round(&mut state, round_idx, true);
            trace.round_states.push(round_state);
            round_idx += 1;
        }

        // Partial rounds
        for _ in 0..PARTIAL_ROUNDS {
            let round_state = self.apply_round(&mut state, round_idx, false);
            trace.round_states.push(round_state);
            round_idx += 1;
        }

        // Second half of full rounds
        for _ in 0..r_f_half {
            let round_state = self.apply_round(&mut state, round_idx, true);
            trace.round_states.push(round_state);
            round_idx += 1;
        }

        trace
    }

    /// Apply one round and return intermediate values
    fn apply_round(&self, state: &mut [Fr; STATE_SIZE], round_idx: usize, is_full: bool) -> RoundState {
        let before_rc = *state;

        // Add round constants
        for i in 0..STATE_SIZE {
            state[i] = state[i] + self.round_constants[round_idx][i];
        }
        let after_rc = *state;

        // S-box layer
        let mut sbox_intermediates = Vec::new();
        if is_full {
            // Full round: all elements go through S-box
            for i in 0..STATE_SIZE {
                let inter = self.sbox_trace(state[i]);
                state[i] = inter.output;
                sbox_intermediates.push(inter);
            }
        } else {
            // Partial round: only first element
            let inter = self.sbox_trace(state[0]);
            state[0] = inter.output;
            sbox_intermediates.push(inter);
        }
        let after_sbox = *state;

        // MDS layer
        let mut new_state = [Fr::zero(); STATE_SIZE];
        for i in 0..STATE_SIZE {
            for j in 0..STATE_SIZE {
                new_state[i] = new_state[i] + self.mds[i][j] * state[j];
            }
        }
        *state = new_state;
        let after_mds = *state;

        RoundState {
            before_rc,
            after_rc,
            sbox_intermediates,
            after_sbox,
            after_mds,
        }
    }

    /// Compute S-box trace: x -> x^5
    fn sbox_trace(&self, x: Fr) -> SboxIntermediate {
        let x2 = x * x;
        let x4 = x2 * x2;
        let x5 = x4 * x;
        SboxIntermediate {
            input: x,
            x2,
            x4,
            output: x5,
        }
    }

    /// Add gates for a full round
    fn add_full_round(
        &self,
        cs: &mut ConstraintSystem,
        input_wires: [Wire; STATE_SIZE],
        round_idx: usize,
        trace: &PoseidonTrace,
    ) -> [Wire; STATE_SIZE] {
        let round_state = &trace.round_states[round_idx];

        // Add round constants and S-boxes for all state elements
        let mut sbox_outputs = [Wire::a(0); STATE_SIZE];
        for i in 0..STATE_SIZE {
            let rc = self.round_constants[round_idx][i];
            let input_val = round_state.before_rc[i];

            // Add constant gate: temp = input + rc
            let temp_val = input_val + rc;
            let add_rc_gate = self.add_add_constant_gate(cs, input_wires[i], rc, temp_val);

            // S-box: output = temp^5
            sbox_outputs[i] = self.add_sbox_gates(
                cs,
                Wire::c(add_rc_gate),
                &round_state.sbox_intermediates[i]
            );
        }

        // MDS layer
        self.add_mds_layer(cs, sbox_outputs, &round_state.after_mds)
    }

    /// Add gates for a partial round
    fn add_partial_round(
        &self,
        cs: &mut ConstraintSystem,
        input_wires: [Wire; STATE_SIZE],
        round_idx: usize,
        trace: &PoseidonTrace,
    ) -> [Wire; STATE_SIZE] {
        let round_state = &trace.round_states[round_idx];

        // Add round constants to all elements, but S-box only for first
        let mut after_rc_wires = [Wire::a(0); STATE_SIZE];

        for i in 0..STATE_SIZE {
            let rc = self.round_constants[round_idx][i];
            let input_val = round_state.before_rc[i];
            let temp_val = input_val + rc;
            let add_rc_gate = self.add_add_constant_gate(cs, input_wires[i], rc, temp_val);
            after_rc_wires[i] = Wire::c(add_rc_gate);
        }

        // S-box only for first element
        let mut sbox_outputs = after_rc_wires;
        sbox_outputs[0] = self.add_sbox_gates(
            cs,
            after_rc_wires[0],
            &round_state.sbox_intermediates[0]
        );

        // MDS layer
        self.add_mds_layer(cs, sbox_outputs, &round_state.after_mds)
    }

    /// Add S-box gates: x -> x^5
    /// Uses 2 multiplication gates:
    /// - Gate 1: a=x, b=x -> c=x^2
    /// - Gate 2: a=x^2, b=x^2 -> c=x^4
    /// - Gate 3: a=x^4, b=x -> c=x^5
    fn add_sbox_gates(&self, cs: &mut ConstraintSystem, input: Wire, inter: &SboxIntermediate) -> Wire {
        let x = inter.input;
        let x2 = inter.x2;
        let x4 = inter.x4;
        let x5 = inter.output;

        // Gate 1: x^2 = x * x
        let gate1_idx = cs.gates.len();
        let mut gate1 = Gate::mul(gate1_idx);
        gate1.description = "S-box: x^2 = x * x".to_string();
        gate1.set_wires(x, x, x2);
        cs.add_gate(gate1);

        // Copy constraint: input wire = a[gate1]
        cs.add_copy_constraint(input, Wire::a(gate1_idx), "S-box input");
        cs.add_copy_constraint(input, Wire::b(gate1_idx), "S-box input duplicate");

        // Gate 2: x^4 = x^2 * x^2
        let gate2_idx = cs.gates.len();
        let mut gate2 = Gate::mul(gate2_idx);
        gate2.description = "S-box: x^4 = x^2 * x^2".to_string();
        gate2.set_wires(x2, x2, x4);
        cs.add_gate(gate2);

        // Copy constraints for x^2
        cs.add_copy_constraint(Wire::c(gate1_idx), Wire::a(gate2_idx), "x^2 flow");
        cs.add_copy_constraint(Wire::c(gate1_idx), Wire::b(gate2_idx), "x^2 duplicate");

        // Gate 3: x^5 = x^4 * x
        let gate3_idx = cs.gates.len();
        let mut gate3 = Gate::mul(gate3_idx);
        gate3.description = "S-box: x^5 = x^4 * x".to_string();
        gate3.set_wires(x4, x, x5);
        cs.add_gate(gate3);

        // Copy constraints
        cs.add_copy_constraint(Wire::c(gate2_idx), Wire::a(gate3_idx), "x^4 flow");
        cs.add_copy_constraint(input, Wire::b(gate3_idx), "x for x^5");

        Wire::c(gate3_idx)
    }

    /// Add MDS layer: output = MDS * input
    /// For each output element: out_i = sum_j(MDS[i][j] * in_j)
    fn add_mds_layer(
        &self,
        cs: &mut ConstraintSystem,
        inputs: [Wire; STATE_SIZE],
        expected_outputs: &[Fr; STATE_SIZE],
    ) -> [Wire; STATE_SIZE] {
        let mut output_wires = [Wire::a(0); STATE_SIZE];

        // Get input values from their wires
        let mut input_values = [Fr::zero(); STATE_SIZE];
        for i in 0..STATE_SIZE {
            input_values[i] = cs.gates[inputs[i].gate].get_wire_value(&inputs[i].wire_type)
                .unwrap_or(Fr::zero());
        }

        for i in 0..STATE_SIZE {
            // out_i = MDS[i][0]*in_0 + MDS[i][1]*in_1 + MDS[i][2]*in_2
            // We'll use a series of add_scaled gates

            // First term: MDS[i][0] * in_0
            let term0 = self.mds[i][0] * input_values[0];
            let gate0_idx = self.add_scale_gate(cs, inputs[0], self.mds[i][0], term0);

            // Second term: prev + MDS[i][1] * in_1
            let term01 = term0 + self.mds[i][1] * input_values[1];
            let gate1_idx = self.add_add_scaled_gate(
                cs,
                Wire::c(gate0_idx),
                inputs[1],
                self.mds[i][1],
                term01
            );

            // Third term: prev + MDS[i][2] * in_2
            let gate2_idx = self.add_add_scaled_gate(
                cs,
                Wire::c(gate1_idx),
                inputs[2],
                self.mds[i][2],
                expected_outputs[i]
            );

            output_wires[i] = Wire::c(gate2_idx);
        }

        output_wires
    }

    /// Add a constant gate: c = value
    fn add_constant_gate(&self, cs: &mut ConstraintSystem, value: Fr) -> usize {
        let gate_idx = cs.gates.len();
        let mut gate = Gate::constant(gate_idx, value);
        gate.description = format!("constant = {}", value.to_short_hex());
        gate.set_wires(Fr::zero(), Fr::zero(), value);
        cs.add_gate(gate);
        gate_idx
    }

    /// Add a gate: c = a + constant
    fn add_add_constant_gate(&self, cs: &mut ConstraintSystem, input: Wire, constant: Fr, output: Fr) -> usize {
        let gate_idx = cs.gates.len();

        // q_L * a + q_C + q_O * c = 0
        // a + constant - c = 0
        let mut gate = Gate::new(
            gate_idx,
            "add_const",
            Fr::zero(),                  // q_m
            Fr::one(),                   // q_l = 1
            Fr::zero(),                  // q_r
            Fr::zero() - Fr::one(),      // q_o = -1
            constant,                    // q_c = constant
        );

        let input_val = cs.gates[input.gate].get_wire_value(&input.wire_type)
            .unwrap_or(Fr::zero());

        gate.description = format!("add_const: {} + {}", input_val.to_short_hex(), constant.to_short_hex());
        gate.set_wires(input_val, Fr::zero(), output);
        cs.add_gate(gate);

        // Copy constraint: input wire = a[gate]
        cs.add_copy_constraint(input, Wire::a(gate_idx), "add_const input");

        gate_idx
    }

    /// Add a scale gate: c = k * a
    fn add_scale_gate(&self, cs: &mut ConstraintSystem, input: Wire, k: Fr, output: Fr) -> usize {
        let gate_idx = cs.gates.len();

        // q_L * a + q_O * c = 0
        // k * a - c = 0
        let mut gate = Gate::new(
            gate_idx,
            "scale",
            Fr::zero(),                  // q_m
            k,                           // q_l = k
            Fr::zero(),                  // q_r
            Fr::zero() - Fr::one(),      // q_o = -1
            Fr::zero(),                  // q_c
        );

        let input_val = cs.gates[input.gate].get_wire_value(&input.wire_type)
            .unwrap_or(Fr::zero());

        gate.description = format!("scale: {} * {}", k.to_short_hex(), input_val.to_short_hex());
        gate.set_wires(input_val, Fr::zero(), output);
        cs.add_gate(gate);

        cs.add_copy_constraint(input, Wire::a(gate_idx), "scale input");

        gate_idx
    }

    /// Add a gate: c = a + k * b
    fn add_add_scaled_gate(&self, cs: &mut ConstraintSystem, a_wire: Wire, b_wire: Wire, k: Fr, output: Fr) -> usize {
        let gate_idx = cs.gates.len();

        let mut gate = Gate::add_scaled(gate_idx, k);

        let a_val = cs.gates[a_wire.gate].get_wire_value(&a_wire.wire_type)
            .unwrap_or(Fr::zero());
        let b_val = cs.gates[b_wire.gate].get_wire_value(&b_wire.wire_type)
            .unwrap_or(Fr::zero());

        gate.description = format!("add_scaled: {} + {} * {}",
            a_val.to_short_hex(), k.to_short_hex(), b_val.to_short_hex());
        gate.set_wires(a_val, b_val, output);
        cs.add_gate(gate);

        cs.add_copy_constraint(a_wire, Wire::a(gate_idx), "add_scaled a input");
        cs.add_copy_constraint(b_wire, Wire::b(gate_idx), "add_scaled b input");

        gate_idx
    }

    /// Add a public input gate that constrains a wire to equal expected_output
    fn add_public_input_gate(&self, cs: &mut ConstraintSystem, input: Wire, expected: Fr) -> usize {
        let gate_idx = cs.gates.len();

        // We use a gate that constrains: a = expected (via PI polynomial)
        // q_L * a - PI = 0, where PI = -expected, so a = expected
        let mut gate = Gate::public_input(gate_idx);
        gate.description = format!("public_input: hash output = {}", expected.to_short_hex());

        let input_val = cs.gates[input.gate].get_wire_value(&input.wire_type)
            .unwrap_or(Fr::zero());

        gate.set_wires(input_val, Fr::zero(), Fr::zero());
        cs.add_gate(gate);

        cs.add_copy_constraint(input, Wire::a(gate_idx), "public input constraint");

        // Mark as public input
        cs.mark_public_input(gate_idx);

        gate_idx
    }
}

impl Default for PoseidonGadget {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper trait for Gate to get wire values
trait GateWireAccess {
    fn get_wire_value(&self, wire_type: &crate::circuit::WireType) -> Option<Fr>;
}

impl GateWireAccess for Gate {
    fn get_wire_value(&self, wire_type: &crate::circuit::WireType) -> Option<Fr> {
        match wire_type {
            crate::circuit::WireType::A => self.a,
            crate::circuit::WireType::B => self.b,
            crate::circuit::WireType::C => self.c,
        }
    }
}

/// Trace of a Poseidon hash computation
struct PoseidonTrace {
    initial_state: [Fr; STATE_SIZE],
    round_states: Vec<RoundState>,
}

/// State after each round
struct RoundState {
    before_rc: [Fr; STATE_SIZE],
    after_rc: [Fr; STATE_SIZE],
    sbox_intermediates: Vec<SboxIntermediate>,
    after_sbox: [Fr; STATE_SIZE],
    after_mds: [Fr; STATE_SIZE],
}

/// Intermediate values for S-box computation
struct SboxIntermediate {
    input: Fr,
    x2: Fr,
    x4: Fr,
    output: Fr, // x^5
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon_gadget_creation() {
        let gadget = PoseidonGadget::new();
        assert_eq!(gadget.round_constants.len(), FULL_ROUNDS + PARTIAL_ROUNDS);
    }

    #[test]
    fn test_sbox_trace() {
        let gadget = PoseidonGadget::new();
        let x = Fr::from_u64(3);
        let trace = gadget.sbox_trace(x);

        assert_eq!(trace.input, x);
        assert_eq!(trace.x2, Fr::from_u64(9));   // 3^2
        assert_eq!(trace.x4, Fr::from_u64(81));  // 3^4
        assert_eq!(trace.output, Fr::from_u64(243)); // 3^5
    }

    #[test]
    fn test_hash_trace_matches_direct() {
        let gadget = PoseidonGadget::new();
        let input = Fr::from_u64(42);

        // Compute via trace
        let trace = gadget.compute_hash_trace(input);
        let trace_output = trace.round_states.last().unwrap().after_mds[0];

        // Compute directly
        let direct_output = poseidon_hash(input);

        assert_eq!(trace_output, direct_output);
    }
}
