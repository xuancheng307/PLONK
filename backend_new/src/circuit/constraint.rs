//! Constraint System Definition
//!
//! Defines the structure of PLONK circuits including gates, wires, and constraints.

use crate::field::Fr;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Wire types in the circuit
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WireType {
    /// Left input wire
    A,
    /// Right input wire
    B,
    /// Output wire
    C,
}

/// A wire reference in the circuit
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Wire {
    /// Gate index
    pub gate: usize,
    /// Wire type (A, B, or C)
    pub wire_type: WireType,
}

impl Wire {
    pub fn new(gate: usize, wire_type: WireType) -> Self {
        Wire { gate, wire_type }
    }

    pub fn a(gate: usize) -> Self {
        Wire::new(gate, WireType::A)
    }

    pub fn b(gate: usize) -> Self {
        Wire::new(gate, WireType::B)
    }

    pub fn c(gate: usize) -> Self {
        Wire::new(gate, WireType::C)
    }

    /// Convert to linear index in the wire vector
    /// For n gates: a wires are [0, n-1], b wires are [n, 2n-1], c wires are [2n, 3n-1]
    pub fn to_index(&self, n: usize) -> usize {
        match self.wire_type {
            WireType::A => self.gate,
            WireType::B => n + self.gate,
            WireType::C => 2 * n + self.gate,
        }
    }

    /// Convert from linear index
    pub fn from_index(index: usize, n: usize) -> Self {
        if index < n {
            Wire::a(index)
        } else if index < 2 * n {
            Wire::b(index - n)
        } else {
            Wire::c(index - 2 * n)
        }
    }
}

/// A gate in the PLONK circuit
///
/// Constraint: q_M * a * b + q_L * a + q_R * b + q_O * c + q_C = 0
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Gate {
    /// Gate index
    pub index: usize,
    /// Gate type description
    pub gate_type: String,
    /// Human-readable constraint description
    pub description: String,

    // Selector values
    /// Multiplication selector
    pub q_m: Fr,
    /// Left wire selector
    pub q_l: Fr,
    /// Right wire selector
    pub q_r: Fr,
    /// Output wire selector
    pub q_o: Fr,
    /// Constant selector
    pub q_c: Fr,

    // Wire assignments (set during witness generation)
    /// Left wire value
    pub a: Option<Fr>,
    /// Right wire value
    pub b: Option<Fr>,
    /// Output wire value
    pub c: Option<Fr>,
}

impl Gate {
    /// Create a new gate with given selectors
    pub fn new(
        index: usize,
        gate_type: &str,
        q_m: Fr,
        q_l: Fr,
        q_r: Fr,
        q_o: Fr,
        q_c: Fr,
    ) -> Self {
        Gate {
            index,
            gate_type: gate_type.to_string(),
            description: String::new(),
            q_m,
            q_l,
            q_r,
            q_o,
            q_c,
            a: None,
            b: None,
            c: None,
        }
    }

    /// Create a multiplication gate: a * b = c
    /// Constraint: q_M * a * b - c = 0  =>  q_M=1, q_O=-1
    pub fn mul(index: usize) -> Self {
        Gate::new(
            index,
            "mul",
            Fr::one(),             // q_m = 1
            Fr::zero(),            // q_l = 0
            Fr::zero(),            // q_r = 0
            Fr::zero() - Fr::one(), // q_o = -1
            Fr::zero(),            // q_c = 0
        )
    }

    /// Create an addition gate: a + b = c
    /// Constraint: a + b - c = 0  =>  q_L=1, q_R=1, q_O=-1
    pub fn add(index: usize) -> Self {
        Gate::new(
            index,
            "add",
            Fr::zero(),            // q_m = 0
            Fr::one(),             // q_l = 1
            Fr::one(),             // q_r = 1
            Fr::zero() - Fr::one(), // q_o = -1
            Fr::zero(),            // q_c = 0
        )
    }

    /// Create a scaled addition gate: a + k*b = c
    /// Constraint: a + k*b - c = 0  =>  q_L=1, q_R=k, q_O=-1
    pub fn add_scaled(index: usize, k: Fr) -> Self {
        Gate::new(
            index,
            "add_scaled",
            Fr::zero(),            // q_m = 0
            Fr::one(),             // q_l = 1
            k,                     // q_r = k
            Fr::zero() - Fr::one(), // q_o = -1
            Fr::zero(),            // q_c = 0
        )
    }

    /// Create a booleanity gate: a * a - a = 0  =>  a ∈ {0, 1}
    /// We set a=b for this gate
    /// Constraint: a * a - a = 0  =>  q_M=1, q_L=-1
    pub fn boolean(index: usize) -> Self {
        Gate::new(
            index,
            "boolean",
            Fr::one(),             // q_m = 1  (for a*b = a*a)
            Fr::zero() - Fr::one(), // q_l = -1 (for -a)
            Fr::zero(),            // q_r = 0
            Fr::zero(),            // q_o = 0
            Fr::zero(),            // q_c = 0
        )
    }

    /// Create a constant gate: c = constant
    /// Constraint: -c + constant = 0  =>  q_O=-1, q_C=constant
    pub fn constant(index: usize, value: Fr) -> Self {
        Gate::new(
            index,
            "constant",
            Fr::zero(),            // q_m = 0
            Fr::zero(),            // q_l = 0
            Fr::zero(),            // q_r = 0
            Fr::zero() - Fr::one(), // q_o = -1
            value,                 // q_c = value
        )
    }

    /// Create a public input gate: a = public_input
    /// Constraint: a - PI = 0  =>  q_L=1, handled via PI polynomial
    pub fn public_input(index: usize) -> Self {
        Gate::new(
            index,
            "public_input",
            Fr::zero(),  // q_m = 0
            Fr::one(),   // q_l = 1
            Fr::zero(),  // q_r = 0
            Fr::zero(),  // q_o = 0
            Fr::zero(),  // q_c = 0
        )
    }

    /// Create a dummy/padding gate (all zeros, always satisfied)
    pub fn dummy(index: usize) -> Self {
        let mut gate = Gate::new(
            index,
            "dummy",
            Fr::zero(),
            Fr::zero(),
            Fr::zero(),
            Fr::zero(),
            Fr::zero(),
        );
        // Set wire values to zero for padding
        gate.set_wires(Fr::zero(), Fr::zero(), Fr::zero());
        gate
    }

    /// Set wire values
    pub fn set_wires(&mut self, a: Fr, b: Fr, c: Fr) {
        self.a = Some(a);
        self.b = Some(b);
        self.c = Some(c);
    }

    /// Check if the gate constraint is satisfied
    pub fn is_satisfied(&self) -> bool {
        match (self.a, self.b, self.c) {
            (Some(a), Some(b), Some(c)) => {
                let result = self.q_m * a * b
                    + self.q_l * a
                    + self.q_r * b
                    + self.q_o * c
                    + self.q_c;
                result.is_zero()
            }
            _ => false,
        }
    }

    /// Get the constraint as a string
    pub fn constraint_string(&self) -> String {
        let mut terms = Vec::new();

        if !self.q_m.is_zero() {
            terms.push(format!("{}·a·b", format_coeff(&self.q_m)));
        }
        if !self.q_l.is_zero() {
            terms.push(format!("{}·a", format_coeff(&self.q_l)));
        }
        if !self.q_r.is_zero() {
            terms.push(format!("{}·b", format_coeff(&self.q_r)));
        }
        if !self.q_o.is_zero() {
            terms.push(format!("{}·c", format_coeff(&self.q_o)));
        }
        if !self.q_c.is_zero() {
            terms.push(format!("{}", format_coeff(&self.q_c)));
        }

        if terms.is_empty() {
            "0 = 0".to_string()
        } else {
            format!("{} = 0", terms.join(" + "))
        }
    }
}

fn format_coeff(fr: &Fr) -> String {
    if *fr == Fr::one() {
        "1".to_string()
    } else if *fr == Fr::zero() - Fr::one() {
        "-1".to_string()
    } else {
        fr.to_short_hex()
    }
}

/// Copy constraint: two wires must have the same value
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CopyConstraint {
    /// First wire
    pub wire1: Wire,
    /// Second wire
    pub wire2: Wire,
    /// Description of why these are connected
    pub reason: String,
}

impl CopyConstraint {
    pub fn new(wire1: Wire, wire2: Wire, reason: &str) -> Self {
        CopyConstraint {
            wire1,
            wire2,
            reason: reason.to_string(),
        }
    }
}

/// The complete constraint system
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConstraintSystem {
    /// Number of gates (before padding)
    pub num_gates: usize,
    /// Domain size (power of 2, >= num_gates)
    pub n: usize,
    /// All gates
    pub gates: Vec<Gate>,
    /// Copy constraints
    pub copy_constraints: Vec<CopyConstraint>,
    /// Public input positions (gate indices where a-wire is public)
    pub public_input_positions: Vec<usize>,
    /// Variable names for display
    pub variable_names: HashMap<Wire, String>,
}

impl ConstraintSystem {
    /// Create a new empty constraint system
    pub fn new() -> Self {
        ConstraintSystem {
            num_gates: 0,
            n: 0,
            gates: Vec::new(),
            copy_constraints: Vec::new(),
            public_input_positions: Vec::new(),
            variable_names: HashMap::new(),
        }
    }

    /// Add a gate to the constraint system
    pub fn add_gate(&mut self, gate: Gate) -> usize {
        let index = self.gates.len();
        self.gates.push(gate);
        self.num_gates = self.gates.len();
        index
    }

    /// Add a copy constraint
    pub fn add_copy_constraint(&mut self, wire1: Wire, wire2: Wire, reason: &str) {
        self.copy_constraints.push(CopyConstraint::new(wire1, wire2, reason));
    }

    /// Mark a gate's a-wire as public input
    pub fn mark_public_input(&mut self, gate_index: usize) {
        if !self.public_input_positions.contains(&gate_index) {
            self.public_input_positions.push(gate_index);
        }
    }

    /// Name a variable for display
    pub fn name_variable(&mut self, wire: Wire, name: &str) {
        self.variable_names.insert(wire, name.to_string());
    }

    /// Finalize the constraint system by padding to power of 2
    pub fn finalize(&mut self) {
        // Find smallest power of 2 >= num_gates
        let mut n = 1;
        while n < self.num_gates {
            n *= 2;
        }
        // PLONK needs at least some padding
        if n < 4 {
            n = 4;
        }

        // Pad with dummy gates
        while self.gates.len() < n {
            self.gates.push(Gate::dummy(self.gates.len()));
        }

        self.n = n;
    }

    /// Get selector vectors
    pub fn get_selectors(&self) -> Selectors {
        Selectors {
            q_m: self.gates.iter().map(|g| g.q_m).collect(),
            q_l: self.gates.iter().map(|g| g.q_l).collect(),
            q_r: self.gates.iter().map(|g| g.q_r).collect(),
            q_o: self.gates.iter().map(|g| g.q_o).collect(),
            q_c: self.gates.iter().map(|g| g.q_c).collect(),
        }
    }

    /// Check if all gate constraints are satisfied
    pub fn is_satisfied(&self) -> bool {
        self.gates.iter().all(|g| g.is_satisfied())
    }

    /// Get wire values as vectors
    pub fn get_wire_values(&self) -> Option<(Vec<Fr>, Vec<Fr>, Vec<Fr>)> {
        let a: Option<Vec<Fr>> = self.gates.iter().map(|g| g.a).collect();
        let b: Option<Vec<Fr>> = self.gates.iter().map(|g| g.b).collect();
        let c: Option<Vec<Fr>> = self.gates.iter().map(|g| g.c).collect();

        match (a, b, c) {
            (Some(a), Some(b), Some(c)) => Some((a, b, c)),
            _ => None,
        }
    }
}

impl Default for ConstraintSystem {
    fn default() -> Self {
        Self::new()
    }
}

/// Selector polynomials
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Selectors {
    pub q_m: Vec<Fr>,
    pub q_l: Vec<Fr>,
    pub q_r: Vec<Fr>,
    pub q_o: Vec<Fr>,
    pub q_c: Vec<Fr>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mul_gate() {
        let mut gate = Gate::mul(0);
        gate.set_wires(Fr::from_u64(3), Fr::from_u64(4), Fr::from_u64(12));
        assert!(gate.is_satisfied());

        gate.set_wires(Fr::from_u64(3), Fr::from_u64(4), Fr::from_u64(11));
        assert!(!gate.is_satisfied());
    }

    #[test]
    fn test_add_gate() {
        let mut gate = Gate::add(0);
        gate.set_wires(Fr::from_u64(3), Fr::from_u64(4), Fr::from_u64(7));
        assert!(gate.is_satisfied());
    }

    #[test]
    fn test_boolean_gate() {
        let mut gate = Gate::boolean(0);

        // 0 * 0 - 0 = 0 ✓
        gate.set_wires(Fr::from_u64(0), Fr::from_u64(0), Fr::zero());
        assert!(gate.is_satisfied());

        // 1 * 1 - 1 = 0 ✓
        gate.set_wires(Fr::from_u64(1), Fr::from_u64(1), Fr::zero());
        assert!(gate.is_satisfied());

        // 2 * 2 - 2 = 2 ✗
        gate.set_wires(Fr::from_u64(2), Fr::from_u64(2), Fr::zero());
        assert!(!gate.is_satisfied());
    }

    #[test]
    fn test_wire_index_conversion() {
        let n = 4;

        let w = Wire::a(2);
        assert_eq!(w.to_index(n), 2);
        assert_eq!(Wire::from_index(2, n), w);

        let w = Wire::b(1);
        assert_eq!(w.to_index(n), 5);
        assert_eq!(Wire::from_index(5, n), w);

        let w = Wire::c(3);
        assert_eq!(w.to_index(n), 11);
        assert_eq!(Wire::from_index(11, n), w);
    }
}
