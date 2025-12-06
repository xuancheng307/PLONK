//! Permutation Argument for PLONK
//!
//! This module implements the copy constraint mechanism using permutation polynomials.
//! Following Section 5 of the PLONK paper.
//!
//! Key concepts:
//! - Wires are indexed: a(ω^i), b(ω^i), c(ω^i) for i = 0..n-1
//! - We use cosets: H, k1*H, k2*H for the three wire types
//! - Permutation σ* maps each wire to another in the same equivalence class
//! - S_σ1, S_σ2, S_σ3 encode the permutation as field elements

use crate::circuit::{ConstraintSystem, Wire, WireType};
use crate::field::Fr;
use crate::fft::Domain;
use crate::polynomial::Polynomial;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Permutation data for PLONK
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Permutation {
    /// Domain size
    pub n: usize,
    /// k1 generator for second coset
    pub k1: Fr,
    /// k2 generator for third coset
    pub k2: Fr,
    /// ω (n-th root of unity)
    pub omega: Fr,

    /// σ*(i) for wire a at position i -> maps to (wire_type, position)
    pub sigma_a: Vec<(WireType, usize)>,
    /// σ*(i) for wire b at position i
    pub sigma_b: Vec<(WireType, usize)>,
    /// σ*(i) for wire c at position i
    pub sigma_c: Vec<(WireType, usize)>,

    /// S_σ1 evaluations: S_σ1(ω^i) = σ*(a_i) encoded as field element
    pub s_sigma1_evals: Vec<Fr>,
    /// S_σ2 evaluations: S_σ2(ω^i) = σ*(b_i) encoded as field element
    pub s_sigma2_evals: Vec<Fr>,
    /// S_σ3 evaluations: S_σ3(ω^i) = σ*(c_i) encoded as field element
    pub s_sigma3_evals: Vec<Fr>,
}

impl Permutation {
    /// Compute the permutation from a constraint system
    ///
    /// # Arguments
    /// * `cs` - The constraint system with copy constraints
    /// * `domain` - The FFT domain
    ///
    /// # Returns
    /// The permutation data
    pub fn compute(cs: &ConstraintSystem, domain: &Domain) -> Self {
        let n = domain.n;
        let omega = domain.omega;

        // Choose k1, k2 such that H, k1*H, k2*H are disjoint cosets
        // We use quadratic non-residues
        let k1 = find_coset_generator(&omega, n, 1);
        let k2 = find_coset_generator(&omega, n, 2);

        // Initialize identity permutation
        // σ*(a_i) = a_i, σ*(b_i) = b_i, σ*(c_i) = c_i
        let mut sigma_a: Vec<(WireType, usize)> = (0..n).map(|i| (WireType::A, i)).collect();
        let mut sigma_b: Vec<(WireType, usize)> = (0..n).map(|i| (WireType::B, i)).collect();
        let mut sigma_c: Vec<(WireType, usize)> = (0..n).map(|i| (WireType::C, i)).collect();

        // Build equivalence classes from copy constraints
        // We use union-find to group wires that must be equal
        let mut uf = UnionFind::new(3 * n);

        for cc in &cs.copy_constraints {
            let idx1 = wire_to_index(&cc.wire1, n);
            let idx2 = wire_to_index(&cc.wire2, n);
            uf.union(idx1, idx2);
        }

        // Group wires by their equivalence class (root)
        let mut classes: HashMap<usize, Vec<usize>> = HashMap::new();
        for i in 0..(3 * n) {
            let root = uf.find(i);
            classes.entry(root).or_default().push(i);
        }

        // For each equivalence class, create a cycle
        for (_root, members) in &classes {
            if members.len() > 1 {
                // Create a cycle: member[0] -> member[1] -> ... -> member[k] -> member[0]
                for i in 0..members.len() {
                    let current = members[i];
                    let next = members[(i + 1) % members.len()];

                    let (target_type, target_pos) = index_to_wire(next, n);

                    // Set σ*(current) = next
                    match index_to_wire(current, n) {
                        (WireType::A, pos) => sigma_a[pos] = (target_type, target_pos),
                        (WireType::B, pos) => sigma_b[pos] = (target_type, target_pos),
                        (WireType::C, pos) => sigma_c[pos] = (target_type, target_pos),
                    }
                }
            }
        }

        // Compute S_σ1, S_σ2, S_σ3 evaluations
        // For wire type A at position i, the "address" is ω^i
        // For wire type B at position i, the "address" is k1 * ω^i
        // For wire type C at position i, the "address" is k2 * ω^i
        let powers_of_omega: Vec<Fr> = domain.elements().collect();

        let s_sigma1_evals: Vec<Fr> = sigma_a
            .iter()
            .map(|(wt, pos)| encode_wire(*wt, *pos, &powers_of_omega, k1, k2))
            .collect();

        let s_sigma2_evals: Vec<Fr> = sigma_b
            .iter()
            .map(|(wt, pos)| encode_wire(*wt, *pos, &powers_of_omega, k1, k2))
            .collect();

        let s_sigma3_evals: Vec<Fr> = sigma_c
            .iter()
            .map(|(wt, pos)| encode_wire(*wt, *pos, &powers_of_omega, k1, k2))
            .collect();

        Permutation {
            n,
            k1,
            k2,
            omega,
            sigma_a,
            sigma_b,
            sigma_c,
            s_sigma1_evals,
            s_sigma2_evals,
            s_sigma3_evals,
        }
    }

    /// Get S_σ1 as a polynomial
    pub fn s_sigma1_poly(&self, domain: &Domain) -> Polynomial {
        Polynomial::from_evaluations(&self.s_sigma1_evals, domain)
    }

    /// Get S_σ2 as a polynomial
    pub fn s_sigma2_poly(&self, domain: &Domain) -> Polynomial {
        Polynomial::from_evaluations(&self.s_sigma2_evals, domain)
    }

    /// Get S_σ3 as a polynomial
    pub fn s_sigma3_poly(&self, domain: &Domain) -> Polynomial {
        Polynomial::from_evaluations(&self.s_sigma3_evals, domain)
    }

    /// Verify that the permutation is correct (for testing)
    pub fn verify(&self, cs: &ConstraintSystem) -> bool {
        // Check that each copy constraint is satisfied by the permutation
        for cc in &cs.copy_constraints {
            // Both wires should be in the same cycle
            let idx1 = wire_to_index(&cc.wire1, self.n);
            let idx2 = wire_to_index(&cc.wire2, self.n);

            // Follow the cycle from idx1 and check if we reach idx2
            let mut current = idx1;
            let mut found = false;
            for _ in 0..self.n * 3 {
                if current == idx2 {
                    found = true;
                    break;
                }
                current = self.follow(current);
                if current == idx1 {
                    break;
                }
            }
            if !found {
                return false;
            }
        }
        true
    }

    /// Follow the permutation: σ*(current) -> next
    fn follow(&self, idx: usize) -> usize {
        let (wire_type, pos) = index_to_wire(idx, self.n);
        let (next_type, next_pos) = match wire_type {
            WireType::A => self.sigma_a[pos],
            WireType::B => self.sigma_b[pos],
            WireType::C => self.sigma_c[pos],
        };
        wire_to_index(&Wire::new(next_pos, next_type), self.n)
    }

    /// Get a trace of the permutation for visualization
    pub fn trace(&self) -> PermutationTrace {
        let mut cycles = Vec::new();

        let mut visited = vec![false; 3 * self.n];

        for start in 0..(3 * self.n) {
            if visited[start] {
                continue;
            }

            let mut cycle = Vec::new();
            let mut current = start;

            loop {
                if visited[current] {
                    break;
                }
                visited[current] = true;

                let (wire_type, pos) = index_to_wire(current, self.n);
                cycle.push(format!("{}{}", wire_type_char(wire_type), pos));

                current = self.follow(current);
                if current == start {
                    break;
                }
            }

            if cycle.len() > 1 {
                cycles.push(CycleTrace {
                    wires: cycle,
                    description: "Copy constraint cycle".to_string(),
                });
            }
        }

        PermutationTrace {
            n: self.n,
            k1: self.k1,
            k2: self.k2,
            cycles,
            s_sigma1: self.s_sigma1_evals.clone(),
            s_sigma2: self.s_sigma2_evals.clone(),
            s_sigma3: self.s_sigma3_evals.clone(),
        }
    }
}

/// Trace of permutation for visualization
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PermutationTrace {
    pub n: usize,
    pub k1: Fr,
    pub k2: Fr,
    pub cycles: Vec<CycleTrace>,
    pub s_sigma1: Vec<Fr>,
    pub s_sigma2: Vec<Fr>,
    pub s_sigma3: Vec<Fr>,
}

/// A single cycle in the permutation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CycleTrace {
    pub wires: Vec<String>,
    pub description: String,
}

/// Convert wire to linear index
/// a_i -> i, b_i -> n + i, c_i -> 2n + i
fn wire_to_index(wire: &Wire, n: usize) -> usize {
    match wire.wire_type {
        WireType::A => wire.gate,
        WireType::B => n + wire.gate,
        WireType::C => 2 * n + wire.gate,
    }
}

/// Convert linear index to wire
fn index_to_wire(idx: usize, n: usize) -> (WireType, usize) {
    if idx < n {
        (WireType::A, idx)
    } else if idx < 2 * n {
        (WireType::B, idx - n)
    } else {
        (WireType::C, idx - 2 * n)
    }
}

/// Encode a wire reference as a field element
/// A at position i -> ω^i
/// B at position i -> k1 * ω^i
/// C at position i -> k2 * ω^i
fn encode_wire(wire_type: WireType, pos: usize, powers: &[Fr], k1: Fr, k2: Fr) -> Fr {
    let omega_i = powers[pos];
    match wire_type {
        WireType::A => omega_i,
        WireType::B => k1 * omega_i,
        WireType::C => k2 * omega_i,
    }
}

fn wire_type_char(wt: WireType) -> char {
    match wt {
        WireType::A => 'a',
        WireType::B => 'b',
        WireType::C => 'c',
    }
}

/// Find a coset generator that creates a disjoint coset from H
fn find_coset_generator(omega: &Fr, n: usize, index: usize) -> Fr {
    // We need k such that k*H ∩ H = ∅
    // This is guaranteed if k is not in H (i.e., k^n ≠ 1)
    // We use small primes that are quadratic non-residues

    // Simple approach: use powers of a generator
    // For BLS12-381, we can use specific values known to work
    let mut k = Fr::from_u64(5 + index as u64);

    // Verify k is not in H
    loop {
        let k_n = k.pow(n as u64);
        if k_n != Fr::one() {
            break;
        }
        k = k + Fr::one();
    }

    k
}

/// Union-Find data structure for computing equivalence classes
struct UnionFind {
    parent: Vec<usize>,
    rank: Vec<usize>,
}

impl UnionFind {
    fn new(size: usize) -> Self {
        UnionFind {
            parent: (0..size).collect(),
            rank: vec![0; size],
        }
    }

    fn find(&mut self, x: usize) -> usize {
        if self.parent[x] != x {
            self.parent[x] = self.find(self.parent[x]);
        }
        self.parent[x]
    }

    fn union(&mut self, x: usize, y: usize) {
        let px = self.find(x);
        let py = self.find(y);

        if px == py {
            return;
        }

        if self.rank[px] < self.rank[py] {
            self.parent[px] = py;
        } else if self.rank[px] > self.rank[py] {
            self.parent[py] = px;
        } else {
            self.parent[py] = px;
            self.rank[px] += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::RangeProofCircuit;

    #[test]
    fn test_permutation_identity() {
        // Create a simple constraint system with no copy constraints
        let mut cs = ConstraintSystem::new();
        cs.add_gate(crate::circuit::Gate::dummy(0));
        cs.add_gate(crate::circuit::Gate::dummy(1));
        cs.add_gate(crate::circuit::Gate::dummy(2));
        cs.add_gate(crate::circuit::Gate::dummy(3));
        cs.finalize();

        let domain = Domain::new(cs.n).unwrap();
        let perm = Permutation::compute(&cs, &domain);

        // With no copy constraints, permutation should be identity
        for i in 0..cs.n {
            assert_eq!(perm.sigma_a[i], (WireType::A, i));
            assert_eq!(perm.sigma_b[i], (WireType::B, i));
            assert_eq!(perm.sigma_c[i], (WireType::C, i));
        }
    }

    #[test]
    fn test_permutation_with_copy_constraints() {
        // Use range proof circuit which has copy constraints
        let circuit = RangeProofCircuit::new(8, 42);
        let cs = &circuit.constraint_system;
        let domain = Domain::new(cs.n).unwrap();

        let perm = Permutation::compute(cs, &domain);

        // Verify the permutation
        assert!(perm.verify(cs));
    }

    #[test]
    fn test_coset_generators() {
        let omega = Fr::get_root_of_unity(8).unwrap();
        let k1 = find_coset_generator(&omega, 8, 1);
        let k2 = find_coset_generator(&omega, 8, 2);

        // k1^8 and k2^8 should not be 1
        assert_ne!(k1.pow(8), Fr::one());
        assert_ne!(k2.pow(8), Fr::one());

        // k1 and k2 should be different
        assert_ne!(k1, k2);
    }
}
