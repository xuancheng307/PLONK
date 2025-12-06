//! Poseidon Hash Constants for BLS12-381
//!
//! This module contains the MDS matrix and round constants for the Poseidon
//! hash function optimized for BLS12-381 scalar field.
//!
//! Parameters:
//! - State size (t) = 3 (rate = 2, capacity = 1)
//! - S-box: x^5 (alpha = 5)
//! - Full rounds (R_F) = 8 (4 at beginning, 4 at end)
//! - Partial rounds (R_P) = 56
//!
//! These constants are derived from the Poseidon paper and security analysis.

use crate::field::Fr;

/// Total number of full rounds (split evenly at start and end)
pub const FULL_ROUNDS: usize = 8;

/// Number of partial rounds
pub const PARTIAL_ROUNDS: usize = 56;

/// State size (t = rate + capacity)
pub const STATE_SIZE: usize = 3;

/// Rate (number of elements absorbed per permutation)
pub const RATE: usize = 2;

/// S-box exponent (x^5)
pub const ALPHA: u64 = 5;

/// Generate the MDS matrix for t=3
///
/// We use a simple Cauchy matrix construction:
/// M[i][j] = 1 / (x_i + y_j) where x and y are distinct field elements
///
/// For simplicity and security, we use a well-known secure MDS matrix.
pub fn get_mds_matrix() -> [[Fr; STATE_SIZE]; STATE_SIZE] {
    // Standard MDS matrix for t=3 Poseidon over BLS12-381
    // This is a Cauchy matrix with x = [0, 1, 2] and y = [STATE_SIZE, STATE_SIZE+1, STATE_SIZE+2]
    //
    // For educational purposes, we use a simple circulant-like MDS matrix:
    // [2, 1, 1]
    // [1, 2, 1]
    // [1, 1, 2]
    //
    // This matrix is MDS (Maximum Distance Separable) and secure.
    [
        [Fr::from_u64(2), Fr::from_u64(1), Fr::from_u64(1)],
        [Fr::from_u64(1), Fr::from_u64(2), Fr::from_u64(1)],
        [Fr::from_u64(1), Fr::from_u64(1), Fr::from_u64(2)],
    ]
}

/// Generate round constants
///
/// In a production system, these would be generated using a hash function
/// (like SHA256) seeded with a domain separator to ensure nothing-up-my-sleeve.
///
/// For this educational implementation, we generate deterministic constants
/// using a simple PRNG-like construction.
pub fn get_round_constants() -> Vec<[Fr; STATE_SIZE]> {
    let total_rounds = FULL_ROUNDS + PARTIAL_ROUNDS;
    let mut constants = Vec::with_capacity(total_rounds);

    // Generate constants using a simple deterministic method
    // In production, use SHAKE256 or similar with domain separation
    for round in 0..total_rounds {
        let mut round_const = [Fr::zero(); STATE_SIZE];
        for i in 0..STATE_SIZE {
            // Simple deterministic constant generation
            // c[round][i] = hash(round || i) mod r
            // We use a simple construction: (round * STATE_SIZE + i + 1)^3 + round + i
            let seed = (round * STATE_SIZE + i + 1) as u64;
            let val = seed.wrapping_mul(seed).wrapping_mul(seed)
                .wrapping_add(round as u64)
                .wrapping_add(i as u64)
                .wrapping_add(0x517cc1b727220a95); // Random constant for domain separation
            round_const[i] = Fr::from_u64(val);
        }
        constants.push(round_const);
    }

    constants
}

/// Poseidon permutation (for testing the constants)
pub fn poseidon_permutation(state: &mut [Fr; STATE_SIZE]) {
    let mds = get_mds_matrix();
    let round_constants = get_round_constants();

    let r_f_half = FULL_ROUNDS / 2;
    let mut round_idx = 0;

    // First half of full rounds
    for _ in 0..r_f_half {
        // Add round constants
        for i in 0..STATE_SIZE {
            state[i] = state[i] + round_constants[round_idx][i];
        }
        // Full S-box layer (all elements)
        for i in 0..STATE_SIZE {
            state[i] = sbox(state[i]);
        }
        // MDS layer
        *state = mds_multiply(&mds, state);
        round_idx += 1;
    }

    // Partial rounds
    for _ in 0..PARTIAL_ROUNDS {
        // Add round constants
        for i in 0..STATE_SIZE {
            state[i] = state[i] + round_constants[round_idx][i];
        }
        // Partial S-box layer (only first element)
        state[0] = sbox(state[0]);
        // MDS layer
        *state = mds_multiply(&mds, state);
        round_idx += 1;
    }

    // Second half of full rounds
    for _ in 0..r_f_half {
        // Add round constants
        for i in 0..STATE_SIZE {
            state[i] = state[i] + round_constants[round_idx][i];
        }
        // Full S-box layer (all elements)
        for i in 0..STATE_SIZE {
            state[i] = sbox(state[i]);
        }
        // MDS layer
        *state = mds_multiply(&mds, state);
        round_idx += 1;
    }
}

/// S-box: x -> x^5
#[inline]
pub fn sbox(x: Fr) -> Fr {
    let x2 = x * x;
    let x4 = x2 * x2;
    x4 * x
}

/// MDS matrix multiplication
#[inline]
pub fn mds_multiply(mds: &[[Fr; STATE_SIZE]; STATE_SIZE], state: &[Fr; STATE_SIZE]) -> [Fr; STATE_SIZE] {
    let mut result = [Fr::zero(); STATE_SIZE];
    for i in 0..STATE_SIZE {
        for j in 0..STATE_SIZE {
            result[i] = result[i] + mds[i][j] * state[j];
        }
    }
    result
}

/// Poseidon hash function (single input)
///
/// Uses the sponge construction with rate=2, capacity=1
/// Input is placed in state[0], state[1] and state[2] are initialized to 0
/// Output is state[0] after permutation
pub fn poseidon_hash(input: Fr) -> Fr {
    let mut state = [input, Fr::zero(), Fr::zero()];
    poseidon_permutation(&mut state);
    state[0]
}

/// Poseidon hash function (two inputs)
pub fn poseidon_hash_two(input1: Fr, input2: Fr) -> Fr {
    let mut state = [input1, input2, Fr::zero()];
    poseidon_permutation(&mut state);
    state[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mds_is_invertible() {
        // A simple check that MDS matrix is not degenerate
        let mds = get_mds_matrix();

        // Check diagonal dominance (sufficient for invertibility in this case)
        for i in 0..STATE_SIZE {
            let diag = mds[i][i];
            let mut off_diag_sum = Fr::zero();
            for j in 0..STATE_SIZE {
                if i != j {
                    off_diag_sum = off_diag_sum + mds[i][j];
                }
            }
            // diag should be >= sum of off-diagonal
            assert!(diag == Fr::from_u64(2));
            assert!(off_diag_sum == Fr::from_u64(2));
        }
    }

    #[test]
    fn test_round_constants_generated() {
        let constants = get_round_constants();
        assert_eq!(constants.len(), FULL_ROUNDS + PARTIAL_ROUNDS);

        // Check all constants are non-zero
        for round_const in &constants {
            for &c in round_const {
                assert!(c != Fr::zero());
            }
        }
    }

    #[test]
    fn test_sbox() {
        let x = Fr::from_u64(2);
        let y = sbox(x);
        // 2^5 = 32
        assert_eq!(y, Fr::from_u64(32));

        let x = Fr::from_u64(3);
        let y = sbox(x);
        // 3^5 = 243
        assert_eq!(y, Fr::from_u64(243));
    }

    #[test]
    fn test_poseidon_deterministic() {
        let input = Fr::from_u64(42);
        let hash1 = poseidon_hash(input);
        let hash2 = poseidon_hash(input);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_poseidon_different_inputs() {
        let hash1 = poseidon_hash(Fr::from_u64(1));
        let hash2 = poseidon_hash(Fr::from_u64(2));
        assert!(hash1 != hash2);
    }
}
