//! BLS12-381 Scalar Field Operations
//!
//! This module provides the scalar field Fr for BLS12-381 curve.
//! The field has modulus r ≈ 2^255, providing ~128-bit security.

use ark_bls12_381::Fr as ArkFr;
use ark_ff::{Field, PrimeField, One, Zero, BigInt, FftField};
use ark_std::UniformRand;
use serde::{Serialize, Deserialize, Serializer, Deserializer};
use std::ops::{Add, Sub, Mul, Div, Neg, AddAssign, SubAssign, MulAssign};

/// The scalar field of BLS12-381.
/// This is the field where all polynomial coefficients and evaluations live.
///
/// Field modulus r = 52435875175126190479447740508185965837690552500527637822603658699938581184513
/// Approximately 2^255 (255 bits)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Fr(pub ArkFr);

impl Fr {
    /// The field modulus as a hex string
    pub const MODULUS_HEX: &'static str =
        "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001";

    /// Number of bits in the modulus
    pub const MODULUS_BITS: u32 = 255;

    /// Create a new field element from a u64
    pub fn from_u64(val: u64) -> Self {
        Fr(ArkFr::from(val))
    }

    /// Create a new field element from a u128
    pub fn from_u128(val: u128) -> Self {
        Fr(ArkFr::from(val))
    }

    /// Create the zero element
    pub fn zero() -> Self {
        Fr(ArkFr::zero())
    }

    /// Create the one element
    pub fn one() -> Self {
        Fr(ArkFr::one())
    }

    /// Check if this is zero
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    /// Check if this is one
    pub fn is_one(&self) -> bool {
        self.0.is_one()
    }

    /// Compute the multiplicative inverse (1/x)
    /// Returns None if x is zero
    pub fn inverse(&self) -> Option<Self> {
        self.0.inverse().map(Fr)
    }

    /// Compute x^n using square-and-multiply
    pub fn pow(&self, exp: u64) -> Self {
        let mut result = Fr::one();
        let mut base = *self;
        let mut e = exp;

        while e > 0 {
            if e & 1 == 1 {
                result = result * base;
            }
            base = base * base;
            e >>= 1;
        }
        result
    }

    /// Compute x^exp where exp is a field element (for large exponents)
    pub fn pow_big(&self, exp: &[u64]) -> Self {
        Fr(self.0.pow(exp))
    }

    /// Generate a random field element
    pub fn random<R: rand::Rng>(rng: &mut R) -> Self {
        Fr(ArkFr::rand(rng))
    }

    /// Negate the element (-x)
    pub fn neg(&self) -> Self {
        Fr(-self.0)
    }

    /// Square the element (x^2)
    pub fn square(&self) -> Self {
        Fr(self.0.square())
    }

    /// Double the element (2x)
    pub fn double(&self) -> Self {
        Fr(self.0.double())
    }

    /// Convert to bytes (little-endian)
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        let bigint = self.0.into_bigint();
        for (i, limb) in bigint.0.iter().enumerate() {
            let limb_bytes = limb.to_le_bytes();
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb_bytes);
        }
        bytes
    }

    /// Convert from bytes (little-endian)
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let mut limb_bytes = [0u8; 8];
            limb_bytes.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
            limbs[i] = u64::from_le_bytes(limb_bytes);
        }
        ArkFr::from_bigint(BigInt::new(limbs)).map(Fr)
    }

    /// Convert to hex string (full 64 characters)
    pub fn to_hex(&self) -> String {
        let bytes = self.to_bytes();
        // Reverse for big-endian display
        let mut be_bytes = bytes;
        be_bytes.reverse();
        format!("0x{}", hex::encode(be_bytes))
    }

    /// Convert to short hex string (truncated for display)
    pub fn to_short_hex(&self) -> String {
        let full = self.to_hex();
        if full.len() > 18 {
            format!("{}...{}", &full[..10], &full[full.len()-8..])
        } else {
            full
        }
    }

    /// Parse from hex string
    pub fn from_hex(s: &str) -> Option<Self> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        arr.reverse(); // Convert from big-endian to little-endian
        Self::from_bytes(&arr)
    }

    /// Get the underlying arkworks field element
    pub fn inner(&self) -> &ArkFr {
        &self.0
    }

    /// Get the primitive n-th root of unity
    /// Returns ω such that ω^n = 1 and ω^k ≠ 1 for 0 < k < n
    /// n must be a power of 2 and divide the field's two-adicity
    pub fn get_root_of_unity(n: usize) -> Option<Self> {
        if !n.is_power_of_two() {
            return None;
        }

        // BLS12-381 scalar field has 2^32 as its two-adicity
        // The 2^32-th root of unity is a generator
        let log_n = n.trailing_zeros() as u64;
        if log_n > 32 {
            return None;
        }

        // Get the 2^32-th root of unity from arkworks
        let root_of_unity = ArkFr::get_root_of_unity(n as u64)?;
        Some(Fr(root_of_unity))
    }

    /// Compute the Lagrange basis polynomial L_i(x) evaluated at point x
    /// L_i(x) = ω^(-i) * Z_H(x) / (n * (x - ω^i))
    /// where Z_H(x) = x^n - 1
    pub fn lagrange_basis_eval(i: usize, x: &Fr, omega: &Fr, n: usize) -> Fr {
        let omega_i = omega.pow(i as u64);

        // Z_H(x) = x^n - 1
        let z_h_x = x.pow(n as u64) - Fr::one();

        // n * (x - ω^i)
        let n_fr = Fr::from_u64(n as u64);
        let denom = n_fr * (*x - omega_i);

        // ω^(-i) = ω^(n-i)
        let omega_neg_i = omega.pow((n - i) as u64 % n as u64);

        // L_i(x) = ω^(-i) * Z_H(x) / (n * (x - ω^i))
        if denom.is_zero() {
            // x = ω^i, so L_i(x) = 1
            Fr::one()
        } else {
            omega_neg_i * z_h_x * denom.inverse().unwrap()
        }
    }
}

// Implement arithmetic operations

impl Add for Fr {
    type Output = Fr;
    fn add(self, rhs: Fr) -> Fr {
        Fr(self.0 + rhs.0)
    }
}

impl Sub for Fr {
    type Output = Fr;
    fn sub(self, rhs: Fr) -> Fr {
        Fr(self.0 - rhs.0)
    }
}

impl Mul for Fr {
    type Output = Fr;
    fn mul(self, rhs: Fr) -> Fr {
        Fr(self.0 * rhs.0)
    }
}

impl Div for Fr {
    type Output = Fr;
    fn div(self, rhs: Fr) -> Fr {
        Fr(self.0 / rhs.0)
    }
}

impl Neg for Fr {
    type Output = Fr;
    fn neg(self) -> Fr {
        Fr(-self.0)
    }
}

impl AddAssign for Fr {
    fn add_assign(&mut self, rhs: Fr) {
        self.0 += rhs.0;
    }
}

impl SubAssign for Fr {
    fn sub_assign(&mut self, rhs: Fr) {
        self.0 -= rhs.0;
    }
}

impl MulAssign for Fr {
    fn mul_assign(&mut self, rhs: Fr) {
        self.0 *= rhs.0;
    }
}

impl From<u64> for Fr {
    fn from(val: u64) -> Self {
        Fr::from_u64(val)
    }
}

impl From<u128> for Fr {
    fn from(val: u128) -> Self {
        Fr::from_u128(val)
    }
}

impl From<i32> for Fr {
    fn from(val: i32) -> Self {
        if val >= 0 {
            Fr::from_u64(val as u64)
        } else {
            Fr::zero() - Fr::from_u64((-val) as u64)
        }
    }
}

impl Default for Fr {
    fn default() -> Self {
        Fr::zero()
    }
}

// Serde implementation for JSON
impl Serialize for Fr {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct FrJson {
            full: String,
            short: String,
        }

        let json = FrJson {
            full: self.to_hex(),
            short: self.to_short_hex(),
        };
        json.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Fr {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct FrJson {
            full: String,
        }

        let json = FrJson::deserialize(deserializer)?;
        Fr::from_hex(&json.full)
            .ok_or_else(|| serde::de::Error::custom("Invalid field element hex"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_arithmetic() {
        let a = Fr::from_u64(5);
        let b = Fr::from_u64(3);

        assert_eq!(a + b, Fr::from_u64(8));
        assert_eq!(a - b, Fr::from_u64(2));
        assert_eq!(a * b, Fr::from_u64(15));
    }

    #[test]
    fn test_inverse() {
        let a = Fr::from_u64(5);
        let a_inv = a.inverse().unwrap();
        assert_eq!(a * a_inv, Fr::one());
    }

    #[test]
    fn test_root_of_unity() {
        let n = 16usize;
        let omega = Fr::get_root_of_unity(n).unwrap();

        // ω^n = 1
        assert_eq!(omega.pow(n as u64), Fr::one());

        // ω^(n/2) ≠ 1
        assert_ne!(omega.pow(n as u64 / 2), Fr::one());
    }

    #[test]
    fn test_hex_roundtrip() {
        let a = Fr::from_u64(12345678901234567890);
        let hex = a.to_hex();
        let b = Fr::from_hex(&hex).unwrap();
        assert_eq!(a, b);
    }
}
