//! BLS12-381 Elliptic Curve Groups and Pairing
//!
//! This module provides the elliptic curve groups G1, G2, GT and the
//! bilinear pairing e: G1 × G2 → GT for BLS12-381.
//!
//! # Security
//! BLS12-381 provides approximately 128-bit security level.
//!
//! # Group Sizes
//! - G1 points: 48 bytes (compressed) or 96 bytes (uncompressed)
//! - G2 points: 96 bytes (compressed) or 192 bytes (uncompressed)

use ark_bls12_381::{
    Bls12_381, G1Affine as ArkG1Affine, G1Projective as ArkG1Projective,
    G2Affine as ArkG2Affine, G2Projective as ArkG2Projective,
};
use ark_ec::{
    pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM, Group,
};
use ark_ff::One;
use ark_std::Zero;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use serde::{Deserialize, Serialize, Serializer, Deserializer};
use std::ops::{Add, Mul, Neg, Sub};

use crate::field::Fr;

/// G1 point in affine coordinates
/// This is the "smaller" group with 48-byte compressed representation
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct G1Affine(pub ArkG1Affine);

/// G1 point in projective coordinates (for efficient arithmetic)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct G1Projective(pub ArkG1Projective);

/// G2 point in affine coordinates
/// This is the "larger" group with 96-byte compressed representation
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct G2Affine(pub ArkG2Affine);

/// G2 point in projective coordinates
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct G2Projective(pub ArkG2Projective);

/// Target group element (result of pairing)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gt(pub <Bls12_381 as Pairing>::TargetField);

// ============================================================================
// G1 Implementation
// ============================================================================

impl G1Affine {
    /// Size of compressed representation in bytes
    pub const COMPRESSED_SIZE: usize = 48;

    /// Size of uncompressed representation in bytes
    pub const UNCOMPRESSED_SIZE: usize = 96;

    /// Get the generator point
    pub fn generator() -> Self {
        G1Affine(ArkG1Affine::generator())
    }

    /// Get the identity (point at infinity)
    pub fn identity() -> Self {
        G1Affine(ArkG1Affine::identity())
    }

    /// Check if this is the identity point
    pub fn is_identity(&self) -> bool {
        self.0.is_zero()
    }

    /// Convert to projective coordinates
    pub fn to_projective(&self) -> G1Projective {
        G1Projective(self.0.into())
    }

    /// Serialize to compressed bytes (48 bytes)
    pub fn to_compressed_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.0.serialize_compressed(&mut bytes).unwrap();
        bytes
    }

    /// Deserialize from compressed bytes
    pub fn from_compressed_bytes(bytes: &[u8]) -> Option<Self> {
        ArkG1Affine::deserialize_compressed(bytes).ok().map(G1Affine)
    }

    /// Convert to hex string (compressed)
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.to_compressed_bytes()))
    }

    /// Convert to short hex string for display
    pub fn to_short_hex(&self) -> String {
        let full = self.to_hex();
        if full.len() > 22 {
            format!("{}...{}", &full[..14], &full[full.len()-8..])
        } else {
            full
        }
    }

    /// Get x coordinate as hex (for detailed display)
    pub fn x_hex(&self) -> String {
        if self.is_identity() {
            "infinity".to_string()
        } else {
            // Use serialization to extract coordinates
            let mut bytes = Vec::new();
            self.0.serialize_uncompressed(&mut bytes).unwrap();
            // x coordinate is first 48 bytes in uncompressed form
            format!("0x{}", hex::encode(&bytes[..48]))
        }
    }

    /// Get y coordinate as hex (for detailed display)
    pub fn y_hex(&self) -> String {
        if self.is_identity() {
            "infinity".to_string()
        } else {
            let mut bytes = Vec::new();
            self.0.serialize_uncompressed(&mut bytes).unwrap();
            // y coordinate is second 48 bytes in uncompressed form
            format!("0x{}", hex::encode(&bytes[48..]))
        }
    }

    /// Negate the point
    pub fn neg(&self) -> Self {
        G1Affine((-self.0).into())
    }
}

impl G1Projective {
    /// Get the generator point
    pub fn generator() -> Self {
        G1Projective(ArkG1Projective::generator())
    }

    /// Get the identity (point at infinity)
    pub fn identity() -> Self {
        G1Projective(ArkG1Projective::zero())
    }

    /// Check if this is the identity point
    pub fn is_identity(&self) -> bool {
        self.0.is_zero()
    }

    /// Convert to affine coordinates
    pub fn to_affine(&self) -> G1Affine {
        G1Affine(self.0.into_affine())
    }

    /// Scalar multiplication: scalar * G
    pub fn scalar_mul(&self, scalar: &Fr) -> Self {
        G1Projective(self.0 * scalar.0)
    }

    /// Multi-scalar multiplication (MSM): Σ scalars[i] * points[i]
    /// This is the most efficient way to compute linear combinations
    pub fn msm(points: &[G1Affine], scalars: &[Fr]) -> Self {
        let ark_points: Vec<_> = points.iter().map(|p| p.0).collect();
        let ark_scalars: Vec<_> = scalars.iter().map(|s| s.0.into_bigint()).collect();
        G1Projective(ArkG1Projective::msm_bigint(&ark_points, &ark_scalars))
    }

    /// Double the point
    pub fn double(&self) -> Self {
        G1Projective(self.0.double())
    }

    /// Generate a random point
    pub fn random<R: rand::Rng>(rng: &mut R) -> Self {
        G1Projective(ArkG1Projective::rand(rng))
    }
}

impl Add for G1Projective {
    type Output = G1Projective;
    fn add(self, rhs: G1Projective) -> G1Projective {
        G1Projective(self.0 + rhs.0)
    }
}

impl Sub for G1Projective {
    type Output = G1Projective;
    fn sub(self, rhs: G1Projective) -> G1Projective {
        G1Projective(self.0 - rhs.0)
    }
}

impl Neg for G1Projective {
    type Output = G1Projective;
    fn neg(self) -> G1Projective {
        G1Projective(-self.0)
    }
}

impl Mul<Fr> for G1Projective {
    type Output = G1Projective;
    fn mul(self, rhs: Fr) -> G1Projective {
        self.scalar_mul(&rhs)
    }
}

impl Mul<G1Projective> for Fr {
    type Output = G1Projective;
    fn mul(self, rhs: G1Projective) -> G1Projective {
        rhs.scalar_mul(&self)
    }
}

impl From<G1Affine> for G1Projective {
    fn from(p: G1Affine) -> Self {
        p.to_projective()
    }
}

impl From<G1Projective> for G1Affine {
    fn from(p: G1Projective) -> Self {
        p.to_affine()
    }
}

impl Default for G1Affine {
    fn default() -> Self {
        G1Affine::identity()
    }
}

// ============================================================================
// G2 Implementation
// ============================================================================

impl G2Affine {
    /// Size of compressed representation in bytes
    pub const COMPRESSED_SIZE: usize = 96;

    /// Get the generator point
    pub fn generator() -> Self {
        G2Affine(ArkG2Affine::generator())
    }

    /// Get the identity (point at infinity)
    pub fn identity() -> Self {
        G2Affine(ArkG2Affine::identity())
    }

    /// Check if this is the identity point
    pub fn is_identity(&self) -> bool {
        self.0.is_zero()
    }

    /// Convert to projective coordinates
    pub fn to_projective(&self) -> G2Projective {
        G2Projective(self.0.into())
    }

    /// Serialize to compressed bytes (96 bytes)
    pub fn to_compressed_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.0.serialize_compressed(&mut bytes).unwrap();
        bytes
    }

    /// Deserialize from compressed bytes
    pub fn from_compressed_bytes(bytes: &[u8]) -> Option<Self> {
        ArkG2Affine::deserialize_compressed(bytes).ok().map(G2Affine)
    }

    /// Convert to hex string (compressed)
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.to_compressed_bytes()))
    }

    /// Convert to short hex string for display
    pub fn to_short_hex(&self) -> String {
        let full = self.to_hex();
        if full.len() > 30 {
            format!("{}...{}", &full[..18], &full[full.len()-10..])
        } else {
            full
        }
    }

    /// Negate the point
    pub fn neg(&self) -> Self {
        G2Affine((-self.0).into())
    }
}

impl G2Projective {
    /// Get the generator point
    pub fn generator() -> Self {
        G2Projective(ArkG2Projective::generator())
    }

    /// Get the identity
    pub fn identity() -> Self {
        G2Projective(ArkG2Projective::zero())
    }

    /// Check if this is the identity
    pub fn is_identity(&self) -> bool {
        self.0.is_zero()
    }

    /// Convert to affine coordinates
    pub fn to_affine(&self) -> G2Affine {
        G2Affine(self.0.into_affine())
    }

    /// Scalar multiplication
    pub fn scalar_mul(&self, scalar: &Fr) -> Self {
        G2Projective(self.0 * scalar.0)
    }

    /// Multi-scalar multiplication
    pub fn msm(points: &[G2Affine], scalars: &[Fr]) -> Self {
        let ark_points: Vec<_> = points.iter().map(|p| p.0).collect();
        let ark_scalars: Vec<_> = scalars.iter().map(|s| s.0.into_bigint()).collect();
        G2Projective(ArkG2Projective::msm_bigint(&ark_points, &ark_scalars))
    }

    /// Generate a random point
    pub fn random<R: rand::Rng>(rng: &mut R) -> Self {
        G2Projective(ArkG2Projective::rand(rng))
    }
}

impl Add for G2Projective {
    type Output = G2Projective;
    fn add(self, rhs: G2Projective) -> G2Projective {
        G2Projective(self.0 + rhs.0)
    }
}

impl Sub for G2Projective {
    type Output = G2Projective;
    fn sub(self, rhs: G2Projective) -> G2Projective {
        G2Projective(self.0 - rhs.0)
    }
}

impl Neg for G2Projective {
    type Output = G2Projective;
    fn neg(self) -> G2Projective {
        G2Projective(-self.0)
    }
}

impl Mul<Fr> for G2Projective {
    type Output = G2Projective;
    fn mul(self, rhs: Fr) -> G2Projective {
        self.scalar_mul(&rhs)
    }
}

// ============================================================================
// Pairing Implementation
// ============================================================================

impl Gt {
    /// Get the identity element in GT
    pub fn identity() -> Self {
        Gt(<Bls12_381 as Pairing>::TargetField::one())
    }

    /// Check if this is the identity
    pub fn is_identity(&self) -> bool {
        self.0 == <Bls12_381 as Pairing>::TargetField::one()
    }
}

impl Mul for Gt {
    type Output = Gt;
    fn mul(self, rhs: Gt) -> Gt {
        Gt(self.0 * rhs.0)
    }
}

/// Compute the pairing e(P, Q) for P ∈ G1 and Q ∈ G2
/// Returns an element in GT
pub fn pairing(p: &G1Affine, q: &G2Affine) -> Gt {
    Gt(Bls12_381::pairing(p.0, q.0).0)
}

/// Compute the product of pairings: ∏ e(P_i, Q_i)
/// More efficient than computing pairings separately
pub fn multi_pairing(pairs: &[(G1Affine, G2Affine)]) -> Gt {
    let ark_pairs: Vec<_> = pairs.iter().map(|(p, q)| (p.0, q.0)).collect();
    Gt(Bls12_381::multi_pairing(
        ark_pairs.iter().map(|(p, _)| *p),
        ark_pairs.iter().map(|(_, q)| *q),
    ).0)
}

/// Check if e(P1, Q1) = e(P2, Q2)
/// Equivalent to checking e(P1, Q1) * e(-P2, Q2) = 1
pub fn pairing_check(p1: &G1Affine, q1: &G2Affine, p2: &G1Affine, q2: &G2Affine) -> bool {
    let neg_p2 = p2.neg();
    let result = multi_pairing(&[(*p1, *q1), (neg_p2, *q2)]);
    result.is_identity()
}

// ============================================================================
// Serde Implementation
// ============================================================================

impl Serialize for G1Affine {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct G1Json {
            compressed: String,
            x: String,
            y: String,
        }

        let json = G1Json {
            compressed: self.to_hex(),
            x: self.x_hex(),
            y: self.y_hex(),
        };
        json.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for G1Affine {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct G1Json {
            compressed: String,
        }

        let json = G1Json::deserialize(deserializer)?;
        let hex_str = json.compressed.strip_prefix("0x").unwrap_or(&json.compressed);
        let bytes = hex::decode(hex_str)
            .map_err(|e| serde::de::Error::custom(format!("Invalid hex: {}", e)))?;
        G1Affine::from_compressed_bytes(&bytes)
            .ok_or_else(|| serde::de::Error::custom("Invalid G1 point"))
    }
}

impl Serialize for G2Affine {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct G2Json {
            compressed: String,
        }

        let json = G2Json {
            compressed: self.to_hex(),
        };
        json.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for G2Affine {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct G2Json {
            compressed: String,
        }

        let json = G2Json::deserialize(deserializer)?;
        let hex_str = json.compressed.strip_prefix("0x").unwrap_or(&json.compressed);
        let bytes = hex::decode(hex_str)
            .map_err(|e| serde::de::Error::custom(format!("Invalid hex: {}", e)))?;
        G2Affine::from_compressed_bytes(&bytes)
            .ok_or_else(|| serde::de::Error::custom("Invalid G2 point"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_g1_generator() {
        let g = G1Affine::generator();
        assert!(!g.is_identity());
    }

    #[test]
    fn test_g1_scalar_mul() {
        let g = G1Projective::generator();
        let two_g = g + g;
        let scalar_two_g = g.scalar_mul(&Fr::from_u64(2));
        assert_eq!(two_g, scalar_two_g);
    }

    #[test]
    fn test_pairing_bilinearity() {
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();

        let a = Fr::from_u64(3);
        let b = Fr::from_u64(5);

        // e(aG1, bG2) = e(G1, G2)^(ab)
        let a_g1 = g1.to_projective().scalar_mul(&a).to_affine();
        let b_g2 = g2.to_projective().scalar_mul(&b).to_affine();

        let ab = a * b;
        let ab_g1 = g1.to_projective().scalar_mul(&ab).to_affine();

        let lhs = pairing(&a_g1, &b_g2);
        let rhs = pairing(&ab_g1, &g2);

        assert_eq!(lhs, rhs);
    }

    #[test]
    fn test_pairing_check() {
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();

        let a = Fr::from_u64(7);
        let a_g1 = g1.to_projective().scalar_mul(&a).to_affine();
        let a_g2 = g2.to_projective().scalar_mul(&a).to_affine();

        // e(aG1, G2) = e(G1, aG2)
        assert!(pairing_check(&a_g1, &g2, &g1, &a_g2));
    }

    #[test]
    fn test_msm() {
        let g = G1Affine::generator();
        let points = vec![g, g, g];
        let scalars = vec![Fr::from_u64(1), Fr::from_u64(2), Fr::from_u64(3)];

        let result = G1Projective::msm(&points, &scalars);
        let expected = g.to_projective().scalar_mul(&Fr::from_u64(6));

        assert_eq!(result, expected);
    }
}
