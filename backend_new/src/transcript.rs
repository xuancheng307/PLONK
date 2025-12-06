//! Fiat-Shamir Transcript
//!
//! This module implements a transcript for the Fiat-Shamir transformation,
//! which converts interactive proofs into non-interactive ones.
//!
//! The transcript absorbs all public information (commitments, evaluations)
//! and produces challenges that are deterministic from the prover's messages.

use crate::curve::{G1Affine, G2Affine};
use crate::field::Fr;
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};

/// A Fiat-Shamir transcript for generating challenges
#[derive(Clone, Debug)]
pub struct Transcript {
    hasher: Sha256,
    /// Record of all data absorbed (for tracing)
    pub absorbed: Vec<TranscriptEntry>,
    /// Record of all challenges squeezed (for tracing)
    pub challenges: Vec<ChallengeRecord>,
}

/// A record of data absorbed into the transcript
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TranscriptEntry {
    pub label: String,
    pub data_type: String,
    pub data_hex: String,
}

/// A record of a challenge squeezed from the transcript
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeRecord {
    pub label: String,
    pub value: Fr,
}

impl Transcript {
    /// Create a new transcript with a domain separator
    pub fn new(domain_separator: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(domain_separator);

        Transcript {
            hasher,
            absorbed: vec![TranscriptEntry {
                label: "domain_separator".to_string(),
                data_type: "bytes".to_string(),
                data_hex: hex::encode(domain_separator),
            }],
            challenges: Vec::new(),
        }
    }

    /// Absorb raw bytes into the transcript
    pub fn absorb_bytes(&mut self, label: &str, data: &[u8]) {
        // Include label in the hash to prevent collisions
        self.hasher.update(label.as_bytes());
        self.hasher.update(&(data.len() as u64).to_le_bytes());
        self.hasher.update(data);

        self.absorbed.push(TranscriptEntry {
            label: label.to_string(),
            data_type: "bytes".to_string(),
            data_hex: hex::encode(data),
        });
    }

    /// Absorb a field element
    pub fn absorb_fr(&mut self, label: &str, fr: &Fr) {
        let bytes = fr.to_bytes();
        self.absorb_bytes(label, &bytes);
    }

    /// Absorb a G1 point
    pub fn absorb_g1(&mut self, label: &str, point: &G1Affine) {
        let bytes = point.to_compressed_bytes();
        self.hasher.update(label.as_bytes());
        self.hasher.update(&bytes);

        self.absorbed.push(TranscriptEntry {
            label: label.to_string(),
            data_type: "G1".to_string(),
            data_hex: point.to_hex(),
        });
    }

    /// Absorb a G2 point
    pub fn absorb_g2(&mut self, label: &str, point: &G2Affine) {
        let bytes = point.to_compressed_bytes();
        self.hasher.update(label.as_bytes());
        self.hasher.update(&bytes);

        self.absorbed.push(TranscriptEntry {
            label: label.to_string(),
            data_type: "G2".to_string(),
            data_hex: point.to_hex(),
        });
    }

    /// Absorb a u64 value
    pub fn absorb_u64(&mut self, label: &str, value: u64) {
        let bytes = value.to_le_bytes();
        self.absorb_bytes(label, &bytes);
    }

    /// Squeeze a challenge from the transcript
    /// Returns a field element that is uniformly distributed
    pub fn squeeze_challenge(&mut self, label: &str) -> Fr {
        // Include the label in the squeeze
        self.hasher.update(label.as_bytes());

        // Finalize and get the hash
        let hash = self.hasher.finalize_reset();

        // Re-initialize with the hash to continue the chain
        self.hasher.update(&hash);

        // Convert hash to field element
        // We use rejection sampling conceptually, but for simplicity
        // we just reduce modulo the field order
        let challenge = hash_to_fr(&hash);

        self.challenges.push(ChallengeRecord {
            label: label.to_string(),
            value: challenge,
        });

        challenge
    }

    /// Squeeze multiple challenges at once
    pub fn squeeze_challenges(&mut self, labels: &[&str]) -> Vec<Fr> {
        labels.iter().map(|l| self.squeeze_challenge(l)).collect()
    }

    /// Fork the transcript (for parallel proof construction)
    pub fn fork(&self, label: &str) -> Transcript {
        let mut forked = self.clone();
        forked.absorb_bytes("fork", label.as_bytes());
        forked
    }

    /// Get all absorbed data (for tracing)
    pub fn get_absorbed(&self) -> &[TranscriptEntry] {
        &self.absorbed
    }

    /// Get all challenges (for tracing)
    pub fn get_challenges(&self) -> &[ChallengeRecord] {
        &self.challenges
    }
}

/// Convert a hash output to a field element
fn hash_to_fr(hash: &[u8]) -> Fr {
    // Extend hash if needed and reduce modulo field order
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash[..32]);

    // Try to create a field element
    // If it fails (unlikely), hash again
    loop {
        if let Some(fr) = Fr::from_bytes(&bytes) {
            return fr;
        }
        // Hash again
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        bytes.copy_from_slice(&hasher.finalize());
    }
}

/// Check that a challenge is not in the domain H
/// This is important for PLONK to ensure the quotient polynomial is well-defined
pub fn challenge_not_in_domain(challenge: &Fr, omega: &Fr, n: usize) -> bool {
    // Check that challenge is not ω^i for any i
    let mut power = Fr::one();
    for _ in 0..n {
        if *challenge == power {
            return false;
        }
        power = power * *omega;
    }
    true
}

/// Generate a challenge that is guaranteed not to be in the domain H
pub fn squeeze_challenge_outside_domain(
    transcript: &mut Transcript,
    label: &str,
    omega: &Fr,
    n: usize,
) -> Fr {
    // In practice, the probability of hitting H is negligible
    // But we check anyway for correctness
    loop {
        let challenge = transcript.squeeze_challenge(label);
        if challenge_not_in_domain(&challenge, omega, n) {
            return challenge;
        }
        // Extremely unlikely to reach here
    }
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new(b"PLONK-v1")
    }
}

impl Serialize for Transcript {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct TranscriptJson {
            absorbed: Vec<TranscriptEntry>,
            challenges: Vec<ChallengeRecord>,
        }

        let json = TranscriptJson {
            absorbed: self.absorbed.clone(),
            challenges: self.challenges.clone(),
        };
        json.serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transcript_deterministic() {
        let mut t1 = Transcript::new(b"test");
        let mut t2 = Transcript::new(b"test");

        t1.absorb_fr("value", &Fr::from_u64(42));
        t2.absorb_fr("value", &Fr::from_u64(42));

        let c1 = t1.squeeze_challenge("challenge");
        let c2 = t2.squeeze_challenge("challenge");

        assert_eq!(c1, c2);
    }

    #[test]
    fn test_transcript_different_input() {
        let mut t1 = Transcript::new(b"test");
        let mut t2 = Transcript::new(b"test");

        t1.absorb_fr("value", &Fr::from_u64(42));
        t2.absorb_fr("value", &Fr::from_u64(43));

        let c1 = t1.squeeze_challenge("challenge");
        let c2 = t2.squeeze_challenge("challenge");

        assert_ne!(c1, c2);
    }

    #[test]
    fn test_g1_absorption() {
        let mut t = Transcript::new(b"test");
        let g = G1Affine::generator();
        t.absorb_g1("generator", &g);
        let c = t.squeeze_challenge("challenge");
        assert!(!c.is_zero());
    }

    #[test]
    fn test_challenge_outside_domain() {
        let n = 8;
        let omega = Fr::get_root_of_unity(n).unwrap();
        let mut t = Transcript::new(b"test");

        for i in 0..100 {
            t.absorb_u64("iter", i);
            let c = squeeze_challenge_outside_domain(&mut t, "challenge", &omega, n);
            assert!(challenge_not_in_domain(&c, &omega, n));
        }
    }
}
