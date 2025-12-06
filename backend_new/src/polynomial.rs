//! Polynomial Operations
//!
//! This module provides polynomial arithmetic over the scalar field Fr.
//! Polynomials are represented in coefficient form: f(X) = c_0 + c_1*X + c_2*X^2 + ...

use crate::field::Fr;
use serde::{Deserialize, Serialize};
use std::ops::{Add, Mul, Sub, Neg};

/// A polynomial over Fr in coefficient form
/// coeffs[i] is the coefficient of X^i
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Polynomial {
    pub coeffs: Vec<Fr>,
}

impl Polynomial {
    /// Create the zero polynomial
    pub fn zero() -> Self {
        Polynomial { coeffs: vec![] }
    }

    /// Create a constant polynomial
    pub fn constant(c: Fr) -> Self {
        if c.is_zero() {
            Self::zero()
        } else {
            Polynomial { coeffs: vec![c] }
        }
    }

    /// Create the polynomial X
    pub fn x() -> Self {
        Polynomial {
            coeffs: vec![Fr::zero(), Fr::one()],
        }
    }

    /// Create the polynomial X^n
    pub fn x_pow(n: usize) -> Self {
        let mut coeffs = vec![Fr::zero(); n + 1];
        coeffs[n] = Fr::one();
        Polynomial { coeffs }
    }

    /// Create from coefficient vector
    pub fn from_coeffs(coeffs: Vec<Fr>) -> Self {
        let mut poly = Polynomial { coeffs };
        poly.normalize();
        poly
    }

    /// Create from evaluations using Lagrange interpolation
    /// Given evaluations f(ω^0), f(ω^1), ..., f(ω^{n-1})
    /// Returns the unique polynomial of degree < n passing through these points
    pub fn from_evaluations(evals: &[Fr], domain: &crate::fft::Domain) -> Self {
        let n = evals.len();
        if n == 0 {
            return Self::zero();
        }

        // Use IFFT (inverse FFT) to convert evaluations to coefficients
        // This is more efficient than naive Lagrange interpolation
        crate::fft::ifft(evals, &domain.omega)
    }

    /// Create from evaluations using omega directly (for testing)
    pub fn from_evaluations_with_omega(evals: &[Fr], omega: &Fr) -> Self {
        let n = evals.len();
        if n == 0 {
            return Self::zero();
        }
        crate::fft::ifft(evals, omega)
    }

    /// Get the degree of the polynomial (-1 for zero polynomial)
    pub fn degree(&self) -> isize {
        if self.coeffs.is_empty() {
            -1
        } else {
            (self.coeffs.len() - 1) as isize
        }
    }

    /// Check if this is the zero polynomial
    pub fn is_zero(&self) -> bool {
        self.coeffs.is_empty() || self.coeffs.iter().all(|c| c.is_zero())
    }

    /// Remove leading zeros
    pub fn normalize(&mut self) {
        while let Some(c) = self.coeffs.last() {
            if c.is_zero() {
                self.coeffs.pop();
            } else {
                break;
            }
        }
    }

    /// Evaluate the polynomial at a point
    /// Uses Horner's method: f(x) = c_0 + x*(c_1 + x*(c_2 + ...))
    pub fn evaluate(&self, x: &Fr) -> Fr {
        if self.coeffs.is_empty() {
            return Fr::zero();
        }

        let mut result = Fr::zero();
        for coeff in self.coeffs.iter().rev() {
            result = result * *x + *coeff;
        }
        result
    }

    /// Evaluate at multiple points (using FFT if points form a subgroup)
    pub fn evaluate_domain(&self, omega: &Fr, n: usize) -> Vec<Fr> {
        crate::fft::fft(self, omega, n)
    }

    /// Add a scalar multiple of X^shift * Z_H(X) for blinding
    /// Z_H(X) = X^n - 1
    pub fn add_blinding(&mut self, blinding: Fr, shift: usize, n: usize) {
        // Add blinding * X^shift * (X^n - 1)
        // = blinding * X^{shift+n} - blinding * X^shift

        let min_len = shift + n + 1;
        if self.coeffs.len() < min_len {
            self.coeffs.resize(min_len, Fr::zero());
        }

        self.coeffs[shift] -= blinding;
        self.coeffs[shift + n] += blinding;
    }

    /// Polynomial multiplication
    pub fn mul_poly(&self, other: &Polynomial) -> Polynomial {
        if self.is_zero() || other.is_zero() {
            return Polynomial::zero();
        }

        let n = self.coeffs.len() + other.coeffs.len() - 1;
        let mut result = vec![Fr::zero(); n];

        for (i, a) in self.coeffs.iter().enumerate() {
            for (j, b) in other.coeffs.iter().enumerate() {
                result[i + j] += *a * *b;
            }
        }

        Polynomial::from_coeffs(result)
    }

    /// Polynomial division: returns (quotient, remainder) such that
    /// self = quotient * divisor + remainder
    pub fn div_rem(&self, divisor: &Polynomial) -> (Polynomial, Polynomial) {
        if divisor.is_zero() {
            panic!("Division by zero polynomial");
        }

        if self.degree() < divisor.degree() {
            return (Polynomial::zero(), self.clone());
        }

        let mut remainder = self.coeffs.clone();
        let divisor_leading = *divisor.coeffs.last().unwrap();
        let divisor_degree = divisor.degree() as usize;

        let quotient_degree = (self.degree() - divisor.degree()) as usize;
        let mut quotient = vec![Fr::zero(); quotient_degree + 1];

        for i in (0..=quotient_degree).rev() {
            let coeff = remainder[i + divisor_degree] / divisor_leading;
            quotient[i] = coeff;

            for (j, &d) in divisor.coeffs.iter().enumerate() {
                remainder[i + j] -= coeff * d;
            }
        }

        (
            Polynomial::from_coeffs(quotient),
            Polynomial::from_coeffs(remainder),
        )
    }

    /// Divide by (X - a), returns quotient
    /// Assumes the polynomial is divisible by (X - a)
    pub fn div_by_linear(&self, a: &Fr) -> Polynomial {
        if self.is_zero() {
            return Polynomial::zero();
        }

        // Synthetic division
        let n = self.coeffs.len();
        let mut quotient = vec![Fr::zero(); n - 1];

        let mut carry = Fr::zero();
        for i in (0..n - 1).rev() {
            quotient[i] = self.coeffs[i + 1] + carry;
            carry = quotient[i] * *a;
        }

        Polynomial::from_coeffs(quotient)
    }

    /// Compute f(X) - f(a), which is divisible by (X - a)
    pub fn subtract_evaluation(&self, a: &Fr) -> Polynomial {
        let eval = self.evaluate(a);
        let mut result = self.clone();
        if !result.coeffs.is_empty() {
            result.coeffs[0] -= eval;
        }
        result
    }

    /// Scale all coefficients by a scalar
    pub fn scale(&self, scalar: &Fr) -> Polynomial {
        Polynomial {
            coeffs: self.coeffs.iter().map(|c| *c * *scalar).collect(),
        }
    }

    /// Shift polynomial by multiplying by X^k (multiply by X^k)
    pub fn shift_by_xk(&self, k: usize) -> Polynomial {
        if self.is_zero() {
            return Polynomial::zero();
        }

        let mut coeffs = vec![Fr::zero(); k];
        coeffs.extend(self.coeffs.iter().cloned());
        Polynomial { coeffs }
    }

    /// Get coefficient of X^i
    pub fn coeff(&self, i: usize) -> Fr {
        if i < self.coeffs.len() {
            self.coeffs[i]
        } else {
            Fr::zero()
        }
    }

    /// Create the vanishing polynomial Z_H(X) = X^n - 1
    pub fn vanishing(n: usize) -> Self {
        let mut coeffs = vec![Fr::zero(); n + 1];
        coeffs[0] = -Fr::one();
        coeffs[n] = Fr::one();
        Polynomial { coeffs }
    }

    /// Evaluate Z_H(X) = X^n - 1 at point x
    pub fn eval_vanishing(x: &Fr, n: usize) -> Fr {
        x.pow(n as u64) - Fr::one()
    }

    /// Create Lagrange basis polynomial L_i(X)
    /// L_i(ω^j) = 1 if j = i, else 0
    pub fn lagrange_basis(i: usize, n: usize, domain: &crate::fft::Domain) -> Self {
        // L_i(X) = (X^n - 1) / (n * (X - ω^i)) * ω^(-i)
        // But it's easier to just set up evaluations and IFFT
        let mut evals = vec![Fr::zero(); n];
        evals[i] = Fr::one();
        Self::from_evaluations(&evals, domain)
    }

    /// Shift polynomial: f(X) -> f(ω*X)
    /// Effectively multiplies the coefficient of X^i by ω^i
    pub fn shift(&self, omega: Fr) -> Self {
        let mut result = self.coeffs.clone();
        let mut omega_power = Fr::one();
        for c in result.iter_mut() {
            *c = *c * omega_power;
            omega_power = omega_power * omega;
        }
        Polynomial { coeffs: result }
    }

    /// Evaluate polynomial on a coset k*H
    pub fn evaluate_coset(&self, domain: &crate::fft::Domain, k: Fr) -> Vec<Fr> {
        domain.coset_fft(self, k)
    }

    /// Return coefficients (alias for compatibility)
    pub fn coefficients(&self) -> &Vec<Fr> {
        &self.coeffs
    }
}

impl Add for Polynomial {
    type Output = Polynomial;

    fn add(self, rhs: Polynomial) -> Polynomial {
        let max_len = std::cmp::max(self.coeffs.len(), rhs.coeffs.len());
        let mut result = vec![Fr::zero(); max_len];

        for (i, c) in self.coeffs.iter().enumerate() {
            result[i] += *c;
        }
        for (i, c) in rhs.coeffs.iter().enumerate() {
            result[i] += *c;
        }

        Polynomial::from_coeffs(result)
    }
}

impl Sub for Polynomial {
    type Output = Polynomial;

    fn sub(self, rhs: Polynomial) -> Polynomial {
        let max_len = std::cmp::max(self.coeffs.len(), rhs.coeffs.len());
        let mut result = vec![Fr::zero(); max_len];

        for (i, c) in self.coeffs.iter().enumerate() {
            result[i] += *c;
        }
        for (i, c) in rhs.coeffs.iter().enumerate() {
            result[i] -= *c;
        }

        Polynomial::from_coeffs(result)
    }
}

impl Mul for Polynomial {
    type Output = Polynomial;

    fn mul(self, rhs: Polynomial) -> Polynomial {
        self.mul_poly(&rhs)
    }
}

impl Mul<Fr> for Polynomial {
    type Output = Polynomial;

    fn mul(self, rhs: Fr) -> Polynomial {
        self.scale(&rhs)
    }
}

impl Neg for Polynomial {
    type Output = Polynomial;

    fn neg(self) -> Polynomial {
        Polynomial {
            coeffs: self.coeffs.into_iter().map(|c| -c).collect(),
        }
    }
}

// Reference operators for ergonomic use
impl Add for &Polynomial {
    type Output = Polynomial;

    fn add(self, rhs: &Polynomial) -> Polynomial {
        let max_len = std::cmp::max(self.coeffs.len(), rhs.coeffs.len());
        let mut result = vec![Fr::zero(); max_len];

        for (i, c) in self.coeffs.iter().enumerate() {
            result[i] += *c;
        }
        for (i, c) in rhs.coeffs.iter().enumerate() {
            result[i] += *c;
        }

        Polynomial::from_coeffs(result)
    }
}

impl Sub for &Polynomial {
    type Output = Polynomial;

    fn sub(self, rhs: &Polynomial) -> Polynomial {
        let max_len = std::cmp::max(self.coeffs.len(), rhs.coeffs.len());
        let mut result = vec![Fr::zero(); max_len];

        for (i, c) in self.coeffs.iter().enumerate() {
            result[i] += *c;
        }
        for (i, c) in rhs.coeffs.iter().enumerate() {
            result[i] -= *c;
        }

        Polynomial::from_coeffs(result)
    }
}

impl Mul for &Polynomial {
    type Output = Polynomial;

    fn mul(self, rhs: &Polynomial) -> Polynomial {
        self.mul_poly(rhs)
    }
}

impl Mul<Fr> for &Polynomial {
    type Output = Polynomial;

    fn mul(self, rhs: Fr) -> Polynomial {
        self.scale(&rhs)
    }
}

impl Serialize for Polynomial {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct PolyJson {
            degree: isize,
            coefficients: Vec<Fr>,
        }

        let json = PolyJson {
            degree: self.degree(),
            coefficients: self.coeffs.clone(),
        };
        json.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Polynomial {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct PolyJson {
            coefficients: Vec<Fr>,
        }

        let json = PolyJson::deserialize(deserializer)?;
        Ok(Polynomial::from_coeffs(json.coefficients))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evaluate() {
        // f(X) = 1 + 2X + 3X^2
        let f = Polynomial::from_coeffs(vec![
            Fr::from_u64(1),
            Fr::from_u64(2),
            Fr::from_u64(3),
        ]);

        // f(2) = 1 + 4 + 12 = 17
        let x = Fr::from_u64(2);
        assert_eq!(f.evaluate(&x), Fr::from_u64(17));
    }

    #[test]
    fn test_add_sub() {
        let f = Polynomial::from_coeffs(vec![Fr::from_u64(1), Fr::from_u64(2)]);
        let g = Polynomial::from_coeffs(vec![Fr::from_u64(3), Fr::from_u64(4)]);

        let sum = f.clone() + g.clone();
        assert_eq!(sum.coeffs, vec![Fr::from_u64(4), Fr::from_u64(6)]);

        let diff = f - g;
        assert_eq!(diff.coeffs, vec![Fr::from_u64(1) - Fr::from_u64(3), Fr::from_u64(2) - Fr::from_u64(4)]);
    }

    #[test]
    fn test_mul() {
        // (1 + X) * (1 + X) = 1 + 2X + X^2
        let f = Polynomial::from_coeffs(vec![Fr::from_u64(1), Fr::from_u64(1)]);
        let g = f.clone() * f;
        assert_eq!(
            g.coeffs,
            vec![Fr::from_u64(1), Fr::from_u64(2), Fr::from_u64(1)]
        );
    }

    #[test]
    fn test_div_by_linear() {
        // f(X) = X^2 - 1 = (X-1)(X+1)
        // f(X) / (X - 1) = X + 1
        let f = Polynomial::from_coeffs(vec![
            Fr::from_u64(0) - Fr::from_u64(1),
            Fr::from_u64(0),
            Fr::from_u64(1),
        ]);

        let q = f.div_by_linear(&Fr::from_u64(1));
        assert_eq!(q.coeffs, vec![Fr::from_u64(1), Fr::from_u64(1)]);
    }

    #[test]
    fn test_vanishing() {
        let n = 4;
        let omega = Fr::get_root_of_unity(n).unwrap();
        let z_h = Polynomial::vanishing(n);

        // Z_H should be zero on all points of H
        for i in 0..n {
            let point = omega.pow(i as u64);
            assert!(z_h.evaluate(&point).is_zero());
        }
    }
}
