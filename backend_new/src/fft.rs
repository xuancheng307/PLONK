//! Fast Fourier Transform over Finite Fields
//!
//! This module implements FFT and IFFT for polynomial evaluation and interpolation
//! over multiplicative subgroups of the scalar field.
//!
//! Given a polynomial f(X) of degree < n, and the n-th root of unity ω:
//! - FFT computes [f(ω^0), f(ω^1), ..., f(ω^{n-1})]
//! - IFFT recovers the coefficients from evaluations

use crate::field::Fr;
use crate::polynomial::Polynomial;
use serde::{Deserialize, Serialize};

/// Compute the FFT of a polynomial over the domain H = {ω^0, ω^1, ..., ω^{n-1}}
///
/// # Arguments
/// * `poly` - The polynomial in coefficient form
/// * `omega` - The primitive n-th root of unity
/// * `n` - The domain size (must be a power of 2)
///
/// # Returns
/// Vector of evaluations [f(ω^0), f(ω^1), ..., f(ω^{n-1})]
pub fn fft(poly: &Polynomial, omega: &Fr, n: usize) -> Vec<Fr> {
    assert!(n.is_power_of_two(), "FFT size must be a power of 2");

    // Pad coefficients to size n
    let mut coeffs = poly.coeffs.clone();
    coeffs.resize(n, Fr::zero());

    fft_in_place(&mut coeffs, omega);
    coeffs
}

/// Compute the inverse FFT to recover polynomial coefficients from evaluations
///
/// # Arguments
/// * `evals` - The evaluations [f(ω^0), f(ω^1), ..., f(ω^{n-1})]
/// * `omega` - The primitive n-th root of unity
///
/// # Returns
/// The polynomial with these evaluations
pub fn ifft(evals: &[Fr], omega: &Fr) -> Polynomial {
    let n = evals.len();
    assert!(n.is_power_of_two(), "IFFT size must be a power of 2");

    let mut coeffs = evals.to_vec();

    // IFFT uses ω^{-1} as the root
    let omega_inv = omega.inverse().unwrap();
    fft_in_place(&mut coeffs, &omega_inv);

    // Scale by 1/n
    let n_inv = Fr::from_u64(n as u64).inverse().unwrap();
    for c in &mut coeffs {
        *c = *c * n_inv;
    }

    Polynomial::from_coeffs(coeffs)
}

/// In-place FFT using Cooley-Tukey algorithm
fn fft_in_place(values: &mut [Fr], omega: &Fr) {
    let n = values.len();
    if n == 1 {
        return;
    }

    // Bit-reverse permutation
    bit_reverse_permutation(values);

    // Iterative FFT
    let mut m = 1;
    while m < n {
        let omega_m = omega.pow((n / (2 * m)) as u64);
        let mut k = 0;
        while k < n {
            let mut omega_power = Fr::one();
            for j in 0..m {
                let t = omega_power * values[k + j + m];
                let u = values[k + j];
                values[k + j] = u + t;
                values[k + j + m] = u - t;
                omega_power = omega_power * omega_m;
            }
            k += 2 * m;
        }
        m *= 2;
    }
}

/// Bit-reverse permutation for FFT
fn bit_reverse_permutation(values: &mut [Fr]) {
    let n = values.len();
    let log_n = n.trailing_zeros();

    for i in 0..n {
        let j = bit_reverse(i, log_n);
        if i < j {
            values.swap(i, j);
        }
    }
}

/// Reverse the bits of an integer
fn bit_reverse(mut x: usize, bits: u32) -> usize {
    let mut result = 0;
    for _ in 0..bits {
        result = (result << 1) | (x & 1);
        x >>= 1;
    }
    result
}

/// Coset FFT: evaluate polynomial on k*H = {k*ω^0, k*ω^1, ..., k*ω^{n-1}}
///
/// # Arguments
/// * `poly` - The polynomial in coefficient form
/// * `omega` - The primitive n-th root of unity
/// * `k` - The coset shift
/// * `n` - The domain size
pub fn coset_fft(poly: &Polynomial, omega: &Fr, k: &Fr, n: usize) -> Vec<Fr> {
    // To evaluate on k*H, we compute f(k*X) and then FFT
    // f(k*X) = c_0 + c_1*(k*X) + c_2*(k*X)^2 + ...
    //        = c_0 + (c_1*k)*X + (c_2*k^2)*X^2 + ...

    let mut scaled_coeffs = poly.coeffs.clone();
    scaled_coeffs.resize(n, Fr::zero());

    let mut k_power = Fr::one();
    for c in &mut scaled_coeffs {
        *c = *c * k_power;
        k_power = k_power * *k;
    }

    let scaled_poly = Polynomial::from_coeffs(scaled_coeffs);
    fft(&scaled_poly, omega, n)
}

/// Coset IFFT: interpolate from evaluations on k*H
pub fn coset_ifft(evals: &[Fr], omega: &Fr, k: &Fr) -> Polynomial {
    let n = evals.len();

    // First do regular IFFT
    let mut poly = ifft(evals, omega);

    // Then scale coefficients back
    let k_inv = k.inverse().unwrap();
    let mut k_inv_power = Fr::one();
    for c in &mut poly.coeffs {
        *c = *c * k_inv_power;
        k_inv_power = k_inv_power * k_inv;
    }

    // Ensure we have n coefficients
    poly.coeffs.resize(n, Fr::zero());
    poly
}

/// Compute polynomial multiplication using FFT
/// More efficient than naive O(n^2) for large polynomials
pub fn poly_mul_fft(a: &Polynomial, b: &Polynomial, omega: &Fr, n: usize) -> Polynomial {
    // Evaluate both polynomials
    let a_evals = fft(a, omega, n);
    let b_evals = fft(b, omega, n);

    // Point-wise multiply
    let c_evals: Vec<Fr> = a_evals.iter().zip(&b_evals).map(|(x, y)| *x * *y).collect();

    // Interpolate back
    ifft(&c_evals, omega)
}

/// Domain: multiplicative subgroup H = {ω^0, ω^1, ..., ω^{n-1}}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Domain {
    /// Size of the domain (power of 2)
    pub n: usize,
    /// Primitive n-th root of unity
    pub omega: Fr,
    /// ω^{-1}
    pub omega_inv: Fr,
    /// 1/n in the field
    pub n_inv: Fr,
}

impl Domain {
    /// Create a new domain of the given size
    pub fn new(n: usize) -> Option<Self> {
        if !n.is_power_of_two() {
            return None;
        }

        let omega = Fr::get_root_of_unity(n)?;
        let omega_inv = omega.inverse()?;
        let n_inv = Fr::from_u64(n as u64).inverse()?;

        Some(Domain {
            n,
            omega,
            omega_inv,
            n_inv,
        })
    }

    /// Get the i-th element of the domain: ω^i
    pub fn element(&self, i: usize) -> Fr {
        self.omega.pow(i as u64)
    }

    /// Get all elements of the domain as an iterator
    pub fn elements(&self) -> impl Iterator<Item = Fr> + '_ {
        DomainIterator {
            current: Fr::one(),
            omega: self.omega,
            remaining: self.n,
        }
    }

    /// FFT on a coset: evaluate on k*H
    pub fn coset_fft(&self, poly: &Polynomial, k: Fr) -> Vec<Fr> {
        coset_fft(poly, &self.omega, &k, self.n)
    }

    /// Inverse FFT on a coset
    pub fn coset_ifft(&self, evals: &[Fr], k: Fr) -> Vec<Fr> {
        let poly = coset_ifft(evals, &self.omega, &k);
        poly.coeffs
    }

    /// Evaluate the vanishing polynomial Z_H(X) = X^n - 1 at a point
    pub fn vanishing_eval(&self, x: &Fr) -> Fr {
        x.pow(self.n as u64) - Fr::one()
    }

    /// Evaluate Lagrange basis L_i(X) at a point
    pub fn lagrange_eval(&self, i: usize, x: &Fr) -> Fr {
        Fr::lagrange_basis_eval(i, x, &self.omega, self.n)
    }

    /// FFT on this domain
    pub fn fft(&self, poly: &Polynomial) -> Vec<Fr> {
        fft(poly, &self.omega, self.n)
    }

    /// IFFT on this domain
    pub fn ifft(&self, evals: &[Fr]) -> Polynomial {
        ifft(evals, &self.omega)
    }
}

/// Iterator over domain elements
struct DomainIterator {
    current: Fr,
    omega: Fr,
    remaining: usize,
}

impl Iterator for DomainIterator {
    type Item = Fr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            None
        } else {
            let result = self.current;
            self.current = self.current * self.omega;
            self.remaining -= 1;
            Some(result)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fft_ifft_roundtrip() {
        let n = 8;
        let omega = Fr::get_root_of_unity(n).unwrap();

        // Create a polynomial
        let poly = Polynomial::from_coeffs(vec![
            Fr::from_u64(1),
            Fr::from_u64(2),
            Fr::from_u64(3),
            Fr::from_u64(4),
        ]);

        // FFT then IFFT should recover original
        let evals = fft(&poly, &omega, n);
        let recovered = ifft(&evals, &omega);

        for i in 0..poly.coeffs.len() {
            assert_eq!(poly.coeffs[i], recovered.coeffs[i]);
        }
    }

    #[test]
    fn test_fft_evaluates_correctly() {
        let n = 4;
        let omega = Fr::get_root_of_unity(n).unwrap();

        let poly = Polynomial::from_coeffs(vec![
            Fr::from_u64(1),
            Fr::from_u64(2),
            Fr::from_u64(3),
        ]);

        let evals = fft(&poly, &omega, n);

        // Verify each evaluation
        for i in 0..n {
            let point = omega.pow(i as u64);
            let expected = poly.evaluate(&point);
            assert_eq!(evals[i], expected);
        }
    }

    #[test]
    fn test_domain() {
        let domain = Domain::new(8).unwrap();

        // ω^n should equal 1
        assert_eq!(domain.omega.pow(8), Fr::one());

        // Elements should be correct
        let elems: Vec<Fr> = domain.elements().collect();
        assert_eq!(elems.len(), 8);
        assert_eq!(elems[0], Fr::one());
        assert_eq!(elems[1], domain.omega);
    }

    #[test]
    fn test_vanishing_polynomial() {
        let domain = Domain::new(4).unwrap();

        // Z_H should vanish on all elements of H
        for i in 0..4 {
            let x = domain.element(i);
            assert!(domain.vanishing_eval(&x).is_zero());
        }

        // Z_H should not vanish outside H
        let x = Fr::from_u64(123);
        assert!(!domain.vanishing_eval(&x).is_zero());
    }
}
