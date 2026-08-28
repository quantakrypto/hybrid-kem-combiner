//! The nominal groups used as the traditional component.
//!
//! `draft-irtf-cfrg-hybrid-kems-12` section 4.2 defines a nominal group by
//! `Exp`, `RandomScalar` and `ElementToSharedSecret`.
//! `draft-irtf-cfrg-concrete-hybrid-kems-04` section 3.1 instantiates three
//! of them. This module implements those three definitions on top of `p256`,
//! `p384` and `x25519-dalek`, which provide the field and curve arithmetic
//! and nothing above it.
//!
//! The parts that are easy to get wrong, and that no dependency does for you:
//!
//! - `RandomScalar` for the NIST curves is **rejection sampling over
//!   successive `Nscalar`-byte blocks of the seed**, big endian, rejecting
//!   zero and anything at or above the group order. It is not "reduce the
//!   seed mod n", which would produce different keys from the same seed.
//! - `RandomScalar` for Curve25519 is the **identity function**. The seed is
//!   the scalar; RFC 7748's clamping happens inside `X25519`.
//! - Group elements are **uncompressed** SEC1 points for the NIST curves, 65
//!   and 97 bytes, and 32 byte u-coordinates for Curve25519.
//! - `ElementToSharedSecret` is the **x coordinate only** for the NIST
//!   curves, 32 and 48 bytes, not the whole point.

use alloc::vec::Vec;

use super::SuiteError;

/// Which nominal group a suite's traditional component uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Group {
    /// P-256, `draft-irtf-cfrg-concrete-hybrid-kems-04` section 3.1.1.
    P256,
    /// P-384, section 3.1.1.
    P384,
    /// Curve25519, section 3.1.2.
    X25519,
}

impl Group {
    /// `Nseed`: the length of the seed `RandomScalar` consumes.
    ///
    /// 128 for P-256 and 48 for P-384. The asymmetry is not a typo: section
    /// 3.1.1 sizes each seed so that repeated rejection stays below the
    /// group's security level, and P-256 rejects far more often than P-384.
    pub(super) const fn nseed(self) -> usize {
        match self {
            Group::P256 => 128,
            Group::P384 => 48,
            Group::X25519 => 32,
        }
    }

    /// `Nelem`: the length of a serialized group element.
    pub(super) const fn nelem(self) -> usize {
        match self {
            Group::P256 => 65,
            Group::P384 => 97,
            Group::X25519 => 32,
        }
    }

    /// `Nss`: the length of a shared secret from `ElementToSharedSecret`.
    #[allow(dead_code)]
    pub(super) const fn nss(self) -> usize {
        match self {
            Group::P256 => 32,
            Group::P384 => 48,
            Group::X25519 => 32,
        }
    }

    /// `Exp(g, RandomScalar(seed))`: the public element of `seed`.
    pub(super) fn exp_base(self, seed: &[u8]) -> Result<Vec<u8>, SuiteError> {
        match self {
            Group::P256 => p256_group::exp_base(seed),
            Group::P384 => p384_group::exp_base(seed),
            Group::X25519 => {
                let scalar: [u8; 32] = seed.try_into().map_err(|_| SuiteError::WrongLength {
                    what: "Curve25519 scalar",
                    expected: 32,
                    actual: seed.len(),
                })?;
                Ok(x25519_dalek::x25519(scalar, x25519_dalek::X25519_BASEPOINT_BYTES).to_vec())
            }
        }
    }

    /// `ElementToSharedSecret(Exp(element, RandomScalar(seed)))`: one side of
    /// the Diffie-Hellman exchange.
    pub(super) fn exp_and_extract(
        self,
        element: &[u8],
        seed: &[u8],
    ) -> Result<Vec<u8>, SuiteError> {
        match self {
            Group::P256 => p256_group::exp_and_extract(element, seed),
            Group::P384 => p384_group::exp_and_extract(element, seed),
            Group::X25519 => {
                let scalar: [u8; 32] = seed.try_into().map_err(|_| SuiteError::WrongLength {
                    what: "Curve25519 scalar",
                    expected: 32,
                    actual: seed.len(),
                })?;
                let point: [u8; 32] = element.try_into().map_err(|_| SuiteError::WrongLength {
                    what: "Curve25519 element",
                    expected: 32,
                    actual: element.len(),
                })?;
                // Deliberately no all-zero check. Every 32 byte string is a
                // valid Curve25519 u-coordinate, X-Wing's Encapsulate and
                // Decapsulate
                // (draft-connolly-cfrg-xwing-kem-10 sections 5.4 and 5.5) do
                // not check, and rejecting here would make this
                // implementation disagree with conforming peers on exactly
                // the inputs an attacker chooses. Contributory behaviour is
                // an explicit non-goal of
                // draft-irtf-cfrg-hybrid-kems-12 section 8.
                Ok(x25519_dalek::x25519(scalar, point).to_vec())
            }
        }
    }
}

/// Both NIST curves have the same algorithms and differ only in their types
/// and constants, so they are generated from one definition. Writing them out
/// twice would be two places for the encoding to drift.
macro_rules! nist_group {
    ($module:ident, $curve:ident, $nscalar:expr, $nelem:expr, $what:expr) => {
        mod $module {
            use alloc::vec::Vec;

            use $curve::elliptic_curve::ff::PrimeField;
            use $curve::elliptic_curve::point::AffineCoordinates;
            use $curve::elliptic_curve::sec1::{FromSec1Point, ToSec1Point};
            use $curve::{AffinePoint, ProjectivePoint, Scalar};
            use zeroize::Zeroize;

            use super::SuiteError;

            const NSCALAR: usize = $nscalar;
            const NELEM: usize = $nelem;

            /// `RandomScalar(seed)`,
            /// `draft-irtf-cfrg-concrete-hybrid-kems-04` section 3.1.1.
            ///
            /// Successive `Nscalar`-byte blocks of the seed are read as
            /// big-endian integers until one is nonzero and below the group
            /// order. `Scalar::from_repr` is exactly the "below the order"
            /// test, so this is the specification's loop and not an
            /// approximation of it.
            fn random_scalar(seed: &[u8]) -> Result<Scalar, SuiteError> {
                let mut start = 0usize;
                loop {
                    let end = match start.checked_add(NSCALAR) {
                        Some(end) if end <= seed.len() => end,
                        _ => return Err(SuiteError::RejectionSamplingFailed),
                    };
                    let mut repr = $curve::FieldBytes::default();
                    repr.copy_from_slice(&seed[start..end]);
                    let candidate = Scalar::from_repr(repr).into_option();
                    repr.zeroize();
                    if let Some(scalar) = candidate {
                        // The draft rejects zero as well as out-of-range:
                        // hybrid-kems-12 section 4.2 says RandomScalar MUST
                        // NOT return a zero scalar.
                        if !bool::from(<Scalar as $curve::elliptic_curve::ff::Field>::is_zero(
                            &scalar,
                        )) {
                            return Ok(scalar);
                        }
                    }
                    start = end;
                }
            }

            /// Serialize a projective point as an uncompressed SEC1 element,
            /// refusing the identity.
            fn encode(point: ProjectivePoint) -> Result<Vec<u8>, SuiteError> {
                let affine = point.to_affine();
                if bool::from(affine.is_identity()) {
                    return Err(SuiteError::DegenerateGroupElement);
                }
                Ok(affine.to_sec1_point(false).as_bytes().to_vec())
            }

            /// Decode an uncompressed SEC1 element.
            ///
            /// The length is checked first so that a compressed point, which
            /// SEC1 would happily decode, is refused: the framework's fixed
            /// length encoding is what makes the combiner's unprefixed
            /// concatenation unambiguous.
            fn decode(bytes: &[u8]) -> Result<AffinePoint, SuiteError> {
                if bytes.len() != NELEM {
                    return Err(SuiteError::WrongLength {
                        what: $what,
                        expected: NELEM,
                        actual: bytes.len(),
                    });
                }
                if bytes[0] != 0x04 {
                    return Err(SuiteError::InvalidGroupElement);
                }
                AffinePoint::from_sec1_bytes(bytes).map_err(|_| SuiteError::InvalidGroupElement)
            }

            pub(super) fn exp_base(seed: &[u8]) -> Result<Vec<u8>, SuiteError> {
                let mut scalar = random_scalar(seed)?;
                let result = encode(ProjectivePoint::GENERATOR * scalar);
                scalar.zeroize();
                result
            }

            pub(super) fn exp_and_extract(
                element: &[u8],
                seed: &[u8],
            ) -> Result<Vec<u8>, SuiteError> {
                let point = decode(element)?;
                let mut scalar = random_scalar(seed)?;
                let product = (ProjectivePoint::from(point) * scalar).to_affine();
                scalar.zeroize();
                if bool::from(product.is_identity()) {
                    return Err(SuiteError::DegenerateGroupElement);
                }
                // ElementToSharedSecret: the x coordinate alone, as an
                // Nss-byte string.
                Ok(product.x().to_vec())
            }
        }
    };
}

nist_group!(p256_group, p256, 32, 65, "P-256 element");
nist_group!(p384_group, p384, 48, 97, "P-384 element");

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// The seed lengths are the ones the draft publishes, and getting P-256's
    /// 128 wrong is the kind of mistake that still passes a round trip.
    #[test]
    fn constants_match_the_draft() {
        assert_eq!(
            (Group::P256.nseed(), Group::P256.nelem(), Group::P256.nss()),
            (128, 65, 32)
        );
        assert_eq!(
            (Group::P384.nseed(), Group::P384.nelem(), Group::P384.nss()),
            (48, 97, 48)
        );
        assert_eq!(
            (
                Group::X25519.nseed(),
                Group::X25519.nelem(),
                Group::X25519.nss()
            ),
            (32, 32, 32)
        );
    }

    #[test]
    fn a_non_point_is_refused_rather_than_absorbed() {
        let seed = vec![7u8; Group::P256.nseed()];
        let not_a_point = vec![0x04u8; 65];
        assert_eq!(
            Group::P256.exp_and_extract(&not_a_point, &seed),
            Err(SuiteError::InvalidGroupElement)
        );
    }

    #[test]
    fn a_compressed_point_is_refused_because_the_encoding_is_fixed_length() {
        let seed = vec![7u8; Group::P256.nseed()];
        let element = Group::P256.exp_base(&seed).unwrap();
        let mut compressed = vec![0x02u8];
        compressed.extend_from_slice(&element[1..33]);
        assert!(matches!(
            Group::P256.exp_and_extract(&compressed, &seed),
            Err(SuiteError::WrongLength { .. })
        ));
    }

    /// A seed of all zero bytes contains no valid scalar, so rejection
    /// sampling must run off the end rather than return zero.
    #[test]
    fn rejection_sampling_gives_up_rather_than_returning_zero() {
        let seed = vec![0u8; Group::P384.nseed()];
        assert_eq!(
            Group::P384.exp_base(&seed),
            Err(SuiteError::RejectionSamplingFailed)
        );
    }

    /// Diffie-Hellman has to actually agree, in all three groups.
    #[test]
    fn the_exchange_agrees_in_every_group() {
        for group in [Group::P256, Group::P384, Group::X25519] {
            let a = vec![0x11u8; group.nseed()];
            let b = vec![0x22u8; group.nseed()];
            let ek_a = group.exp_base(&a).unwrap();
            let ek_b = group.exp_base(&b).unwrap();
            assert_eq!(ek_a.len(), group.nelem());
            let ss_ab = group.exp_and_extract(&ek_b, &a).unwrap();
            let ss_ba = group.exp_and_extract(&ek_a, &b).unwrap();
            assert_eq!(ss_ab, ss_ba, "{group:?}");
            assert_eq!(ss_ab.len(), group.nss(), "{group:?}");
        }
    }
}
