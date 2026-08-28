//! The key derivation functions the combiner can be instantiated with.

use crate::Error;
use hkdf::HkdfExtract;
use sha2::Sha512;
use sha3::digest::Digest;
use sha3::Sha3_256 as Sha3_256Hash;
use zeroize::Zeroize;

/// Length of an HMAC-SHA512 output, in bytes.
const HMAC_SHA512_LEN: usize = 64;
/// Length of a SHA3-256 digest, in bytes.
const SHA3_256_LEN: usize = 32;
/// RFC 5869 caps HKDF output at 255 times the hash length.
const HKDF_SHA512_MAX: usize = 255 * HMAC_SHA512_LEN;

/// Which key derivation function the combiner uses, and, for HKDF, where the
/// label goes.
///
/// The choice is a parameter at every call site on purpose. Two
/// implementations that agree on the construction and disagree on the KDF
/// produce different keys and no diagnosable error, so this is not a detail
/// to bury in a default.
///
/// # Why there are two HKDF variants
///
/// `KDF(concat(..., label))` is unambiguous for a plain hash. HKDF is not a
/// plain hash: it has three input positions, and the standards do not say
/// which one the label belongs in.
/// draft-irtf-cfrg-hybrid-kems-12 section 5 requires only that any HKDF based
/// KDF "MUST fully specify HKDF's salt, IKM, info, and L arguments", and
/// section 6.1.5 requires that the mapping never let two different inputs
/// collide. Both variants below are fully specified and non-colliding. They
/// are not interchangeable, and picking the wrong one is the exact silent
/// mismatch this enum exists to prevent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Kdf {
    /// `SHA3-256(inputs || label)`. Output is exactly 32 bytes.
    ///
    /// This is the instantiation used by X-Wing
    /// (draft-connolly-cfrg-xwing-kem-10 section 5.3), by the concrete
    /// instantiations in draft-irtf-cfrg-concrete-hybrid-kems, and by the
    /// LAMPS composite KEMs, and it is the family SP 800-227 section 4.6.3
    /// names for its worked example ("a hash function from the SHA-3
    /// family"). If you want to interoperate with anything published, this is
    /// almost certainly the one.
    Sha3_256,

    /// HKDF-SHA512 with `salt` absent, `ikm` the concatenated inputs without
    /// the label, `info` the label, and `L` the output length.
    ///
    /// "Absent" is RFC 5869's absent salt, which HKDF-Extract replaces with
    /// `HashLen` zero bytes, so 64 zero bytes here. It is not a zero length
    /// salt, and the two produce different keys.
    ///
    /// This is the idiomatic HKDF spelling, where domain separation lives in
    /// `info`. It is what qk-password-manager's combiner uses, and the
    /// crate's conformance vectors pin an interoperability case against it.
    HkdfSha512LabelAsInfo,

    /// HKDF-SHA512 with `salt` absent, `ikm` the concatenated inputs **with**
    /// the label appended, `info` empty, and `L` the output length.
    ///
    /// This is the literal reading of `KDF(concat(ss_PQ, ..., label))`: the
    /// label is part of the single hashed input, exactly where
    /// [`Kdf::Sha3_256`] puts it. Domain separation happens in the extract
    /// step rather than the expand step.
    HkdfSha512LabelInIkm,
}

impl Kdf {
    /// The shortest output this KDF can produce, in bytes.
    pub const fn min_output_len(self) -> usize {
        match self {
            Kdf::Sha3_256 => SHA3_256_LEN,
            Kdf::HkdfSha512LabelAsInfo | Kdf::HkdfSha512LabelInIkm => 1,
        }
    }

    /// The longest output this KDF can produce, in bytes.
    pub const fn max_output_len(self) -> usize {
        match self {
            Kdf::Sha3_256 => SHA3_256_LEN,
            Kdf::HkdfSha512LabelAsInfo | Kdf::HkdfSha512LabelInIkm => HKDF_SHA512_MAX,
        }
    }

    /// Absorb `parts` and `label` and write `out.len()` bytes of key.
    ///
    /// `parts` are absorbed in order, directly into the hash or HMAC state.
    /// Nothing is concatenated into an intermediate buffer, so there is no
    /// heap copy of the shared secrets to leak.
    pub(crate) fn derive(self, parts: &[&[u8]], label: &[u8], out: &mut [u8]) -> Result<(), Error> {
        let (min, max) = (self.min_output_len(), self.max_output_len());
        if out.len() < min || out.len() > max {
            return Err(Error::UnsupportedOutputLength {
                requested: out.len(),
                min,
                max,
            });
        }

        match self {
            Kdf::Sha3_256 => {
                let mut hasher = Sha3_256Hash::new();
                for part in parts {
                    hasher.update(part);
                }
                hasher.update(label);
                let mut digest = hasher.finalize();
                out.copy_from_slice(&digest);
                digest.as_mut_slice().zeroize();
                Ok(())
            }
            Kdf::HkdfSha512LabelAsInfo => {
                let ikm_len: usize = parts.iter().map(|p| p.len()).sum();
                check_hkdf_domains(ikm_len, label.len())?;
                hkdf_sha512(parts, None, label, out)
            }
            Kdf::HkdfSha512LabelInIkm => {
                let ikm_len: usize = parts.iter().map(|p| p.len()).sum::<usize>() + label.len();
                check_hkdf_domains(ikm_len, 0)?;
                hkdf_sha512(parts, Some(label), &[], out)
            }
        }
    }
}

/// HKDF-SHA512 with an absent salt, absorbing `parts` (and `ikm_tail`, if
/// given) as the input keying material.
fn hkdf_sha512(
    parts: &[&[u8]],
    ikm_tail: Option<&[u8]>,
    info: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    let mut extract = HkdfExtract::<Sha512>::new(None);
    for part in parts {
        extract.input_ikm(part);
    }
    if let Some(tail) = ikm_tail {
        extract.input_ikm(tail);
    }
    let (mut prk, hkdf) = extract.finalize();
    let result = hkdf.expand(info, out);
    prk.as_mut_slice().zeroize();
    // Unreachable: the output length was range checked by the caller. Mapped
    // rather than unwrapped so that no panic path exists at all.
    result.map_err(|_| Error::UnsupportedOutputLength {
        requested: out.len(),
        min: 1,
        max: HKDF_SHA512_MAX,
    })
}

/// Enforce the HKDF input domain disjointness condition of
/// draft-irtf-cfrg-hybrid-kems-12 section 6.1.5.
///
/// Following Lemma 6 of Lehmann, Bellare and Bhargavan, it suffices that
/// `len(IKM)` differs from `len(info) + 1` and from
/// `len(info) + 1 + len(HMAC output)`. The draft says instantiations MUST
/// enforce this, so it is enforced here rather than assumed.
const fn check_hkdf_domains(ikm_len: usize, info_len: usize) -> Result<(), Error> {
    let first = info_len + 1;
    let second = info_len + 1 + HMAC_SHA512_LEN;
    if ikm_len == first || ikm_len == second {
        return Err(Error::HkdfDomainSeparation { ikm_len, info_len });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_domain_condition_rejects_exactly_the_two_forbidden_lengths() {
        // info_len = 10, so IKM may not be 11 or 75.
        assert!(check_hkdf_domains(11, 10).is_err());
        assert!(check_hkdf_domains(75, 10).is_err());
        assert!(check_hkdf_domains(10, 10).is_ok());
        assert!(check_hkdf_domains(12, 10).is_ok());
        assert!(check_hkdf_domains(74, 10).is_ok());
        assert!(check_hkdf_domains(76, 10).is_ok());
    }

    #[test]
    fn output_length_bounds_are_enforced() {
        let parts: [&[u8]; 2] = [b"a", b"b"];
        let mut short = [0u8; 31];
        assert!(matches!(
            Kdf::Sha3_256.derive(&parts, b"label", &mut short),
            Err(Error::UnsupportedOutputLength { requested: 31, .. })
        ));
        let mut empty = [0u8; 0];
        assert!(matches!(
            Kdf::HkdfSha512LabelAsInfo.derive(&parts, b"label", &mut empty),
            Err(Error::UnsupportedOutputLength { requested: 0, .. })
        ));
    }
}
