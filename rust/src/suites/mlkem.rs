//! The ML-KEM parameter sets used as the post-quantum component.
//!
//! `draft-irtf-cfrg-concrete-hybrid-kems-04` section 3.2.1 maps FIPS 203 onto
//! the framework's KEM interface. Two points that a wrapper has to get right:
//!
//! - `DeriveKeyPair(seed)` is `KeyGen_internal(seed[0:32], seed[32:64])`, so
//!   the KEM's `Nseed` is **64**, not 32. `libcrux-ml-kem`'s
//!   `generate_key_pair` takes exactly those 64 bytes.
//! - `EncapsDerand` is `Encaps_internal`, with `Nrandom` 32.
//!
//! The arithmetic is `libcrux-ml-kem`'s. Everything here is the mapping.

use alloc::boxed::Box;
use alloc::vec::Vec;
use zeroize::Zeroizing;

use libcrux_ml_kem::{mlkem1024, mlkem768};

use super::SuiteError;

/// Which ML-KEM parameter set a suite's post-quantum component uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MlKem {
    /// ML-KEM-768, Category 3.
    MlKem768,
    /// ML-KEM-1024, Category 5.
    MlKem1024,
}

impl MlKem {
    /// `Nseed`: 64, the `(d, z)` pair of FIPS 203 `KeyGen_internal`.
    pub(super) const fn nseed(self) -> usize {
        64
    }

    /// `Nek`: the encapsulation key length.
    pub(super) const fn nek(self) -> usize {
        match self {
            MlKem::MlKem768 => 1184,
            MlKem::MlKem1024 => 1568,
        }
    }

    /// `Nct`: the ciphertext length.
    pub(super) const fn nct(self) -> usize {
        match self {
            MlKem::MlKem768 => 1088,
            MlKem::MlKem1024 => 1568,
        }
    }

    /// `Nrandom`: 32, the message `m` of FIPS 203 `Encaps_internal`.
    pub(super) const fn nrandom(self) -> usize {
        32
    }

    /// `DeriveKeyPair(seed)`.
    ///
    /// The caller has already produced `Nseed` bytes from the PRG, so this
    /// cannot fail.
    pub(super) fn derive_key_pair(self, seed: &[u8]) -> MlKemKeyPair {
        debug_assert_eq!(seed.len(), self.nseed());
        let mut randomness = Zeroizing::new([0u8; 64]);
        randomness.copy_from_slice(seed);
        match self {
            MlKem::MlKem768 => {
                MlKemKeyPair::MlKem768(Box::new(mlkem768::portable::generate_key_pair(*randomness)))
            }
            MlKem::MlKem1024 => MlKemKeyPair::MlKem1024(Box::new(
                mlkem1024::portable::generate_key_pair(*randomness),
            )),
        }
    }

    /// `EncapsDerand(ek, m)`, which is FIPS 203 `Encaps_internal`.
    ///
    /// The encapsulation key check of FIPS 203 section 7.2 is performed
    /// first, and a failure is an error rather than a silently derived key.
    /// `draft-connolly-cfrg-xwing-kem-10` section 3 requires exactly that.
    pub(super) fn encapsulate_derand(
        self,
        ek: &[u8],
        m: &[u8],
    ) -> Result<MlKemEncapsulation, SuiteError> {
        let mut message = Zeroizing::new([0u8; 32]);
        message.copy_from_slice(m);
        match self {
            MlKem::MlKem768 => {
                let key = mlkem768::MlKem768PublicKey::try_from(ek)
                    .map_err(|_| SuiteError::InvalidMlKemEncapsulationKey)?;
                if !mlkem768::portable::validate_public_key(&key) {
                    return Err(SuiteError::InvalidMlKemEncapsulationKey);
                }
                let (ciphertext, shared_secret) = mlkem768::portable::encapsulate(&key, *message);
                Ok(MlKemEncapsulation {
                    shared_secret: Zeroizing::new(shared_secret.to_vec()),
                    ciphertext: ciphertext.as_slice().to_vec(),
                })
            }
            MlKem::MlKem1024 => {
                let key = mlkem1024::MlKem1024PublicKey::try_from(ek)
                    .map_err(|_| SuiteError::InvalidMlKemEncapsulationKey)?;
                if !mlkem1024::portable::validate_public_key(&key) {
                    return Err(SuiteError::InvalidMlKemEncapsulationKey);
                }
                let (ciphertext, shared_secret) = mlkem1024::portable::encapsulate(&key, *message);
                Ok(MlKemEncapsulation {
                    shared_secret: Zeroizing::new(shared_secret.to_vec()),
                    ciphertext: ciphertext.as_slice().to_vec(),
                })
            }
        }
    }

    /// `Decaps(dk, ct)`.
    ///
    /// ML-KEM rejects implicitly: a ciphertext that does not decrypt yields a
    /// pseudorandom shared secret rather than an error, which is what keeps
    /// the KEM IND-CCA. The only error here is a wrong ciphertext length.
    pub(super) fn decapsulate(
        self,
        key_pair: &MlKemKeyPair,
        ct: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SuiteError> {
        let wrong_length = || SuiteError::WrongLength {
            what: "ML-KEM ciphertext",
            expected: self.nct(),
            actual: ct.len(),
        };
        match (self, key_pair) {
            (MlKem::MlKem768, MlKemKeyPair::MlKem768(pair)) => {
                let ciphertext =
                    mlkem768::MlKem768Ciphertext::try_from(ct).map_err(|_| wrong_length())?;
                let shared = mlkem768::portable::decapsulate(pair.private_key(), &ciphertext);
                Ok(Zeroizing::new(shared.to_vec()))
            }
            (MlKem::MlKem1024, MlKemKeyPair::MlKem1024(pair)) => {
                let ciphertext =
                    mlkem1024::MlKem1024Ciphertext::try_from(ct).map_err(|_| wrong_length())?;
                let shared = mlkem1024::portable::decapsulate(pair.private_key(), &ciphertext);
                Ok(Zeroizing::new(shared.to_vec()))
            }
            // Unreachable: the key pair is always built by this same suite.
            _ => Err(wrong_length()),
        }
    }
}

/// A component ML-KEM key pair, holding the expanded private key that
/// `Decaps` needs.
///
/// Boxed because an ML-KEM-1024 expanded private key is over four kilobytes,
/// which is more than belongs on the stack of every call.
///
/// What this crate cannot do is zeroize it on drop: `libcrux-ml-kem` exposes
/// no mutable view of its key types, and copying the key out to zeroize a
/// copy would leave the original untouched. The seed this is derived from is
/// zeroized; the expanded key is the dependency's to manage. Stated rather
/// than glossed over, because "we zeroize" is exactly the kind of claim that
/// gets believed.
pub(super) enum MlKemKeyPair {
    MlKem768(Box<mlkem768::MlKem768KeyPair>),
    MlKem1024(Box<mlkem1024::MlKem1024KeyPair>),
}

impl MlKemKeyPair {
    /// `ek_PQ`, the serialized encapsulation key.
    pub(super) fn public_key_bytes(&self) -> &[u8] {
        match self {
            MlKemKeyPair::MlKem768(pair) => pair.pk(),
            MlKemKeyPair::MlKem1024(pair) => pair.pk(),
        }
    }
}

/// The output of `EncapsDerand`.
pub(super) struct MlKemEncapsulation {
    pub(super) shared_secret: Zeroizing<Vec<u8>>,
    ciphertext: Vec<u8>,
}

impl MlKemEncapsulation {
    /// `ct_PQ`.
    pub(super) fn ciphertext_bytes(&self) -> &[u8] {
        &self.ciphertext
    }
}
