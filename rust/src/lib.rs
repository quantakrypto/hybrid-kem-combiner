//! A generic, standalone hybrid KEM combiner.
//!
//! When you build a hybrid KEM you run two independent key encapsulation
//! mechanisms, one post-quantum and one traditional, and you end up holding
//! two shared secrets. The combiner is the function that turns them into the
//! one key you actually use. It is the only place in a hybrid where "if
//! either component is secure, the whole thing is secure" is either achieved
//! or lost. Neither component KEM provides that property, and neither does
//! the AEAD that consumes the output.
//!
//! This crate implements the construction that carries that guarantee, and
//! nothing else. It does no key generation, no encapsulation, and no
//! decapsulation: it takes the byte strings a hybrid KEM already has and
//! derives the combined secret from them.
//!
//! # The construction
//!
//! ```text
//! UniversalCombiner(ss_PQ, ss_T, ct_PQ, ct_T, ek_PQ, ek_T, label)
//!     = KDF(ss_PQ || ss_T || ct_PQ || ct_T || ek_PQ || ek_T || label)
//! ```
//!
//! Specified in two places, in this exact shape:
//!
//! - **NIST SP 800-227**, *Recommendations for Key-Encapsulation Mechanisms*,
//!   September 2025. Section 4.6.2 defines it as Expression (15),
//!   `KeyCombine(K1, K2, c1, c2, ek1, ek2, p) := H(K1, K2, c1, c2, ek1, ek2,
//!   domain_sep)`. Section 4.6.3 names the same function `KeyCombine^CCA_H`
//!   and states that NIST "encourages the use of key combiners that
//!   generically preserve IND-CCA security".
//! - **draft-irtf-cfrg-hybrid-kems-12**, section 5.1.3, as
//!   `UniversalCombiner`, with those seven arguments in that order.
//!
//! [`combine_c2pri`] is the optimised variant that omits the post-quantum
//! ciphertext and encapsulation key. It is only sound for a post-quantum KEM
//! that is ciphertext second preimage resistant, so reaching it requires
//! constructing a [`C2priAssertion`] by name. Read that type's documentation
//! before you use it.
//!
//! # Example
//!
//! ```
//! use hybrid_kem_combiner::{
//!     combine_universal, Ciphertext, EncapsulationKey, Kdf, Label,
//!     SharedSecret, UniversalInputs,
//! };
//!
//! // These would be the real outputs of your two component KEMs.
//! let ss_pq = [0x11u8; 32];
//! let ss_t = [0x22u8; 32];
//! let ct_pq = [0x33u8; 1088];
//! let ct_t = [0x44u8; 32];
//! let ek_pq = [0x55u8; 1184];
//! let ek_t = [0x66u8; 32];
//!
//! let inputs = UniversalInputs {
//!     pq_shared_secret: SharedSecret::new(&ss_pq),
//!     traditional_shared_secret: SharedSecret::new(&ss_t),
//!     pq_ciphertext: Ciphertext::new(&ct_pq),
//!     traditional_ciphertext: Ciphertext::new(&ct_t),
//!     pq_encapsulation_key: EncapsulationKey::new(&ek_pq),
//!     traditional_encapsulation_key: EncapsulationKey::new(&ek_t),
//!     label: Label::new(b"example.org/v1/ml-kem-768+x25519"),
//! };
//!
//! let mut key = [0u8; 32];
//! combine_universal(Kdf::Sha3_256, &inputs, &mut key).unwrap();
//! ```
//!
//! # What this crate does not do
//!
//! It implements a specified construction. **The implementation itself has
//! had no external cryptographic review.** See the repository README.
//!
//! # Input encoding
//!
//! The inputs are concatenated with no length prefixes and no separators,
//! because that is what the standards specify and what interoperability
//! requires. SP 800-227 warns in section 4.6.2 that `H(x, y)` is only safely
//! rendered as `H(x || y)` when the encoding fixes the lengths. Real KEMs
//! have fixed output lengths per parameter set, so this holds as long as the
//! `label` uniquely identifies the parameter sets of both components, which
//! is exactly what SP 800-227 asks of `domain_sep` and what
//! draft-irtf-cfrg-hybrid-kems asks of `label`. **Choosing a label that does
//! not pin both parameter sets is a real error and this crate cannot detect
//! it.**
//!
//! # Zeroization
//!
//! The combiner never copies its inputs into a heap buffer: every input is
//! absorbed directly into the hash or HMAC state. There is therefore no
//! intermediate concatenation to leak through a reallocated or freed `Vec`.
//! Derived intermediates that this crate does own (the HKDF pseudorandom key,
//! the SHA3 digest) are zeroized before they are dropped. What this crate
//! cannot promise is the internal state of `sha2`, `sha3` and `hkdf`, or the
//! output buffer you supply: zeroize that yourself.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod kdf;

pub use kdf::Kdf;

/// Which input a validation error refers to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Input {
    /// The post-quantum component's shared secret.
    PqSharedSecret,
    /// The traditional component's shared secret.
    TraditionalSharedSecret,
    /// The post-quantum component's ciphertext.
    PqCiphertext,
    /// The traditional component's ciphertext.
    TraditionalCiphertext,
    /// The post-quantum component's encapsulation key.
    PqEncapsulationKey,
    /// The traditional component's encapsulation key.
    TraditionalEncapsulationKey,
    /// The domain separation label.
    Label,
}

impl Input {
    /// The name of this input, as it appears in the standards.
    pub const fn as_str(self) -> &'static str {
        match self {
            Input::PqSharedSecret => "ss_PQ",
            Input::TraditionalSharedSecret => "ss_T",
            Input::PqCiphertext => "ct_PQ",
            Input::TraditionalCiphertext => "ct_T",
            Input::PqEncapsulationKey => "ek_PQ",
            Input::TraditionalEncapsulationKey => "ek_T",
            Input::Label => "label",
        }
    }
}

impl core::fmt::Display for Input {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What can go wrong. Every variant is a caller error, caught before any
/// key material is derived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// An input was zero length.
    ///
    /// No KEM produces an empty shared secret, ciphertext or encapsulation
    /// key, and an empty label provides no domain separation. A zero length
    /// input is almost always a dropped value, which would silently weaken
    /// the combined secret, so it is refused rather than absorbed.
    Empty(Input),
    /// The chosen KDF cannot produce an output of the requested length.
    UnsupportedOutputLength {
        /// The length the caller asked for, in bytes.
        requested: usize,
        /// The shortest output this KDF supports, in bytes.
        min: usize,
        /// The longest output this KDF supports, in bytes.
        max: usize,
    },
    /// The HKDF input domain separation condition does not hold for these
    /// input lengths.
    ///
    /// draft-irtf-cfrg-hybrid-kems-12 section 6.1.5 requires, for HKDF to be
    /// indifferentiable from a random oracle, that the input domains of
    /// HKDF's internal HMAC calls be pairwise disjoint, and states that it
    /// suffices for `len(IKM)` to differ from `len(info) + 1` and from
    /// `len(info) + 1 + len(HMAC output)`. It says concrete instantiations
    /// MUST enforce this. This crate enforces it, and this is the refusal.
    ///
    /// The fix is a different label length, or a different KDF.
    HkdfDomainSeparation {
        /// The total length of the concatenated input keying material.
        ikm_len: usize,
        /// The length of HKDF's `info` argument.
        info_len: usize,
    },
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Empty(which) => write!(f, "combiner input {which} is empty"),
            Error::UnsupportedOutputLength { requested, min, max } => write!(
                f,
                "requested output length {requested} is outside the range \
                 {min}..={max} supported by this KDF"
            ),
            Error::HkdfDomainSeparation { ikm_len, info_len } => write!(
                f,
                "HKDF input domains are not disjoint for ikm_len={ikm_len} \
                 and info_len={info_len}"
            ),
        }
    }
}

impl core::error::Error for Error {}

/// A component KEM's shared secret. Secret input.
///
/// `Debug` deliberately redacts the contents.
#[derive(Clone, Copy)]
pub struct SharedSecret<'a>(&'a [u8]);

impl<'a> SharedSecret<'a> {
    /// Wrap a shared secret.
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    /// The wrapped bytes.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.0
    }
}

impl core::fmt::Debug for SharedSecret<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SharedSecret([redacted; {} bytes])", self.0.len())
    }
}

/// A component KEM's ciphertext. Public input.
///
/// For a nominal group used as the traditional component, this is the
/// sender's ephemeral public key, which is how
/// draft-irtf-cfrg-hybrid-kems-12 section 5.1.1 maps a group onto the KEM
/// interface.
#[derive(Clone, Copy, Debug)]
pub struct Ciphertext<'a>(&'a [u8]);

impl<'a> Ciphertext<'a> {
    /// Wrap a ciphertext.
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    /// The wrapped bytes.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.0
    }
}

/// A component KEM's encapsulation key, that is, the recipient's public key.
/// Public input.
#[derive(Clone, Copy, Debug)]
pub struct EncapsulationKey<'a>(&'a [u8]);

impl<'a> EncapsulationKey<'a> {
    /// Wrap an encapsulation key.
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    /// The wrapped bytes.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.0
    }
}

/// The domain separation label.
///
/// SP 800-227 section 4.6.3: the domain separator "should be used to uniquely
/// identify the composite scheme in use (e.g., Pi_1, Pi_2, order of
/// composition, choice of parameter set, key combiner, KDF)". That is not
/// decoration. Because the inputs are concatenated without length prefixes,
/// the label pinning both parameter sets is what makes the encoding
/// unambiguous. See the crate level "Input encoding" section.
#[derive(Clone, Copy, Debug)]
pub struct Label<'a>(&'a [u8]);

impl<'a> Label<'a> {
    /// Wrap a label.
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    /// The wrapped bytes.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.0
    }
}

/// The six inputs of the universal combiner, plus the label.
///
/// The fields are named rather than positional because the single most
/// likely implementation error in a combiner is passing the right bytes in
/// the wrong order, and a swap of two same-length inputs produces a
/// well-formed key that silently disagrees with the peer.
#[derive(Clone, Copy, Debug)]
pub struct UniversalInputs<'a> {
    /// `ss_PQ`, the post-quantum shared secret.
    pub pq_shared_secret: SharedSecret<'a>,
    /// `ss_T`, the traditional shared secret.
    pub traditional_shared_secret: SharedSecret<'a>,
    /// `ct_PQ`, the post-quantum ciphertext.
    pub pq_ciphertext: Ciphertext<'a>,
    /// `ct_T`, the traditional ciphertext.
    pub traditional_ciphertext: Ciphertext<'a>,
    /// `ek_PQ`, the post-quantum encapsulation key.
    pub pq_encapsulation_key: EncapsulationKey<'a>,
    /// `ek_T`, the traditional encapsulation key.
    pub traditional_encapsulation_key: EncapsulationKey<'a>,
    /// The domain separation label.
    pub label: Label<'a>,
}

/// A statement, which only you can make, that your post-quantum KEM is
/// ciphertext second preimage resistant.
///
/// The C2PRI combiner drops `ct_PQ` and `ek_PQ` from the derivation. That is
/// sound only if the post-quantum KEM is C2PRI: given an honest key pair,
/// ciphertext and shared secret, no adversary can find a second ciphertext
/// that decapsulates to the same shared secret. ML-KEM is believed to satisfy
/// this because of the specifics of the Fujisaki-Okamoto transform it uses,
/// and X-Wing's security argument rests on exactly that. It is a property of
/// your KEM, not of this crate, and this crate has no way to check it.
///
/// draft-connolly-cfrg-xwing-kem-10 section 6 states the risk directly: "the
/// X-Wing combiner cannot be assumed to be secure, when used with different
/// KEMs. In particular it is not known to be safe to leave out the
/// post-quantum ciphertext from the combiner in the general case."
///
/// If you are not certain, use [`combine_universal`]. It costs one extra pass
/// over the ciphertext and encapsulation key and it assumes nothing.
///
/// This type exists so that choosing the optimisation is a visible,
/// searchable act in your source, and so that it cannot be reached by
/// accident. It has no `Default` and no other constructor.
#[derive(Clone, Copy, Debug)]
pub struct C2priAssertion(());

impl C2priAssertion {
    /// Assert that the post-quantum KEM you are combining is ciphertext
    /// second preimage resistant.
    ///
    /// Read the type documentation before calling this.
    #[allow(clippy::new_without_default)]
    pub const fn assert_pq_kem_is_ciphertext_second_preimage_resistant() -> Self {
        Self(())
    }
}

/// The four inputs of the C2PRI combiner, plus the label and the assertion.
#[derive(Clone, Copy, Debug)]
pub struct C2priInputs<'a> {
    /// `ss_PQ`, the post-quantum shared secret.
    pub pq_shared_secret: SharedSecret<'a>,
    /// `ss_T`, the traditional shared secret.
    pub traditional_shared_secret: SharedSecret<'a>,
    /// `ct_T`, the traditional ciphertext.
    pub traditional_ciphertext: Ciphertext<'a>,
    /// `ek_T`, the traditional encapsulation key.
    pub traditional_encapsulation_key: EncapsulationKey<'a>,
    /// The domain separation label.
    pub label: Label<'a>,
    /// Your statement that the post-quantum KEM is C2PRI.
    pub assertion: C2priAssertion,
}

fn require_nonempty(bytes: &[u8], which: Input) -> Result<(), Error> {
    if bytes.is_empty() {
        Err(Error::Empty(which))
    } else {
        Ok(())
    }
}

/// The universal combiner: `KDF(ss_PQ || ss_T || ct_PQ || ct_T || ek_PQ ||
/// ek_T || label)`.
///
/// Preserves IND-CCA as long as at least one component KEM is IND-CCA, with
/// no further assumption about either component. This is the form to use
/// unless you have a specific reason not to.
///
/// The combined key is written into `out`, whose length selects the output
/// length. See [`Kdf`] for what each KDF supports.
///
/// # Errors
///
/// Returns [`Error::Empty`] if any input is zero length,
/// [`Error::UnsupportedOutputLength`] if `out` is a length the KDF cannot
/// produce, and [`Error::HkdfDomainSeparation`] if an HKDF variant was chosen
/// and the input lengths break the disjointness condition. Nothing is written
/// to `out` on error.
pub fn combine_universal(
    kdf: Kdf,
    inputs: &UniversalInputs<'_>,
    out: &mut [u8],
) -> Result<(), Error> {
    let parts = [
        inputs.pq_shared_secret.as_bytes(),
        inputs.traditional_shared_secret.as_bytes(),
        inputs.pq_ciphertext.as_bytes(),
        inputs.traditional_ciphertext.as_bytes(),
        inputs.pq_encapsulation_key.as_bytes(),
        inputs.traditional_encapsulation_key.as_bytes(),
    ];
    const NAMES: [Input; 6] = [
        Input::PqSharedSecret,
        Input::TraditionalSharedSecret,
        Input::PqCiphertext,
        Input::TraditionalCiphertext,
        Input::PqEncapsulationKey,
        Input::TraditionalEncapsulationKey,
    ];
    for (part, name) in parts.iter().zip(NAMES) {
        require_nonempty(part, name)?;
    }
    let label = inputs.label.as_bytes();
    require_nonempty(label, Input::Label)?;

    kdf.derive(&parts, label, out)
}

/// The C2PRI combiner: `KDF(ss_PQ || ss_T || ct_T || ek_T || label)`.
///
/// This is the optimised form. It omits the post-quantum ciphertext and
/// encapsulation key, which for ML-KEM-1024 is 1568 plus 1568 bytes that do
/// not have to be hashed. The resulting hybrid KEM is secure if the
/// post-quantum component is IND-CCA, or if the traditional component is
/// secure **and the post-quantum component is C2PRI**
/// (draft-irtf-cfrg-hybrid-kems-12 section 5.1.3).
///
/// That second condition is an assumption about your KEM that this crate
/// cannot verify, which is why an explicit [`C2priAssertion`] is required.
/// draft-ietf-lamps-pq-composite-kem is candid about the tradeoff: omitting
/// the ML-KEM ciphertext "does not fully protect against implementation
/// errors in the ML-KEM component", and was chosen "to increase performance".
///
/// With [`Kdf::Sha3_256`] and the six byte X-Wing label, this function is
/// byte for byte the X-Wing combiner
/// (draft-connolly-cfrg-xwing-kem-10 section 5.3), and the crate's
/// conformance vectors check exactly that against the draft's own test
/// vectors.
///
/// # Errors
///
/// The same as [`combine_universal`].
pub fn combine_c2pri(
    kdf: Kdf,
    inputs: &C2priInputs<'_>,
    out: &mut [u8],
) -> Result<(), Error> {
    let parts = [
        inputs.pq_shared_secret.as_bytes(),
        inputs.traditional_shared_secret.as_bytes(),
        inputs.traditional_ciphertext.as_bytes(),
        inputs.traditional_encapsulation_key.as_bytes(),
    ];
    const NAMES: [Input; 4] = [
        Input::PqSharedSecret,
        Input::TraditionalSharedSecret,
        Input::TraditionalCiphertext,
        Input::TraditionalEncapsulationKey,
    ];
    for (part, name) in parts.iter().zip(NAMES) {
        require_nonempty(part, name)?;
    }
    let label = inputs.label.as_bytes();
    require_nonempty(label, Input::Label)?;

    kdf.derive(&parts, label, out)
}

/// [`combine_universal`], returning a heap buffer of `len` bytes that
/// zeroizes itself when dropped.
///
/// # Errors
///
/// The same as [`combine_universal`].
#[cfg(feature = "alloc")]
pub fn combine_universal_to_vec(
    kdf: Kdf,
    inputs: &UniversalInputs<'_>,
    len: usize,
) -> Result<zeroize::Zeroizing<alloc::vec::Vec<u8>>, Error> {
    let mut out = zeroize::Zeroizing::new(alloc::vec![0u8; len]);
    combine_universal(kdf, inputs, &mut out)?;
    Ok(out)
}

/// [`combine_c2pri`], returning a heap buffer of `len` bytes that zeroizes
/// itself when dropped.
///
/// # Errors
///
/// The same as [`combine_universal`].
#[cfg(feature = "alloc")]
pub fn combine_c2pri_to_vec(
    kdf: Kdf,
    inputs: &C2priInputs<'_>,
    len: usize,
) -> Result<zeroize::Zeroizing<alloc::vec::Vec<u8>>, Error> {
    let mut out = zeroize::Zeroizing::new(alloc::vec![0u8; len]);
    combine_c2pri(kdf, inputs, &mut out)?;
    Ok(out)
}
