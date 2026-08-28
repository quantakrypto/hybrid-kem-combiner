# References

Primary sources for the construction and for the suites this library
implements. Everything quoted in the README and in the source comments comes
from these documents, read directly. Where a claim was checked and turned out to need qualifying,
that is recorded here rather than quietly dropped.

Last verified 28 August 2026.

## The construction

### NIST SP 800-227, *Recommendations for Key-Encapsulation Mechanisms*

Final, September 2025. Alagic, Barker, Chen, Moody, Robinson, Silberg, Waller.

<https://doi.org/10.6028/NIST.SP.800-227>
(PDF: <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-227.pdf>)

- **Section 4.6.1** constructs a composite KEM and puts the key combiner in
  the middle of it: `K <- KeyCombine(K1, K2, c1, c2, ek1, ek2, p)`,
  Expressions (9) and (10). It also notes the practical consequence that
  "since the inputs to KeyCombine include the composite encapsulation key, the
  decapsulating party must retain a copy of that key or maintain the ability
  to recreate it after performing key generation".
- **Section 4.6.2, Expression (15)** is the construction:

  ```text
  KeyCombine(K1, K2, c1, c2, ek1, ek2, p) := H(K1, K2, c1, c2, ek1, ek2, domain_sep)
  ```

  reached by choosing the one-step key derivation method of SP 800-56C with an
  approved hash function and setting `OtherInput` to the ciphertexts,
  encapsulation keys and domain separator.
- **Section 4.6.2, "Concatenation of inputs"** is the note this library's
  input encoding section answers: `H(x, y)` is distinct from `H(x || y)`, and
  simple concatenation is safe only when the encoding fixes the lengths. The
  change log at the back of the document records that this note was added in
  the final version, in response to public comment.
- **Section 4.6.3** is where the IND-CCA argument lives, which is why citing
  "4.6.2" alone for the security property is slightly wrong. It states that
  `K <- KDF(K1, K2)` over the two shared secrets alone "does not preserve
  IND-CCA security, regardless of the properties of the KDF" (Expression
  (16)), names `KeyCombine^CCA_H` with `H` from the SHA-3 family, and says
  NIST "encourages the use of key combiners that generically preserve IND-CCA
  security". It attributes the negative result to reference [24] (X-Wing,
  ePrint 2024/039) and the preservation result to [25] (Giacon, Heuer and
  Poettering), and observes that [25] does not include the encapsulation keys,
  "as this is not needed to achieve the IND-CCA-preserving property", but that
  including them "can have other potential advantages in secure protocols,
  such as binding the final shared secret to the identities of the
  participating parties".

### draft-irtf-cfrg-hybrid-kems

Connolly, Schwabe, Westerbaan, and others. CFRG research group document.
Version 12, 6 July 2026, expires 7 January 2027.

<https://datatracker.ietf.org/doc/draft-irtf-cfrg-hybrid-kems/>

- **Section 5.1.3** defines both combiners this library implements:

  ```text
  def UniversalCombiner(ss_PQ, ss_T, ct_PQ, ct_T, ek_PQ, ek_T, label):
      return KDF(concat(ss_PQ, ss_T, ct_PQ, ct_T, ek_PQ, ek_T, label))

  def C2PRICombiner(ss_PQ, ss_T, ct_T, ek_T, label):
      return KDF(concat(ss_PQ, ss_T, ct_T, ek_T, label))
  ```

  The universal form "allows the resulting hybrid KEM to be secure as long as
  either component is secure, with no further assumptions on the components".
  The C2PRI form "does not compute over the ciphertext or encapsulation key
  from the PQ component", and its hybrid "will be secure if the PQ component
  is IND-CCA secure, or, the traditional component is secure and the PQ
  component also satisfies the C2PRI property". Note that it drops **both**
  the PQ ciphertext and the PQ encapsulation key, not the ciphertext alone.
- The same section makes explicit that the names are suggestive rather than
  binding: "when the framework is instantiated with a nominal group, the
  'ciphertext' component is an ephemeral group element, and the 'encapsulation
  key' is the group element that functions as the recipient's public key".
  That is how X25519 and X448 map onto the six inputs.
- **Section 5.1.1** defines `expandDecapsKeyG`, `prepareEncapsG` and
  `prepareDecapsG`, the subroutines every nominal group framework shares, and
  **section 5.5** defines the **CG framework**: the C2PRI combiner with a
  nominal group. All four suites in this library's `suites` module are CG.
- **Section 5.2** specifies that the hybrid decapsulation key is the seed, and
  says why: deriving the per-component private keys inside the hybrid is what
  prevents a component key pair from being reused outside it, and what
  upgrades the binding properties from LEAK-BIND to MAL-BIND.
- **Section 4.2** defines the nominal group abstraction, requires that
  `RandomScalar` never return zero, and states that a group whose `Exp` can
  fail on a malformed element makes the hybrid an explicitly rejecting KEM.
- **Section 7** establishes the IANA hybrid KEM label registry and requires
  registered labels to be **suffix free**. That requirement is why this
  project's own `MLKEM1024-X25519` uses a namespaced label rather than the
  bare name: it cannot be registered, and a future registration of the bare
  name for a different construction would collide silently.
- **Section 8** lists the non-goals, including anonymity, deniability and
  other key-robustness properties. That is the basis for not rejecting an
  all-zero X25519 output in the suites.
- **Appendix A** defines deterministic encapsulation: `Nrandom = PQ.Nrandom +
  T.Nrandom`, the post-quantum component takes the **first** `PQ.Nrandom`
  bytes and the traditional component the **last** `T.Nrandom` bytes. Getting
  that order backwards reproduces nothing and looks like a broken KEM.
- **Section 5** requires that "any KDF that utilizes HKDF MUST fully specify
  HKDF's salt, IKM, info, and L arguments". This library's two HKDF variants
  each do, and they are named separately because the specification does not
  choose between them.
- **Section 6.1.5** requires the KDF to be indifferentiable from a random
  oracle, including against a quantum attacker, and gives the conditions under
  which HKDF qualifies, citing [LBB20]: HMAC indifferentiable from a random
  oracle, and the input domains of HKDF's internal HMAC calls pairwise
  disjoint. It states the sufficient condition concretely, that `len(IKM)`
  differ from `len(info) + 1` and from `len(info) + 1 + len(HMAC output)`, and
  says this "MUST be enforced by the concrete instantiations that use HKDF as
  a KDF". Both implementations here enforce it and return a specific error.
  The section also requires that the mapping onto HKDF's arguments be defined
  "in such a way that no input value will ever map to colliding IKM and info
  values".

## The concrete suites

### draft-irtf-cfrg-concrete-hybrid-kems

Connolly, Barnes. CFRG research group document. Version 4, 6 July 2026,
expires 7 January 2027.

<https://datatracker.ietf.org/doc/draft-irtf-cfrg-concrete-hybrid-kems/>

The specification of three of the four suites in this library's `suites`
module, and the source of the only external test vectors that exist for them.

- **Section 3.1.1** defines the P-256 and P-384 nominal groups: uncompressed
  SEC1 point encoding, the x coordinate alone as the shared secret, and
  `RandomScalar` as rejection sampling over successive `Nscalar`-byte blocks
  of the seed, big endian, rejecting zero and anything at or above the group
  order. It is **not** a reduction of the seed modulo the group order, and the
  two produce different keys. `Nseed` is 128 for P-256 and 48 for P-384; the
  asymmetry is deliberate, because P-256 rejects far more often.
- **Section 3.1.2** defines the Curve25519 nominal group, where
  `RandomScalar` and `ElementToSharedSecret` are both the identity function.
- **Section 3.2.1** maps FIPS 203 onto the KEM abstraction: `DeriveKeyPair`
  is `KeyGen_internal(seed[0:32], seed[32:64])`, so `Nseed` is 64, and
  `EncapsDerand` is `Encaps_internal` with `Nrandom` 32.
- **Section 4** defines `MLKEM768-P256`, `MLKEM768-X25519` and
  `MLKEM1024-P384`, all three using the CG framework with SHAKE256 as the PRG
  and SHA3-256 as the KDF, with their labels and lengths.
- **Section 5** states the security requirements the components must meet and
  where each is established, including that ML-KEM's C2PRI property is what
  licenses the C2PRI combiner. It applies that to ML-KEM-1024, not only to
  ML-KEM-768.
- **Section 6** requests the IANA registrations, and names the framework of
  all three as `CG`.
- **Appendix B** publishes ten test vectors per suite. This repository
  transcribes them into
  `vectors/concrete-hybrid-kems-04-appendix-b.json` with
  `vectors/extract_appendix_b.py`, which computes nothing.

  One inconsistency in the draft, recorded because an implementer will hit it:
  the appendix prose says the `decapsulation_key_pq` values are "ML-KEM
  expanded private keys in the format defined by [FIPS203]", which would be
  2400 and 3168 bytes. Every published value is 64 bytes, which is the seed
  form that section 3.2.1 gives as the KEM's `Ndk`. The data is right and the
  prose is loose; this project follows the data.

## The C2PRI optimisation

### draft-connolly-cfrg-xwing-kem

Connolly, Schwabe, Westerbaan. Version 10, 2 March 2026, expires 3 September
2026. An **individual** Internet-Draft: the `-cfrg-` in the name is the
intended stream, not adoption status.

<https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/>

- **Section 5.3** is the combiner:

  ```text
  def Combiner(ss_M, ss_X, ct_X, pk_X):
    return SHA3-256(concat(ss_M, ss_X, ct_X, pk_X, XWingLabel))
  ```

  with `XWingLabel` the six byte ASCII string whose hex is `5c2e2f2f5e5c`.
  This is `C2PRICombiner` with SHA3-256, and this library reproduces it
  exactly.
- **Section 6** carries the caveat that gates the optimisation: "The security
  of X-Wing relies crucially on the specifics of the Fujisaki-Okamoto
  transformation used in ML-KEM-768: the X-Wing combiner cannot be assumed to
  be secure, when used with different KEMs. In particular it is not known to
  be safe to leave out the post-quantum ciphertext from the combiner in the
  general case."
- **Appendix C** publishes the test vectors that three of this library's
  conformance cases are anchored to.

### Barbosa, Connolly, Duarte, Kaiser, Schwabe, Varner, Westerbaan, *X-Wing: The Hybrid KEM You've Been Looking For*

IACR Communications in Cryptology 1(1), 2024. ePrint 2024/039.

<https://doi.org/10.62056/a3qj89n4e>, <https://eprint.iacr.org/2024/039>

Reference [24] of SP 800-227, cited there for the result that the shared
secrets only combiner does not preserve IND-CCA. This is the peer reviewed
security analysis behind X-Wing, and the source of the C2PRI framing.

### Alagic, Bajaj, Kocoglu, *The Best of Both KEMs: Securely Combining KEMs in Post-Quantum Hybrid Schemes*

August 2025. ePrint 2025/1444.

<https://eprint.iacr.org/2025/1444>

Proves that `F(k1, ..., kn, x) := H(k1 || ... || kn || x)` is a split-key PRF
when `H` is a random oracle, and proves C2PRI for KEMs built from a class of
Fujisaki-Okamoto transforms, naming ML-KEM without restricting to a parameter
set. It also asserts, in passing rather than as a theorem, that NIST's
recommended key derivation functions "which include popular methods like HKDF,
can be shown to be split-key PRFs in the random oracle model". That sentence
is the closest published support for this library's HKDF variants, and it is
an outline, not a proof about a specific salt, IKM and info mapping. It is why
`Sha3_256` is the recommended default here.

### Giacon, Heuer, Poettering, *KEM Combiners*

PKC 2018. ePrint 2018/024.

<https://eprint.iacr.org/2018/024>

Reference [25] of SP 800-227, cited there as the source of the IND-CCA
preserving property. The original result on split-key pseudorandom
combination, without the encapsulation keys.

## Supporting documents

- **RFC 5869**, *HMAC-based Extract-and-Expand Key Derivation Function
  (HKDF)*. <https://www.rfc-editor.org/rfc/rfc5869> The absent salt of section
  2.2, which HKDF-Extract replaces with `HashLen` zero bytes, is what both
  HKDF variants here use.
- **FIPS 202**, SHA-3 and SHAKE.
  <https://doi.org/10.6028/NIST.FIPS.202>
- **FIPS 203**, ML-KEM. <https://doi.org/10.6028/NIST.FIPS.203> Sections 6,
  7.1, 7.2 and 7.3 for `KeyGen_internal`, `KeyGen`, `Encaps` and `Decaps`, and
  the section 7.2 encapsulation key check that the suites perform and refuse
  on.
- **RFC 7748**, *Elliptic Curves for Security*, for `X25519` and the
  Curve25519 base point.
  <https://www.rfc-editor.org/rfc/rfc7748>
- **SEC 1 v2**, for the uncompressed elliptic curve point encoding the NIST
  curve suites use. <https://secg.org/sec1-v2.pdf>
- **NIST SP 800-186**, for the P-256 and P-384 domain parameters and group
  orders. <https://doi.org/10.6028/NIST.SP.800-186>
- **draft-ietf-lamps-pq-composite-kem**, whose section 9.2.3 states the
  tradeoff of omitting the ML-KEM ciphertext plainly: it "does not fully
  protect against implementation errors in the ML-KEM component", and was
  chosen "to increase performance".
  <https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-kem/>
- **RFC 10024**, *Post-Quantum Traditional (PQ/T) Hybrid Key Agreement
  Mechanisms for TLS 1.3*, August 2026, for how the same problem is solved
  when the combiner can live in a protocol transcript instead.
  <https://www.rfc-editor.org/rfc/rfc10024.html>

## Written by this project, and not a standard

### MLKEM1024-X25519

[`mlkem1024-x25519.md`](mlkem1024-x25519.md), in this repository. It is listed
in its own section so that it is not mistaken for one of the documents above.
It has no standards status, it has had no external review, no formal analysis
of the pairing exists, and no external test vectors exist for it or can. Its
rationale section argues the case against it as well as the case for it, and
records that its absence from the CFRG drafts is a deliberate choice by their
authors.

## Survey sources

### The correction

The first version of the README claimed that no generic KEM combiner existed
in any ecosystem. That was wrong, and the corrected claim is narrower: no
standalone byte-level combiner in Rust or TypeScript.

**`katzenpost/hpqc`**, package `kem/combiner`, Go, AGPL-3.0-only.
<https://github.com/katzenpost/hpqc>

It is a genuine generic combiner over an arbitrary number of sub-KEMs, and it
cites the same Giacon, Heuer and Poettering result this library does. Its own
package documentation gives the construction:

```text
for each i in 1..n:
    hash_i := H(label || u32be(len(ss_i)) || ss_i ||
                u32be(n)  || u32be(len(cct_j)) || cct_j ...)
return hash_1 XOR hash_2 XOR ... XOR hash_n
```

with `H` BLAKE2b. Two differences, neither of them a criticism:

- It exposes **whole KEM types** (`kem.Scheme`, `PublicKey`, `PrivateKey`),
  so you combine schemes rather than bytes you already hold.
- It is the **XOR-of-PRF-outputs** shape of the original paper, with
  length-prefixed inputs, and it binds ciphertexts but not encapsulation keys.
  `UniversalCombiner` is a single hash over an unprefixed concatenation that
  binds both. The two are not byte compatible and were never meant to be.

Checked against the package source on 28 August 2026, not against a secondary
description of it.

### The registries

The gap claim in the README was checked against the registries themselves, not
against secondary write-ups, on 28 August 2026:

- crates.io search API for `kem combiner`, `kem-combiner`, `hybrid kem` and
  `x-wing`, plus the published `.crate` archive of `pq-kem-combiner` 0.0.1,
  whose `src/lib.rs` is three lines of documentation ending "Implementation
  coming soon".
- The npm registry search API for `kem combiner`, `hybrid kem post-quantum`
  and `x-wing kem`, plus the installed source of `@noble/post-quantum` 0.7.1
  (`hybrid.js`), where `QSF` and `createKitchenSink` build hybrid KEMs from
  component KEM objects and the combiner itself is an unexported closure.

## Related, and deliberately not a dependency

`qk-password-manager` has an internal combiner of the same shape
(ML-KEM-1024 plus X25519, universal form, HKDF-SHA512 with the label in
`info`) and its own review notes on that instantiation. One conformance vector
here reproduces its pinned value, so the two are known to agree. This library
does not depend on it and it does not yet depend on this library.
