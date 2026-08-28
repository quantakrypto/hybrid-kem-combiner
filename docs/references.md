# References

Primary sources for the construction this library implements. Everything
quoted in the README and in the source comments comes from these documents,
read directly. Where a claim was checked and turned out to need qualifying,
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
- **FIPS 202**, SHA-3. <https://doi.org/10.6028/NIST.FIPS.202>
- **FIPS 203**, ML-KEM. <https://doi.org/10.6028/NIST.FIPS.203>
- **draft-irtf-cfrg-concrete-hybrid-kems**, which applies the C2PRI combiner
  to ML-KEM-1024 in `MLKEM1024-P384`, showing that the optimisation is not
  restricted to ML-KEM-768.
  <https://datatracker.ietf.org/doc/draft-irtf-cfrg-concrete-hybrid-kems/>
- **draft-ietf-lamps-pq-composite-kem**, whose section 9.2.3 states the
  tradeoff of omitting the ML-KEM ciphertext plainly: it "does not fully
  protect against implementation errors in the ML-KEM component", and was
  chosen "to increase performance".
  <https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-kem/>
- **RFC 10024**, *Post-Quantum Traditional (PQ/T) Hybrid Key Agreement
  Mechanisms for TLS 1.3*, August 2026, for how the same problem is solved
  when the combiner can live in a protocol transcript instead.
  <https://www.rfc-editor.org/rfc/rfc10024.html>

## Survey sources

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
