# hybrid-kem-combiner

A generic, standalone hybrid KEM combiner, in Rust and TypeScript, tested
against one shared set of conformance vectors.

- Rust crate: [`hybrid-kem-combiner`](rust/) (`no_std`, no allocator required)
- npm package: [`@quantakrypto/hybrid-kem-combiner`](ts/) (ESM, one dependency)
- Vectors: [`vectors/`](vectors/), consumed by both

## What a KEM combiner is, and why it carries the whole guarantee

A hybrid KEM runs two independent key encapsulation mechanisms, one
post-quantum and one traditional, and derives one shared secret from both. The
point of running two is that one of them may turn out to be broken, by
cryptanalysis or by an implementation flaw, and the other should still carry
the session.

The **combiner** is the function that turns the two component outputs into the
one secret that is actually used. It is the only place where "either one being
secure is enough" is either achieved or lost. Nothing else in the hybrid
provides that property: the post-quantum KEM does not, the traditional KEM does
not, and the AEAD that consumes the output certainly does not. If the combiner
is wrong, the hybrid degrades to the security of whichever component happens to
be weaker, which is the exact opposite of the design intent.

This is not a theoretical worry. NIST SP 800-227 section 4.6.3 states it
plainly: the obvious combiner `K <- KDF(K1, K2)`, over the two shared secrets
alone, "does not preserve IND-CCA security, regardless of the properties of the
KDF". A broken second component can destroy IND-CCA for the whole hybrid even
when the first component is perfectly sound. The combiner has to bind more than
the two secrets, which is what the construction below does.

## The construction

```text
UniversalCombiner(ss_PQ, ss_T, ct_PQ, ct_T, ek_PQ, ek_T, label)
    = KDF(ss_PQ || ss_T || ct_PQ || ct_T || ek_PQ || ek_T || label)
```

Two standards documents specify exactly this shape.

**NIST SP 800-227**, *Recommendations for Key-Encapsulation Mechanisms*, final,
September 2025. Section 4.6.2, Expression (15), defines

```text
KeyCombine(K1, K2, c1, c2, ek1, ek2, p) := H(K1, K2, c1, c2, ek1, ek2, domain_sep)
```

and section 4.6.3 names the same function `KeyCombine^CCA_H`, with `H` "a hash
function from the SHA-3 family", and says: "NIST encourages the use of key
combiners that generically preserve IND-CCA security, in the sense that the
combined scheme is IND-CCA, provided at least one of the ingredient KEMs is
IND-CCA. One example of such a key combiner is as in (15)." The IND-CCA
preserving property is attributed to Giacon, Heuer and Poettering (PKC 2018),
and the document notes that including the encapsulation keys, which that paper
does not, "can have other potential advantages in secure protocols, such as
binding the final shared secret to the identities of the participating
parties".

Worth being precise about, because it is easy to cite loosely: the expression
lives in 4.6.2 and the IND-CCA preservation argument lives in 4.6.3.

**draft-irtf-cfrg-hybrid-kems-12**, 6 July 2026, section 5.1.3, defines

```text
def UniversalCombiner(ss_PQ, ss_T, ct_PQ, ct_T, ek_PQ, ek_T, label):
    return KDF(concat(ss_PQ, ss_T, ct_PQ, ct_T, ek_PQ, ek_T, label))
```

with the note that it "allows the resulting hybrid KEM to be secure as long as
either component is secure, with no further assumptions on the components".

Both citations were checked against the primary documents, not against
secondary sources. See [`docs/references.md`](docs/references.md).

## The gap this fills

The construction is specified. What did not exist, in either the Rust or the
JavaScript ecosystem, is a **generic, standalone implementation of it**: one
that takes six byte strings and a label and gives you the combined key, over
whatever pair of KEMs you are actually using.

Survey as of 28 August 2026:

| Where | What exists | Why it is not this |
| --- | --- | --- |
| crates.io | `x-wing` 0.1.0 | X-Wing at draft 06, hardwired to ML-KEM-768 plus X25519. A whole KEM, not a combiner. |
| crates.io | `rxwing` 0.1.0-draft10 | Same, at draft 10. |
| crates.io | `pq-kem-combiner` 0.0.1 | The name is taken. The crate is three lines of documentation saying "Implementation coming soon", with no repository and no code. |
| crates.io | `hpke`, `hpke-ng` | RFC 9180 HPKE. Where a hybrid KEM appears it is an HPKE KEM id, usable only inside HPKE. |
| crates.io | `dcrypt-hybrid`, `saorsa-pqc`, `mlkem-tls` and similar | Library internal hybrid schemes with the combiner welded to one KEM pair and not exposed. |
| npm | `@noble/post-quantum` 0.7.1 | The closest thing that exists. `QSF()` and `createKitchenSink()` are parameterised over the component KEMs, so this is more generic than it is usually given credit for. But they are hybrid KEM factories: they build a whole KEM and require component KEMs implementing noble's own object interface, and the combiner itself is a closure that is never exported. You cannot call it on bytes you already have. `KitchenSink`'s combiner is also HKDF-SHA256 with a `hybrid_prk` prefix and a fixed `info`, so it is not byte compatible with the standards' `UniversalCombiner`. |
| npm | `@hpke/hybridkem-x-wing`, `@hpke/ml-kem` | HPKE bound, same as the Rust HPKE crates. |
| npm | `xwing-wasm`, `ts-mls`, `mlkem` | Fixed suites or whole protocols. |
| npm | searches for "kem combiner" | Nothing. The hits are stream combiners and Salesforce manifest tools. |

So the gap claim holds, with one correction and one caveat worth stating
plainly rather than hiding: the crate name `pq-kem-combiner` is already taken on
crates.io by an empty placeholder, and `@noble/post-quantum` is closer to
generic than "ships X-Wing" suggests. Neither gives you a combiner you can call
on byte strings.

## What is and is not reviewed

**This implements a specified construction. The implementation itself has had
no external cryptographic review.** No cryptographer outside this project has
read this code.

What that leaves you with, stated honestly:

- The **construction** is standardised and its IND-CCA preservation is
  attributed in SP 800-227 to a peer reviewed result (Giacon, Heuer and
  Poettering, PKC 2018). That is not this project's work and does not depend on
  this project being correct.
- The **conformance** of this code to that construction is checked against
  external anchors, not only against itself. Three of the vectors are the
  shared secrets published in Appendix C of draft-connolly-cfrg-xwing-kem-10,
  reproduced here by the C2PRI form with SHA3-256. One vector is the value
  pinned independently by `qk-password-manager`'s unrelated Rust
  implementation of the universal form with HKDF-SHA512. Those cases would
  fail if the input order, the KDF mapping or the label placement were wrong.
- What is **not** established: that this code is free of side channels, that
  its zeroization is complete in the presence of an optimising compiler or a
  moving garbage collector, or that the HKDF instantiations (as opposed to the
  SHA3-256 one, which matches published instantiations byte for byte) sit
  correctly in the split-key PRF role the security argument needs. The last of
  those is an open question about the construction, not about this code, and
  it is why [`Kdf::Sha3_256`](rust/src/kdf.rs) is the default recommendation.

If you are deploying this where it matters, commission a review. If you do,
please open an issue with the outcome.

## Which form to use

### Universal (`combine_universal` / `combineUniversal`)

Binds all six values. Preserves IND-CCA as long as at least one component KEM
is IND-CCA, **with no further assumption about either component**. Use this
unless you have a specific reason not to.

### C2PRI (`combine_c2pri` / `combineC2pri`)

```text
C2PRICombiner(ss_PQ, ss_T, ct_T, ek_T, label)
    = KDF(ss_PQ || ss_T || ct_T || ek_T || label)
```

Omits the post-quantum ciphertext and encapsulation key
(draft-irtf-cfrg-hybrid-kems-12 section 5.1.3). For ML-KEM-1024 that is 1568
plus 1568 bytes that never have to be hashed, which is a real saving on a
constrained device or a hot path. The resulting hybrid KEM is secure if the
post-quantum component is IND-CCA, or if the traditional component is secure
**and the post-quantum component is C2PRI**.

Ciphertext second preimage resistance means: given an honest key pair,
ciphertext and shared secret, no adversary can find a second ciphertext that
decapsulates to the same shared secret. ML-KEM is believed to have it, and the
reason is specific: it comes from the Fujisaki-Okamoto transform ML-KEM is
built with, not from anything general about lattice KEMs.

**The caveat, verbatim from draft-connolly-cfrg-xwing-kem-10 section 6:**

> The security of X-Wing relies crucially on the specifics of the
> Fujisaki-Okamoto transformation used in ML-KEM-768: the X-Wing combiner
> cannot be assumed to be secure, when used with different KEMs. In particular
> it is not known to be safe to leave out the post-quantum ciphertext from the
> combiner in the general case.

Read that carefully. It says *different KEMs*, not different parameter sets of
ML-KEM: draft-irtf-cfrg-concrete-hybrid-kems applies the C2PRI combiner to
ML-KEM-1024, and the LAMPS composite KEMs omit the ML-KEM ciphertext at 768 and
1024 alike. So the optimisation is available across ML-KEM parameter sets. It
is not available for an arbitrary post-quantum KEM, and this library is generic
over the KEM pair, so it cannot know which you have.

draft-ietf-lamps-pq-composite-kem is candid about what you are buying, in
section 9.2.3: omitting the ML-KEM ciphertext "makes a fundamental assumption
on ML-KEM remaining ciphertext second pre-image resistant, and therefore this
formulation of KEM combiner does not fully protect against implementation
errors in the ML-KEM component", and the choice was made "to increase
performance".

Because choosing it wrongly is a real security error and not a style
preference, reaching the C2PRI form requires stating the assumption by name:

```rust
assertion: C2priAssertion::assert_pq_kem_is_ciphertext_second_preimage_resistant()
```

```ts
assertion: assertPqKemIsCiphertextSecondPreimageResistant()
```

There is no other constructor, no `Default`, and in TypeScript the brand is a
module private symbol, so an object literal will not do. It is deliberately
long enough to be seen in a code review and greppable across a codebase.

With SHA3-256 and the six byte X-Wing label, the C2PRI form **is** the X-Wing
combiner, byte for byte, and the vectors prove it against the draft's own test
vectors.

## Choosing a KDF

The KDF is a parameter at every call site, never a default, because two
implementations that agree on the construction and disagree on the KDF produce
different keys and no diagnosable error.

| Name | Definition | Notes |
| --- | --- | --- |
| `Sha3_256` / `sha3-256` | `SHA3-256(inputs \|\| label)` | Exactly 32 bytes out. What X-Wing, draft-irtf-cfrg-concrete-hybrid-kems and the LAMPS composite KEMs use, and the family SP 800-227 names in its worked example. **Use this if you want to interoperate with anything published.** |
| `HkdfSha512LabelAsInfo` / `hkdf-sha512-label-as-info` | HKDF-SHA512, salt absent, `ikm` the inputs without the label, `info` the label | The idiomatic HKDF spelling, domain separation in `info`. |
| `HkdfSha512LabelInIkm` / `hkdf-sha512-label-in-ikm` | HKDF-SHA512, salt absent, `ikm` the inputs with the label appended, `info` empty | The literal reading of `KDF(concat(..., label))`. |

Two HKDF variants exist because HKDF is not a plain hash: it has three input
positions and the standards do not say which one the label belongs in.
draft-irtf-cfrg-hybrid-kems-12 requires only that an HKDF based KDF "MUST fully
specify HKDF's salt, IKM, info, and L arguments" and that the mapping never let
two inputs collide. Both variants here are fully specified and non-colliding.
They are not interchangeable, and picking the wrong one is exactly the silent
mismatch that naming them separately prevents.

"Salt absent" is RFC 5869's absent salt, which HKDF-Extract replaces with
`HashLen` zero bytes, so 64 zero bytes here. It is not a zero length salt, and
the two produce different keys.

Both libraries **enforce**, rather than assume, the HKDF input domain
disjointness condition of draft-irtf-cfrg-hybrid-kems-12 section 6.1.5:
`len(IKM)` must differ from `len(info) + 1` and from `len(info) + 1 + 64`. The
draft says concrete instantiations MUST enforce it. A violation is refused with
a specific error rather than silently derived.

## Input encoding, and the one thing this library cannot check for you

The inputs are concatenated with no length prefixes and no separators, because
that is what the standards specify and what interoperability requires.

SP 800-227 section 4.6.2 warns that `H(x, y)` is only safely rendered as
`H(x || y)` when the encoding fixes the lengths, since otherwise
`x || y = x' || y'` for different pairs. Real KEMs have fixed output lengths
per parameter set, so the encoding is unambiguous **as long as the label
uniquely identifies the parameter sets of both components**, which is exactly
what SP 800-227 asks of `domain_sep` ("uniquely identify the composite scheme
in use") and what the CFRG draft asks of `label`.

A label that does not pin both parameter sets is a real error, and no library
that is generic over the KEM pair can detect it. Pick something like
`example.org/v1/ml-kem-768+x25519` rather than `v1`.

## Worked example

### Rust

```toml
[dependencies]
hybrid-kem-combiner = "0.1"
```

```rust
use hybrid_kem_combiner::{
    combine_universal, Ciphertext, EncapsulationKey, Kdf, Label, SharedSecret,
    UniversalInputs,
};

// Whatever your two KEMs produced. This library does not run them:
// ss_pq, ct_pq, ek_pq come from your ML-KEM encapsulation, and
// ss_t, ct_t, ek_t from your X25519 exchange, as plain byte slices.
let inputs = UniversalInputs {
    pq_shared_secret: SharedSecret::new(&ss_pq),
    traditional_shared_secret: SharedSecret::new(&ss_t),
    pq_ciphertext: Ciphertext::new(&ct_pq),
    traditional_ciphertext: Ciphertext::new(&ct_t),
    pq_encapsulation_key: EncapsulationKey::new(&ek_pq),
    traditional_encapsulation_key: EncapsulationKey::new(&ek_t),
    label: Label::new(b"example.org/v1/ml-kem-768+x25519"),
};

let mut key = [0u8; 32];
combine_universal(Kdf::Sha3_256, &inputs, &mut key)?;
```

### TypeScript

```sh
npm install @quantakrypto/hybrid-kem-combiner
```

```ts
import { combineUniversal } from '@quantakrypto/hybrid-kem-combiner';

const key = combineUniversal('sha3-256', {
  pqSharedSecret: ssPq,
  traditionalSharedSecret: ssT,
  pqCiphertext: ctPq,
  traditionalCiphertext: ctT,
  pqEncapsulationKey: ekPq,
  traditionalEncapsulationKey: ekT,
  label: new TextEncoder().encode('example.org/v1/ml-kem-768+x25519'),
});
```

Both produce the same 32 bytes. That is the point of the vectors.

## API shape, and why it is not a trait over KEMs

The obvious alternative was a `Kem` trait, with the combiner generic over two
implementations of it. It was rejected, for three reasons.

1. **Nothing implements it.** `ml-kem`, `x25519-dalek`, `oqs`, `libcrux`,
   `@noble/post-quantum` and the WebCrypto surface all have different KEM
   shapes. A trait would mean every user writing an adapter before they could
   use a function that only ever needed six byte strings.
2. **It would drag in what a combiner has no business owning.** Key generation,
   encapsulation, an RNG, error types, parameter sets. The combiner is a pure
   function of bytes that already exist. Anything more is scope this library
   would then have to be trusted with.
3. **It solves the wrong problem.** The realistic failure mode is not calling
   the wrong KEM. It is passing the right bytes in the wrong position, and a
   swap of two same length inputs produces a well formed key that silently
   disagrees with the peer.

So the inputs are byte slices, wrapped in distinct newtypes (`SharedSecret`,
`Ciphertext`, `EncapsulationKey`, `Label`) and carried in a struct with named
fields. You cannot pass a ciphertext where an encapsulation key belongs, and
there is no positional order to get wrong. `SharedSecret`'s `Debug` redacts
itself, so a secret does not reach a log by accident.

## Zeroization

The combiner never copies its inputs into a heap buffer. Every input is
absorbed directly into the hash or HMAC state, so there is no concatenated
copy of the shared secrets to leak through a reallocated or freed `Vec`, which
is the classic trap in this construction: a growing `Vec` memcpys its prefix,
which begins with both raw shared secrets, into a new allocation and frees the
old one without clearing it.

Intermediates this library does own (the HKDF pseudorandom key, the SHA3
digest) are zeroized before they are dropped. `combine_universal_to_vec` and
`combine_c2pri_to_vec` return `Zeroizing<Vec<u8>>`.

What is not promised: the internal state of `sha2`, `sha3`, `hkdf` and
`@noble/hashes`, the output buffer you supply, and anything a JavaScript engine
copies while garbage collecting. Treat the TypeScript package's memory hygiene
as best effort, because in that runtime it cannot be more than that.

## Conformance vectors

[`vectors/hybrid-kem-combiner-v1.json`](vectors/hybrid-kem-combiner-v1.json) is
language agnostic and is run by **both** implementations. It publishes the
intermediate values, not just the final key, so a mismatch is diagnosable:
`kdf_input_hex` is the exact byte string absorbed, and the HKDF cases also
publish the pseudorandom key. If your output is wrong and your `kdf_input_hex`
is right, the fault is in the KDF, and the other way around.

Coverage: both forms, all three KDFs, realistic ML-KEM-768 plus X25519 and
ML-KEM-1024 plus X448 sizes, single byte inputs, a 64 byte output that spans
two HKDF blocks, an all zero degenerate case, the three X-Wing interoperability
cases, the `qk-password-manager` interoperability case, and four negative cases
that must be refused. See [`vectors/README.md`](vectors/README.md).

## Repository layout

```text
rust/      the Rust crate
ts/        the npm package
vectors/   the shared conformance vectors and their generator
docs/      references and the build report
```

The crate and the package live in subdirectories rather than at the root
because a root `Cargo.toml` and a root `package.json` in one repository is a
long running source of tooling confusion, and because neither language's
publish step should have to be told to ignore the other's. `cargo publish` runs
in `rust/` and `npm publish` runs in `ts/`; both reach the vectors by relative
path in tests only, never at build time.

## Licence

MIT or Apache-2.0, at your option.
