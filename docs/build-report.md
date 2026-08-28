# Build report

28 August 2026. Initial build of `hybrid-kem-combiner`, v0.1.0 in both
languages, unpublished.

## Status

DONE_WITH_CONCERNS. Everything asked for is built, tested and pushed. The
concerns are about what the artefact does and does not establish, not about
missing work. They are at the end.

## What was built

```text
rust/       the crate: no_std, forbid(unsafe_code), deny(missing_docs),
            MIT OR Apache-2.0, no allocator needed for the core
ts/         the npm package: ESM, typed, one runtime dependency
vectors/    15 positive and 4 negative cases, plus the generator
docs/       references.md and this report
```

The crate and the package live in subdirectories. A root `Cargo.toml` next to
a root `package.json` is a durable source of tooling confusion, and neither
publish step should have to be told to ignore the other language. `cargo
publish` runs in `rust/`, `npm publish` runs in `ts/`, and both reach the
shared vectors by relative path in tests only, never at build time.

## Design decisions worth recording

**Byte slices plus typed wrappers, not a trait over KEMs.** A `Kem` trait was
considered and rejected. Nothing in either ecosystem implements a common KEM
shape (`ml-kem`, `x25519-dalek`, `oqs`, `libcrux`, `@noble/post-quantum` and
WebCrypto all differ), so a trait would mean every user writing an adapter
before they could call a function that only ever needed six byte strings. It
would also pull key generation, encapsulation, an RNG and parameter sets into
a library that is a pure function of bytes. And it solves the wrong problem:
the realistic failure is not calling the wrong KEM, it is putting the right
bytes in the wrong position, since a swap of two same length inputs yields a
well formed key that silently disagrees with the peer. So the inputs are byte
slices in distinct newtypes (`SharedSecret`, `Ciphertext`, `EncapsulationKey`,
`Label`) inside a struct with named fields: no positional order to get wrong,
and no way to pass a ciphertext where a key belongs.

**Three KDFs, not two.** SHA3-256 and HKDF-SHA512 were required. HKDF turned
out to need splitting, because HKDF is not a plain hash: it has three input
positions and neither standard says which one the label belongs in.
draft-irtf-cfrg-hybrid-kems-12 requires only that an HKDF based KDF fully
specify salt, IKM, info and L, and that the mapping never let two inputs
collide. Both spellings are legitimate and they produce different keys, so
they are named separately (`HkdfSha512LabelAsInfo`, `HkdfSha512LabelInIkm`)
rather than one being picked silently.

**The HKDF domain separation condition is enforced, not assumed.**
draft-irtf-cfrg-hybrid-kems-12 section 6.1.5 says instantiations MUST ensure
`len(IKM)` differs from `len(info) + 1` and from `len(info) + 1 + 64`. Both
implementations check it and return a specific error. No other library found
in the survey does this.

**Nothing is concatenated.** The brief warned about the `Vec` reallocation
trap, where a growing buffer memcpys a prefix beginning with both raw shared
secrets into a new allocation and frees the old one uncleared. Rather than
allocating exact capacity, the combiner absorbs every input directly into the
hash or HMAC state, so the intermediate buffer does not exist at all. That is
strictly stronger than the exact capacity approach, and it is why the core
needs no allocator: `alloc` is a default-on feature covering only the
`*_to_vec` convenience helpers.

**The C2PRI gate.** In Rust,
`C2priAssertion::assert_pq_kem_is_ciphertext_second_preimage_resistant()`. In
TypeScript, `assertPqKemIsCiphertextSecondPreimageResistant()`. No `Default`,
no other constructor, and in TypeScript the brand is a module private symbol
so an object literal does not satisfy it. Long enough to be visible in review and greppable across a
codebase.

## Verification

Both suites run the same `vectors/hybrid-kem-combiner-v1.json`.

- Rust: 13 tests, all passing (`cargo test --all-features`). Clippy clean at
  `-D warnings`. Builds with `--no-default-features`. `cargo package`
  verification build succeeds.
- TypeScript: 10 tests, all passing (`npm test`), run against the built
  `dist/`, which is what npm publishes.

Two conformance cases are anchored outside this project, so they check
correctness and not merely self consistency:

- The three `xwing-draft-10` cases carry the shared secrets published in
  Appendix C of draft-connolly-cfrg-xwing-kem-10. The combiner inputs were
  recovered from that vector's own `seed` and `eseed` with an independent
  ML-KEM-768 and X25519 implementation, which also reproduced the draft's
  published `pk` and `ct` on the way. The C2PRI form with SHA3-256 reproduces
  the draft's `ss` exactly.
- The `interop-qk-password-manager-v1` case reproduces the value pinned by
  that project's unrelated Rust implementation of the universal form with
  HKDF-SHA512.

Beyond the committed vectors, a one off differential run appended 300
randomized cases (random form, random KDF, input lengths from 1 to 1568 bytes,
output lengths from 1 to 129 bytes) generated by the Python implementation,
and both suites were run against the enlarged file. All 315 cases matched in
all three implementations. The committed file was then restored.

## Publishing

Nothing was published. There are no credentials on this machine. Both
manifests are complete and packaging was exercised end to end.

```sh
# Rust, to crates.io
cd rust && cargo login && cargo publish

# TypeScript, to npm
cd ts && npm login && npm publish
```

`npm publish` needs no `--access public` flag: `publishConfig.access` is set
in `package.json`. `cargo package` and `npm pack --dry-run` were both run and
their contents inspected. The published crate excludes `tests/`, which reads
the shared vectors by a path that only exists in a checkout.

## Concerns

**The two implementations do produce identical bytes on every vector.** All 15
committed cases and all 4 negative cases agree, and so did the 300 randomized
differential cases across both forms, all three KDFs and a wide range of input
and output lengths. The agreement is genuine and not an artefact of one
implementation generating the other's expectations: the vectors come from a
third implementation written in Python from the standards text using only
`hashlib` and `hmac`, and two of the cases come from outside this project
entirely.

**The survey confirmed the gap claim, with two corrections.** No standalone
generic KEM combiner exists in either registry. Two details in the brief did
not survive checking, and both are recorded in the README rather than
smoothed over:

- The name `pq-kem-combiner` is already taken on crates.io. Version 0.0.1, 26
  January 2026, is three lines of documentation saying "Implementation coming
  soon", with no repository and no code. The name is claimed; the gap is not
  filled.
- `@noble/post-quantum` is more generic than "ships X-Wing as
  `ml_kem768_x25519`" suggests. It also exports `QSF()` and
  `createKitchenSink()`, which are parameterised over the component KEMs. They
  are still hybrid KEM factories rather than combiners: they build a whole KEM
  and require component KEMs implementing noble's object interface, and the
  combiner is an unexported closure. `KitchenSink`'s combiner is HKDF-SHA256
  with a `hybrid_prk` IKM prefix and a fixed `info`, so it is not byte
  compatible with `UniversalCombiner` either.

**One citation in the brief needed qualifying.** SP 800-227 puts the
expression `H(K1, K2, c1, c2, ek1, ek2, domain_sep)` in section 4.6.2 as
Expression (15), but the IND-CCA preservation argument, the name
`KeyCombine^CCA_H` and the encouragement to use such combiners are all in
section 4.6.3. Citing 4.6.2 for "IND-CCA preserving" is loose. Both sections
are cited where each belongs.

**The C2PRI form omits two inputs, not one.** The brief described it as
omitting the post-quantum ciphertext. draft-irtf-cfrg-hybrid-kems-12 section
5.1.3 defines `C2PRICombiner(ss_PQ, ss_T, ct_T, ek_T, label)`, which drops the
post-quantum encapsulation key as well, and X-Wing's combiner does the same.
The implementation follows the draft.

**The HKDF variants are the weakest part of the offering, and are documented
as such.** The SHA3-256 instantiation matches published instantiations byte
for byte, and its correctness is anchored by the X-Wing vectors. The HKDF
variants are fully specified and satisfy the conditions the CFRG draft names,
but the only published support for HKDF in the split-key PRF role that the
IND-CCA argument needs is a passing remark in ePrint 2025/1444, not a theorem
about a specific salt, IKM and info mapping. The README and the crate
documentation recommend SHA3-256 and say why.

**No external cryptographic review.** Stated in the README in its own section,
in both package READMEs, and in the crate's module documentation. The
construction is specified and its security property is attributed to peer
reviewed work; this implementation of it has been read by nobody outside this
project. Side channel behaviour is unexamined, and the TypeScript package's
memory hygiene is best effort because in that runtime it cannot be more.

**Vector regeneration is checked but not enforced offline.** CI re-runs the
generator and diffs the result, so a hand edit to the JSON fails the build. A
local commit can still bypass it.
