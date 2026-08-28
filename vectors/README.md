# Conformance vectors

`hybrid-kem-combiner-v1.json` is the interop contract between the Rust crate
and the TypeScript package. Both run every case in it. An implementation in
any other language that reproduces every value here implements the same
combiner.

Nothing in this directory requires Rust or JavaScript to consume. Every value
is hex.

## Files

| File | What it is |
| --- | --- |
| `hybrid-kem-combiner-v1.json` | The vectors. Generated. |
| `generate.py` | The generator, and deliberately a third implementation. |
| `qk-password-manager-ek-pq.hex` | The 1568 byte ML-KEM-1024 encapsulation key of the interoperability case, kept out of the generator so the generator stays readable. |

Regenerate with `python3 vectors/generate.py`. It depends on nothing outside
the Python standard library.

## Why the generator is a third implementation

The vectors are not dumped from the Rust crate. `generate.py` implements
HKDF-Extract, HKDF-Expand and the combiner from the standards text using only
`hashlib` and `hmac`, so a bug would have to occur independently in three
implementations built on three sets of primitives (RustCrypto, `@noble/hashes`
and CPython's OpenSSL bindings) before it could hide.

Two cases go further and are anchored outside this project entirely. The
generator **asserts** against those published values rather than recording
whatever it computed, so if the construction were wrong the generator would
fail rather than produce a self consistent lie:

- `c2pri/sha3-256/xwing-draft-10-vector-{1,2,3}`. The `output` is the shared
  secret published in Appendix C of draft-connolly-cfrg-xwing-kem-10. The four
  combiner inputs are the intermediates of that vector's own `seed` and
  `eseed`, recovered with an independent ML-KEM-768 and X25519 implementation
  (`@noble/post-quantum` 0.7.1), which also reproduced the draft's published
  `pk` and `ct` on the way. The C2PRI form with SHA3-256 and the six byte
  X-Wing label **is** the X-Wing combiner.
- `universal/hkdf-sha512-label-as-info/interop-qk-password-manager-v1`. The
  `output` is the value pinned by `qk-password-manager`'s own conformance
  vectors, produced by an unrelated Rust implementation of this same
  construction on ML-KEM-1024 plus X25519.

Every other case is a regression pin: it proves the construction has not
changed, not that it is sound.

## The two forms

```text
universal:  KDF(ss_PQ || ss_T || ct_PQ || ct_T || ek_PQ || ek_T || label)
c2pri:      KDF(ss_PQ || ss_T ||          ct_T ||          ek_T || label)
```

Inputs are concatenated in exactly that order, with **no length prefixes and
no separators**. The C2PRI form omits both the post-quantum ciphertext and the
post-quantum encapsulation key, not the ciphertext alone.

## The three KDFs

| `kdf` | Definition |
| --- | --- |
| `sha3-256` | `SHA3-256(inputs \|\| label)`. Exactly 32 bytes out. |
| `hkdf-sha512-label-as-info` | HKDF-SHA512. `salt` absent, `ikm` the concatenated inputs **without** the label, `info` the label, `L` = `output_length`. |
| `hkdf-sha512-label-in-ikm` | HKDF-SHA512. `salt` absent, `ikm` the concatenated inputs **with** the label appended, `info` empty, `L` = `output_length`. |

## Conventions that silently produce wrong output

Details that no value in this file reveals on its own, and that a
reimplementation can get wrong while still producing a well formed 32 byte
key. Each one changes bytes without changing shape, so the failure looks like
a mismatched vector with no other clue.

- **The HKDF salt is absent, not empty.** RFC 5869 defines an absent salt as
  `HashLen` zero bytes, which for HKDF-SHA512 is 64 zero bytes, not a zero
  length string. The two produce different pseudorandom keys. Every HKDF case
  here uses the absent salt.
- **The label is the last thing hashed, when it is hashed at all.** Under
  `sha3-256` and `hkdf-sha512-label-in-ikm` it is appended to the inputs.
  Under `hkdf-sha512-label-as-info` it is not in the hashed material at all:
  it is HKDF's `info` argument and reaches HMAC in the expand step. That is
  why the same six inputs give three different keys.
- **Every value is hex, including `label`.** It is not a plain string, even
  though most of the labels here decode to readable ASCII.
- **`output_length` is not always 32.** One HKDF case asks for 64 bytes, which
  spans two HKDF-Expand blocks. Its first 32 bytes equal the 32 byte case's
  output, because HKDF-Expand's first block does not depend on `L`. That is
  correct, not a duplicated vector.

## Case fields

```text
name             stable identifier: form/kdf/description
form             "universal" or "c2pri"
kdf              one of the three above
inputs           every input, hex, keyed by its name in the standards
input_lengths    the same, in bytes, so a truncation is obvious
intermediates    see below
output_length    bytes of key requested
output           the key, hex
note             what this case is for
```

### Intermediates, and why they are published

`intermediates.kdf_input_hex` is the exact byte string absorbed by the KDF. On
the HKDF cases there are also `hkdf_ikm_hex`, `hkdf_info_hex`, `hkdf_salt` and
`hkdf_prk_hex`.

An opaque terminal key alone cannot tell you which stage is wrong. With these,
each stage is independently checkable:

- your `kdf_input_hex` differs: the input order, the set of inputs, or the
  label placement is wrong
- `kdf_input_hex` matches but `hkdf_prk_hex` differs: the extract step is
  wrong, and the salt is the usual reason
- both match but `output` differs: the expand step or the output length
  handling is wrong

This is the same principle the `qk-password-manager` vectors README argues for
when it publishes `public_keys` and `bundle_encoding` alongside an opaque
commitment.

## Coverage

15 positive cases:

- both forms, all three KDFs
- ML-KEM-768 plus X25519 sizes, and ML-KEM-1024 plus X448 sizes, so an
  implementation that assumes a 32 byte traditional half fails
- single byte inputs, all distinct, so a dropped or reordered input cannot
  survive
- a 64 byte output
- **an all zero degenerate case**, under SHA3-256 and under HKDF. Every input
  is zero bytes. An implementation that drops an input entirely, or treats an
  all zero input as absent, passes every other case and fails this one. Under
  HKDF it also pins that the all zero absent salt and the all zero IKM are not
  conflated.
- the four external interoperability cases described above

4 negative cases, in `negative_cases`, which every implementation must refuse.
They carry an `error` field instead of an `output`:

| `error` | Why |
| --- | --- |
| `empty-input` | A zero length input is a dropped value. Twice: once for a shared secret, once for the label. |
| `unsupported-output-length` | SHA3-256 asked for 64 bytes. Truncating or extending silently would be worse than refusing. |
| `hkdf-domain-separation` | `ikm_len == info_len + 1`, which draft-irtf-cfrg-hybrid-kems-12 section 6.1.5 says instantiations MUST refuse. |

## Changing this file

A change here is a wire format break for anyone who has stored a combined key
derived from these rules. Regenerate deliberately, bump the version in the
filename, and say so.
