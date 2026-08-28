# @quantakrypto/hybrid-kem-combiner

A generic, standalone hybrid KEM combiner.

When you build a hybrid KEM you run two independent key encapsulation
mechanisms, one post-quantum and one traditional, and you end up holding two
shared secrets. The combiner turns them into the one key you actually use. It
is the only place in a hybrid where "if either component is secure, the whole
thing is secure" is either achieved or lost.

This package implements the construction that carries that guarantee, and
nothing else. It does no key generation, no encapsulation and no
decapsulation: it takes the byte strings a hybrid KEM already has, over
whatever pair of KEMs you are using.

```text
UniversalCombiner(ss_PQ, ss_T, ct_PQ, ct_T, ek_PQ, ek_T, label)
    = KDF(ss_PQ || ss_T || ct_PQ || ct_T || ek_PQ || ek_T || label)
```

- **NIST SP 800-227** (final, September 2025), section 4.6.2, Expression (15),
  with the IND-CCA preservation argument in section 4.6.3
- **draft-irtf-cfrg-hybrid-kems-12**, section 5.1.3, `UniversalCombiner`

## Status

This implements a specified construction. **The implementation itself has had
no external cryptographic review.** Conformance is checked against external
anchors: three of the shared conformance vectors are the shared secrets
published in Appendix C of draft-connolly-cfrg-xwing-kem-10, which the C2PRI
form with SHA3-256 reproduces exactly.

## Install

```sh
npm install @quantakrypto/hybrid-kem-combiner
```

ESM only. One runtime dependency, `@noble/hashes`, for HKDF and SHA-3.
Primitives are not hand rolled here.

## Usage

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

The C2PRI optimised form, which omits the post-quantum ciphertext and
encapsulation key, is `combineC2pri`. It is only sound for a post-quantum KEM
that is ciphertext second preimage resistant, so it requires an assertion
obtained from `assertPqKemIsCiphertextSecondPreimageResistant()`. Read that
function's documentation first.

Three KDFs, chosen explicitly at every call site: `sha3-256` (what X-Wing and
the published instantiations use, and the one to pick for interoperability),
`hkdf-sha512-label-as-info` and `hkdf-sha512-label-in-ikm`.

## Interoperability

Byte for byte identical to the Rust crate `hybrid-kem-combiner`. Both are
tested against the same conformance vectors, which live in the repository at
`vectors/`.

Full documentation, the survey of what else exists, and the argument for when
each form and each KDF is appropriate are in the
[repository README](https://github.com/quantakrypto/hybrid-kem-combiner).

## Licence

MIT or Apache-2.0, at your option.
