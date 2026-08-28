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
form with SHA3-256 reproduces exactly, and the three CFRG suites are checked
against all thirty test vectors published in Appendix B of
draft-irtf-cfrg-concrete-hybrid-kems-04.

## Install

```sh
npm install @quantakrypto/hybrid-kem-combiner
```

ESM only. Three runtime dependencies: `@noble/hashes` for HKDF, SHA-3 and
SHAKE, and `@noble/curves` and `@noble/post-quantum` for the suites. No
primitive is hand rolled here.

If you only want the combiner you still install all three, because npm cannot
make a subpath's dependencies conditional the way a Cargo feature can. A
bundler will drop the two suite dependencies if `./suites` is never imported.

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

## Complete hybrid KEM suites

`@quantakrypto/hybrid-kem-combiner/suites` ships four complete hybrid KEMs:
key generation, encapsulation and decapsulation as one primitive, layered on
the combiner. **They are not all the same kind of thing.**

| Suite | Specified by | External test vectors |
| --- | --- | --- |
| `MLKEM768_P256` | CFRG, draft-irtf-cfrg-concrete-hybrid-kems-04 section 4.1 | **Yes**, the draft's Appendix B |
| `MLKEM768_X25519` | CFRG, section 4.2, identical to X-Wing | **Yes**, the draft's Appendix B |
| `MLKEM1024_P384` | CFRG, section 4.3 | **Yes**, the draft's Appendix B |
| `MLKEM1024_X25519` | **This project, and nobody else** | **No, and none can exist** |

All thirty of the draft's published vectors pass, and the three CFRG suites are
additionally checked against `@noble/post-quantum`'s independent
implementations of the same three specifications, in both directions of
decapsulation. `MLKEM1024_X25519` is specified in `docs/mlkem1024-x25519.md` in
the repository, which argues the case against it as well as the case for it,
and its vectors are regression pins rather than an external anchor.
`suite.provenance` carries the distinction at runtime.

```ts
import { MLKEM768_X25519 } from '@quantakrypto/hybrid-kem-combiner/suites';

const recipient = MLKEM768_X25519.generateKeyPair();
const sent = MLKEM768_X25519.encapsulate(recipient.encapsulationKey);
const received = MLKEM768_X25519.decapsulate(
  recipient.decapsulationKey,
  sent.ciphertext,
);
```

## Interoperability

Byte for byte identical to the Rust crate `hybrid-kem-combiner`. Both are
tested against the same conformance vectors, which live in the repository at
`vectors/`.

Full documentation, the survey of what else exists, and the argument for when
each form and each KDF is appropriate are in the
[repository README](https://github.com/quantakrypto/hybrid-kem-combiner).

## Licence

MIT or Apache-2.0, at your option.
