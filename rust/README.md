# hybrid-kem-combiner

A generic, standalone hybrid KEM combiner.

When you build a hybrid KEM you run two independent key encapsulation
mechanisms, one post-quantum and one traditional, and you end up holding two
shared secrets. The combiner turns them into the one key you actually use. It
is the only place in a hybrid where "if either component is secure, the whole
thing is secure" is either achieved or lost.

This crate implements the construction that carries that guarantee, and
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

## Usage

```rust
use hybrid_kem_combiner::{
    combine_universal, Ciphertext, EncapsulationKey, Kdf, Label, SharedSecret,
    UniversalInputs,
};

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

The C2PRI optimised form, which omits the post-quantum ciphertext and
encapsulation key, is [`combine_c2pri`]. It is only sound for a post-quantum
KEM that is ciphertext second preimage resistant, so it requires a
[`C2priAssertion`] constructed by name. Read its documentation first.

## Features

- `alloc` (default): the `combine_*_to_vec` helpers, which return
  `Zeroizing<Vec<u8>>`. The core combiner needs no allocator: inputs are
  absorbed straight into the hash or HMAC state and nothing is concatenated
  into an intermediate buffer.

## Interoperability

Byte for byte identical to the npm package
`@quantakrypto/hybrid-kem-combiner`. Both are tested against the same
conformance vectors, which live in the repository at `vectors/`.

Full documentation, the survey of what else exists, and the argument for when
each form and each KDF is appropriate are in the
[repository README](https://github.com/quantakrypto/hybrid-kem-combiner).

## Licence

MIT or Apache-2.0, at your option.
