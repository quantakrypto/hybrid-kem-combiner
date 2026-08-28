//! Generate `vectors/x25519-degenerate-v1.json`.
//!
//! ```sh
//! cd rust && cargo run --features suites --example generate_x25519_degenerate_vectors
//! ```
//!
//! These are **adversarial inputs, not conformance vectors**, and they live
//! in their own file for that reason. Every case here supplies a group
//! element that no honest peer would ever send: one of the five Curve25519
//! u-coordinates whose `X25519` output is the all-zero string. A
//! reimplementer reading `concrete-hybrid-kems-04-appendix-b.json` is reading
//! the specification's own vectors and should not have to sort the normative
//! cases from the hostile ones, so nothing hostile was added there.
//!
//! What this file pins is the behaviour of
//! `draft-connolly-cfrg-xwing-kem-10` sections 5.4 and 5.5 and of
//! `docs/mlkem1024-x25519.md` section 3.7: the all-zero `X25519` output is
//! **not** rejected, it is fed to the combiner like any other. An
//! implementation that rejects it, or that substitutes anything other than 32
//! zero bytes for `ss_T`, fails every case here and passes every case in the
//! other two files. That is exactly the gap this file exists to close, and it
//! is the gap through which this project's TypeScript package once diverged
//! from X-Wing.
//!
//! The two suites covered are the two that use the Curve25519 nominal group.
//! `MLKEM768-X25519` is X-Wing, so its rows are a claim about a CFRG
//! specified suite; `MLKEM1024-X25519` is this project's own, so its rows are
//! a claim about `docs/mlkem1024-x25519.md`. The P-256 and P-384 suites have
//! no analogue: their groups have cofactor 1, the identity is the only
//! element a scalar multiplication could degenerate to, and the identity has
//! no uncompressed SEC1 encoding to send.

use hybrid_kem_combiner::suites::Suite;

const SUITES: [Suite; 2] = [Suite::MlKem768X25519, Suite::MlKem1024X25519];

/// The five u-coordinates whose `X25519` output is 32 zero bytes, with the
/// order of the corresponding point and which curve it lies on.
///
/// The list is complete. X-only doubling sends `u` to
/// `(u^2 - 1)^2 / 4u(u^2 + Au + 1)`, so order dividing 2 needs
/// `4u(u^2 + Au + 1) = 0`, and `A^2 - 4` is a non-residue mod `p`, leaving
/// `u = 0`; order dividing 4 additionally needs `(u^2 - 1)^2 = 0`, giving
/// `1` and `p - 1`; order dividing 8 additionally needs `dbl(u)` to be `1` or
/// `p - 1`, and over `F_p` the first quartic has exactly the two roots below
/// while the second has none. Curve25519 has cofactor 8 and its twist
/// cofactor 4, so no point of larger order can be sent to zero by an
/// RFC 7748 clamped scalar: such a scalar is `8m` with
/// `2^251 <= m < 2^252`, smaller than either prime subgroup order and so
/// never a multiple of one.
const DEGENERATE_U: [(&str, &str, u32, &str); 5] = [
    (
        "zero",
        "0000000000000000000000000000000000000000000000000000000000000000",
        2,
        "curve and twist",
    ),
    (
        "one",
        "0100000000000000000000000000000000000000000000000000000000000000",
        4,
        "curve",
    ),
    (
        "p-minus-one",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        4,
        "twist",
    ),
    (
        "order-eight-a",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        8,
        "curve",
    ),
    (
        "order-eight-b",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        8,
        "curve",
    ),
];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

fn main() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../vectors/x25519-degenerate-v1.json"
    );

    let mut cases = String::new();
    let mut first = true;
    for suite in SUITES {
        let nelem = 32;
        let nek_pq = suite.nek() - nelem;
        let nct_pq = suite.nct() - nelem;

        for (index, (u_name, u_hex, _, _)) in DEGENERATE_U.iter().enumerate() {
            let seed = vec![index as u8; suite.nseed()];
            let randomness = vec![0x64u8.wrapping_add(index as u8); suite.nrandom()];
            let u = unhex(u_hex);

            let key_pair = suite.derive_key_pair(&seed).expect("key generation");
            let honest = suite
                .encapsulate_derand(key_pair.encapsulation_key(), &randomness)
                .expect("honest encapsulation");

            // Encapsulation against an attacker-chosen ek_T.
            let mut hostile_ek = key_pair.encapsulation_key().to_vec();
            hostile_ek[nek_pq..].copy_from_slice(&u);
            let encapsulated = suite
                .encapsulate_derand(&hostile_ek, &randomness)
                .expect("encapsulation must not reject a degenerate ek_T");

            // Decapsulation of an attacker-chosen ct_T.
            let mut hostile_ct = honest.ciphertext().to_vec();
            hostile_ct[nct_pq..].copy_from_slice(&u);
            let decapsulated = suite
                .decapsulate(key_pair.decapsulation_key(), &hostile_ct)
                .expect("decapsulation must not reject a degenerate ct_T");

            if !first {
                cases.push_str(",\n");
            }
            first = false;
            cases.push_str(&format!(
                r#"    {{
      "suite": "{suite}",
      "name": "{suite}/degenerate-{u_name}",
      "u_name": "{u_name}",
      "u": "{u}",
      "seed": "{seed}",
      "randomness": "{randomness}",
      "encapsulation_key": "{ek}",
      "encapsulation_shared_secret": "{enc_ss}",
      "decapsulation_shared_secret": "{dec_ss}"
    }}"#,
                suite = suite.name(),
                u_name = u_name,
                u = u_hex,
                seed = hex(&seed),
                randomness = hex(&randomness),
                ek = hex(key_pair.encapsulation_key()),
                enc_ss = hex(encapsulated.shared_secret()),
                dec_ss = hex(decapsulated.as_slice()),
            ));
        }
    }

    let mut coordinates = String::new();
    for (index, (name, u, order, lies_on)) in DEGENERATE_U.iter().enumerate() {
        if index > 0 {
            coordinates.push_str(",\n");
        }
        coordinates.push_str(&format!(
            r#"    {{ "name": "{name}", "u": "{u}", "point_order": {order}, "lies_on": "{lies_on}" }}"#
        ));
    }

    let document = format!(
        r#"{{
  "version": 1,
  "kind": "adversarial",
  "anchor": "none",
  "source": {{
    "specification": "draft-connolly-cfrg-xwing-kem-10 sections 5.4 and 5.5; docs/mlkem1024-x25519.md section 3.7",
    "generated_by": "rust/examples/generate_x25519_degenerate_vectors.rs",
    "note": "ADVERSARIAL INPUTS, NOT CONFORMANCE VECTORS. Every group element here is one an honest peer would never send. They are kept out of concrete-hybrid-kems-04-appendix-b.json, which is the CFRG's own published Appendix B and must stay a verbatim transcription, and out of mlkem1024-x25519-v1.json, which is a round-trip regression pin. What these cases pin is that the all-zero X25519 output is NOT rejected and NOT substituted: it is fed to the combiner as 32 zero bytes, exactly as X-Wing does. MLKEM768-X25519 is X-Wing, so those rows are a claim about a CFRG specified suite. The expected values were produced by this project's Rust implementation and are reproduced byte for byte by its TypeScript implementation."
  }},
  "construction": {{
    "encapsulation": "Replace the last Nelem_T = 32 bytes of the honest encapsulation key with u, then EncapsDerand(ek', randomness). The expected value is its shared secret.",
    "decapsulation": "Replace the last 32 bytes of EncapsDerand(ek, randomness).ciphertext with u, then Decaps(dk, ct'). The expected value is its shared secret.",
    "decapsulation_key": "The seed. DeriveKeyPair(seed) gives both the honest encapsulation key recorded here and the decapsulation key."
  }},
  "degenerate_u_coordinates": {{
    "note": "The complete set of Curve25519 u-coordinates whose X25519 output is the all-zero string, for every RFC 7748 clamped scalar: the points of order dividing 8 on the curve and on its quadratic twist. Completeness is argued in rust/examples/generate_x25519_degenerate_vectors.rs and in ts/src/suites.ts.",
    "coordinates": [
{coordinates}
    ]
  }},
  "cases": [
{cases}
  ]
}}
"#
    );

    std::fs::write(path, document).expect("write vectors");
    println!(
        "wrote {path}: {} adversarial cases",
        SUITES.len() * DEGENERATE_U.len()
    );
}
