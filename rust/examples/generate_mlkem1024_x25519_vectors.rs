//! Generate `vectors/mlkem1024-x25519-v1.json`.
//!
//! ```sh
//! cd rust && cargo run --features suites --example generate_mlkem1024_x25519_vectors
//! ```
//!
//! These are **regression pins, not an external anchor**, and the difference
//! matters enough to repeat here. `MLKEM1024-X25519` is specified in
//! `docs/mlkem1024-x25519.md` and nowhere else, so there exists no published
//! vector to check against: any vector for it must come from an
//! implementation of it, and the only implementations are this one and its
//! TypeScript twin. What these cases establish is that the bytes have not
//! drifted between commits and that the two languages agree. What they cannot
//! establish is conformance, because there is nothing external to conform to.
//!
//! The three CFRG suites are the opposite case, and they are what makes this
//! file trustworthy at all: they run against
//! `vectors/concrete-hybrid-kems-04-appendix-b.json`, which nobody here
//! produced. `MLKEM1024-X25519` differs from the anchored `MLKEM1024-P384`
//! only in the nominal group and the label, and from the anchored
//! `MLKEM768-X25519` only in the ML-KEM parameter set and the label. Every
//! other line of the framework is shared code that the published vectors
//! exercise.
//!
//! The seed and randomness patterns deliberately copy Appendix B's: seed is
//! the byte `i` repeated, randomness is the byte `0x64 + i` repeated. That
//! makes the two files comparable at a glance.

use hybrid_kem_combiner::suites::Suite;

const SUITE: Suite = Suite::MlKem1024X25519;
const CASES: usize = 10;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../vectors/mlkem1024-x25519-v1.json"
    );

    let mut cases = String::new();
    for index in 0..CASES {
        let seed = vec![index as u8; SUITE.nseed()];
        let randomness = vec![0x64u8.wrapping_add(index as u8); SUITE.nrandom()];

        let key_pair = SUITE.derive_key_pair(&seed).expect("key generation");
        let encapsulated = SUITE
            .encapsulate_derand(key_pair.encapsulation_key(), &randomness)
            .expect("encapsulation");
        let decapsulated = SUITE
            .decapsulate(key_pair.decapsulation_key(), encapsulated.ciphertext())
            .expect("decapsulation");
        assert_eq!(
            encapsulated.shared_secret().as_slice(),
            decapsulated.as_slice(),
            "case {index} does not round trip, which is a bug and not a vector"
        );

        // The component sub-keys, for the same reason the combiner vectors
        // publish `kdf_input_hex`: an opaque terminal secret cannot tell you
        // which stage is wrong.
        let mut expanded = vec![0u8; 96];
        libcrux_sha3::shake256_ema(&mut expanded, &seed);

        if index > 0 {
            cases.push_str(",\n");
        }
        cases.push_str(&format!(
            r#"    {{
      "suite": "MLKEM1024-X25519",
      "index": {index},
      "name": "MLKEM1024-X25519/pin-{index}",
      "seed": "{seed}",
      "decapsulation_key": "{dk}",
      "decapsulation_key_pq": "{dk_pq}",
      "decapsulation_key_t": "{dk_t}",
      "encapsulation_key": "{ek}",
      "randomness": "{randomness}",
      "ciphertext": "{ct}",
      "shared_secret": "{ss}"
    }}"#,
            index = index,
            seed = hex(&seed),
            dk = hex(key_pair.decapsulation_key()),
            dk_pq = hex(&expanded[..64]),
            dk_t = hex(&expanded[64..96]),
            ek = hex(key_pair.encapsulation_key()),
            randomness = hex(&randomness),
            ct = hex(encapsulated.ciphertext()),
            ss = hex(encapsulated.shared_secret()),
        ));
    }

    let document = format!(
        r#"{{
  "version": 1,
  "suite": "MLKEM1024-X25519",
  "anchor": "none",
  "source": {{
    "specification": "docs/mlkem1024-x25519.md",
    "generated_by": "rust/examples/generate_mlkem1024_x25519_vectors.rs",
    "note": "REGRESSION PINS, NOT AN EXTERNAL ANCHOR. This suite is specified by this project and by no standards body, so no published vector for it exists and none can. These values were produced by this project's own Rust implementation and are reproduced by its TypeScript implementation. They prove that the bytes have not drifted and that the two languages agree. They do not prove conformance to anything, because there is nothing external to conform to. The three CFRG suites in concrete-hybrid-kems-04-appendix-b.json are the anchored ones."
  }},
  "label": "{label}",
  "lengths": {{
    "seed": {nseed},
    "decapsulation_key": {ndk},
    "decapsulation_key_pq": 64,
    "decapsulation_key_t": 32,
    "encapsulation_key": {nek},
    "randomness": {nrandom},
    "ciphertext": {nct},
    "shared_secret": {nss}
  }},
  "cases": [
{cases}
  ]
}}
"#,
        label = hex(SUITE.label()),
        nseed = SUITE.nseed(),
        ndk = SUITE.ndk(),
        nek = SUITE.nek(),
        nrandom = SUITE.nrandom(),
        nct = SUITE.nct(),
        nss = SUITE.nss(),
        cases = cases,
    );

    std::fs::write(path, document).expect("write vectors");
    println!("wrote {path}: {CASES} regression pins");
}
