//! The Rust half of the hybrid KEM suite conformance suite.
//!
//! Two vector files are run here, and they are not the same kind of thing.
//!
//! `vectors/concrete-hybrid-kems-04-appendix-b.json` is transcribed from
//! Appendix B of `draft-irtf-cfrg-concrete-hybrid-kems-04`. Nothing in it was
//! computed by this project. It is an **external anchor**: if the PRG output
//! length, the seed split, the rejection sampling, the point encoding, the
//! shared secret extraction, the combiner input order or the label were
//! wrong, these tests would fail.
//!
//! `vectors/mlkem1024-x25519-v1.json` is a **regression pin**. `MLKEM1024-
//! X25519` is specified only by this project, so no external anchor can
//! exist. Those cases prove that the bytes have not drifted and that Rust and
//! TypeScript agree. They prove nothing about whether the suite is a good
//! idea; `docs/mlkem1024-x25519.md` argues that question in both directions.
//!
//! The same two files are run by `ts/test/suites.test.js`.

use hybrid_kem_combiner::suites::{Provenance, Suite, SuiteError, SUITES};
use serde_json::Value;

const APPENDIX_B: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../vectors/concrete-hybrid-kems-04-appendix-b.json"
);
const PINS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../vectors/mlkem1024-x25519-v1.json"
);

fn load(path: &str) -> Value {
    let raw = std::fs::read_to_string(path).unwrap_or_else(|e| {
        panic!(
            "cannot read {path}: {e}. The vectors live at the repository \
             root and are shared with the TypeScript package."
        )
    });
    serde_json::from_str(&raw).expect("vectors are valid JSON")
}

fn suite_by_name(name: &str) -> Suite {
    SUITES
        .into_iter()
        .find(|suite| suite.name() == name)
        .unwrap_or_else(|| panic!("unknown suite in vectors: {name}"))
}

fn hex_field(case: &Value, name: &str) -> Vec<u8> {
    hex::decode(
        case[name]
            .as_str()
            .unwrap_or_else(|| panic!("case has no field {name}")),
    )
    .expect("vector fields are hex")
}

/// Run one published vector end to end: derive the key pair from the seed,
/// encapsulate with the published randomness, and decapsulate the result.
fn run(case: &Value) {
    let suite = suite_by_name(case["suite"].as_str().unwrap());
    let name = case["name"].as_str().unwrap();

    let seed = hex_field(case, "seed");
    let expected_dk = hex_field(case, "decapsulation_key");
    let expected_ek = hex_field(case, "encapsulation_key");
    let randomness = hex_field(case, "randomness");
    let expected_ct = hex_field(case, "ciphertext");
    let expected_ss = hex_field(case, "shared_secret");

    let key_pair = suite
        .derive_key_pair(&seed)
        .unwrap_or_else(|e| panic!("{name}: derive_key_pair: {e}"));
    assert_eq!(
        key_pair.decapsulation_key().as_slice(),
        expected_dk.as_slice(),
        "{name}: decapsulation key"
    );
    assert_eq!(
        hex::encode(key_pair.encapsulation_key()),
        hex::encode(&expected_ek),
        "{name}: encapsulation key"
    );

    let encapsulation = suite
        .encapsulate_derand(&expected_ek, &randomness)
        .unwrap_or_else(|e| panic!("{name}: encapsulate_derand: {e}"));
    assert_eq!(
        hex::encode(encapsulation.ciphertext()),
        hex::encode(&expected_ct),
        "{name}: ciphertext"
    );
    assert_eq!(
        hex::encode(encapsulation.shared_secret()),
        hex::encode(&expected_ss),
        "{name}: shared secret from encapsulation"
    );

    let decapsulated = suite
        .decapsulate(&expected_dk, &expected_ct)
        .unwrap_or_else(|e| panic!("{name}: decapsulate: {e}"));
    assert_eq!(
        hex::encode(decapsulated.as_slice()),
        hex::encode(&expected_ss),
        "{name}: shared secret from decapsulation"
    );
}

#[test]
fn every_published_cfrg_vector_matches() {
    let doc = load(APPENDIX_B);
    let cases = doc["cases"].as_array().expect("cases is an array");
    assert_eq!(
        cases.len(),
        30,
        "Appendix B publishes ten vectors for each of three suites"
    );
    for case in cases {
        run(case);
    }
}

/// The three CFRG suites must each be covered, or a silently empty filter
/// would let a broken suite pass.
#[test]
fn the_published_vectors_cover_all_three_cfrg_suites() {
    let doc = load(APPENDIX_B);
    for suite in SUITES {
        let count = doc["cases"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|case| case["suite"] == suite.name())
            .count();
        match suite.provenance() {
            Provenance::CfrgConcreteHybridKems => {
                assert_eq!(count, 10, "{} has no published vectors", suite.name())
            }
            _ => assert_eq!(
                count,
                0,
                "{} cannot have published vectors: nobody else specifies it",
                suite.name()
            ),
        }
    }
}

/// The labels the vectors were produced under. A label mismatch changes every
/// shared secret, so pinning them separately makes that failure legible.
#[test]
fn the_labels_match_the_draft() {
    let doc = load(APPENDIX_B);
    let labels = doc["labels"].as_object().unwrap();
    for (name, label) in labels {
        let suite = suite_by_name(name);
        assert_eq!(
            hex::encode(suite.label()),
            label.as_str().unwrap(),
            "{name}: label"
        );
    }
}

/// The published length constants of sections 3 and 4, checked against the
/// crate's own. A wrong `Nrandom` or `Nek` is caught by the vectors too, but
/// with a far less obvious error.
#[test]
fn the_lengths_match_the_draft() {
    let doc = load(APPENDIX_B);
    for (name, lengths) in doc["lengths"].as_object().unwrap() {
        let suite = suite_by_name(name);
        let get = |field: &str| lengths[field].as_u64().unwrap() as usize;
        assert_eq!(suite.nseed(), get("seed"), "{name}: Nseed");
        assert_eq!(suite.ndk(), get("decapsulation_key"), "{name}: Ndk");
        assert_eq!(suite.nek(), get("encapsulation_key"), "{name}: Nek");
        assert_eq!(suite.nct(), get("ciphertext"), "{name}: Nct");
        assert_eq!(suite.nss(), get("shared_secret"), "{name}: Nss");
        assert_eq!(suite.nrandom(), get("randomness"), "{name}: Nrandom");
    }
}

#[test]
fn every_mlkem1024_x25519_regression_pin_matches() {
    let doc = load(PINS);
    assert_eq!(
        doc["anchor"], "none",
        "these vectors must not claim an external anchor"
    );
    let cases = doc["cases"].as_array().expect("cases is an array");
    assert!(cases.len() >= 5, "the pin suite lost cases");
    for case in cases {
        assert_eq!(case["suite"], "MLKEM1024-X25519");
        run(case);
    }
}

// --- Properties the vectors alone cannot pin ------------------------------

/// Encapsulation and decapsulation must agree on a key pair the suite
/// generated itself, in every suite. The vectors only cover fixed seeds.
#[test]
fn every_suite_round_trips() {
    for suite in SUITES {
        let seed = vec![0x5au8; suite.nseed()];
        let key_pair = suite.derive_key_pair(&seed).unwrap();
        let randomness = vec![0xa5u8; suite.nrandom()];
        let sent = suite
            .encapsulate_derand(key_pair.encapsulation_key(), &randomness)
            .unwrap();
        let received = suite
            .decapsulate(key_pair.decapsulation_key(), sent.ciphertext())
            .unwrap();
        assert_eq!(
            sent.shared_secret().as_slice(),
            received.as_slice(),
            "{}",
            suite.name()
        );
        assert_eq!(key_pair.encapsulation_key().len(), suite.nek());
        assert_eq!(sent.ciphertext().len(), suite.nct());
    }
}

/// `DecapsToEncaps` must recover exactly the key `DeriveKeyPair` produced.
#[test]
fn the_encapsulation_key_is_recoverable_from_the_decapsulation_key() {
    for suite in SUITES {
        let seed = vec![0x31u8; suite.nseed()];
        let key_pair = suite.derive_key_pair(&seed).unwrap();
        let recovered = suite
            .encapsulation_key_from_decapsulation_key(key_pair.decapsulation_key())
            .unwrap();
        assert_eq!(recovered, key_pair.encapsulation_key(), "{}", suite.name());
    }
}

/// The labels differ, so the same component secrets must never give the same
/// hybrid secret across suites. This is what stops a `MLKEM1024-P384` peer
/// and a `MLKEM1024-X25519` peer from silently agreeing on anything.
#[test]
fn no_two_suites_agree_on_a_shared_secret() {
    let mut seen = std::collections::HashSet::new();
    for suite in SUITES {
        let seed = vec![0x77u8; suite.nseed()];
        let key_pair = suite.derive_key_pair(&seed).unwrap();
        let randomness = vec![0x88u8; suite.nrandom()];
        let sent = suite
            .encapsulate_derand(key_pair.encapsulation_key(), &randomness)
            .unwrap();
        assert!(
            seen.insert(*sent.shared_secret()),
            "{} collided with another suite",
            suite.name()
        );
    }
}

/// A ciphertext whose group element is not a point must be refused, not
/// absorbed. Only the NIST curves can fail this way: every 32 byte string is
/// a valid Curve25519 u-coordinate.
#[test]
fn a_malformed_group_element_is_refused() {
    for suite in [Suite::MlKem768P256, Suite::MlKem1024P384] {
        let seed = vec![0x13u8; suite.nseed()];
        let key_pair = suite.derive_key_pair(&seed).unwrap();
        let randomness = vec![0x14u8; suite.nrandom()];
        let sent = suite
            .encapsulate_derand(key_pair.encapsulation_key(), &randomness)
            .unwrap();

        let mut broken = sent.ciphertext().to_vec();
        let len = broken.len();
        broken[len - 1] ^= 0xff;
        assert!(
            matches!(
                suite.decapsulate(key_pair.decapsulation_key(), &broken),
                Err(SuiteError::InvalidGroupElement)
            ),
            "{}",
            suite.name()
        );
    }
}

/// A wrong length is named rather than panicking or truncating.
#[test]
fn wrong_lengths_are_named_in_the_error() {
    let suite = Suite::MlKem768X25519;
    assert!(matches!(
        suite.derive_key_pair(&[0u8; 31]),
        Err(SuiteError::WrongLength { what: "seed", .. })
    ));
    let key_pair = suite.derive_key_pair(&[0u8; 32]).unwrap();
    assert!(matches!(
        suite.encapsulate_derand(key_pair.encapsulation_key(), &[0u8; 63]),
        Err(SuiteError::WrongLength {
            what: "randomness",
            expected: 64,
            actual: 63
        })
    ));
    assert!(matches!(
        suite.encapsulate_derand(&[0u8; 100], &[0u8; 64]),
        Err(SuiteError::WrongLength {
            what: "encapsulation key",
            ..
        })
    ));
    assert!(matches!(
        suite.decapsulate(key_pair.decapsulation_key(), &[0u8; 1119]),
        Err(SuiteError::WrongLength {
            what: "ciphertext",
            ..
        })
    ));
}

/// An ML-KEM encapsulation key that fails the check of FIPS 203 section 7.2
/// must be refused, which `draft-connolly-cfrg-xwing-kem-10` section 3
/// requires.
#[test]
fn an_invalid_ml_kem_encapsulation_key_is_refused() {
    let suite = Suite::MlKem768X25519;
    let key_pair = suite.derive_key_pair(&[0x21u8; 32]).unwrap();
    let mut ek = key_pair.encapsulation_key().to_vec();
    // The check is that the encoded polynomial coefficients are all below q,
    // so setting the first twelve-bit field to its maximum breaks it.
    ek[0] = 0xff;
    ek[1] = 0xff;
    assert!(matches!(
        suite.encapsulate_derand(&ek, &[0u8; 64]),
        Err(SuiteError::InvalidMlKemEncapsulationKey)
    ));
}

/// The provenance of each suite is part of the API, because a caller has a
/// right to know which of these has an external anchor and which does not.
#[test]
fn provenance_says_which_suites_are_externally_specified() {
    assert_eq!(
        Suite::MlKem768P256.provenance(),
        Provenance::CfrgConcreteHybridKems
    );
    assert_eq!(
        Suite::MlKem768X25519.provenance(),
        Provenance::CfrgConcreteHybridKems
    );
    assert_eq!(
        Suite::MlKem1024P384.provenance(),
        Provenance::CfrgConcreteHybridKems
    );
    assert_eq!(
        Suite::MlKem1024X25519.provenance(),
        Provenance::ThisProjectOnly
    );
}

/// A shared secret must not print itself into a log.
#[test]
fn secrets_redact_themselves_in_debug_output() {
    let suite = Suite::MlKem768X25519;
    let key_pair = suite.derive_key_pair(&[0xabu8; 32]).unwrap();
    let rendered = format!("{key_pair:?}");
    assert!(rendered.contains("redacted"), "{rendered}");
    assert!(!rendered.contains("abab"), "{rendered}");

    let sent = suite
        .encapsulate_derand(key_pair.encapsulation_key(), &[0xcdu8; 64])
        .unwrap();
    let rendered = format!("{sent:?}");
    assert!(rendered.contains("redacted"), "{rendered}");
    assert!(
        !rendered.contains(&hex::encode(sent.shared_secret())),
        "{rendered}"
    );
}

#[cfg(feature = "os-rng")]
#[test]
fn the_os_rng_helpers_produce_working_key_pairs() {
    for suite in SUITES {
        let key_pair = suite.generate_key_pair().unwrap();
        let sent = suite.encapsulate(key_pair.encapsulation_key()).unwrap();
        let received = suite
            .decapsulate(key_pair.decapsulation_key(), sent.ciphertext())
            .unwrap();
        assert_eq!(sent.shared_secret().as_slice(), received.as_slice());
    }
}
