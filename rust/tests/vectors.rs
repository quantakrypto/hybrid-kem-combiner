//! The Rust half of the shared conformance suite.
//!
//! Every case in `vectors/hybrid-kem-combiner-v1.json` is run here and, by
//! the identical suite in `ts/test/vectors.test.js`, in TypeScript. The file
//! is the contract between the two.

use hybrid_kem_combiner::{
    combine_c2pri, combine_c2pri_to_vec, combine_universal, combine_universal_to_vec,
    C2priAssertion, C2priInputs, Ciphertext, EncapsulationKey, Error, Input, Kdf, Label,
    SharedSecret, UniversalInputs,
};
use serde_json::Value;

const VECTORS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../vectors/hybrid-kem-combiner-v1.json"
);

fn load() -> Value {
    let raw = std::fs::read_to_string(VECTORS).unwrap_or_else(|e| {
        panic!(
            "cannot read {VECTORS}: {e}. The conformance vectors live at \
                the repository root and are shared with the TypeScript \
                package."
        )
    });
    serde_json::from_str(&raw).expect("vectors are valid JSON")
}

fn kdf_from(name: &str) -> Kdf {
    match name {
        "sha3-256" => Kdf::Sha3_256,
        "hkdf-sha512-label-as-info" => Kdf::HkdfSha512LabelAsInfo,
        "hkdf-sha512-label-in-ikm" => Kdf::HkdfSha512LabelInIkm,
        other => panic!("unknown kdf in vectors: {other}"),
    }
}

fn field(case: &Value, name: &str) -> Vec<u8> {
    let hex_str = case["inputs"][name]
        .as_str()
        .unwrap_or_else(|| panic!("case {} has no input {name}", case["name"]));
    hex::decode(hex_str).expect("inputs are hex")
}

fn run_case(case: &Value, out: &mut [u8]) -> Result<(), Error> {
    let kdf = kdf_from(case["kdf"].as_str().unwrap());
    let ss_pq = field(case, "ss_pq");
    let ss_t = field(case, "ss_t");
    let ct_t = field(case, "ct_t");
    let ek_t = field(case, "ek_t");
    let label = field(case, "label");

    match case["form"].as_str().unwrap() {
        "universal" => {
            let ct_pq = field(case, "ct_pq");
            let ek_pq = field(case, "ek_pq");
            combine_universal(
                kdf,
                &UniversalInputs {
                    pq_shared_secret: SharedSecret::new(&ss_pq),
                    traditional_shared_secret: SharedSecret::new(&ss_t),
                    pq_ciphertext: Ciphertext::new(&ct_pq),
                    traditional_ciphertext: Ciphertext::new(&ct_t),
                    pq_encapsulation_key: EncapsulationKey::new(&ek_pq),
                    traditional_encapsulation_key: EncapsulationKey::new(&ek_t),
                    label: Label::new(&label),
                },
                out,
            )
        }
        "c2pri" => combine_c2pri(
            kdf,
            &C2priInputs {
                pq_shared_secret: SharedSecret::new(&ss_pq),
                traditional_shared_secret: SharedSecret::new(&ss_t),
                traditional_ciphertext: Ciphertext::new(&ct_t),
                traditional_encapsulation_key: EncapsulationKey::new(&ek_t),
                label: Label::new(&label),
                assertion: C2priAssertion::assert_pq_kem_is_ciphertext_second_preimage_resistant(),
            },
            out,
        ),
        other => panic!("unknown form in vectors: {other}"),
    }
}

#[test]
fn every_vector_case_matches() {
    let doc = load();
    let cases = doc["cases"].as_array().expect("cases is an array");
    assert!(cases.len() >= 15, "the suite lost cases");

    for case in cases {
        let name = case["name"].as_str().unwrap();
        let len = case["output_length"].as_u64().unwrap() as usize;
        let mut out = vec![0u8; len];
        run_case(case, &mut out).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            hex::encode(&out),
            case["output"].as_str().unwrap(),
            "{name}"
        );
    }
}

/// The vector file publishes the exact byte string fed to the KDF. If that
/// disagrees with the input order this crate uses, a mismatch elsewhere would
/// be undiagnosable, so check the intermediate too.
#[test]
fn every_vector_publishes_the_kdf_input_this_crate_builds() {
    let doc = load();
    for case in doc["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(&field(case, "ss_pq"));
        expected.extend_from_slice(&field(case, "ss_t"));
        if case["form"] == "universal" {
            expected.extend_from_slice(&field(case, "ct_pq"));
        }
        expected.extend_from_slice(&field(case, "ct_t"));
        if case["form"] == "universal" {
            expected.extend_from_slice(&field(case, "ek_pq"));
        }
        expected.extend_from_slice(&field(case, "ek_t"));
        if case["kdf"] != "hkdf-sha512-label-as-info" {
            expected.extend_from_slice(&field(case, "label"));
        }
        assert_eq!(
            hex::encode(&expected),
            case["intermediates"]["kdf_input_hex"].as_str().unwrap(),
            "{name}"
        );
    }
}

#[test]
fn every_negative_case_is_refused() {
    let doc = load();
    let cases = doc["negative_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 4);

    for case in cases {
        let name = case["name"].as_str().unwrap();
        let len = case["output_length"].as_u64().unwrap() as usize;
        let mut out = vec![0u8; len];
        let err = run_case(case, &mut out).expect_err(&format!("{name} was accepted"));
        let kind = match err {
            Error::Empty(_) => "empty-input",
            Error::UnsupportedOutputLength { .. } => "unsupported-output-length",
            Error::HkdfDomainSeparation { .. } => "hkdf-domain-separation",
            other => panic!("{name}: unmapped error {other:?}"),
        };
        assert_eq!(kind, case["error"].as_str().unwrap(), "{name}");
        assert_eq!(out, vec![0u8; len], "{name}: wrote to out on error");
    }
}

// --- Properties the vectors alone cannot pin ------------------------------

/// ss_pq, ss_t, ct_pq, ct_t, ek_pq, ek_t, label, in the combiner's own order.
fn sample() -> [Vec<u8>; 7] {
    [
        vec![0x11; 32],
        vec![0x22; 32],
        vec![0x33; 1088],
        vec![0x44; 32],
        vec![0x55; 1184],
        vec![0x66; 32],
        b"example.org/v1/ml-kem-768+x25519".to_vec(),
    ]
}

fn universal_of(kdf: Kdf, parts: &[Vec<u8>; 7]) -> [u8; 32] {
    let mut out = [0u8; 32];
    combine_universal(
        kdf,
        &UniversalInputs {
            pq_shared_secret: SharedSecret::new(&parts[0]),
            traditional_shared_secret: SharedSecret::new(&parts[1]),
            pq_ciphertext: Ciphertext::new(&parts[2]),
            traditional_ciphertext: Ciphertext::new(&parts[3]),
            pq_encapsulation_key: EncapsulationKey::new(&parts[4]),
            traditional_encapsulation_key: EncapsulationKey::new(&parts[5]),
            label: Label::new(&parts[6]),
        },
        &mut out,
    )
    .unwrap();
    out
}

/// Every single input must reach the output. A combiner that drops one is
/// still self consistent, still round trips between two peers running the
/// same code, and is broken.
#[test]
fn every_input_is_bound() {
    for kdf in [
        Kdf::Sha3_256,
        Kdf::HkdfSha512LabelAsInfo,
        Kdf::HkdfSha512LabelInIkm,
    ] {
        let base = sample();
        let baseline = universal_of(kdf, &base);
        for i in 0..7 {
            let mut mutated = base.clone();
            mutated[i][0] ^= 0xFF;
            assert_ne!(
                baseline,
                universal_of(kdf, &mutated),
                "input {i} does not reach the output under {kdf:?}"
            );
        }
    }
}

/// Two inputs of the same length must not be interchangeable.
#[test]
fn the_combiner_is_not_symmetric_in_its_shared_secrets() {
    let base = sample();
    let mut swapped = base.clone();
    swapped.swap(0, 1);
    assert_ne!(
        universal_of(Kdf::Sha3_256, &base),
        universal_of(Kdf::Sha3_256, &swapped)
    );
}

/// The two forms must not agree, or the C2PRI gate would be decorative.
#[test]
fn the_two_forms_disagree() {
    let [ss_pq, ss_t, ct_pq, ct_t, ek_pq, ek_t, label] = sample();
    let mut u = [0u8; 32];
    combine_universal(
        Kdf::Sha3_256,
        &UniversalInputs {
            pq_shared_secret: SharedSecret::new(&ss_pq),
            traditional_shared_secret: SharedSecret::new(&ss_t),
            pq_ciphertext: Ciphertext::new(&ct_pq),
            traditional_ciphertext: Ciphertext::new(&ct_t),
            pq_encapsulation_key: EncapsulationKey::new(&ek_pq),
            traditional_encapsulation_key: EncapsulationKey::new(&ek_t),
            label: Label::new(&label),
        },
        &mut u,
    )
    .unwrap();

    let mut c = [0u8; 32];
    combine_c2pri(
        Kdf::Sha3_256,
        &C2priInputs {
            pq_shared_secret: SharedSecret::new(&ss_pq),
            traditional_shared_secret: SharedSecret::new(&ss_t),
            traditional_ciphertext: Ciphertext::new(&ct_t),
            traditional_encapsulation_key: EncapsulationKey::new(&ek_t),
            label: Label::new(&label),
            assertion: C2priAssertion::assert_pq_kem_is_ciphertext_second_preimage_resistant(),
        },
        &mut c,
    )
    .unwrap();

    assert_ne!(u, c);
}

/// The three KDFs must not agree with each other on the same inputs.
#[test]
fn the_three_kdfs_disagree() {
    let base = sample();
    let one = universal_of(Kdf::Sha3_256, &base);
    let two = universal_of(Kdf::HkdfSha512LabelAsInfo, &base);
    let three = universal_of(Kdf::HkdfSha512LabelInIkm, &base);
    assert_ne!(one, two);
    assert_ne!(two, three);
    assert_ne!(one, three);
}

#[test]
fn the_vec_helpers_agree_with_the_slice_api() {
    let [ss_pq, ss_t, ct_pq, ct_t, ek_pq, ek_t, label] = sample();
    let universal = UniversalInputs {
        pq_shared_secret: SharedSecret::new(&ss_pq),
        traditional_shared_secret: SharedSecret::new(&ss_t),
        pq_ciphertext: Ciphertext::new(&ct_pq),
        traditional_ciphertext: Ciphertext::new(&ct_t),
        pq_encapsulation_key: EncapsulationKey::new(&ek_pq),
        traditional_encapsulation_key: EncapsulationKey::new(&ek_t),
        label: Label::new(&label),
    };
    let mut out = [0u8; 32];
    combine_universal(Kdf::Sha3_256, &universal, &mut out).unwrap();
    let boxed = combine_universal_to_vec(Kdf::Sha3_256, &universal, 32).unwrap();
    assert_eq!(&out[..], &boxed[..]);

    let c2pri = C2priInputs {
        pq_shared_secret: SharedSecret::new(&ss_pq),
        traditional_shared_secret: SharedSecret::new(&ss_t),
        traditional_ciphertext: Ciphertext::new(&ct_t),
        traditional_encapsulation_key: EncapsulationKey::new(&ek_t),
        label: Label::new(&label),
        assertion: C2priAssertion::assert_pq_kem_is_ciphertext_second_preimage_resistant(),
    };
    let mut out = [0u8; 32];
    combine_c2pri(Kdf::Sha3_256, &c2pri, &mut out).unwrap();
    let boxed = combine_c2pri_to_vec(Kdf::Sha3_256, &c2pri, 32).unwrap();
    assert_eq!(&out[..], &boxed[..]);
}

/// The error names the input that was empty, so a caller can find it.
#[test]
fn an_empty_input_is_named_in_the_error() {
    let [ss_pq, ss_t, ct_pq, ct_t, ek_pq, _ek_t, label] = sample();
    let err = combine_universal(
        Kdf::Sha3_256,
        &UniversalInputs {
            pq_shared_secret: SharedSecret::new(&ss_pq),
            traditional_shared_secret: SharedSecret::new(&ss_t),
            pq_ciphertext: Ciphertext::new(&ct_pq),
            traditional_ciphertext: Ciphertext::new(&ct_t),
            pq_encapsulation_key: EncapsulationKey::new(&ek_pq),
            traditional_encapsulation_key: EncapsulationKey::new(&[]),
            label: Label::new(&label),
        },
        &mut [0u8; 32],
    )
    .unwrap_err();
    assert_eq!(err, Error::Empty(Input::TraditionalEncapsulationKey));
    assert!(err.to_string().contains("ek_T"));
}

/// A shared secret must not print itself into a log.
#[test]
fn shared_secrets_redact_themselves_in_debug_output() {
    let secret = [0xABu8; 32];
    let rendered = format!("{:?}", SharedSecret::new(&secret));
    assert!(!rendered.contains("ab"), "{rendered}");
    assert!(rendered.contains("redacted"), "{rendered}");
}
