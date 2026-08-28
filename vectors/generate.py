#!/usr/bin/env python3
"""Regenerate hybrid-kem-combiner-v1.json.

This script is deliberately a THIRD implementation of the combiner, written
from the standards text alone and depending on nothing but the Python
standard library. The Rust crate and the TypeScript package are both tested
against its output, so a shared bug would have to occur independently in
three implementations built from different primitives.

Two cases are not generated from this file's own idea of what is correct:

* The three ``xwing-draft-10-*`` cases carry the shared secret published in
  Appendix C of draft-connolly-cfrg-xwing-kem-10. This script asserts that
  the C2PRI combiner reproduces it. If the assertion ever fails, the
  construction is wrong, not the vector.
* ``interop-qk-password-manager-v1`` carries the value pinned in that
  project's own conformance vectors, computed by an unrelated Rust
  implementation. Same rule: the assertion is the point.

Run: python3 vectors/generate.py
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "hybrid-kem-combiner-v1.json")

SHA3_256 = "sha3-256"
HKDF_INFO = "hkdf-sha512-label-as-info"
HKDF_IKM = "hkdf-sha512-label-in-ikm"

HMAC_SHA512_LEN = 64


def hkdf_extract(ikm: bytes, salt: bytes | None) -> bytes:
    """RFC 5869 HKDF-Extract. An absent salt is HashLen zero bytes."""
    if salt is None:
        salt = b"\x00" * HMAC_SHA512_LEN
    return hmac.new(salt, ikm, hashlib.sha512).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-Expand."""
    if length > 255 * HMAC_SHA512_LEN:
        raise ValueError("output too long")
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]),
                         hashlib.sha512).digest()
        okm += block
        counter += 1
    return okm[:length]


def check_hkdf_domains(ikm_len: int, info_len: int) -> None:
    """draft-irtf-cfrg-hybrid-kems-12 section 6.1.5, Lemma 6 of [LBB20]."""
    forbidden = (info_len + 1, info_len + 1 + HMAC_SHA512_LEN)
    if ikm_len in forbidden:
        raise ValueError(
            f"HKDF input domains not disjoint: ikm_len={ikm_len}, "
            f"info_len={info_len}")


def combine(kdf: str, parts: list[bytes], label: bytes,
            length: int) -> tuple[bytes, dict]:
    """The combiner. `parts` is six values for universal, four for C2PRI."""
    joined = b"".join(parts)
    if kdf == SHA3_256:
        if length != 32:
            raise ValueError("SHA3-256 produces exactly 32 bytes")
        preimage = joined + label
        return hashlib.sha3_256(preimage).digest(), {
            "kdf_input_hex": preimage.hex(),
        }
    if kdf == HKDF_INFO:
        check_hkdf_domains(len(joined), len(label))
        prk = hkdf_extract(joined, None)
        return hkdf_expand(prk, label, length), {
            "kdf_input_hex": joined.hex(),
            "hkdf_salt": "absent (RFC 5869: 64 zero bytes)",
            "hkdf_ikm_hex": joined.hex(),
            "hkdf_info_hex": label.hex(),
            "hkdf_prk_hex": prk.hex(),
        }
    if kdf == HKDF_IKM:
        ikm = joined + label
        check_hkdf_domains(len(ikm), 0)
        prk = hkdf_extract(ikm, None)
        return hkdf_expand(prk, b"", length), {
            "kdf_input_hex": ikm.hex(),
            "hkdf_salt": "absent (RFC 5869: 64 zero bytes)",
            "hkdf_ikm_hex": ikm.hex(),
            "hkdf_info_hex": "",
            "hkdf_prk_hex": prk.hex(),
        }
    raise ValueError(f"unknown kdf {kdf}")


def universal(name, kdf, ss_pq, ss_t, ct_pq, ct_t, ek_pq, ek_t, label,
              length=32, note=None, expect=None):
    parts = [ss_pq, ss_t, ct_pq, ct_t, ek_pq, ek_t]
    out, inter = combine(kdf, parts, label, length)
    if expect is not None:
        assert out.hex() == expect, f"{name}: {out.hex()} != {expect}"
    case = {
        "name": name,
        "form": "universal",
        "kdf": kdf,
        "inputs": {
            "ss_pq": ss_pq.hex(),
            "ss_t": ss_t.hex(),
            "ct_pq": ct_pq.hex(),
            "ct_t": ct_t.hex(),
            "ek_pq": ek_pq.hex(),
            "ek_t": ek_t.hex(),
            "label": label.hex(),
        },
        "input_lengths": {
            "ss_pq": len(ss_pq), "ss_t": len(ss_t),
            "ct_pq": len(ct_pq), "ct_t": len(ct_t),
            "ek_pq": len(ek_pq), "ek_t": len(ek_t),
            "label": len(label),
        },
        "intermediates": inter,
        "output_length": length,
        "output": out.hex(),
    }
    if note:
        case["note"] = note
    return case


def c2pri(name, kdf, ss_pq, ss_t, ct_t, ek_t, label, length=32, note=None,
          expect=None):
    parts = [ss_pq, ss_t, ct_t, ek_t]
    out, inter = combine(kdf, parts, label, length)
    if expect is not None:
        assert out.hex() == expect, f"{name}: {out.hex()} != {expect}"
    case = {
        "name": name,
        "form": "c2pri",
        "kdf": kdf,
        "inputs": {
            "ss_pq": ss_pq.hex(),
            "ss_t": ss_t.hex(),
            "ct_t": ct_t.hex(),
            "ek_t": ek_t.hex(),
            "label": label.hex(),
        },
        "input_lengths": {
            "ss_pq": len(ss_pq), "ss_t": len(ss_t),
            "ct_t": len(ct_t), "ek_t": len(ek_t),
            "label": len(label),
        },
        "intermediates": inter,
        "output_length": length,
        "output": out.hex(),
    }
    if note:
        case["note"] = note
    return case


# --- Fixed inputs -----------------------------------------------------------
#
# Distinct fill bytes per input, so that swapping any two inputs of equal
# length changes the output. Sizes are the real sizes of ML-KEM-768 plus
# X25519 unless the case name says otherwise.

MLKEM768_LABEL = b"example.org/v1/ml-kem-768+x25519"
MLKEM1024_LABEL = b"example.org/v1/ml-kem-1024+x448"

SS_PQ = bytes([0x11]) * 32
SS_T = bytes([0x22]) * 32
CT_PQ = bytes([0x33]) * 1088
CT_T = bytes([0x44]) * 32
EK_PQ = bytes([0x55]) * 1184
EK_T = bytes([0x66]) * 32

# X-Wing, draft-connolly-cfrg-xwing-kem-10 Appendix C. The four combiner
# inputs are the intermediates of the published (seed, eseed) pairs,
# recomputed with an independent ML-KEM-768 and X25519 implementation
# (@noble/post-quantum 0.7.1); `ss` is the draft's own published value.
XWING_LABEL = bytes.fromhex("5c2e2f2f5e5c")
XWING = [
    {
        "ss_pq": "7631eaf24bcc7ba2d1656d8f53778f8caa5f1ce33180e8ab405b9247eab76dfc",
        "ss_t": "1e53cb26910141b4a09b0664deb8ec55376bcdbdfe2bfc8277883939a76d6131",
        "ct_t": "e56f17576740ce2a32fc5145030145cfb97e63e0e41d354274a079d3e6fb2e15",
        "ek_t": "859edb06eff389b27dce59844570216223593d4ba32d9abac8cd049040ef6534",
        "ss": "d2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384",
    },
    {
        "ss_pq": "9177e31fee338e5fd415e210c1be872eca3d1e903feae6af84219d380fb8c5cf",
        "ss_t": "20186d4893a532728e4b680920defab6f98fb8e2281cd66c70c3162b149d8258",
        "ct_t": "c91bdf6e0e03200693c9651e469aee6f91c98bea4127ae66312f4ae3ea155b67",
        "ek_t": "9f7ed34bcbb48fd4c562a576549f85b528c953926d96ea8a160b8843f1c89c62",
        "ss": "f2e86241c64d60f6649fbc6c5b7d17180b780a3f34355e64a85749949c45f150",
    },
    {
        "ss_pq": "b0fed41fbda2f75581406ce86c3ab89cc403fe081165001a5aff5d175a46d626",
        "ss_t": "9abf1e2692957defb8b66c0aae9fc4e28bba311c05a75a271d6ce209b5ed265f",
        "ct_t": "fa64de6b6e1c3c8e03db5971a445992227c825590688d203523f527161137334",
        "ek_t": "d31ae3cbc1c013747dfee80fb35b5299f555dcc2b787ea4f6f16ffdf66952461",
        "ss": "953f7f4e8c5b5049bdc771d1dffada0dd961477d1a2ae0988baa7ea6898d893f",
    },
]

# qk-password-manager, vectors/qk-crypto-constructions-v1.json, case
# `kem_combiner`. ML-KEM-1024 plus X25519, universal form, HKDF-SHA512 with
# the label in `info`. The expected output is that project's pinned value,
# produced by an unrelated Rust implementation.
QK_LABEL = b"qk-password-manager/v1/kem-combine"
QK_SS_PQ = bytes([0x11]) * 32
QK_SS_T = bytes([0x22]) * 32
QK_CT_PQ = bytes([0x33]) * 1568
QK_CT_T = bytes([0x44]) * 32
QK_EK_T = bytes.fromhex(
    "2aed3abbeb5a3bab312eb4725734ea732678a1acd7cf1de80a4e6da15cc0ff0e")
QK_EK_PQ_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "qk-password-manager-ek-pq.hex")
QK_EXPECTED = \
    "7afb6c744e85367a7138a9e0db33b353336f9ce4328edfd0a5f80accb50bbddf"


def build() -> dict:
    cases = []

    # The same six inputs under all three KDFs. Three different keys from one
    # input set: the KDF choice is not cosmetic.
    for kdf in (SHA3_256, HKDF_INFO, HKDF_IKM):
        cases.append(universal(
            f"universal/{kdf}/ml-kem-768+x25519-sizes",
            kdf, SS_PQ, SS_T, CT_PQ, CT_T, EK_PQ, EK_T, MLKEM768_LABEL,
            note="Realistic ML-KEM-768 plus X25519 input sizes with distinct "
                 "fill bytes per input."))

    # Category 5 sizes, and a traditional half that is neither 32 bytes nor
    # the same length as anything else, so a length assumption shows up.
    cases.append(universal(
        f"universal/{SHA3_256}/ml-kem-1024+x448-sizes",
        SHA3_256,
        bytes([0x01]) * 32, bytes([0x02]) * 56,
        bytes([0x03]) * 1568, bytes([0x04]) * 56,
        bytes([0x05]) * 1568, bytes([0x06]) * 56,
        MLKEM1024_LABEL,
        note="ML-KEM-1024 plus X448 sizes. The traditional half is 56 bytes, "
             "so an implementation that assumes 32 fails here."))

    # A 64 byte output, which only HKDF can produce.
    cases.append(universal(
        f"universal/{HKDF_INFO}/64-byte-output",
        HKDF_INFO, SS_PQ, SS_T, CT_PQ, CT_T, EK_PQ, EK_T, MLKEM768_LABEL,
        length=64,
        note="Two HKDF-Expand blocks, so a single block implementation fails "
             "here."))

    # Smallest legal inputs. Every input is one byte and every byte differs,
    # so dropping or reordering any input changes the output.
    one = [bytes([n]) for n in range(1, 8)]
    cases.append(universal(
        f"universal/{SHA3_256}/single-byte-inputs",
        SHA3_256, one[0], one[1], one[2], one[3], one[4], one[5], one[6],
        note="One byte per input, all distinct. A dropped or reordered input "
             "cannot survive this case."))

    # Degenerate: every input is all zero bytes. A combiner that skipped an
    # input entirely, or that treated an all zero input as absent, agrees
    # with a correct one on the other cases and disagrees here.
    cases.append(universal(
        f"universal/{SHA3_256}/all-zero-inputs",
        SHA3_256,
        bytes(32), bytes(32), bytes(1088), bytes(32), bytes(1184), bytes(32),
        MLKEM768_LABEL,
        note="Every KEM input is all zero bytes. Degenerate on purpose: an "
             "implementation that drops an input or short circuits on zeros "
             "still passes every other case and fails this one."))
    cases.append(universal(
        f"universal/{HKDF_INFO}/all-zero-inputs",
        HKDF_INFO,
        bytes(32), bytes(32), bytes(1088), bytes(32), bytes(1184), bytes(32),
        MLKEM768_LABEL,
        note="The all zero case again under HKDF, where the absent salt is "
             "also all zero bytes: two different zero strings that must not "
             "be conflated."))

    # C2PRI under all three KDFs, same traditional inputs.
    for kdf in (SHA3_256, HKDF_INFO, HKDF_IKM):
        cases.append(c2pri(
            f"c2pri/{kdf}/ml-kem-768+x25519-sizes",
            kdf, SS_PQ, SS_T, CT_T, EK_T, MLKEM768_LABEL,
            note="The C2PRI form over the same shared secrets as the "
                 "universal case of the same name. The outputs differ: the "
                 "two forms are not interchangeable."))

    # X-Wing interoperability. The C2PRI form with SHA3-256 and the X-Wing
    # label IS the X-Wing combiner.
    for i, v in enumerate(XWING, start=1):
        cases.append(c2pri(
            f"c2pri/{SHA3_256}/xwing-draft-10-vector-{i}",
            SHA3_256,
            bytes.fromhex(v["ss_pq"]), bytes.fromhex(v["ss_t"]),
            bytes.fromhex(v["ct_t"]), bytes.fromhex(v["ek_t"]),
            XWING_LABEL, expect=v["ss"],
            note="Interoperability. `output` is the shared secret published "
                 "in Appendix C of draft-connolly-cfrg-xwing-kem-10, not a "
                 "value this project computed. The four inputs are that "
                 "vector's intermediates."))

    # qk-password-manager interoperability.
    with open(QK_EK_PQ_PATH, "r", encoding="ascii") as fh:
        qk_ek_pq = bytes.fromhex(fh.read().strip())
    cases.append(universal(
        f"universal/{HKDF_INFO}/interop-qk-password-manager-v1",
        HKDF_INFO, QK_SS_PQ, QK_SS_T, QK_CT_PQ, QK_CT_T, qk_ek_pq, QK_EK_T,
        QK_LABEL, expect=QK_EXPECTED,
        note="Interoperability. `output` is the value pinned by "
             "qk-password-manager's own conformance vectors, computed by an "
             "unrelated Rust implementation of this same construction."))

    negative = [
        {
            "name": "reject/empty-ss-pq",
            "form": "universal",
            "kdf": SHA3_256,
            "inputs": {
                "ss_pq": "", "ss_t": SS_T.hex(), "ct_pq": CT_PQ.hex(),
                "ct_t": CT_T.hex(), "ek_pq": EK_PQ.hex(), "ek_t": EK_T.hex(),
                "label": MLKEM768_LABEL.hex(),
            },
            "output_length": 32,
            "error": "empty-input",
            "note": "A zero length shared secret is a dropped value, not a "
                    "valid input.",
        },
        {
            "name": "reject/empty-label",
            "form": "universal",
            "kdf": SHA3_256,
            "inputs": {
                "ss_pq": SS_PQ.hex(), "ss_t": SS_T.hex(),
                "ct_pq": CT_PQ.hex(), "ct_t": CT_T.hex(),
                "ek_pq": EK_PQ.hex(), "ek_t": EK_T.hex(), "label": "",
            },
            "output_length": 32,
            "error": "empty-input",
            "note": "An empty label provides no domain separation.",
        },
        {
            "name": "reject/sha3-256-wrong-output-length",
            "form": "universal",
            "kdf": SHA3_256,
            "inputs": {
                "ss_pq": SS_PQ.hex(), "ss_t": SS_T.hex(),
                "ct_pq": CT_PQ.hex(), "ct_t": CT_T.hex(),
                "ek_pq": EK_PQ.hex(), "ek_t": EK_T.hex(),
                "label": MLKEM768_LABEL.hex(),
            },
            "output_length": 64,
            "error": "unsupported-output-length",
            "note": "SHA3-256 produces 32 bytes. Truncating or extending it "
                    "silently would be worse than refusing.",
        },
        {
            "name": "reject/hkdf-domain-separation",
            "form": "c2pri",
            "kdf": HKDF_INFO,
            "inputs": {
                "ss_pq": "01", "ss_t": "02", "ct_t": "03", "ek_t": "04",
                "label": "aabbcc",
            },
            "output_length": 32,
            "error": "hkdf-domain-separation",
            "note": "Four one byte inputs give ikm_len = 4, and the label is "
                    "3 bytes, so ikm_len == info_len + 1. "
                    "draft-irtf-cfrg-hybrid-kems-12 section 6.1.5 says "
                    "instantiations MUST refuse this.",
        },
    ]

    return {
        "version": 1,
        "construction": {
            "universal":
                "KDF(ss_PQ || ss_T || ct_PQ || ct_T || ek_PQ || ek_T || label)",
            "c2pri":
                "KDF(ss_PQ || ss_T || ct_T || ek_T || label)",
            "sources": [
                "NIST SP 800-227 section 4.6.2, Expression (15), and section "
                "4.6.3",
                "draft-irtf-cfrg-hybrid-kems-12 section 5.1.3",
            ],
        },
        "kdfs": {
            SHA3_256:
                "SHA3-256 over the concatenated inputs followed by the "
                "label. Output is exactly 32 bytes.",
            HKDF_INFO:
                "HKDF-SHA512. salt absent (RFC 5869: 64 zero bytes), ikm is "
                "the concatenated inputs WITHOUT the label, info is the "
                "label, L is output_length.",
            HKDF_IKM:
                "HKDF-SHA512. salt absent (RFC 5869: 64 zero bytes), ikm is "
                "the concatenated inputs WITH the label appended, info is "
                "empty, L is output_length.",
        },
        "encoding": "Every value in `inputs`, `intermediates` and `output` "
                    "is hex. Inputs are concatenated with no length prefixes "
                    "and no separators.",
        "cases": cases,
        "negative_cases": negative,
    }


if __name__ == "__main__":
    doc = build()
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")
    print(f"wrote {OUT}: {len(doc['cases'])} cases, "
          f"{len(doc['negative_cases'])} negative cases")
