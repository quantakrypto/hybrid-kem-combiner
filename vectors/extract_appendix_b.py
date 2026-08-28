#!/usr/bin/env python3
"""Transcribe Appendix B of draft-irtf-cfrg-concrete-hybrid-kems-04 into JSON.

The draft publishes its test vectors as wrapped hex inside a plain text
Internet-Draft. This script fetches that text, parses the appendix and writes
`concrete-hybrid-kems-04-appendix-b.json`. It computes nothing: every byte in
the output comes from the draft, which is the entire point. The vectors are an
external anchor, so generating them from this project's own implementation
would be circular.

Usage:
    python3 vectors/extract_appendix_b.py [path-or-url]

With no argument it fetches the draft from ietf.org. Pass a local copy of the
.txt to run offline.
"""

import hashlib
import json
import os
import re
import sys
import urllib.request

DRAFT = "draft-irtf-cfrg-concrete-hybrid-kems-04"
URL = f"https://www.ietf.org/archive/id/{DRAFT}.txt"

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "concrete-hybrid-kems-04-appendix-b.json")

# Appendix B, section headings, in document order.
SUITES = [
    ("B.1", "MLKEM768-P256"),
    ("B.2", "MLKEM768-X25519"),
    ("B.3", "MLKEM1024-P384"),
]

# The fields of each vector, in the order Appendix B introduces them.
FIELDS = [
    "seed",
    "decapsulation_key",
    "decapsulation_key_pq",
    "decapsulation_key_t",
    "encapsulation_key",
    "randomness",
    "ciphertext",
    "shared_secret",
]

# Lengths in bytes, from sections 3 and 4 of the draft. Checked, not assumed:
# a wrapped-hex parser that loses a line is otherwise silently wrong.
LENGTHS = {
    "MLKEM768-P256": {
        "seed": 32,
        "decapsulation_key": 32,
        "decapsulation_key_pq": 64,
        "decapsulation_key_t": 32,
        "encapsulation_key": 1249,
        "randomness": 160,
        "ciphertext": 1153,
        "shared_secret": 32,
    },
    "MLKEM768-X25519": {
        "seed": 32,
        "decapsulation_key": 32,
        "decapsulation_key_pq": 64,
        "decapsulation_key_t": 32,
        "encapsulation_key": 1216,
        "randomness": 64,
        "ciphertext": 1120,
        "shared_secret": 32,
    },
    "MLKEM1024-P384": {
        "seed": 32,
        "decapsulation_key": 32,
        "decapsulation_key_pq": 64,
        "decapsulation_key_t": 48,
        "encapsulation_key": 1665,
        "randomness": 80,
        "ciphertext": 1665,
        "shared_secret": 32,
    },
}

LABELS = {
    "MLKEM768-P256": "4d4c4b454d3736382d50323536",
    "MLKEM768-X25519": "5c2e2f2f5e5c",
    "MLKEM1024-P384": "4d4c4b454d313032342d50333834",
}

ASSIGN = re.compile(r"^\s{2,}([a-z_]+) = ([0-9a-f]*)\s*$")
CONTINUE = re.compile(r"^\s{2,}([0-9a-f]+)\s*$")
HEADING = re.compile(r"^(B\.\d)\.\s+(\S+)\s*$")
NOISE = re.compile(r"^(Connolly & Barnes|Internet-Draft|Appendix|\f)")


def fetch(source):
    if source and not source.startswith("http"):
        with open(source, "r", encoding="utf-8") as handle:
            return handle.read()
    with urllib.request.urlopen(source or URL, timeout=120) as response:
        return response.read().decode("utf-8")


def parse(text):
    """Walk the appendix, gathering `name = hex` fields with wrapped values."""
    suites = {}
    current_suite = None
    current_vector = None
    field = None
    chunks = []

    def flush():
        nonlocal field, chunks
        if field is not None:
            current_vector[field] = "".join(chunks)
        field, chunks = None, []

    in_appendix = False
    for line in text.splitlines():
        heading = HEADING.match(line)
        if heading:
            in_appendix = True
            flush()
            name = dict(SUITES).get(heading.group(1))
            if name is None or name != heading.group(2):
                raise SystemExit(f"unexpected appendix heading: {line!r}")
            current_suite = name
            suites[name] = []
            current_vector = None
            continue
        if not in_appendix or current_suite is None:
            continue
        # Page breaks split long hex values. Skipping them without closing
        # the current field is the whole trick: a flush here silently
        # truncates every value that spans a page.
        if NOISE.match(line) or not line.strip():
            continue

        assignment = ASSIGN.match(line)
        if assignment:
            name, head = assignment.group(1), assignment.group(2)
            if name not in FIELDS:
                raise SystemExit(f"unknown field {name!r} in {current_suite}")
            # `seed` opens a new vector in every published block.
            if name == "seed":
                flush()
                current_vector = {}
                suites[current_suite].append(current_vector)
            else:
                flush()
            field, chunks = name, [head]
            continue

        continuation = CONTINUE.match(line)
        if continuation and field is not None:
            chunks.append(continuation.group(1))
            continue

        # Anything else is prose, and ends the current value.
        flush()
    flush()
    return suites


def main():
    source = sys.argv[1] if len(sys.argv) > 1 else None
    text = fetch(source)
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    suites = parse(text)

    cases = []
    for _, name in SUITES:
        vectors = suites.get(name) or []
        if not vectors:
            raise SystemExit(f"no vectors parsed for {name}")
        for index, vector in enumerate(vectors):
            missing = [f for f in FIELDS if f not in vector]
            if missing:
                raise SystemExit(f"{name}[{index}] is missing {missing}")
            for key, expected in LENGTHS[name].items():
                actual = len(vector[key]) // 2
                if actual != expected:
                    raise SystemExit(
                        f"{name}[{index}].{key} is {actual} bytes, "
                        f"the draft says {expected}"
                    )
                if len(vector[key]) % 2:
                    raise SystemExit(f"{name}[{index}].{key} is odd-length hex")
            cases.append(
                {
                    "suite": name,
                    "index": index,
                    "name": f"{name}/appendix-b-{index}",
                    **{key: vector[key] for key in FIELDS},
                }
            )

    document = {
        "version": 1,
        "source": {
            "draft": DRAFT,
            "url": URL,
            "appendix": "B",
            "date": "6 July 2026",
            "sha256_of_draft_text": digest,
            "note": (
                "Every value here is transcribed from the draft. Nothing in "
                "this file was computed by this project. These are the "
                "external anchor for the three CFRG-specified suites."
            ),
        },
        "labels": LABELS,
        "lengths": LENGTHS,
        "fields": {
            "seed": "Nseed-byte seed for DeriveKeyPair",
            "decapsulation_key": "the hybrid decapsulation key, which is the seed",
            "decapsulation_key_pq": "ML-KEM expanded private key (FIPS 203 format)",
            "decapsulation_key_t": (
                "X25519: opaque 32 bytes. NIST curves: the private scalar as a "
                "big-endian integer."
            ),
            "encapsulation_key": "concat(ek_PQ, ek_T)",
            "randomness": "EncapsDerand randomness, PQ first then traditional",
            "ciphertext": "concat(ct_PQ, ct_T)",
            "shared_secret": "the hybrid shared secret",
        },
        "cases": cases,
    }

    with open(OUT, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2)
        handle.write("\n")
    counts = {name: len(suites[name]) for _, name in SUITES}
    print(f"wrote {OUT}: {counts}")


if __name__ == "__main__":
    main()
