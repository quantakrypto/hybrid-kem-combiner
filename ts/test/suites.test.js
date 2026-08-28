// The TypeScript half of the hybrid KEM suite conformance suite.
//
// Three vector files are run here, and they are not the same kind of thing.
//
// vectors/concrete-hybrid-kems-04-appendix-b.json is transcribed from
// Appendix B of draft-irtf-cfrg-concrete-hybrid-kems-04. Nothing in it was
// computed by this project. It is an external anchor.
//
// vectors/mlkem1024-x25519-v1.json is a regression pin. MLKEM1024-X25519 is
// specified only by this project, so no external anchor can exist. Those
// cases prove that the bytes have not drifted and that Rust and TypeScript
// agree, and nothing more.
//
// vectors/x25519-degenerate-v1.json is adversarial. Every group element in it
// is one no honest peer would send: a Curve25519 u-coordinate of small order,
// whose X25519 output is the all-zero string. What those cases pin is that the
// output is absorbed rather than rejected, which is X-Wing's behaviour and so
// a claim about a CFRG specified suite for the MLKEM768-X25519 half of them.
//
// The same three files are run by rust/tests/suites.rs.
//
// There is also a differential check against @noble/post-quantum's own
// MLKEM768-P256, MLKEM768-X25519 and MLKEM1024-P384. That is an independent
// implementation of the same three specifications, so agreement with it is
// evidence about the framework code here. It is not evidence about ML-KEM
// itself, since both implementations get ML-KEM from the same place, which
// is why the published vectors and the Rust crate's libcrux-ml-kem are the
// checks that matter.
//
// Written as plain JavaScript against the built package, so that what is
// tested is exactly what npm publishes.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  ml_kem1024_p384,
  ml_kem768_p256,
  ml_kem768_x25519,
} from '@noble/post-quantum/hybrid.js';
import { ml_kem1024, ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { x25519 } from '@noble/curves/ed25519.js';

import {
  assertPqKemIsCiphertextSecondPreimageResistant,
  combineC2pri,
} from '../dist/index.js';
import {
  MLKEM1024_P384,
  MLKEM1024_X25519,
  MLKEM768_P256,
  MLKEM768_X25519,
  SUITES,
  SuiteError,
  getSuite,
} from '../dist/suites.js';

const read = (name) =>
  JSON.parse(
    readFileSync(
      fileURLToPath(new URL(`../../vectors/${name}`, import.meta.url)),
      'utf8',
    ),
  );

const appendixB = read('concrete-hybrid-kems-04-appendix-b.json');
const pins = read('mlkem1024-x25519-v1.json');
const degenerate = read('x25519-degenerate-v1.json');

const fromHex = (hex) => Uint8Array.from(Buffer.from(hex, 'hex'));
const toHex = (bytes) => Buffer.from(bytes).toString('hex');
const allSuites = Object.values(SUITES);

/** Run one vector end to end: derive, encapsulate, decapsulate. */
function runCase(vector) {
  const suite = getSuite(vector.suite);
  const name = vector.name;

  const keyPair = suite.deriveKeyPair(fromHex(vector.seed));
  assert.equal(
    toHex(keyPair.decapsulationKey),
    vector.decapsulation_key,
    `${name}: decapsulation key`,
  );
  assert.equal(
    toHex(keyPair.encapsulationKey),
    vector.encapsulation_key,
    `${name}: encapsulation key`,
  );

  const encapsulation = suite.encapsulateDerand(
    fromHex(vector.encapsulation_key),
    fromHex(vector.randomness),
  );
  assert.equal(
    toHex(encapsulation.ciphertext),
    vector.ciphertext,
    `${name}: ciphertext`,
  );
  assert.equal(
    toHex(encapsulation.sharedSecret),
    vector.shared_secret,
    `${name}: shared secret from encapsulation`,
  );

  const decapsulated = suite.decapsulate(
    fromHex(vector.decapsulation_key),
    fromHex(vector.ciphertext),
  );
  assert.equal(
    toHex(decapsulated),
    vector.shared_secret,
    `${name}: shared secret from decapsulation`,
  );
}

test('every published CFRG vector matches', () => {
  assert.equal(
    appendixB.cases.length,
    30,
    'Appendix B publishes ten vectors for each of three suites',
  );
  for (const vector of appendixB.cases) runCase(vector);
});

test('the published vectors cover all three CFRG suites', () => {
  for (const suite of allSuites) {
    const count = appendixB.cases.filter((c) => c.suite === suite.name).length;
    if (suite.provenance === 'cfrg-concrete-hybrid-kems') {
      assert.equal(count, 10, `${suite.name} has no published vectors`);
    } else {
      assert.equal(
        count,
        0,
        `${suite.name} cannot have published vectors: nobody else specifies it`,
      );
    }
  }
});

test('the labels match the draft', () => {
  for (const [name, label] of Object.entries(appendixB.labels)) {
    assert.equal(toHex(getSuite(name).label), label, `${name}: label`);
  }
});

test('the lengths match the draft', () => {
  for (const [name, lengths] of Object.entries(appendixB.lengths)) {
    const suite = getSuite(name);
    assert.equal(suite.lengths.seed, lengths.seed, `${name}: Nseed`);
    assert.equal(
      suite.lengths.decapsulationKey,
      lengths.decapsulation_key,
      `${name}: Ndk`,
    );
    assert.equal(
      suite.lengths.encapsulationKey,
      lengths.encapsulation_key,
      `${name}: Nek`,
    );
    assert.equal(suite.lengths.ciphertext, lengths.ciphertext, `${name}: Nct`);
    assert.equal(
      suite.lengths.sharedSecret,
      lengths.shared_secret,
      `${name}: Nss`,
    );
    assert.equal(
      suite.lengths.randomness,
      lengths.randomness,
      `${name}: Nrandom`,
    );
  }
});

test('every MLKEM1024-X25519 regression pin matches', () => {
  assert.equal(
    pins.anchor,
    'none',
    'these vectors must not claim an external anchor',
  );
  assert.ok(pins.cases.length >= 5, 'the pin suite lost cases');
  for (const vector of pins.cases) {
    assert.equal(vector.suite, 'MLKEM1024-X25519');
    runCase(vector);
  }
});

// --- Differential check against an independent implementation --------------

test('the three CFRG suites agree with @noble/post-quantum', () => {
  const oracles = [
    [MLKEM768_P256, ml_kem768_p256],
    [MLKEM768_X25519, ml_kem768_x25519],
    [MLKEM1024_P384, ml_kem1024_p384],
  ];
  for (const [ours, theirs] of oracles) {
    for (let i = 0; i < 8; i += 1) {
      const seed = new Uint8Array(ours.lengths.seed).fill(0x40 + i);
      const randomness = new Uint8Array(ours.lengths.randomness).fill(0x90 + i);

      const mine = ours.deriveKeyPair(seed);
      const yours = theirs.keygen(seed);
      assert.equal(
        toHex(mine.encapsulationKey),
        toHex(yours.publicKey),
        `${ours.name}: encapsulation key disagrees with noble`,
      );

      const myEnc = ours.encapsulateDerand(mine.encapsulationKey, randomness);
      const yourEnc = theirs.encapsulate(yours.publicKey, randomness);
      assert.equal(
        toHex(myEnc.ciphertext),
        toHex(yourEnc.cipherText),
        `${ours.name}: ciphertext disagrees with noble`,
      );
      assert.equal(
        toHex(myEnc.sharedSecret),
        toHex(yourEnc.sharedSecret),
        `${ours.name}: shared secret disagrees with noble`,
      );

      // Cross decapsulation, so that neither implementation is only ever
      // checked against its own ciphertexts.
      assert.equal(
        toHex(ours.decapsulate(mine.decapsulationKey, yourEnc.cipherText)),
        toHex(yourEnc.sharedSecret),
        `${ours.name}: cannot decapsulate noble's ciphertext`,
      );
      assert.equal(
        toHex(theirs.decapsulate(myEnc.ciphertext, yours.secretKey)),
        toHex(myEnc.sharedSecret),
        `${ours.name}: noble cannot decapsulate our ciphertext`,
      );
    }
  }
});

// --- Adversarial group elements --------------------------------------------
//
// X25519 returns 32 zero bytes when the input u-coordinate has small order,
// and neither X-Wing (draft-connolly-cfrg-xwing-kem-10 sections 5.4 and 5.5)
// nor docs/mlkem1024-x25519.md section 3.7 rejects that. MLKEM768-X25519 is
// X-Wing, so half of these cases are a claim about a CFRG specified suite: an
// implementation that rejects here disagrees with every conforming X-Wing
// peer on exactly the inputs an adversary gets to choose.
//
// This is the case that was missing, and its absence is what let this package
// ship a divergence from Rust and from X-Wing: @noble/curves' scalarMult
// refuses the low-order u-coordinates underneath our wrapper, so
// encapsulateDerand threw where it should have returned a shared secret.

/** Swap the last 32 bytes, which is `ek_T` or `ct_T`, for `u`. */
const withElement = (bytes, u) => {
  const out = Uint8Array.from(bytes);
  out.set(u, out.length - 32);
  return out;
};

test('every degenerate X25519 vector matches', () => {
  assert.equal(degenerate.kind, 'adversarial');
  assert.equal(
    degenerate.anchor,
    'none',
    'these vectors must not claim an external anchor',
  );
  assert.equal(
    degenerate.cases.length,
    10,
    'five u-coordinates for each of two suites',
  );

  for (const vector of degenerate.cases) {
    const suite = getSuite(vector.suite);
    const name = vector.name;
    const u = fromHex(vector.u);
    assert.equal(u.length, 32, `${name}: u is a Curve25519 element`);

    const keyPair = suite.deriveKeyPair(fromHex(vector.seed));
    assert.equal(
      toHex(keyPair.encapsulationKey),
      vector.encapsulation_key,
      `${name}: the honest encapsulation key`,
    );
    const randomness = fromHex(vector.randomness);

    // Encapsulation against an attacker-chosen ek_T.
    const encapsulated = suite.encapsulateDerand(
      withElement(keyPair.encapsulationKey, u),
      randomness,
    );
    assert.equal(
      toHex(encapsulated.sharedSecret),
      vector.encapsulation_shared_secret,
      `${name}: shared secret from encapsulation`,
    );

    // Decapsulation of an attacker-chosen ct_T.
    const honest = suite.encapsulateDerand(keyPair.encapsulationKey, randomness);
    const decapsulated = suite.decapsulate(
      keyPair.decapsulationKey,
      withElement(honest.ciphertext, u),
    );
    assert.equal(
      toHex(decapsulated),
      vector.decapsulation_shared_secret,
      `${name}: shared secret from decapsulation`,
    );
  }
});

test('the degenerate vectors cover both Curve25519 suites', () => {
  for (const name of ['MLKEM768-X25519', 'MLKEM1024-X25519']) {
    const count = degenerate.cases.filter((c) => c.suite === name).length;
    assert.equal(count, 5, `${name} has no degenerate vectors`);
  }
});

// The recorded bytes above say the two languages agree. They do not by
// themselves say *what* was fed to the combiner as ss_T, so this rebuilds the
// expected value from the specification's formula with ss_T written out as 32
// zero bytes. ML-KEM comes from @noble/post-quantum directly and the KDF from
// this package's own exported combiner, so nothing in suites.ts contributes
// to the expected side. An implementation that substituted anything else for
// the degenerate shared secret, or that hashed a rejection sentinel, would
// reproduce the file and still fail here.
test('a degenerate ek_T contributes exactly 32 zero bytes as ss_T', () => {
  const kems = { 'MLKEM768-X25519': ml_kem768, 'MLKEM1024-X25519': ml_kem1024 };
  for (const vector of degenerate.cases) {
    const suite = getSuite(vector.suite);
    const kem = kems[vector.suite];
    const u = fromHex(vector.u);
    const keyPair = suite.deriveKeyPair(fromHex(vector.seed));
    const randomness = fromHex(vector.randomness);

    const ekPq = keyPair.encapsulationKey.subarray(
      0,
      suite.lengths.encapsulationKey - 32,
    );
    const message = randomness.subarray(0, 32);
    const seedE = randomness.subarray(32);
    const pq = kem.encapsulate(ekPq, message);
    // ct_T = Exp(g, RandomScalar(seed_E)), and RandomScalar is the identity
    // for Curve25519. The base point is not degenerate, so scalarMultBase
    // needs no special handling and can come straight from @noble/curves.
    const ctT = x25519.scalarMultBase(seedE);

    const expected = combineC2pri(
      'sha3-256',
      {
        pqSharedSecret: pq.sharedSecret,
        traditionalSharedSecret: new Uint8Array(32),
        traditionalCiphertext: ctT,
        traditionalEncapsulationKey: u,
        label: suite.label,
        assertion: assertPqKemIsCiphertextSecondPreimageResistant(),
      },
      32,
    );
    const actual = suite.encapsulateDerand(
      withElement(keyPair.encapsulationKey, u),
      randomness,
    ).sharedSecret;
    assert.equal(
      toHex(actual),
      toHex(expected),
      `${vector.name}: ss_T is not 32 zero bytes`,
    );
    assert.equal(
      toHex(expected),
      vector.encapsulation_shared_secret,
      `${vector.name}: the recorded vector is not what the formula gives`,
    );
  }
});

test('decapsulation of a small-order ct_T is not an error', () => {
  // docs/mlkem1024-x25519.md section 3.6 says Decaps errors only on a wrong
  // length ciphertext. A small-order ct_T is the input most likely to break
  // that claim, so it is the one checked.
  for (const vector of degenerate.cases) {
    const suite = getSuite(vector.suite);
    const keyPair = suite.deriveKeyPair(fromHex(vector.seed));
    const ciphertext = withElement(
      new Uint8Array(suite.lengths.ciphertext),
      fromHex(vector.u),
    );
    assert.doesNotThrow(
      () => suite.decapsulate(keyPair.decapsulationKey, ciphertext),
      `${vector.name}: a small-order ct_T must decapsulate, not throw`,
    );
  }
});

// --- Properties the vectors alone cannot pin -------------------------------

test('every suite round trips', () => {
  for (const suite of allSuites) {
    const keyPair = suite.deriveKeyPair(
      new Uint8Array(suite.lengths.seed).fill(0x5a),
    );
    const sent = suite.encapsulateDerand(
      keyPair.encapsulationKey,
      new Uint8Array(suite.lengths.randomness).fill(0xa5),
    );
    const received = suite.decapsulate(
      keyPair.decapsulationKey,
      sent.ciphertext,
    );
    assert.equal(toHex(sent.sharedSecret), toHex(received), suite.name);
    assert.equal(keyPair.encapsulationKey.length, suite.lengths.encapsulationKey);
    assert.equal(sent.ciphertext.length, suite.lengths.ciphertext);
  }
});

test('generateKeyPair produces working key pairs', () => {
  for (const suite of allSuites) {
    const keyPair = suite.generateKeyPair();
    const sent = suite.encapsulate(keyPair.encapsulationKey);
    const received = suite.decapsulate(
      keyPair.decapsulationKey,
      sent.ciphertext,
    );
    assert.equal(toHex(sent.sharedSecret), toHex(received), suite.name);
  }
});

test('the encapsulation key is recoverable from the decapsulation key', () => {
  for (const suite of allSuites) {
    const keyPair = suite.deriveKeyPair(
      new Uint8Array(suite.lengths.seed).fill(0x31),
    );
    assert.equal(
      toHex(suite.encapsulationKeyFromDecapsulationKey(keyPair.decapsulationKey)),
      toHex(keyPair.encapsulationKey),
      suite.name,
    );
  }
});

test('no two suites agree on a shared secret', () => {
  const seen = new Set();
  for (const suite of allSuites) {
    const keyPair = suite.deriveKeyPair(
      new Uint8Array(suite.lengths.seed).fill(0x77),
    );
    const sent = suite.encapsulateDerand(
      keyPair.encapsulationKey,
      new Uint8Array(suite.lengths.randomness).fill(0x88),
    );
    const hex = toHex(sent.sharedSecret);
    assert.ok(!seen.has(hex), `${suite.name} collided with another suite`);
    seen.add(hex);
  }
});

test('a malformed group element is refused', () => {
  // Only the NIST curves can fail this way: every 32 byte string is a valid
  // Curve25519 u-coordinate.
  for (const suite of [MLKEM768_P256, MLKEM1024_P384]) {
    const keyPair = suite.deriveKeyPair(
      new Uint8Array(suite.lengths.seed).fill(0x13),
    );
    const sent = suite.encapsulateDerand(
      keyPair.encapsulationKey,
      new Uint8Array(suite.lengths.randomness).fill(0x14),
    );
    const broken = Uint8Array.from(sent.ciphertext);
    broken[broken.length - 1] ^= 0xff;
    assert.throws(
      () => suite.decapsulate(keyPair.decapsulationKey, broken),
      (err) => {
        assert.ok(err instanceof SuiteError, `${suite.name}: ${err}`);
        assert.equal(err.code, 'invalid-group-element', suite.name);
        return true;
      },
    );
  }
});

test('wrong lengths are named in the error', () => {
  const suite = MLKEM768_X25519;
  const keyPair = suite.deriveKeyPair(new Uint8Array(32));
  const cases = [
    () => suite.deriveKeyPair(new Uint8Array(31)),
    () => suite.encapsulateDerand(keyPair.encapsulationKey, new Uint8Array(63)),
    () => suite.encapsulateDerand(new Uint8Array(100), new Uint8Array(64)),
    () => suite.decapsulate(keyPair.decapsulationKey, new Uint8Array(1119)),
  ];
  for (const [index, run] of cases.entries()) {
    assert.throws(
      run,
      (err) => {
        assert.ok(err instanceof SuiteError, `case ${index}: ${err}`);
        assert.equal(err.code, 'wrong-length', `case ${index}`);
        assert.match(err.message, /must be \d+ bytes/, `case ${index}`);
        return true;
      },
      `case ${index}`,
    );
  }
});

test('an invalid ML-KEM encapsulation key is refused', () => {
  const suite = MLKEM768_X25519;
  const keyPair = suite.deriveKeyPair(new Uint8Array(32).fill(0x21));
  const ek = Uint8Array.from(keyPair.encapsulationKey);
  // The check of FIPS 203 section 7.2 is that the encoded polynomial
  // coefficients are all below q, so setting the first twelve-bit field to
  // its maximum breaks it.
  ek[0] = 0xff;
  ek[1] = 0xff;
  assert.throws(
    () => suite.encapsulateDerand(ek, new Uint8Array(64)),
    (err) => {
      assert.ok(err instanceof SuiteError);
      assert.equal(err.code, 'invalid-ml-kem-encapsulation-key');
      return true;
    },
  );
});

test('provenance says which suites are externally specified', () => {
  assert.equal(MLKEM768_P256.provenance, 'cfrg-concrete-hybrid-kems');
  assert.equal(MLKEM768_X25519.provenance, 'cfrg-concrete-hybrid-kems');
  assert.equal(MLKEM1024_P384.provenance, 'cfrg-concrete-hybrid-kems');
  assert.equal(MLKEM1024_X25519.provenance, 'this-project-only');
});

test('an unknown suite name is refused rather than returning undefined', () => {
  assert.throws(
    () => getSuite('MLKEM1024-X448'),
    (err) => {
      assert.ok(err instanceof SuiteError);
      assert.equal(err.code, 'unknown-suite');
      return true;
    },
  );
});
