// The TypeScript half of the hybrid KEM suite conformance suite.
//
// Two vector files are run here, and they are not the same kind of thing.
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
// The same two files are run by rust/tests/suites.rs.
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
