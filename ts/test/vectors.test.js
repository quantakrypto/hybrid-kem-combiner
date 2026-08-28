// The TypeScript half of the shared conformance suite.
//
// Every case in vectors/hybrid-kem-combiner-v1.json is run here and, by the
// identical suite in rust/tests/vectors.rs, in Rust. The file is the contract
// between the two.
//
// Written as plain JavaScript against the built package, so that what is
// tested is exactly what npm publishes.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  KDFS,
  CombinerError,
  assertPqKemIsCiphertextSecondPreimageResistant,
  combineC2pri,
  combineUniversal,
} from '../dist/index.js';

const VECTORS = fileURLToPath(
  new URL('../../vectors/hybrid-kem-combiner-v1.json', import.meta.url),
);
const doc = JSON.parse(readFileSync(VECTORS, 'utf8'));

const fromHex = (hex) => Uint8Array.from(Buffer.from(hex, 'hex'));
const toHex = (bytes) => Buffer.from(bytes).toString('hex');

function runCase(vector) {
  const input = (name) => fromHex(vector.inputs[name]);
  const length = vector.output_length;
  if (vector.form === 'universal') {
    return combineUniversal(
      vector.kdf,
      {
        pqSharedSecret: input('ss_pq'),
        traditionalSharedSecret: input('ss_t'),
        pqCiphertext: input('ct_pq'),
        traditionalCiphertext: input('ct_t'),
        pqEncapsulationKey: input('ek_pq'),
        traditionalEncapsulationKey: input('ek_t'),
        label: input('label'),
      },
      length,
    );
  }
  if (vector.form === 'c2pri') {
    return combineC2pri(
      vector.kdf,
      {
        pqSharedSecret: input('ss_pq'),
        traditionalSharedSecret: input('ss_t'),
        traditionalCiphertext: input('ct_t'),
        traditionalEncapsulationKey: input('ek_t'),
        label: input('label'),
        assertion: assertPqKemIsCiphertextSecondPreimageResistant(),
      },
      length,
    );
  }
  throw new Error(`unknown form in vectors: ${vector.form}`);
}

test('every vector case matches', () => {
  assert.ok(doc.cases.length >= 15, 'the suite lost cases');
  for (const vector of doc.cases) {
    assert.equal(toHex(runCase(vector)), vector.output, vector.name);
  }
});

test('every vector publishes the kdf input this package builds', () => {
  for (const vector of doc.cases) {
    const parts = [vector.inputs.ss_pq, vector.inputs.ss_t];
    if (vector.form === 'universal') parts.push(vector.inputs.ct_pq);
    parts.push(vector.inputs.ct_t);
    if (vector.form === 'universal') parts.push(vector.inputs.ek_pq);
    parts.push(vector.inputs.ek_t);
    if (vector.kdf !== 'hkdf-sha512-label-as-info') {
      parts.push(vector.inputs.label);
    }
    assert.equal(
      parts.join(''),
      vector.intermediates.kdf_input_hex,
      vector.name,
    );
  }
});

test('every negative case is refused', () => {
  assert.equal(doc.negative_cases.length, 4);
  for (const vector of doc.negative_cases) {
    assert.throws(
      () => runCase(vector),
      (err) => {
        assert.ok(err instanceof CombinerError, `${vector.name}: ${err}`);
        assert.equal(err.code, vector.error, vector.name);
        return true;
      },
      vector.name,
    );
  }
});

// --- Properties the vectors alone cannot pin -------------------------------

const sample = () => ({
  pqSharedSecret: new Uint8Array(32).fill(0x11),
  traditionalSharedSecret: new Uint8Array(32).fill(0x22),
  pqCiphertext: new Uint8Array(1088).fill(0x33),
  traditionalCiphertext: new Uint8Array(32).fill(0x44),
  pqEncapsulationKey: new Uint8Array(1184).fill(0x55),
  traditionalEncapsulationKey: new Uint8Array(32).fill(0x66),
  label: new TextEncoder().encode('example.org/v1/ml-kem-768+x25519'),
});

test('every input is bound', () => {
  for (const kdf of KDFS) {
    const baseline = toHex(combineUniversal(kdf, sample()));
    for (const field of Object.keys(sample())) {
      const mutated = sample();
      mutated[field][0] ^= 0xff;
      assert.notEqual(
        toHex(combineUniversal(kdf, mutated)),
        baseline,
        `${field} does not reach the output under ${kdf}`,
      );
    }
  }
});

test('the combiner is not symmetric in its shared secrets', () => {
  const base = sample();
  const swapped = sample();
  swapped.pqSharedSecret = base.traditionalSharedSecret;
  swapped.traditionalSharedSecret = base.pqSharedSecret;
  assert.notEqual(
    toHex(combineUniversal('sha3-256', swapped)),
    toHex(combineUniversal('sha3-256', base)),
  );
});

test('the two forms disagree', () => {
  const base = sample();
  const universal = combineUniversal('sha3-256', base);
  const c2pri = combineC2pri('sha3-256', {
    pqSharedSecret: base.pqSharedSecret,
    traditionalSharedSecret: base.traditionalSharedSecret,
    traditionalCiphertext: base.traditionalCiphertext,
    traditionalEncapsulationKey: base.traditionalEncapsulationKey,
    label: base.label,
    assertion: assertPqKemIsCiphertextSecondPreimageResistant(),
  });
  assert.notEqual(toHex(universal), toHex(c2pri));
});

test('the three kdfs disagree', () => {
  const outputs = KDFS.map((kdf) => toHex(combineUniversal(kdf, sample())));
  assert.equal(new Set(outputs).size, KDFS.length);
});

test('the c2pri form cannot be reached without the assertion', () => {
  const base = sample();
  const inputs = {
    pqSharedSecret: base.pqSharedSecret,
    traditionalSharedSecret: base.traditionalSharedSecret,
    traditionalCiphertext: base.traditionalCiphertext,
    traditionalEncapsulationKey: base.traditionalEncapsulationKey,
    label: base.label,
  };
  assert.throws(() => combineC2pri('sha3-256', inputs), TypeError);
  // A hand rolled object shaped like an assertion is not one: the brand is a
  // module private symbol.
  assert.throws(
    () => combineC2pri('sha3-256', { ...inputs, assertion: { branded: true } }),
    TypeError,
  );
});

test('an empty input is named in the error', () => {
  const base = sample();
  base.traditionalEncapsulationKey = new Uint8Array(0);
  assert.throws(
    () => combineUniversal('sha3-256', base),
    (err) => {
      assert.ok(err instanceof CombinerError);
      assert.equal(err.code, 'empty-input');
      assert.equal(err.input, 'ek_T');
      return true;
    },
  );
});

test('a non Uint8Array input is a TypeError, not a silent coercion', () => {
  const base = sample();
  base.pqSharedSecret = 'not bytes';
  assert.throws(() => combineUniversal('sha3-256', base), TypeError);
});
