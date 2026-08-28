/**
 * A generic, standalone hybrid KEM combiner.
 *
 * When you build a hybrid KEM you run two independent key encapsulation
 * mechanisms, one post-quantum and one traditional, and you end up holding
 * two shared secrets. The combiner is the function that turns them into the
 * one key you actually use. It is the only place in a hybrid where "if either
 * component is secure, the whole thing is secure" is either achieved or lost.
 *
 * The construction:
 *
 *     UniversalCombiner(ss_PQ, ss_T, ct_PQ, ct_T, ek_PQ, ek_T, label)
 *         = KDF(ss_PQ || ss_T || ct_PQ || ct_T || ek_PQ || ek_T || label)
 *
 * specified as Expression (15) of NIST SP 800-227 section 4.6.2 (September
 * 2025) and as `UniversalCombiner` in draft-irtf-cfrg-hybrid-kems-12 section
 * 5.1.3.
 *
 * This package is byte for byte identical to the `hybrid-kem-combiner` Rust
 * crate. Both are tested against the same conformance vectors.
 *
 * It implements a specified construction. The implementation itself has had
 * no external cryptographic review. See the repository README.
 *
 * @packageDocumentation
 */

import { hmac } from '@noble/hashes/hmac.js';
import { expand } from '@noble/hashes/hkdf.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { sha3_256 } from '@noble/hashes/sha3.js';

/** Length of an HMAC-SHA512 output, in bytes. */
const HMAC_SHA512_LEN = 64;
/** Length of a SHA3-256 digest, in bytes. */
const SHA3_256_LEN = 32;
/** RFC 5869 caps HKDF output at 255 times the hash length. */
const HKDF_SHA512_MAX = 255 * HMAC_SHA512_LEN;

/**
 * Which key derivation function the combiner uses, and, for HKDF, where the
 * label goes.
 *
 * - `sha3-256`: `SHA3-256(inputs || label)`, exactly 32 bytes out. This is
 *   what X-Wing, the CFRG concrete instantiations and the LAMPS composite
 *   KEMs use, and the family SP 800-227 names in its worked example. If you
 *   want to interoperate with anything published, use this one.
 * - `hkdf-sha512-label-as-info`: HKDF-SHA512, salt absent, `ikm` the
 *   concatenated inputs without the label, `info` the label.
 * - `hkdf-sha512-label-in-ikm`: HKDF-SHA512, salt absent, `ikm` the
 *   concatenated inputs with the label appended, `info` empty. This is the
 *   literal reading of `KDF(concat(..., label))`.
 *
 * An absent salt is RFC 5869's absent salt, which HKDF-Extract replaces with
 * `HashLen` zero bytes, so 64 zero bytes here. It is not a zero length salt,
 * and the two produce different keys.
 *
 * The choice is a parameter at every call site on purpose: two
 * implementations that agree on the construction and disagree on the KDF
 * produce different keys and no diagnosable error.
 */
export type Kdf =
  | 'sha3-256'
  | 'hkdf-sha512-label-as-info'
  | 'hkdf-sha512-label-in-ikm';

/** Every supported KDF, in a form you can iterate. */
export const KDFS: readonly Kdf[] = [
  'sha3-256',
  'hkdf-sha512-label-as-info',
  'hkdf-sha512-label-in-ikm',
];

/** The name of an input, as it appears in the standards. */
export type InputName =
  | 'ss_PQ'
  | 'ss_T'
  | 'ct_PQ'
  | 'ct_T'
  | 'ek_PQ'
  | 'ek_T'
  | 'label';

/** What kind of caller error occurred. */
export type ErrorCode =
  | 'empty-input'
  | 'unsupported-output-length'
  | 'hkdf-domain-separation';

/**
 * A caller error, thrown before any key material is derived.
 *
 * `code` mirrors the `error` field of the shared conformance vectors and the
 * variants of the Rust crate's `Error` enum.
 */
export class CombinerError extends Error {
  readonly code: ErrorCode;
  /** Which input was at fault, for `empty-input`. */
  readonly input?: InputName;

  constructor(code: ErrorCode, message: string, input?: InputName) {
    super(message);
    this.name = 'CombinerError';
    this.code = code;
    this.input = input;
  }
}

/** The six inputs of the universal combiner, plus the label. */
export interface UniversalInputs {
  /** `ss_PQ`, the post-quantum shared secret. */
  pqSharedSecret: Uint8Array;
  /** `ss_T`, the traditional shared secret. */
  traditionalSharedSecret: Uint8Array;
  /** `ct_PQ`, the post-quantum ciphertext. */
  pqCiphertext: Uint8Array;
  /** `ct_T`, the traditional ciphertext. */
  traditionalCiphertext: Uint8Array;
  /** `ek_PQ`, the post-quantum encapsulation key. */
  pqEncapsulationKey: Uint8Array;
  /** `ek_T`, the traditional encapsulation key. */
  traditionalEncapsulationKey: Uint8Array;
  /**
   * The domain separation label.
   *
   * SP 800-227 section 4.6.3 asks that it "uniquely identify the composite
   * scheme in use". Because the inputs are concatenated without length
   * prefixes, the label pinning both parameter sets is what makes the
   * encoding unambiguous. This library cannot check that for you.
   */
  label: Uint8Array;
}

const C2PRI_BRAND: unique symbol = Symbol('hybrid-kem-combiner.c2pri');

/**
 * A statement, which only you can make, that your post-quantum KEM is
 * ciphertext second preimage resistant.
 *
 * The only way to obtain one is
 * {@link assertPqKemIsCiphertextSecondPreimageResistant}. Read its
 * documentation before you call it.
 */
export interface C2priAssertion {
  readonly [C2PRI_BRAND]: true;
}

/**
 * Assert that the post-quantum KEM you are combining is ciphertext second
 * preimage resistant, unlocking {@link combineC2pri}.
 *
 * The C2PRI combiner drops `ct_PQ` and `ek_PQ` from the derivation. That is
 * sound only if the post-quantum KEM is C2PRI: given an honest key pair,
 * ciphertext and shared secret, no adversary can find a second ciphertext
 * that decapsulates to the same shared secret. ML-KEM is believed to satisfy
 * this because of the specifics of the Fujisaki-Okamoto transform it uses,
 * and X-Wing's security argument rests on exactly that. It is a property of
 * your KEM, not of this package, and this package has no way to check it.
 *
 * draft-connolly-cfrg-xwing-kem-10 section 6 states the risk directly: "the
 * X-Wing combiner cannot be assumed to be secure, when used with different
 * KEMs. In particular it is not known to be safe to leave out the
 * post-quantum ciphertext from the combiner in the general case."
 *
 * If you are not certain, use {@link combineUniversal}. It costs one extra
 * pass over the ciphertext and encapsulation key and it assumes nothing.
 */
export function assertPqKemIsCiphertextSecondPreimageResistant(): C2priAssertion {
  return { [C2PRI_BRAND]: true };
}

/** The four inputs of the C2PRI combiner, plus the label and the assertion. */
export interface C2priInputs {
  /** `ss_PQ`, the post-quantum shared secret. */
  pqSharedSecret: Uint8Array;
  /** `ss_T`, the traditional shared secret. */
  traditionalSharedSecret: Uint8Array;
  /** `ct_T`, the traditional ciphertext. */
  traditionalCiphertext: Uint8Array;
  /** `ek_T`, the traditional encapsulation key. */
  traditionalEncapsulationKey: Uint8Array;
  /** The domain separation label. */
  label: Uint8Array;
  /** Your statement that the post-quantum KEM is C2PRI. */
  assertion: C2priAssertion;
}

function requireBytes(value: unknown, which: InputName): Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`combiner input ${which} must be a Uint8Array`);
  }
  if (value.length === 0) {
    throw new CombinerError(
      'empty-input',
      `combiner input ${which} is empty`,
      which,
    );
  }
  return value;
}

function outputBounds(kdf: Kdf): { min: number; max: number } {
  return kdf === 'sha3-256'
    ? { min: SHA3_256_LEN, max: SHA3_256_LEN }
    : { min: 1, max: HKDF_SHA512_MAX };
}

/**
 * Enforce the HKDF input domain disjointness condition of
 * draft-irtf-cfrg-hybrid-kems-12 section 6.1.5. The draft says
 * instantiations MUST enforce it, so it is enforced rather than assumed.
 */
function checkHkdfDomains(ikmLen: number, infoLen: number): void {
  if (ikmLen === infoLen + 1 || ikmLen === infoLen + 1 + HMAC_SHA512_LEN) {
    throw new CombinerError(
      'hkdf-domain-separation',
      `HKDF input domains are not disjoint for ikm_len=${ikmLen} and ` +
        `info_len=${infoLen}`,
    );
  }
}

/**
 * Absorb `parts` and `label` and return `outputLength` bytes of key.
 *
 * Parts are absorbed in order, straight into the hash or HMAC state. Nothing
 * is concatenated into an intermediate buffer, so there is no copy of the
 * shared secrets left behind for the garbage collector.
 */
function derive(
  kdf: Kdf,
  parts: Uint8Array[],
  label: Uint8Array,
  outputLength: number,
): Uint8Array {
  const { min, max } = outputBounds(kdf);
  if (
    !Number.isInteger(outputLength) ||
    outputLength < min ||
    outputLength > max
  ) {
    throw new CombinerError(
      'unsupported-output-length',
      `requested output length ${outputLength} is outside the range ` +
        `${min}..=${max} supported by ${kdf}`,
    );
  }

  if (kdf === 'sha3-256') {
    const hasher = sha3_256.create();
    for (const part of parts) hasher.update(part);
    hasher.update(label);
    return hasher.digest();
  }

  const labelInIkm = kdf === 'hkdf-sha512-label-in-ikm';
  let ikmLen = 0;
  for (const part of parts) ikmLen += part.length;
  if (labelInIkm) ikmLen += label.length;
  const info = labelInIkm ? new Uint8Array(0) : label;
  checkHkdfDomains(ikmLen, info.length);

  // RFC 5869 HKDF-Extract with an absent salt, which is HashLen zero bytes.
  const extractor = hmac.create(sha512, new Uint8Array(HMAC_SHA512_LEN));
  for (const part of parts) extractor.update(part);
  if (labelInIkm) extractor.update(label);
  const prk = extractor.digest();

  try {
    return expand(sha512, prk, info, outputLength);
  } finally {
    prk.fill(0);
  }
}

/**
 * The universal combiner:
 * `KDF(ss_PQ || ss_T || ct_PQ || ct_T || ek_PQ || ek_T || label)`.
 *
 * Preserves IND-CCA as long as at least one component KEM is IND-CCA, with no
 * further assumption about either component. This is the form to use unless
 * you have a specific reason not to.
 *
 * @param kdf - which KDF to instantiate the combiner with
 * @param inputs - the six KEM inputs and the label
 * @param outputLength - bytes of key to derive, 32 by default
 * @throws {CombinerError} if an input is empty, the output length is not
 *   supported by the KDF, or the HKDF domain condition fails
 */
export function combineUniversal(
  kdf: Kdf,
  inputs: UniversalInputs,
  outputLength = 32,
): Uint8Array {
  const parts = [
    requireBytes(inputs.pqSharedSecret, 'ss_PQ'),
    requireBytes(inputs.traditionalSharedSecret, 'ss_T'),
    requireBytes(inputs.pqCiphertext, 'ct_PQ'),
    requireBytes(inputs.traditionalCiphertext, 'ct_T'),
    requireBytes(inputs.pqEncapsulationKey, 'ek_PQ'),
    requireBytes(inputs.traditionalEncapsulationKey, 'ek_T'),
  ];
  const label = requireBytes(inputs.label, 'label');
  return derive(kdf, parts, label, outputLength);
}

/**
 * The C2PRI combiner: `KDF(ss_PQ || ss_T || ct_T || ek_T || label)`.
 *
 * The optimised form. It omits the post-quantum ciphertext and encapsulation
 * key, which for ML-KEM-1024 is 1568 plus 1568 bytes that do not have to be
 * hashed. The resulting hybrid KEM is secure if the post-quantum component is
 * IND-CCA, or if the traditional component is secure and the post-quantum
 * component is also C2PRI.
 *
 * With `sha3-256` and the six byte X-Wing label this is byte for byte the
 * X-Wing combiner, and the conformance vectors check exactly that against the
 * X-Wing draft's own test vectors.
 *
 * @param kdf - which KDF to instantiate the combiner with
 * @param inputs - the four KEM inputs, the label, and your C2PRI assertion
 * @param outputLength - bytes of key to derive, 32 by default
 * @throws {CombinerError} on the same conditions as {@link combineUniversal}
 * @throws {TypeError} if `assertion` did not come from
 *   {@link assertPqKemIsCiphertextSecondPreimageResistant}
 */
export function combineC2pri(
  kdf: Kdf,
  inputs: C2priInputs,
  outputLength = 32,
): Uint8Array {
  if (inputs.assertion?.[C2PRI_BRAND] !== true) {
    throw new TypeError(
      'combineC2pri requires an assertion from ' +
        'assertPqKemIsCiphertextSecondPreimageResistant(). The C2PRI form is ' +
        'only sound for a ciphertext second preimage resistant PQ KEM; if you ' +
        'are not certain yours is, call combineUniversal instead.',
    );
  }
  const parts = [
    requireBytes(inputs.pqSharedSecret, 'ss_PQ'),
    requireBytes(inputs.traditionalSharedSecret, 'ss_T'),
    requireBytes(inputs.traditionalCiphertext, 'ct_T'),
    requireBytes(inputs.traditionalEncapsulationKey, 'ek_T'),
  ];
  const label = requireBytes(inputs.label, 'label');
  return derive(kdf, parts, label, outputLength);
}
