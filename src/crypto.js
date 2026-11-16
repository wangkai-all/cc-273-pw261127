// src/crypto.js
// AES-256-GCM envelope primitives using only node:crypto.
//
// Design constraints for this workbench:
//  - Only standard primitives, no home-grown cryptography.
//  - Every ciphertext is self-describing: version, purpose, key id, nonce.
//  - Associated data binds version+purpose+keyId+rowId+column so a blob cannot
//    be silently moved to another column with a different data class.
//  - Secrets (key material, plaintext) never touch temp files.

import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";

export const CIPHER = "AES-256-GCM";
export const ENVELOPE_VERSION = 1;
export const KEY_BYTES = 32;
export const GCM_TAG_BYTES = 16;
export const NONCE_BYTES = 12;
const MAGIC_BYTES = 4;
const KEY_ID_BYTES = 16;
// magic(4) + version(1) + purpose(1) + keyId(16) + nonce(12)
export const HEADER_BYTES = MAGIC_BYTES + 1 + 1 + KEY_ID_BYTES + NONCE_BYTES;
const KEY_ID_OFFSET = MAGIC_BYTES + 1 + 1;
const NONCE_OFFSET = KEY_ID_OFFSET + KEY_ID_BYTES;
const MIN_ENVELOPE_BYTES = HEADER_BYTES + GCM_TAG_BYTES;
const MAGIC = Buffer.from("RK01", "ascii");

export const PURPOSES = Object.freeze(["analytics", "pii", "audit"]);

export class CryptoError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = "CryptoError";
    this.code = code;
    Object.assign(this, details);
  }
}

/** Derive the AAD used to bind a ciphertext to its identity. */
export function buildAad({ purpose, keyId, rowId, column, version = ENVELOPE_VERSION }) {
  if (!PURPOSES.includes(purpose)) {
    throw new CryptoError("BAD_PURPOSE", `unknown purpose: ${purpose}`);
  }
  if (!Number.isInteger(rowId) || rowId < 1) {
    throw new CryptoError("BAD_ROW_ID", "rowId must be a positive integer");
  }
  if (typeof column !== "string" || column.length === 0) {
    throw new CryptoError("BAD_COLUMN", "column must be a non-empty string");
  }
  return Buffer.from(
    JSON.stringify({
      v: version,
      cipher: CIPHER,
      purpose,
      keyId,
      rowId,
      column,
    }),
    "utf8",
  );
}

/**
 * Envelope layout (all lengths fixed, no delimiters):
 *   magic "RK01" | version u8 | purpose u8 | keyId ascii(16) | nonce(12)
 *   | ciphertext(len) | tag(16)
 *
 * keyId is %016x of a monotonic key sequence, so it is always 16 ASCII bytes.
 */
const KEY_ID_RE = /^[0-9a-f]{16}$/;
const PURPOSE_CODE = { analytics: 1, pii: 2, audit: 3 };
const PURPOSE_BY_CODE = { 1: "analytics", 2: "pii", 3: "audit" };

export function encodeKeyId(seq) {
  return seq.toString(16).padStart(16, "0");
}

export function parseKeyId(keyId) {
  return Number.parseInt(keyId, 16);
}

export function isValidKeyId(keyId) {
  return typeof keyId === "string" && KEY_ID_RE.test(keyId);
}

/** Encrypt a UTF-8 string. Returns a Buffer envelope. */
export function encryptValue(plaintext, { key, keyId, purpose, rowId, column }) {
  if (typeof plaintext !== "string") {
    throw new CryptoError("BAD_PLAINTEXT", "plaintext must be a string");
  }
  if (!Buffer.isBuffer(key) || key.length !== KEY_BYTES) {
    throw new CryptoError("BAD_KEY", "key must be 32 raw bytes");
  }
  if (!isValidKeyId(keyId)) {
    throw new CryptoError("BAD_KEY_ID", `keyId must be 16 hex chars, got ${keyId}`);
  }
  const aad = buildAad({ purpose, keyId, rowId, column });
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv(CIPHER, key, nonce, { authTagLength: GCM_TAG_BYTES });
  cipher.setAAD(aad, { plaintextLength: Buffer.byteLength(plaintext, "utf8") });
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  const header = Buffer.alloc(HEADER_BYTES);
  MAGIC.copy(header, 0);
  header.writeUInt8(ENVELOPE_VERSION, MAGIC_BYTES);
  header.writeUInt8(PURPOSE_CODE[purpose], MAGIC_BYTES + 1);
  header.write(keyId, KEY_ID_OFFSET, KEY_ID_BYTES, "ascii");
  nonce.copy(header, NONCE_OFFSET);
  return Buffer.concat([header, ct, tag]);
}

/**
 * Decrypt an envelope. Throws CryptoError with a stable code; never returns
 * partial plaintext and never logs the supplied key or plaintext.
 */
export function decryptValue(envelope, { key, purpose, rowId, column }) {
  if (!Buffer.isBuffer(envelope) || envelope.length < MIN_ENVELOPE_BYTES) {
    throw new CryptoError("MALFORMED_ENVELOPE", "ciphertext envelope is truncated");
  }
  if (!envelope.subarray(0, MAGIC_BYTES).equals(MAGIC)) {
    throw new CryptoError("MALFORMED_ENVELOPE", "bad envelope magic");
  }
  const version = envelope.readUInt8(MAGIC_BYTES);
  if (version !== ENVELOPE_VERSION) {
    throw new CryptoError("UNSUPPORTED_VERSION", `unsupported envelope version ${version}`);
  }
  const purposeCode = envelope.readUInt8(MAGIC_BYTES + 1);
  const envelopePurpose = PURPOSE_BY_CODE[purposeCode];
  if (!envelopePurpose) {
    throw new CryptoError("MALFORMED_ENVELOPE", "unknown purpose code");
  }
  const keyId = envelope.subarray(KEY_ID_OFFSET, KEY_ID_OFFSET + KEY_ID_BYTES).toString("ascii");
  const nonce = envelope.subarray(NONCE_OFFSET, NONCE_OFFSET + NONCE_BYTES);
  const tag = envelope.subarray(envelope.length - GCM_TAG_BYTES);
  const ct = envelope.subarray(NONCE_OFFSET + NONCE_BYTES, envelope.length - GCM_TAG_BYTES);

  if (envelopePurpose !== purpose) {
    throw new CryptoError(
      "PURPOSE_MISMATCH",
      `ciphertext belongs to purpose "${envelopePurpose}", requested "${purpose}"`,
      { envelopePurpose, requestedPurpose: purpose },
    );
  }
  if (!Buffer.isBuffer(key) || key.length !== KEY_BYTES) {
    throw new CryptoError("BAD_KEY", "key must be 32 raw bytes");
  }
  let aad;
  try {
    aad = buildAad({ purpose, keyId, rowId, column, version });
  } catch (err) {
    throw new CryptoError("BAD_AAD", `cannot build AAD: ${err.message}`);
  }
  const decipher = createDecipheriv(CIPHER, key, nonce, { authTagLength: GCM_TAG_BYTES });
  decipher.setAAD(aad, { plaintextLength: ct.length });
  decipher.setAuthTag(tag);
  let pt;
  try {
    pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch {
    // Deliberately opaque: do not leak key material or partial plaintext.
    throw new CryptoError("AUTH_FAILED", "authentication failed (wrong key, purpose, or tampered ciphertext)");
  }
  return pt.toString("utf8");
}

/** Read the key id from an envelope without decrypting. */
export function envelopeKeyId(envelope) {
  if (!Buffer.isBuffer(envelope) || envelope.length < HEADER_BYTES) {
    throw new CryptoError("MALFORMED_ENVELOPE", "ciphertext envelope is truncated");
  }
  return envelope.subarray(KEY_ID_OFFSET, KEY_ID_OFFSET + KEY_ID_BYTES).toString("ascii");
}

/**
 * Best-effort key id for inventory/reporting paths. Returns null (never throws)
 * for truncated or non-buffer values so a corrupt row cannot break a status page.
 */
export function tryEnvelopeKeyId(value) {
  if (value == null) return null;
  const buf = Buffer.isBuffer(value) ? value : Buffer.from(value);
  if (buf.length < HEADER_BYTES) return null;
  if (!buf.subarray(0, MAGIC_BYTES).equals(MAGIC)) return null;
  return buf.subarray(KEY_ID_OFFSET, KEY_ID_OFFSET + KEY_ID_BYTES).toString("ascii");
}

/** Read the purpose from an envelope without decrypting. */
export function envelopePurpose(envelope) {
  if (!Buffer.isBuffer(envelope) || envelope.length < MAGIC_BYTES + 2) {
    throw new CryptoError("MALFORMED_ENVELOPE", "ciphertext envelope is truncated");
  }
  const code = envelope.readUInt8(MAGIC_BYTES + 1);
  const purpose = PURPOSE_BY_CODE[code];
  if (!purpose) throw new CryptoError("MALFORMED_ENVELOPE", "unknown purpose code");
  return purpose;
}

export { KEY_ID_OFFSET, KEY_ID_BYTES, MIN_ENVELOPE_BYTES };

/** Constant-time helper for comparing key fingerprints if ever needed. */
export function safeEqual(a, b) {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b) || a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

/**
 * Fingerprint: SHA-256 truncated, hex. Used in the manifest and UI so operators
 * can identify a key without ever seeing its bytes.
 */
export function fingerprint(key) {
  return createHash("sha256").update(key).digest("hex").slice(0, 16);
}
