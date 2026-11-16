import { test } from "node:test";
import assert from "node:assert/strict";
import {
  encryptValue,
  decryptValue,
  envelopeKeyId,
  envelopePurpose,
  encodeKeyId,
  CryptoError,
  CIPHER,
  HEADER_BYTES,
  GCM_TAG_BYTES,
  KEY_ID_OFFSET,
  KEY_ID_BYTES,
} from "../src/crypto.js";
import { randomBytes } from "node:crypto";

const key = randomBytes(32);
const keyId = encodeKeyId(7);
const args = { key, keyId, purpose: "pii", rowId: 42, column: "customer_email" };

test("encrypt/decrypt round-trips UTF-8", () => {
  const plaintext = "客户 a@example.test · 你好 🌏";
  const env = encryptValue(plaintext, args);
  assert.equal(decryptValue(env, { key, purpose: "pii", rowId: 42, column: "customer_email" }), plaintext);
});

test("envelope is self-describing and does not contain plaintext", () => {
  const plaintext = "very-secret-value-123";
  const env = encryptValue(plaintext, args);
  assert.equal(envelopeKeyId(env), keyId);
  assert.equal(envelopePurpose(env), "pii");
  assert.equal(env.subarray(0, 4).toString("ascii"), "RK01");
  assert.equal(env.includes(Buffer.from(plaintext)), false);
  assert.equal(CIPHER, "AES-256-GCM");
  assert.equal(env.length, HEADER_BYTES + plaintext.length + GCM_TAG_BYTES);
});

test("nonces are unique per encryption", () => {
  const a = encryptValue("same", args);
  const b = encryptValue("same", args);
  assert.notEqual(a.subarray(22, 34).toString("hex"), b.subarray(22, 34).toString("hex"));
  assert.notDeepEqual(a, b);
});

test("wrong key is rejected with AUTH_FAILED", () => {
  const env = encryptValue("x", args);
  assert.throws(
    () => decryptValue(env, { key: randomBytes(32), purpose: "pii", rowId: 42, column: "customer_email" }),
    (err) => err instanceof CryptoError && err.code === "AUTH_FAILED",
  );
});

test("cross-purpose decryption is refused before touching the cipher", () => {
  const env = encryptValue("x", args);
  assert.throws(
    () => decryptValue(env, { key, purpose: "analytics", rowId: 42, column: "customer_email" }),
    (err) => err.code === "PURPOSE_MISMATCH",
  );
});

test("AAD binds row and column: moving ciphertext fails auth", () => {
  const env = encryptValue("x", args);
  assert.throws(
    () => decryptValue(env, { key, purpose: "pii", rowId: 43, column: "customer_email" }),
    (err) => err.code === "AUTH_FAILED",
  );
  assert.throws(
    () => decryptValue(env, { key, purpose: "pii", rowId: 42, column: "session_label" }),
    (err) => err.code === "AUTH_FAILED",
  );
});

test("tampered ciphertext fails auth", () => {
  const env = encryptValue("payload", args);
  env[env.length - 20] ^= 0xff;
  assert.throws(() => decryptValue(env, args), (err) => err.code === "AUTH_FAILED");
});

test("tampered key id is detected as auth failure, not silently accepted", () => {
  const env = encryptValue("payload", args);
  env.write(encodeKeyId(9), KEY_ID_OFFSET, KEY_ID_BYTES, "ascii");
  assert.throws(() => decryptValue(env, args), (err) => err.code === "AUTH_FAILED");
});

test("truncated envelope is rejected", () => {
  assert.throws(() => decryptValue(Buffer.alloc(10), args), (err) => err.code === "MALFORMED_ENVELOPE");
});

test("bad purpose / row / column are rejected at encryption", () => {
  assert.throws(() => encryptValue("x", { ...args, purpose: "billing" }), (err) => err.code === "BAD_PURPOSE");
  assert.throws(() => encryptValue("x", { ...args, rowId: 0 }), (err) => err.code === "BAD_ROW_ID");
  assert.throws(() => encryptValue("x", { ...args, column: "" }), (err) => err.code === "BAD_COLUMN");
  assert.throws(() => encryptValue("x", { ...args, key: randomBytes(16) }), (err) => err.code === "BAD_KEY");
});

test("empty string round-trips (not confused with null)", () => {
  const env = encryptValue("", args);
  assert.equal(decryptValue(env, args), "");
});
