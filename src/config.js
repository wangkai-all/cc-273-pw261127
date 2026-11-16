// src/config.js
import path from "node:path";

export const APP_NAME = "rekey-workbench";
export const APP_VERSION = "1.0.0";
export const SCHEMA_VERSION = 1;

export function resolveConfig(overrides = {}) {
  const dataDir = path.resolve(
    overrides.dataDir || process.env.REKEY_DATA_DIR || path.join(process.cwd(), "data"),
  );
  const graceSecondsRaw = overrides.graceSeconds ?? process.env.REKEY_GRACE_SECONDS ?? "0";
  const graceSeconds = Number(graceSecondsRaw);
  if (!Number.isFinite(graceSeconds) || graceSeconds < 0) {
    throw new Error("REKEY_GRACE_SECONDS must be a non-negative number");
  }
  return {
    dataDir,
    dbPath: path.join(dataDir, "workbench.sqlite"),
    keyringDir: path.join(dataDir, "keyring"),
    graceSeconds,
    defaultChunkSize: 50,
    maxChunkSize: 500,
    maxLeaseTtlMs: 30 * 60 * 1000,
    defaultPinnedLeaseTtlMs: 10 * 60 * 1000,
    queryLeaseTtlMs: 30 * 1000,
    cacheMaxEntries: 5000,
  };
}

export function nowIso() {
  return new Date().toISOString();
}
