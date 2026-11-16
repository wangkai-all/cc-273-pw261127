import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { resolveConfig } from "../src/config.js";
import { openDb, ensureSchema, decodeBlob } from "../src/db.js";
import { WorkbenchService } from "../src/service.js";
import { activeKeyForPurpose, countSourceReferences, getKeyRecord } from "../src/keyring.js";
import {
  startRun,
  getRun,
  migrateChunk,
  verifyChunk,
  rollbackChunk,
  dropRunBackup,
  resumeRun,
  findLiveRun,
} from "../src/rotation.js";
import { PlaintextCache } from "../src/cache.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export function makeWorkbench({ rows = 40, graceSeconds = 0 } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rk-test-"));
  const config = resolveConfig({ dataDir: dir, graceSeconds });
  const db = openDb(config.dbPath);
  ensureSchema(db);
  const service = new WorkbenchService({ db, config });
  service.bootstrap({ rowCount: rows, rotateSome: true, graceSeconds });
  return { dir, config, db, service, cleanup: () => { try { db.close(); } catch {} fs.rmSync(dir, { recursive: true, force: true }); } };
}

function rotateAll(db, config, runId) {
  for (let i = 0; i < 10_000; i += 1) {
    const run = getRun(db, runId);
    if (run.status === "completed") return run;
    if (run.status === "running") migrateChunk(db, config.keyringDir, runId, { chunkSize: run.chunk_size });
    else if (run.status === "verifying") verifyChunk(db, config.keyringDir, runId, { chunkSize: 50 });
    else return run;
  }
  throw new Error("rotation did not terminate");
}

test("rotation moves every live row to the target key and verifies", async () => {
  const wb = makeWorkbench({ rows: 40 });
  try {
    const live = findLiveRun(wb.db);
    assert.ok(live, "bootstrap leaves a paused run");
    resumeRun(wb.db, live.id);
    const done = rotateAll(wb.db, wb.config, live.id);
    assert.equal(done.status, "completed");
    assert.equal(done.verification_errors, 0);
    const refs = countSourceReferences(wb.db, done.purpose, done.from_key_id);
    assert.equal(refs.live, 0, "no live rows remain under the old key");
    assert.ok(refs.backup > 0, "backup retains pre-images before drop");
    const dst = getKeyRecord(wb.db, done.to_key_id);
    assert.equal(dst.status, "active");
  } finally {
    wb.cleanup();
  }
});

test("two generations coexist and both decrypt through the read path", async () => {
  const wb = makeWorkbench({ rows: 40 });
  try {
    const dist = wb.service.keyDistribution().customer_email;
    assert.ok(Object.keys(dist).length >= 2, "seed produces both generations");
    const rows = wb.service.listEvents({ limit: 40 });
    for (const row of rows.items) {
      assert.equal(typeof row.values.customer_email, "string");
      assert.match(row.values.customer_email, /@example\.test$/);
      assert.equal(typeof row.values.session_label, "string");
      assert.equal(typeof row.values.audit_ref, "string");
    }
  } finally {
    wb.cleanup();
  }
});

test("a chunk failure rolls back atomically and leaves the run recoverable", async () => {
  const wb = makeWorkbench({ rows: 40 });
  try {
    const live = findLiveRun(wb.db);
    resumeRun(wb.db, live.id);
    const first = migrateChunk(wb.db, wb.config.keyringDir, live.id, { chunkSize: 5 });
    assert.ok(first.migrated > 0);
    const before = getRun(wb.db, live.id);

    // Corrupt one not-yet-migrated live row under a third, unknown key id so the
    // chunk hits UNEXPECTED_KEY_ID.
    const { encryptValue, encodeKeyId } = await import("../src/crypto.js");
    const bogusKey = Buffer.alloc(32, 1);
    const bogus = encryptValue("tampered", {
      key: bogusKey,
      keyId: encodeKeyId(99),
      purpose: "pii",
      rowId: before.last_row_id + 1,
      column: "customer_email",
    });
    wb.db
      .prepare("UPDATE events SET customer_email = ? WHERE id = ?")
      .run(new Uint8Array(bogus), before.last_row_id + 1);

    assert.throws(() => migrateChunk(wb.db, wb.config.keyringDir, live.id, { chunkSize: 10 }), /carries key/);
    const after = getRun(wb.db, live.id);
    assert.equal(after.status, "failed");
    assert.equal(after.last_row_id, before.last_row_id, "cursor unchanged by failed chunk");
    assert.equal(after.processed_rows, before.processed_rows, "no partial progress recorded");

    // Repair the row and resume from the same cursor.
    const oldKeyId = before.from_key_id;
    const src = getKeyRecord(wb.db, oldKeyId);
    assert.equal(src.status, "retiring");
    const fixed = encryptValue("repaired", {
      key: (await import("../src/keyring.js")).loadKeyForMigration(wb.db, wb.config.keyringDir, oldKeyId).key,
      keyId: oldKeyId,
      purpose: "pii",
      rowId: before.last_row_id + 1,
      column: "customer_email",
    });
    wb.db.prepare("UPDATE events SET customer_email = ? WHERE id = ?").run(new Uint8Array(fixed), before.last_row_id + 1);
    resumeRun(wb.db, live.id);
    const done = rotateAll(wb.db, wb.config, live.id);
    assert.equal(done.status, "completed");
  } finally {
    wb.cleanup();
  }
});

test("rollback restores pre-images and does not clobber concurrent writes", async () => {
  const wb = makeWorkbench({ rows: 40 });
  try {
    const live = findLiveRun(wb.db);
    resumeRun(wb.db, live.id);
    migrateChunk(wb.db, wb.config.keyringDir, live.id, { chunkSize: 10 });
    const mid = getRun(wb.db, live.id);
    // Concurrent writer rewrites a migrated row under the target key, changing
    // its plaintext after our backup pre-image was taken.
    const targetRow = 3;
    const liveEnv = wb.db.prepare("SELECT customer_email AS v FROM events WHERE id = ?").get(targetRow).v;
    const { decryptValue, encryptValue } = await import("../src/crypto.js");
    const { loadKeyForMigration } = await import("../src/keyring.js");
    const dst = loadKeyForMigration(wb.db, wb.config.keyringDir, mid.to_key_id);
    const pt = decryptValue(decodeBlob(liveEnv), {
      key: dst.key,
      purpose: "pii",
      rowId: targetRow,
      column: "customer_email",
    });
    const newer = encryptValue(`${pt}-newer`, {
      key: dst.key,
      keyId: mid.to_key_id,
      purpose: "pii",
      rowId: targetRow,
      column: "customer_email",
    });
    wb.db.prepare("UPDATE events SET customer_email = ? WHERE id = ?").run(new Uint8Array(newer), targetRow);

    // Force the run into a rollback-eligible state.
    wb.db.prepare("UPDATE runs SET status = 'failed' WHERE id = ?").run(live.id);
    let rb = { done: false };
    for (let i = 0; i < 100 && !rb.done; i += 1) {
      rb = rollbackChunk(wb.db, wb.config.keyringDir, live.id, { chunkSize: 50 });
    }
    assert.equal(rb.done, true);
    const run = getRun(wb.db, live.id);
    assert.equal(run.status, "rolled_back");
    assert.ok(run.rollback_restored > 0, "most rows restored");
    assert.ok(run.rollback_conflicts >= 1, "the concurrently-changed row is a conflict");
    // The concurrently changed row still decrypts to the newer plaintext.
    const val = wb.service.readValue({ rowId: targetRow, column: "customer_email", useCache: false });
    assert.match(val.plaintext, /-newer$/);
    // Restored rows are back under the source key.
    assert.equal(wb.service.keyDistribution().customer_email[mid.from_key_id] >= 9, true);
  } finally {
    wb.cleanup();
  }
});

test("old key cannot be destroyed while backup still holds its ciphertext", async () => {
  const wb = makeWorkbench({ rows: 40 });
  try {
    const live = findLiveRun(wb.db);
    resumeRun(wb.db, live.id);
    rotateAll(wb.db, wb.config, live.id);
    const run = getRun(wb.db, live.id);
    assert.equal(run.status, "completed");
    const oldId = run.from_key_id;
    const readiness = wb.service.keyDestroyReadiness(oldId);
    assert.equal(readiness.ready, false);
    assert.ok(readiness.reasons.some((r) => r.startsWith("backup_rows_still_under_key")));
    assert.throws(() => wb.service.destroy({ keyId: oldId }), /not eligible/);
    dropRunBackup(wb.db, live.id);
    const ready = wb.service.keyDestroyReadiness(oldId);
    assert.deepEqual(ready.reasons, []);
    wb.service.destroy({ keyId: oldId });
    assert.equal(getKeyRecord(wb.db, oldId).status, "destroyed");
  } finally {
    wb.cleanup();
  }
});

test("a backup from one purpose never pins another purpose's key", async () => {
  const wb = makeWorkbench({ rows: 40 });
  try {
    // Finish the seeded pii rotation. Its backup holds customer_email only.
    const live = findLiveRun(wb.db);
    resumeRun(wb.db, live.id);
    rotateAll(wb.db, wb.config, live.id);
    const piiOld = getRun(wb.db, live.id).from_key_id;
    const piiBackup = getRun(wb.db, live.id).backup_table;

    // The pii backup pins the pii key (rollback still possible for that column).
    assert.ok(countSourceReferences(wb.db, "pii", piiOld).backup > 0);

    // Schema-level guarantee: the backup is one column wide, not a row copy.
    const columns = wb.db
      .prepare(`SELECT name FROM pragma_table_info(?)`)
      .all(piiBackup)
      .map((r) => r.name)
      .sort();
    assert.deepEqual(columns, ["customer_email", "id"]);

    // The analytics column still has old-generation live rows, but that does
    // not create a backup reference to the analytics key.
    const analyticsOld = wb.db
      .prepare("SELECT key_id FROM keyring WHERE purpose = 'analytics' AND status = 'retiring'")
      .get();
    assert.ok(analyticsOld, "bootstrap leaves an older analytics key");
    const refs = countSourceReferences(wb.db, "analytics", analyticsOld.key_id);
    assert.equal(refs.backup, 0, "pii backup does not contain session_label");
    assert.ok(refs.live > 0, "analytics column still holds old ciphertext");

    // Exit path: rotate analytics, drop its own backup, then the old key is
    // genuinely destroyable. No unrelated backup table blocks it.
    const run = wb.service.startRotation({ purpose: "analytics", chunkSize: 20 });
    wb.service.runAll(run.id);
    wb.service.dropBackup(run.id);
    assert.deepEqual(wb.service.keyDestroyReadiness(analyticsOld.key_id).reasons, []);
    wb.service.destroy({ keyId: analyticsOld.key_id });
    assert.equal(getKeyRecord(wb.db, analyticsOld.key_id).status, "destroyed");
  } finally {
    wb.cleanup();
  }
});

test("destroy is refused while a query lease pins the old key", async () => {
  const wb = makeWorkbench({ rows: 40 });
  try {
    const live = findLiveRun(wb.db);
    resumeRun(wb.db, live.id);
    rotateAll(wb.db, wb.config, live.id);
    dropRunBackup(wb.db, live.id);
    const oldId = getRun(wb.db, live.id).from_key_id;
    const { acquireLease, releaseLease } = await import("../src/leases.js");
    const lease = acquireLease(wb.db, {
      kind: "manual",
      holder: "test",
      keyId: oldId,
      purpose: "pii",
      column: "customer_email",
      ttlMs: 60_000,
    });
    const readiness = wb.service.keyDestroyReadiness(oldId);
    assert.equal(readiness.ready, false);
    assert.ok(readiness.reasons.some((r) => r.startsWith("active_leases")));
    releaseLease(wb.db, lease.id);
    assert.equal(wb.service.keyDestroyReadiness(oldId).ready, true);
  } finally {
    wb.cleanup();
  }
});

test("revocation purges cache and blocks reads/writes", async () => {
  const wb = makeWorkbench({ rows: 40 });
  try {
    const first = wb.service.readValue({ rowId: 1, column: "customer_email" });
    assert.equal(first.source, "db");
    const second = wb.service.readValue({ rowId: 1, column: "customer_email" });
    assert.equal(second.source, "cache");
    const revoked = wb.service.revoke("pii");
    assert.ok(revoked.cachePurged >= 1);
    assert.throws(() => wb.service.readValue({ rowId: 1, column: "customer_email" }), /revoked/);
    assert.throws(() => wb.service.createEvent({}), /revoked/);
    // Restore allows reads again, and the old cache is gone (fresh DB read).
    wb.service.restore("pii");
    const after = wb.service.readValue({ rowId: 1, column: "customer_email" });
    assert.equal(after.source, "db");
  } finally {
    wb.cleanup();
  }
});

test("cache refuses entries for destroyed keys even if not explicitly purged", async () => {
  const cache = new PlaintextCache();
  cache.set({ purpose: "pii", column: "customer_email", rowId: 1, keyId: "0000000000000001", plaintext: "x" });
  assert.equal(
    cache.get({ purpose: "pii", column: "customer_email", rowId: 1, keyId: "0000000000000001", keyStatus: "destroyed", revoked: false }),
    null,
  );
  cache.set({ purpose: "pii", column: "customer_email", rowId: 2, keyId: "0000000000000001", plaintext: "y" });
  assert.equal(
    cache.get({ purpose: "pii", column: "customer_email", rowId: 2, keyId: "0000000000000001", keyStatus: "active", revoked: true }),
    null,
  );
});

test("crash in the middle of rotation is resumable from the persisted cursor", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rk-crash-"));
  try {
    const script = path.join(__dirname, "..", "fixtures", "crash-worker.mjs");
    const init = spawn(process.execPath, [path.join(__dirname, "..", "src", "cli.js"), "init", "--data-dir", dir, "--rows", "120"], {
      cwd: path.join(__dirname, ".."),
      stdio: ["ignore", "pipe", "pipe"],
    });
    await new Promise((resolve, reject) => {
      init.on("exit", (code) => (code === 0 ? resolve() : reject(new Error(`init exited ${code}`))));
    });

    // Worker runs a few chunks then SIGKILLs itself between transactions.
    const worker = spawn(process.execPath, [script, dir], {
      cwd: path.join(__dirname, ".."),
      stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    worker.stdout.on("data", (d) => { out += d.toString(); });
    const code = await new Promise((resolve) => worker.on("exit", (c, sig) => resolve(sig || c)));
    assert.equal(code, "SIGKILL", `worker should die by SIGKILL, got ${code}; output=${out}`);

    const config = resolveConfig({ dataDir: dir });
    const db = openDb(config.dbPath);
    ensureSchema(db);
    const service = new WorkbenchService({ db, config });
    const live = findLiveRun(db);
    assert.ok(live, "a live run row survived the crash");
    assert.equal(live.status, "interrupted", "startup reconciliation marks it interrupted");
    assert.ok(live.last_row_id > 0, "cursor persisted at least one chunk");

    // Every row still decrypts: no half-written chunk.
    const listed = service.listEvents({ limit: 200, decrypt: true });
    assert.equal(listed.items.filter((r) => r.errors).length, 0, "no unreadable rows after crash");

    service.resume(live.id);
    const done = service.runAll(live.id);
    assert.equal(done.run.status, "completed");
    assert.equal(done.run.verification_errors, 0);
    const refs = countSourceReferences(db, done.run.purpose, done.run.from_key_id);
    assert.equal(refs.live, 0);
    db.close();
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
