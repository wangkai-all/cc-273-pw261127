import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { resolveConfig } from "../src/config.js";
import { openDb, ensureSchema } from "../src/db.js";
import { WorkbenchService } from "../src/service.js";
import { decodeBlob } from "../src/db.js";
import { envelopeKeyId } from "../src/crypto.js";

function fresh({ rows = 24 } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rk-write-"));
  const config = resolveConfig({ dataDir: dir, graceSeconds: 0 });
  const db = openDb(config.dbPath);
  ensureSchema(db);
  const service = new WorkbenchService({ db, config });
  service.bootstrap({ rowCount: rows });
  return {
    config, db, service,
    close: () => { db.close(); fs.rmSync(dir, { recursive: true, force: true }); },
  };
}

test("new writes use the active key and bind the real row id", () => {
  const wb = fresh();
  try {
    const before = wb.service.status().purposes.find((p) => p.purpose === "pii");
    const created = wb.service.createEvent({ customerEmail: "fixed@example.test" });
    const row = wb.db.prepare("SELECT customer_email AS v FROM events WHERE id = ?").get(created.id);
    assert.equal(envelopeKeyId(decodeBlob(row.v)), before.activeKeyId);
    // AAD must match the stored id, not a guessed one: decryption succeeds.
    const read = wb.service.readValue({ rowId: created.id, column: "customer_email", useCache: false });
    assert.equal(read.plaintext, "fixed@example.test");
    assert.equal(created.encrypted.customer_email, before.activeKeyId);
  } finally {
    wb.close();
  }
});

test("a mid-rotation write lands on the new key and the walk skips it", () => {
  const wb = fresh({ rows: 40 });
  try {
    const live = wb.service.status().liveRun;
    wb.service.resume(live.id);
    const target = wb.db.prepare("SELECT to_key_id FROM runs WHERE id = ?").get(live.id).to_key_id;
    // Write a brand-new row before the walk reaches high ids.
    const created = wb.service.createEvent({ customerEmail: "mid@example.test" });
    assert.equal(created.encrypted.customer_email, target);
    const out = wb.service.runAll(live.id);
    assert.equal(out.run.status, "completed");
    // The new row is untouched by the walk and still decrypts.
    assert.equal(
      wb.service.readValue({ rowId: created.id, column: "customer_email", useCache: false }).plaintext,
      "mid@example.test",
    );
    // No row anywhere is left under the old key in the live table.
    const dist = wb.service.keyDistribution().customer_email;
    assert.equal(dist[live.from_key_id], undefined);
  } finally {
    wb.close();
  }
});

test("rewriting a single cell moves it to the active key", () => {
  const wb = fresh({ rows: 40 });
  try {
    const live = wb.service.status().liveRun;
    const oldKeyId = live.from_key_id;
    // Pick a row that is still under the old key (the seeded walk migrated a
    // prefix already, so id 1 may be on the new key).
    const candidate = wb.db
      .prepare("SELECT id, customer_email AS v FROM events ORDER BY id")
      .all()
      .find((r) => envelopeKeyId(decodeBlob(r.v)) === oldKeyId);
    assert.ok(candidate, "seed leaves some rows under the old key");
    const targetRow = candidate.id;
    const res = wb.service.rewriteEvent(targetRow, "customer_email");
    assert.equal(res.fromKeyId, oldKeyId);
    assert.equal(res.toKeyId, live.to_key_id);
    assert.equal(
      wb.service.readValue({ rowId: targetRow, column: "customer_email", useCache: false }).keyId,
      live.to_key_id,
    );
  } finally {
    wb.close();
  }
});

test("rewriting under a revoked purpose is refused", () => {
  const wb = fresh();
  try {
    wb.service.revoke("pii");
    assert.throws(() => wb.service.rewriteEvent(1, "customer_email"), /revoked/);
    wb.service.restore("pii");
    const ok = wb.service.rewriteEvent(1, "customer_email");
    assert.ok(ok.toKeyId);
  } finally {
    wb.close();
  }
});
