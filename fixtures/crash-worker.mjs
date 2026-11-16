// test/fixtures/crash-worker.mjs
// Child process: open an existing workbench, resume the seeded paused run, do a
// few chunks, then SIGKILL itself so no shutdown hooks can run. The parent test
// then asserts the on-disk state is resumable and no row was left half-written.

import process from "node:process";
import { resolveConfig } from "../src/config.js";
import { openDb, ensureSchema } from "../src/db.js";
import { WorkbenchService } from "../src/service.js";
import { findLiveRun, migrateChunk, resumeRun } from "../src/rotation.js";

const dataDir = process.argv[2];
if (!dataDir) {
  console.error("usage: crash-worker.mjs <data-dir>");
  process.exit(2);
}

const config = resolveConfig({ dataDir });
const db = openDb(config.dbPath);
ensureSchema(db);
const service = new WorkbenchService({ db, config });
const live = findLiveRun(db);
if (!live) {
  console.error("no live run to resume");
  process.exit(3);
}
resumeRun(db, live.id);
console.log(`resumed ${live.id} at row ${live.last_row_id}`);

for (let i = 0; i < 3; i += 1) {
  const res = migrateChunk(db, config.keyringDir, live.id, { chunkSize: live.chunk_size });
  console.log(`chunk ${i} migrated=${res.migrated} lastRowId=${res.lastRowId}`);
  if (res.done) break;
}

// Hard kill between chunk transactions: no finally, no WAL checkpoint request,
// no graceful close. This is the "stop the process halfway" scenario.
process.kill(process.pid, "SIGKILL");
