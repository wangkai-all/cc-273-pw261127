#!/usr/bin/env node
// src/cli.js
// Operator CLI for the local rekey workbench.
//
// Commands:
//   init      create data dir, schema, local test keys and fictional rows
//   serve     run the local web workbench (default port 4173)
//   status    print keyring/run/cache/lease state as JSON
//   rekey     drive an in-place rotation to completion
//   verify    verify all ciphertext rows under the active key
//   keys      list keys and destroy-readiness
//   destroy   destroy a key if all conditions are met

import process from "node:process";
import { parseArgs } from "node:util";
import { resolveConfig } from "./config.js";
import { openDb, ensureSchema } from "./db.js";
import { WorkbenchService } from "./service.js";
import { createServer } from "./server.js";
import { ServiceError } from "./service.js";

function usage() {
  return `用法: node src/cli.js <command> [options]

命令:
  init     初始化本地数据目录、密钥、虚构数据（可重复执行，不会覆盖已有数据）
  serve    启动本地网页工作台
  status   输出工作台状态 JSON
  rekey    启动并跑完一次原地轮换
  verify   校验当前活动钥下的全部密文
  keys     列出密钥与销毁条件
  destroy  在条件全部满足后销毁旧钥

选项:
  --data-dir <path>       数据目录（默认 ./data）
  --port <n>              serve 端口（默认 4173）
  --host <addr>           serve 地址（默认 127.0.0.1，仅本机）
  --rows <n>              init 生成行数（默认 240）
  --purpose <p>           analytics|pii|audit
  --chunk-size <n>        每块行数
  --grace-seconds <n>     旧钥退休后的静默期
  --key-id <id>           destroy 目标钥
  --json                  紧凑 JSON 输出
`;
}

async function main(argv) {
  const rawArgs = argv.slice(2);
  if (rawArgs.length === 0 || rawArgs[0] === "--help" || rawArgs[0] === "-h") {
    console.log(usage());
    return 0;
  }
  const command = rawArgs[0];
  const { values } = parseArgs({
    args: rawArgs.slice(1),
    options: {
      "data-dir": { type: "string" },
      port: { type: "string" },
      host: { type: "string" },
      rows: { type: "string" },
      purpose: { type: "string" },
      "chunk-size": { type: "string" },
      "grace-seconds": { type: "string" },
      "key-id": { type: "string" },
      json: { type: "boolean", default: false },
      help: { type: "boolean", default: false },
    },
    allowPositionals: false,
    strict: true,
  });
  if (values.help) {
    console.log(usage());
    return 0;
  }

  const config = resolveConfig({
    dataDir: values["data-dir"],
    graceSeconds: values["grace-seconds"],
  });
  const db = openDb(config.dbPath);
  ensureSchema(db);
  const service = new WorkbenchService({ db, config });

  const close = () => {
    try {
      db.close();
    } catch {
      /* ignore */
    }
  };

  try {
    if (command === "init") {
      const result = service.bootstrap({
        rowCount: Number(values.rows || 240),
        graceSeconds: config.graceSeconds,
      });
      console.log(JSON.stringify(result, null, values.json ? 0 : 2));
      return 0;
    }
    if (command === "serve") {
      const port = Number(values.port || 4173);
      const host = values.host || "127.0.0.1";
      if (host !== "127.0.0.1" && host !== "localhost" && host !== "::1") {
        console.error("拒绝绑定非本机地址：本工作台只应在本机运行。");
        return 2;
      }
      if (!service.status().totalRows) {
        const seeded = service.bootstrap({ rowCount: Number(values.rows || 240) });
        console.log(`[init] seeded ${seeded.rows} fictional rows`);
      }
      const server = createServer(service);
      await new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(port, host, resolve);
      });
      console.log(`rekey workbench: http://${host}:${port}`);
      console.log(`data dir: ${config.dataDir}`);
      console.log(`process instance: ${service.instanceId}`);
      const shutdown = () => {
        server.close(() => {
          close();
          process.exit(0);
        });
        // Do not let a hung socket keep the process alive forever.
        setTimeout(() => process.exit(0), 3000).unref();
      };
      process.on("SIGINT", shutdown);
      process.on("SIGTERM", shutdown);
      await new Promise(() => {});
      return 0;
    }
    if (command === "status") {
      console.log(JSON.stringify(service.status(), null, values.json ? 0 : 2));
      return 0;
    }
    if (command === "keys") {
      const status = service.status();
      console.log(
        JSON.stringify(
          status.keys.map((k) => ({
            keyId: k.key_id,
            purpose: k.purpose,
            status: k.status,
            label: k.label,
            destroyReady: k.readiness?.ready ?? null,
            reasons: k.readiness?.reasons ?? null,
          })),
          null,
          2,
        ),
      );
      return 0;
    }
    if (command === "destroy") {
      if (!values["key-id"]) {
        console.error("需要 --key-id");
        return 2;
      }
      const result = service.destroy({
        keyId: values["key-id"],
        graceSeconds: config.graceSeconds,
      });
      console.log(JSON.stringify(result, null, 2));
      return 0;
    }
    if (command === "verify") {
      const status = service.status();
      if (!status.liveRun) {
        console.error("没有进行中的轮换；无需校验。");
        return 2;
      }
      const result = service.rotateStep(status.liveRun.id, { phase: "verify" });
      console.log(JSON.stringify(result, null, 2));
      return 0;
    }
    if (command === "rekey") {
      const purpose = values.purpose;
      if (!purpose) {
        console.error("需要 --purpose analytics|pii|audit");
        return 2;
      }
      const running = service.status().liveRun;
      if (running) {
        const resumed = service.resume(running.id);
        console.log(JSON.stringify({ resumed: resumed.id, status: resumed.status }, null, 2));
        const out = service.runAll(running.id);
        console.log(JSON.stringify({ run: out.run.status, processed: out.run.processed_rows }, null, 2));
        return out.run.status === "completed" ? 0 : 1;
      }
      const run = service.startRotation({
        purpose,
        chunkSize: Number(values["chunk-size"] || config.defaultChunkSize),
      });
      console.log(JSON.stringify({ started: run.id, from: run.from_key_id, to: run.to_key_id }, null, 2));
      const out = service.runAll(run.id);
      console.log(JSON.stringify({ run: out.run.status, processed: out.run.processed_rows }, null, 2));
      return out.run.status === "completed" ? 0 : 1;
    }
    console.error(`未知命令: ${command}\n`);
    console.error(usage());
    return 2;
  } catch (err) {
    if (err instanceof ServiceError) {
      console.error(JSON.stringify({ error: { code: err.code, message: err.message, details: err } }, null, 2));
      return 1;
    }
    console.error(`[${err?.name || "Error"}] ${err?.message || err}`);
    return 1;
  } finally {
    if (command !== "serve") close();
  }
}

main(process.argv).then((code) => {
  process.exitCode = code;
});
