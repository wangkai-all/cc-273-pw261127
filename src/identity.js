// src/identity.js
// Per-process identity used to tell "this process owns the live run" apart from
// "a previous process died leaving a stale run". A restart must never adopt an
// old run silently; it reconciles it to "interrupted" instead.

import { randomBytes } from "node:crypto";

export const PROCESS_TAG = [
  process.env.HOSTNAME || "local",
  process.pid,
  randomBytes(4).toString("hex"),
].join(":");

export const PROCESS_PID = process.pid;
export const HOST = process.env.HOSTNAME || "local";

export function hostTag() {
  return HOST;
}
