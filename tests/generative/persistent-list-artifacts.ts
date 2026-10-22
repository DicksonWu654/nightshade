/** Strict, bounded evidence files for the fixed owned List fixture; no saved code or paths are executed. */
import { closeSync, constants, fstatSync, fsyncSync, openSync, readFileSync, readSync, writeSync } from "node:fs";
import { basename, dirname, resolve } from "node:path";
import type { ExecutionLimits } from "../../src/runtime/process.js";
import { buildIdentity, type BuildIdentity } from "./artifacts.js";
import {
  persistentListDigest, PERSISTENT_LIST_LOCK_SHA256, PERSISTENT_LIST_MANIFEST_SHA256, PERSISTENT_LIST_SOURCE_SHA256,
  validatePersistentListResult, validatePersistentListSequence, type PersistentListResult, type PersistentListSequence,
} from "./persistent-list-model.js";
import { validatePersistentListLimits } from "./persistent-list-runtime.js";

export interface PersistentListIdentity extends BuildIdentity {
  runtimeLockSha256: string; runtimeInputsManifestSha256: string;
  listWorkerSourceSha256: string; listWorkerBuildSha256: string; listFixtureSha256: string;
}
export interface PersistentListArtifact {
  schemaVersion: "nightshade-owned-persistent-list-case-1";
  purpose: "owned-fixture-runtime-properties";
  executionLayer: "compiled-evaluation-only";
  identity: PersistentListIdentity; sequence: PersistentListSequence;
  limits: Required<ExecutionLimits>; result: PersistentListResult;
}
export interface PersistentListArtifactReference { name: string; sha256: string; bytes: number }
export interface PersistentListArtifactRead { artifact: PersistentListArtifact; originalBytes: Buffer; sha256: string; bytes: number }
export const PERSISTENT_LIST_FILE_BYTES = 1048576;
const identityKeys = [
  "analyzerSourceSha256", "harnessSourceSha256", "builtJavaScriptSha256", "parserRuntimeSha256", "compilerSha256",
  "compilerDistributionSha256", "semanticProfile", "node", "platform", "arch", "runtimeLockSha256", "runtimeInputsManifestSha256",
  "listWorkerSourceSha256", "listWorkerBuildSha256", "listFixtureSha256",
] as const;
const sha = (path: string): string => persistentListDigest(readFileSync(path));

function record(value: unknown, keys: readonly string[], label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new Error(`Invalid List ${label}`);
  const own = Reflect.ownKeys(value);
  if (own.length !== keys.length || own.some(key => typeof key !== "string" || !keys.includes(key))) throw new Error(`Invalid List ${label} fields`);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key)!;
    if (!("value" in descriptor) || !descriptor.enumerable) throw new Error(`Invalid List ${label} accessor/hidden data field`);
  }
  return value as Record<string, unknown>;
}
function filePath(path: string): string {
  if (typeof path !== "string" || !path || path.includes("\0")) throw new Error("Expected a nonempty List artifact path without NUL");
  return resolve(path);
}
function noFollow(): number {
  // Fail closed where the OS cannot enforce final-component no-follow opening.
  if (typeof constants.O_NOFOLLOW !== "number" || constants.O_NOFOLLOW === 0) throw new Error("List artifact no-follow file opening is unavailable on this platform");
  return constants.O_NOFOLLOW;
}
/** Only call with the detached, strictly validated artifact tree. */
function encodedArtifact(artifact: PersistentListArtifact): Buffer {
  const bytes = Buffer.from(`${JSON.stringify(artifact)}\n`, "utf8");
  if (bytes.length > PERSISTENT_LIST_FILE_BYTES) throw new Error("List artifact exceeds 1 MiB");
  return bytes;
}

/** An identity's shape and fixed pins are checked independently of saved claims. */
export function validatePersistentListIdentity(value: unknown): PersistentListIdentity {
  const identity = record(value, identityKeys, "identity");
  const detached: Record<string, string> = {};
  for (const key of identityKeys) {
    const entry = identity[key];
    if (typeof entry !== "string" || !entry || entry.length > 256 || entry.trim() !== entry || key.endsWith("Sha256") && (entry.length !== 64 || !/^[a-f0-9]{64}$/.test(entry))) throw new Error(`Invalid List identity ${key}`);
    detached[key] = entry;
  }
  if (detached.semanticProfile !== "compact-0.34.0-zkir2" || !/^v\d+\.\d+\.\d+$/.test(detached.node)) throw new Error("Unqualified List semantic profile/Node identity");
  if (!/^[a-z0-9_+-]+$/.test(detached.platform) || !/^[a-z0-9_+-]+$/.test(detached.arch)) throw new Error("Invalid List platform/architecture identity");
  if (detached.listFixtureSha256 !== PERSISTENT_LIST_SOURCE_SHA256 || detached.runtimeLockSha256 !== PERSISTENT_LIST_LOCK_SHA256 || detached.runtimeInputsManifestSha256 !== PERSISTENT_LIST_MANIFEST_SHA256) throw new Error("Unqualified fixed List fixture/runtime identity");
  return detached as unknown as PersistentListIdentity;
}

/** Run from the repository root; hashes actual source/build/input files without executing the compiler. */
export function persistentListBuildIdentity(compiler: string, runtimeDirectory: string): PersistentListIdentity {
  if (typeof compiler !== "string" || !compiler || typeof runtimeDirectory !== "string" || !runtimeDirectory) throw new Error("List build identity requires compiler and runtime paths");
  const listFixtureSha256 = sha("tests/runtime-fixtures/list-guarded.compact");
  const runtimeInputsManifestSha256 = sha("tests/runtime-fixtures/runtime-inputs.json");
  const repositoryLockSha256 = sha("tests/runtime-fixtures/qualification-inputs/package-lock.json");
  const runtimeLockSha256 = sha(resolve(runtimeDirectory, "package-lock.json"));
  if (listFixtureSha256 !== PERSISTENT_LIST_SOURCE_SHA256 || runtimeInputsManifestSha256 !== PERSISTENT_LIST_MANIFEST_SHA256 || repositoryLockSha256 !== PERSISTENT_LIST_LOCK_SHA256 || runtimeLockSha256 !== PERSISTENT_LIST_LOCK_SHA256) throw new Error("Fixed List fixture/runtime input identity mismatch");
  return validatePersistentListIdentity({ ...buildIdentity(compiler), runtimeLockSha256, runtimeInputsManifestSha256, listFixtureSha256,
    listWorkerSourceSha256: sha("tests/runtime-fixtures/persistent-list-worker.ts"),
    listWorkerBuildSha256: sha("dist/tests/runtime-fixtures/persistent-list-worker.js") });
}

/** Both operands are independently validated; every recorded identity field participates. */
export function persistentListIdentityChanges(before: PersistentListIdentity, after: PersistentListIdentity): string[] {
  const left = validatePersistentListIdentity(before), right = validatePersistentListIdentity(after);
  return identityKeys.filter(key => left[key] !== right[key]).sort();
}

/** Detached result qualification is repeated at every evidence boundary. */
export function validatePersistentListArtifact(value: unknown): PersistentListArtifact {
  const raw = record(value, ["schemaVersion", "purpose", "executionLayer", "identity", "sequence", "limits", "result"], "artifact");
  if (raw.schemaVersion !== "nightshade-owned-persistent-list-case-1" || raw.purpose !== "owned-fixture-runtime-properties" || raw.executionLayer !== "compiled-evaluation-only") throw new Error("Unsupported List artifact schema/purpose/execution layer");
  if (raw.limits === undefined) throw new Error("Missing explicit saved List execution limits");
  const sequence = validatePersistentListSequence(raw.sequence);
  const artifact: PersistentListArtifact = {
    schemaVersion: "nightshade-owned-persistent-list-case-1", purpose: "owned-fixture-runtime-properties", executionLayer: "compiled-evaluation-only",
    identity: validatePersistentListIdentity(raw.identity), sequence, limits: validatePersistentListLimits(raw.limits), result: validatePersistentListResult(sequence, raw.result),
  };
  encodedArtifact(artifact);
  return artifact;
}

export function makePersistentListArtifact(sequence: PersistentListSequence, identity: PersistentListIdentity, limits: Required<ExecutionLimits>, result: PersistentListResult): PersistentListArtifact {
  return validatePersistentListArtifact({ schemaVersion: "nightshade-owned-persistent-list-case-1", purpose: "owned-fixture-runtime-properties", executionLayer: "compiled-evaluation-only", identity, sequence, limits, result });
}

/** One no-follow open, a bounded growth probe, fatal UTF-8 and one detached audit. */
export function readPersistentListArtifact(path: string): PersistentListArtifactRead {
  const descriptor = openSync(filePath(path), constants.O_RDONLY | constants.O_NONBLOCK | noFollow());
  let originalBytes: Buffer;
  try {
    const before = fstatSync(descriptor);
    if (!before.isFile()) throw new Error("List artifact input must be a regular file");
    if (before.size > PERSISTENT_LIST_FILE_BYTES) throw new Error("List artifact input exceeds 1 MiB");
    const buffer = Buffer.alloc(PERSISTENT_LIST_FILE_BYTES + 1);
    let length = 0;
    while (length < buffer.length) {
      const count = readSync(descriptor, buffer, length, buffer.length - length, null);
      if (!count) break;
      length += count;
    }
    if (length > PERSISTENT_LIST_FILE_BYTES) throw new Error("List artifact input exceeds 1 MiB");
    const after = fstatSync(descriptor);
    if (!after.isFile() || before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || length !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) throw new Error("List artifact changed during bounded read");
    originalBytes = Buffer.from(buffer.subarray(0, length));
  } finally { closeSync(descriptor); }
  const parsed: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(originalBytes));
  return { artifact: validatePersistentListArtifact(parsed), originalBytes, sha256: persistentListDigest(originalBytes), bytes: originalBytes.length };
}

/** Validate first, exclusively create, then durably flush file and parent directory. */
export function writePersistentListArtifact(path: string, value: PersistentListArtifact): PersistentListArtifactReference {
  const artifact = validatePersistentListArtifact(value), bytes = encodedArtifact(artifact), resolved = filePath(path);
  const descriptor = openSync(resolved, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | noFollow(), 0o600);
  try {
    let offset = 0;
    while (offset < bytes.length) {
      const count = writeSync(descriptor, bytes, offset, bytes.length - offset, null);
      if (count <= 0) throw new Error("List artifact write made no progress");
      offset += count;
    }
    fsyncSync(descriptor);
  } finally { closeSync(descriptor); }
  // No partial-file deletion: a failure must not remove a replaced path or claim
  // completed durability. The caller owns its fresh output directory and failure.
  const directory = openSync(dirname(resolved), constants.O_RDONLY | constants.O_DIRECTORY | noFollow());
  try { fsyncSync(directory); } finally { closeSync(directory); }
  return { name: basename(resolved), sha256: persistentListDigest(bytes), bytes: bytes.length };
}
