import assert from "node:assert/strict";
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import test from "node:test";
import type { ExecutionLimits } from "../src/runtime/process.js";
import {
  makePersistentListArtifact, persistentListBuildIdentity, persistentListIdentityChanges, PERSISTENT_LIST_FILE_BYTES,
  readPersistentListArtifact, validatePersistentListArtifact, validatePersistentListIdentity, writePersistentListArtifact,
  type PersistentListArtifact, type PersistentListIdentity,
} from "./generative/persistent-list-artifacts.js";
import {
  checkPersistentListObservation, expectedPersistentListSequence, incompletePersistentListResult, persistentListDigest,
  PERSISTENT_LIST_LIMITS, PERSISTENT_LIST_LOCK_SHA256, PERSISTENT_LIST_MANIFEST_SHA256, PERSISTENT_LIST_SOURCE_SHA256,
  validatePersistentListSequence, type PersistentListObservation, type PersistentListSequence, type PersistentListSnapshot,
} from "./generative/persistent-list-model.js";

const sequence = validatePersistentListSequence({ schemaVersion: "nightshade-persistent-list-sequence-1", seed: 5,
  operations: [{ kind: "push", value: 255 }, { kind: "save", slot: 0 }, { kind: "guardedPop" }, { kind: "restore", slot: 0 }, { kind: "inspect" }] });
/** Deliberately synthetic identity/evidence for schema tests, never runtime attestation. */
const identity: PersistentListIdentity = {
  analyzerSourceSha256: "a".repeat(64), harnessSourceSha256: "b".repeat(64), builtJavaScriptSha256: "c".repeat(64),
  parserRuntimeSha256: "d".repeat(64), compilerSha256: "e".repeat(64), compilerDistributionSha256: "f".repeat(64),
  semanticProfile: "compact-0.34.0-zkir2", node: "v24.15.0", platform: "linux", arch: "x64",
  runtimeLockSha256: PERSISTENT_LIST_LOCK_SHA256, runtimeInputsManifestSha256: PERSISTENT_LIST_MANIFEST_SHA256,
  listWorkerSourceSha256: "1".repeat(64), listWorkerBuildSha256: "2".repeat(64), listFixtureSha256: PERSISTENT_LIST_SOURCE_SHA256,
};
function observation(input: PersistentListSequence = sequence): PersistentListObservation {
  const expected = expectedPersistentListSequence(input);
  const snapshot = (state: typeof expected.initial): PersistentListSnapshot => ({ ...state, publicSha256: persistentListDigest(`synthetic values:${JSON.stringify(state.values)}`) });
  return {
    schemaVersion: "nightshade-persistent-list-observation-1", layer: "compiled-evaluation-only", fixture: "owned-persistent-guarded-list",
    compiler: "0.34.0", language: "0.26.0", runtime: "0.19.0", onchainRuntime: "4.0.0-rc.3", fixedTime: 1700000000,
    runtimeLockSha256: PERSISTENT_LIST_LOCK_SHA256, runtimeInputsManifestSha256: PERSISTENT_LIST_MANIFEST_SHA256,
    sourceSha256: PERSISTENT_LIST_SOURCE_SHA256, compiledJavaScriptSha256: "3".repeat(64), sequenceSha256: persistentListDigest(JSON.stringify(input)),
    initial: snapshot(expected.initial), rows: expected.rows.map(row => ({ ...row, before: snapshot(row.before), after: snapshot(row.after), slots: row.slots.map(snapshot) })), final: snapshot(expected.final),
  };
}
function artifact(): PersistentListArtifact { return makePersistentListArtifact(sequence, identity, PERSISTENT_LIST_LIMITS, checkPersistentListObservation(sequence, observation())); }
function temporary(): string { return fs.mkdtempSync(resolve(tmpdir(), "nightshade-list-artifacts-")); }

test("List artifact construction detaches identity, grammar, limits and fully requalified evidence", () => {
  const input = structuredClone(sequence), stamp = { ...identity }, result = checkPersistentListObservation(input, observation(input));
  const limits: Required<ExecutionLimits> = { ...PERSISTENT_LIST_LIMITS };
  assert.equal(result.status, "passed");
  const stored = makePersistentListArtifact(input, stamp, limits, result);
  assert.deepEqual(validatePersistentListArtifact(JSON.parse(JSON.stringify(stored))), stored);
  assert.throws(() => validatePersistentListArtifact({ ...stored, limits: undefined }), /explicit saved List execution limits/);
  assert.deepEqual({ schemaVersion: stored.schemaVersion, purpose: stored.purpose, executionLayer: stored.executionLayer }, {
    schemaVersion: "nightshade-owned-persistent-list-case-1", purpose: "owned-fixture-runtime-properties", executionLayer: "compiled-evaluation-only",
  });
  input.operations.length = 0; stamp.listWorkerBuildSha256 = "4".repeat(64); limits.timeoutMs = 1;
  result.observation.initial.values[0] = "99";
  assert.equal(stored.sequence.operations.length, 5); assert.equal(stored.identity.listWorkerBuildSha256, identity.listWorkerBuildSha256);
  assert.equal(stored.limits.timeoutMs, 60000);
  assert.ok(stored.result.status !== "incomplete"); assert.deepEqual(stored.result.observation.initial.values, ["3"]);
});

test("List artifacts retain qualified property failures and incomplete cases without trusting saved labels", () => {
  const bad = observation(); bad.rows[0].after.values[0] = "254";
  const result = checkPersistentListObservation(sequence, bad);
  assert.equal(result.status, "failed");
  const failed = makePersistentListArtifact(sequence, identity, PERSISTENT_LIST_LIMITS, result);
  assert.deepEqual(validatePersistentListArtifact(failed).result, result);
  assert.throws(() => validatePersistentListArtifact({ ...failed, result: { ...result, signature: "persistent-list-model|forged" } }));
  assert.throws(() => validatePersistentListArtifact({ ...failed, result: { ...result, message: "forged" } }));
  const clean = artifact();
  assert.throws(() => validatePersistentListArtifact({ ...clean, result: { ...clean.result, observation: bad } }));
  assert.throws(() => validatePersistentListArtifact({ ...failed, result: { ...result, status: "passed" } }));
  for (const diagnostic of ["worker-timeout", "worker-output-budget", "worker-interrupted", "persistent-list-input-identity"] as const) {
    const incomplete = incompletePersistentListResult(diagnostic, "synthetic transport outcome");
    const saved = makePersistentListArtifact(sequence, identity, PERSISTENT_LIST_LIMITS, incomplete);
    assert.deepEqual(validatePersistentListArtifact(saved).result, incomplete);
    assert.throws(() => validatePersistentListArtifact({ ...saved, result: { ...incomplete, observation: observation() } }));
  }
});

test("List artifact identities validate all fields and independently enforce fixed qualification pins", () => {
  assert.deepEqual(validatePersistentListIdentity(identity), identity);
  for (const field of ["listFixtureSha256", "runtimeLockSha256", "runtimeInputsManifestSha256"] as const) assert.throws(() => validatePersistentListIdentity({ ...identity, [field]: "0".repeat(64) }), /fixed List fixture\/runtime/);
  for (const value of ["", "a".repeat(63), "A".repeat(64), "not a digest"]) assert.throws(() => validatePersistentListIdentity({ ...identity, compilerDistributionSha256: value }));
  for (const node of ["24.15.0", "v24", "v24.15.0-prerelease", "v24.15.0\n"]) assert.throws(() => validatePersistentListIdentity({ ...identity, node }));
  assert.throws(() => validatePersistentListIdentity({ ...identity, semanticProfile: "compact-other" }));
  for (const arch of ["", "x".repeat(257), "x64/other", "x64\n"]) assert.throws(() => validatePersistentListIdentity({ ...identity, arch }));
  const missing = { ...identity } as Partial<PersistentListIdentity>; delete missing.listWorkerSourceSha256;
  assert.throws(() => validatePersistentListIdentity(missing));
  assert.throws(() => validatePersistentListIdentity({ ...identity, storedSource: "ignored?" }));
  assert.throws(() => validatePersistentListIdentity(Object.assign(Object.create({ inherited: true }), identity)));
});

test("List identity comparison validates both sides and includes every mutable recorded field", () => {
  assert.deepEqual(persistentListIdentityChanges(identity, { ...identity }), []);
  const changed = { ...identity, analyzerSourceSha256: "9".repeat(64), harnessSourceSha256: "9".repeat(64), builtJavaScriptSha256: "9".repeat(64),
    parserRuntimeSha256: "9".repeat(64), compilerSha256: "9".repeat(64), compilerDistributionSha256: "9".repeat(64), listWorkerSourceSha256: "9".repeat(64), listWorkerBuildSha256: "9".repeat(64), node: "v22.23.3", platform: "darwin", arch: "arm64" };
  assert.deepEqual(persistentListIdentityChanges(identity, changed), ["analyzerSourceSha256", "arch", "builtJavaScriptSha256", "compilerDistributionSha256", "compilerSha256", "harnessSourceSha256", "listWorkerBuildSha256", "listWorkerSourceSha256", "node", "parserRuntimeSha256", "platform"]);
  assert.throws(() => persistentListIdentityChanges({ ...identity, listFixtureSha256: "9".repeat(64) }, identity));
  assert.throws(() => persistentListIdentityChanges(identity, { ...identity, runtimeInputsManifestSha256: "9".repeat(64) }));
});

test("List artifact schema rejects alternate scopes, arbitrary inputs, invalid saved limits and unknown data", () => {
  const value = artifact();
  for (const field of ["source", "state", "adapter", "target", "witness", "callback", "path"]) assert.throws(() => validatePersistentListArtifact({ ...value, [field]: "not accepted" }));
  for (const [field, content] of [["schemaVersion", "nightshade-owned-persistent-case-1"], ["purpose", "owned-fixture-persistent-correctness"], ["executionLayer", "transaction-accepted"]]) assert.throws(() => validatePersistentListArtifact({ ...value, [field]: content }));
  assert.throws(() => validatePersistentListArtifact({ ...value, sequence: { ...sequence, operations: [{ kind: "call", name: "arbitrary" }] } }));
  for (const limits of [{ timeoutMs: 1 }, { ...PERSISTENT_LIST_LIMITS, timeoutMs: 0 }, { ...PERSISTENT_LIST_LIMITS, timeoutMs: 60001 },
    { ...PERSISTENT_LIST_LIMITS, heapMiB: 31 }, { ...PERSISTENT_LIST_LIMITS, heapMiB: 257 }, { ...PERSISTENT_LIST_LIMITS, maxOutputBytes: 1048577 },
    { ...PERSISTENT_LIST_LIMITS, extra: 1 }]) assert.throws(() => validatePersistentListArtifact({ ...value, limits }));
  assert.deepEqual(makePersistentListArtifact(sequence, identity, { timeoutMs: 1, heapMiB: 32, maxOutputBytes: 1024 }, incompletePersistentListResult("worker-timeout", "small limit")).limits, { timeoutMs: 1, heapMiB: 32, maxOutputBytes: 1024 });
});

test("List artifact boundaries reject accessors and hidden/symbol fields without reading getters", () => {
  let reads = 0;
  const getter = { enumerable: true, get() { reads++; return "unexpected"; } };
  const top = Object.defineProperty(artifact(), "result", getter);
  const stamp = artifact(); Object.defineProperty(stamp.identity, "listWorkerBuildSha256", getter);
  const limits = artifact(); Object.defineProperty(limits.limits, "timeoutMs", getter);
  const nested = artifact(); if (nested.result.status !== "incomplete") Object.defineProperty(nested.result.observation.rows[0].after, "values", getter);
  const hidden = artifact(); Object.defineProperty(hidden.identity, "listWorkerBuildSha256", { value: identity.listWorkerBuildSha256, enumerable: false });
  const symbol = Object.assign(artifact(), { [Symbol("unexpected")]: true });
  for (const value of [top, stamp, limits, nested, hidden, symbol]) assert.throws(() => validatePersistentListArtifact(value));
  assert.equal(reads, 0);
  // Ordinary null-prototype data remains accepted and is detached into plain data.
  const plain = artifact(); const nullTop = Object.assign(Object.create(null), plain);
  assert.deepEqual(validatePersistentListArtifact(nullTop), plain);
});

test("List canonical artifact cap accounts for envelope bytes beyond bounded complete observation", () => {
  const input = validatePersistentListSequence({ schemaVersion: "nightshade-persistent-list-sequence-1", seed: 0, operations: Array.from({ length: 32 }, () => ({ kind: "inspect" })) });
  const measured = observation(input), views = [measured.initial, ...measured.rows.flatMap(row => [row.before, row.after, ...row.slots]), measured.final];
  for (const view of views) view.values = Array<string>(64).fill("1".repeat(80));
  // Place a readable synthetic semantic disagreement just below the observation
  // cap; the additional artifact identity/result envelope must still be counted.
  let excess = Buffer.byteLength(JSON.stringify(measured)) - (PERSISTENT_LIST_FILE_BYTES - 128);
  assert.ok(excess > 0);
  for (const view of views) for (let index = 0; index < view.values.length && excess > 0; index++) {
    const remove = Math.min(79, excess); view.values[index] = view.values[index].slice(remove); excess -= remove;
  }
  assert.equal(excess, 0);
  const result = checkPersistentListObservation(input, measured);
  assert.equal(result.status, "failed");
  assert.throws(() => makePersistentListArtifact(input, identity, PERSISTENT_LIST_LIMITS, result), /artifact exceeds 1 MiB/);
});

test("List evidence files preserve exact original formatting and detached data separately from canonical writes", () => {
  const directory = temporary();
  try {
    const value = artifact(), path = resolve(directory, "case.json");
    const reference = writePersistentListArtifact(path, value), canonical = fs.readFileSync(path);
    assert.deepEqual(reference, { name: "case.json", sha256: persistentListDigest(canonical), bytes: canonical.length });
    assert.equal(canonical.toString("utf8"), `${JSON.stringify(value)}\n`);
    const read = readPersistentListArtifact(path);
    assert.deepEqual(read.artifact, value); assert.deepEqual(read.originalBytes, canonical);
    assert.equal(read.sha256, reference.sha256); assert.equal(read.bytes, reference.bytes);
    const reordered = { result: value.result, limits: value.limits, sequence: value.sequence, identity: value.identity, executionLayer: value.executionLayer, purpose: value.purpose, schemaVersion: value.schemaVersion };
    const formattedPath = resolve(directory, "formatted.json"), original = Buffer.from(`\n  ${JSON.stringify(reordered, null, 2)}\n\t`);
    fs.writeFileSync(formattedPath, original);
    const formatted = readPersistentListArtifact(formattedPath);
    assert.deepEqual(formatted.artifact, value); assert.deepEqual(formatted.originalBytes, original);
    assert.equal(formatted.sha256, persistentListDigest(original)); assert.notEqual(formatted.sha256, reference.sha256);
    fs.writeFileSync(formattedPath, "file replaced after detached read");
    assert.deepEqual(formatted.originalBytes, original); assert.deepEqual(formatted.artifact, value);
    formatted.originalBytes.fill(0);
    assert.deepEqual(formatted.artifact, value, "decoded artifact cannot alias the byte buffer");
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test("List artifact writes requalify before creating files and refuse existing files or symlinks", () => {
  const directory = temporary();
  try {
    const path = resolve(directory, "case.json"), invalid = artifact();
    invalid.identity.listFixtureSha256 = "0".repeat(64);
    assert.throws(() => writePersistentListArtifact(path, invalid)); assert.equal(fs.existsSync(path), false);
    const reference = writePersistentListArtifact(path, artifact()), original = fs.readFileSync(path);
    assert.throws(() => writePersistentListArtifact(path, artifact()), /EEXIST/);
    assert.equal(persistentListDigest(fs.readFileSync(path)), reference.sha256); assert.deepEqual(fs.readFileSync(path), original);
    const link = resolve(directory, "linked.json"); fs.symlinkSync(path, link);
    assert.throws(() => writePersistentListArtifact(link, artifact()));
    assert.deepEqual(fs.readFileSync(path), original);
    assert.equal(fs.statSync(path).mode & 0o777, 0o600);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test("List artifact reading caps original bytes including whitespace and rejects symlinks, nonfiles and invalid UTF8", () => {
  const directory = temporary();
  try {
    const path = resolve(directory, "case.json"), body = Buffer.from(JSON.stringify(artifact()));
    fs.writeFileSync(path, Buffer.concat([body, Buffer.alloc(PERSISTENT_LIST_FILE_BYTES - body.length, 32)]));
    const exact = readPersistentListArtifact(path);
    assert.equal(exact.bytes, PERSISTENT_LIST_FILE_BYTES); assert.deepEqual(exact.artifact, artifact());
    fs.appendFileSync(path, " "); assert.throws(() => readPersistentListArtifact(path), /exceeds 1 MiB/);
    fs.writeFileSync(path, body);
    const link = resolve(directory, "linked.json"); fs.symlinkSync(path, link);
    assert.throws(() => readPersistentListArtifact(link));
    assert.throws(() => readPersistentListArtifact(directory), /regular file|EISDIR/);
    for (const bad of [Buffer.from("{malformed"), Buffer.concat([body, Buffer.from([0xff])]), Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), body])]) {
      fs.writeFileSync(path, bad); assert.throws(() => readPersistentListArtifact(path));
    }
    fs.writeFileSync(path, JSON.stringify({ ...artifact(), adapter: "/not/read/or/executed.js" }));
    assert.throws(() => readPersistentListArtifact(path), /artifact fields/);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test("List bounded reads detect growth after initial fstat and never allocate/read beyond the overflow probe", context => {
  const directory = temporary(), path = resolve(directory, "growing.json");
  const nativeRead = fs.readSync;
  try {
    for (const [appended, expected] of [[" ", /changed during bounded read/], [" ".repeat(PERSISTENT_LIST_FILE_BYTES), /exceeds 1 MiB/]] as const) {
      fs.writeFileSync(path, JSON.stringify(artifact()));
      let first = true;
      const spy = context.mock.method(fs, "readSync", ((descriptor: number, buffer: Buffer, offset: number, length: number, position: number | null) => {
        assert.ok(buffer.length <= PERSISTENT_LIST_FILE_BYTES + 1); assert.ok(offset + length <= buffer.length);
        const bytes = nativeRead(descriptor, buffer, offset, length, position);
        if (first) { first = false; fs.appendFileSync(path, appended); }
        return bytes;
      }) as typeof fs.readSync);
      syncBuiltinESMExports();
      try { assert.throws(() => readPersistentListArtifact(path), expected); }
      finally { spy.mock.restore(); syncBuiltinESMExports(); }
      assert.equal(first, false);
    }
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test("List writes flush the complete file and parent directory, handling partial writes", context => {
  const directory = temporary(), path = resolve(directory, "case.json");
  const nativeWrite = fs.writeSync, nativeFsync = fs.fsyncSync;
  const flushed: string[] = [];
  let writes = 0;
  const writeSpy = context.mock.method(fs, "writeSync", ((descriptor: number, bytes: Buffer, offset: number, length: number, position: number | null) => {
    writes++; return nativeWrite(descriptor, bytes, offset, Math.min(37, length), position);
  }) as typeof fs.writeSync);
  const syncSpy = context.mock.method(fs, "fsyncSync", (descriptor: number) => {
    flushed.push(fs.fstatSync(descriptor).isFile() ? "file" : "directory"); nativeFsync(descriptor);
  });
  syncBuiltinESMExports();
  try {
    const reference = writePersistentListArtifact(path, artifact());
    assert.ok(writes > 1); assert.deepEqual(flushed, ["file", "directory"]);
    assert.equal(reference.sha256, persistentListDigest(fs.readFileSync(path)));
    assert.deepEqual(readPersistentListArtifact(path).artifact, artifact());
  } finally { writeSpy.mock.restore(); syncSpy.mock.restore(); syncBuiltinESMExports(); fs.rmSync(directory, { recursive: true, force: true }); }
});

test("List durability failures throw and preserve existing evidence instead of reporting a completed write", context => {
  const directory = temporary(), path = resolve(directory, "case.json");
  const spy = context.mock.method(fs, "fsyncSync", () => { throw new Error("synthetic flush failure"); });
  syncBuiltinESMExports();
  try {
    assert.throws(() => writePersistentListArtifact(path, artifact()), /synthetic flush failure/);
    assert.equal(fs.existsSync(path), true);
    assert.deepEqual(JSON.parse(fs.readFileSync(path, "utf8")), artifact());
    assert.throws(() => writePersistentListArtifact(path, artifact()), /EEXIST/);
  } finally { spy.mock.restore(); syncBuiltinESMExports(); fs.rmSync(directory, { recursive: true, force: true }); }
});

test("List live identity construction refuses wrong restored lock before compiler or build reads", () => {
  const directory = temporary();
  try {
    fs.writeFileSync(resolve(directory, "package-lock.json"), "{}");
    assert.throws(() => persistentListBuildIdentity("/not/a/compiler", directory), /input identity mismatch/);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test("List live identities hash actual qualified fixture, worker source/build and runtime inputs", {
  skip: !process.env.COMPACT_RUNTIME_TEST ? "Requires pinned external COMPACT_RUNTIME_TEST" : false,
}, () => {
  assert.ok(process.env.COMPACTC_TEST, "COMPACT_RUNTIME_TEST also requires pinned compiler");
  const live = persistentListBuildIdentity(process.env.COMPACTC_TEST, process.env.COMPACT_RUNTIME_TEST!);
  assert.equal(live.node, process.version); assert.equal(live.platform, process.platform); assert.equal(live.arch, process.arch);
  assert.equal(live.listWorkerSourceSha256, persistentListDigest(fs.readFileSync("tests/runtime-fixtures/persistent-list-worker.ts")));
  assert.equal(live.listWorkerBuildSha256, persistentListDigest(fs.readFileSync("dist/tests/runtime-fixtures/persistent-list-worker.js")));
  assert.equal(live.listFixtureSha256, PERSISTENT_LIST_SOURCE_SHA256);
  assert.equal(live.runtimeLockSha256, PERSISTENT_LIST_LOCK_SHA256);
  assert.equal(live.runtimeInputsManifestSha256, PERSISTENT_LIST_MANIFEST_SHA256);
  assert.equal(live.compilerSha256, persistentListDigest(fs.readFileSync(process.env.COMPACTC_TEST)));
  assert.deepEqual(persistentListIdentityChanges(live, persistentListBuildIdentity(process.env.COMPACTC_TEST, process.env.COMPACT_RUNTIME_TEST!)), []);
});
