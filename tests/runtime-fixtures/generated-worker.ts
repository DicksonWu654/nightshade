// Test-only adapter: render a validated owned grammar, never accept source text.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { renderCase, validateCase } from "../generative/model.js";

const chunks: Buffer[] = [];
let inputBytes = 0;
for await (const chunk of process.stdin) {
  const bytes = Buffer.from(chunk);
  inputBytes += bytes.length;
  if (inputBytes > 1024 * 1024) throw new Error("generated-runtime-input-budget: request exceeds 1 MiB");
  chunks.push(bytes);
}
const request: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
assert.ok(request && typeof request === "object" && !Array.isArray(request));
assert.deepEqual(Object.keys(request).sort(), ["case", "compiler", "runtimeDirectory"]);
const configuration = request as { case: unknown; compiler: unknown; runtimeDirectory: unknown };
// Validate before loading any external runtime or launching the compiler.
const input = validateCase(configuration.case);
assert.equal(typeof configuration.compiler, "string");
assert.equal(typeof configuration.runtimeDirectory, "string");
const compilerPath = configuration.compiler as string;
const runtimeDirectory = configuration.runtimeDirectory as string;
const source = renderCase(input);
const digest = (value: string | Buffer) => createHash("sha256").update(value).digest("hex");

function compiler(args: string[]): string {
  const result = spawnSync(compilerPath, args, {
    encoding: "utf8", timeout: 30000, maxBuffer: 1024 * 1024, killSignal: "SIGKILL",
  });
  assert.equal(result.status, 0, String(result.error ?? result.stderr));
  return result.stdout.trim();
}
assert.equal(compiler(["--version"]), "0.34.0");
assert.equal(compiler(["--language-version"]), "0.26.0");
assert.equal(compiler(["--runtime-version"]), "0.19.0");
const modules = resolve(runtimeDirectory, "node_modules");
for (const [name, version] of Object.entries({
  "@midnight-ntwrk/compact-runtime": "0.19.0", "@midnightntwrk/onchain-runtime-v4": "4.0.0-rc.3",
  "@noble/curves": "2.3.0", "@noble/hashes": "2.3.0", "@types/object-inspect": "1.13.0", "object-inspect": "1.13.4",
})) assert.equal(JSON.parse(readFileSync(resolve(modules, name, "package.json"), "utf8")).version, version, name);
const runtime = await import(pathToFileURL(resolve(modules, "@midnight-ntwrk/compact-runtime/dist/index.js")).href);
assert.equal(runtime.versionString, "0.19.0");

type Observation = { kind: "integer" | "boolean"; value: string } | Observation[];
function observe(value: unknown): Observation {
  if (Array.isArray(value)) return value.map(observe);
  if (typeof value === "bigint") return { kind: "integer", value: String(value) };
  if (typeof value === "boolean") return { kind: "boolean", value: String(value) };
  throw new Error(`unsupported-generated-runtime-result: ${typeof value}`);
}

const directory = mkdtempSync(resolve(tmpdir(), "nightshade-generated-runtime-"));
try {
  writeFileSync(resolve(directory, "package.json"), '{"private":true,"type":"module"}\n');
  symlinkSync(modules, resolve(directory, "node_modules"), process.platform === "win32" ? "junction" : "dir");
  const sourcePath = resolve(directory, "main.compact");
  writeFileSync(sourcePath, source);
  const compiled = resolve(directory, "compiled");
  compiler(["--skip-zk", sourcePath, compiled]);
  const compiledPath = resolve(compiled, "contract/index.js");
  const compiledJavaScriptSha256 = digest(readFileSync(compiledPath));
  const contractModule = await import(pathToFileURL(compiledPath).href);
  const executions: unknown[] = [];
  const initialSnapshots: string[] = [];
  const fixedTime = 1700000000;
  for (const flag of [false, true]) {
    // A distinct constructor and deserialized snapshot for each input; no accepted
    // state or call context is threaded from the other execution.
    const contract = new contractModule.Contract({});
    const privateState = Object.freeze({});
    const initialized = await contract.initialState(runtime.createConstructorContext(privateState, "0".repeat(64)));
    const state = runtime.ContractState.deserialize(initialized.currentContractState.serialize());
    const initialSnapshot = state.data.toString();
    initialSnapshots.push(initialSnapshot);
    const context = runtime.createCircuitContext("entry", runtime.dummyContractAddress(), "0".repeat(64),
      state, initialized.currentPrivateState, undefined, undefined, undefined, fixedTime);
    const evaluated = await contract.circuits.entry(context, flag);
    assert.equal(context.callContext.currentQueryContext.state.toString(), initialSnapshot, "input public snapshot changed");
    assert.equal(context.callContext.currentPrivateState, privateState, "input private snapshot changed");
    assert.equal(evaluated.context.callProofDataTrace.length, 1);
    const transcript = evaluated.context.callProofDataTrace[0];
    assert.equal(transcript.circuitId, "entry");
    assert.equal(transcript.privateTranscriptOutputs.length, 0);
    assert.equal(evaluated.context.events.length, 0);
    executions.push({ flag, outcome: "evaluation-success", result: observe(evaluated.result) });
  }
  assert.equal(initialSnapshots[0], initialSnapshots[1], "Boolean inputs must start with equal independent ledger snapshots");
  process.stdout.write(JSON.stringify({ layer: "compiled-evaluation-only", source: "validated-owned-generated-model",
    compiler: "0.34.0", language: "0.26.0", runtime: "0.19.0", onchainRuntime: "4.0.0-rc.3",
    generatedSourceSha256: digest(source), compiledJavaScriptSha256, fixedTime, executions }));
} finally {
  rmSync(directory, { recursive: true, force: true });
}
