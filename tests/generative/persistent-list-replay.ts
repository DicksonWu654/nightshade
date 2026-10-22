/** Bounded case evidence only: replay cannot attest to its originating run envelope. */
import { closeSync, fsyncSync, mkdirSync, openSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";
import type { ExecutionLimits } from "../../src/runtime/process.js";
import {
  makePersistentListArtifact, persistentListBuildIdentity, persistentListIdentityChanges,
  readPersistentListArtifact, validatePersistentListIdentity, writePersistentListArtifact,
  type PersistentListArtifact, type PersistentListArtifactRead, type PersistentListArtifactReference, type PersistentListIdentity,
} from "./persistent-list-artifacts.js";
import {
  generatePersistentListSequence, incompletePersistentListResult, PERSISTENT_LIST_LIMITS,
  type PersistentListIncompleteDiagnostic, type PersistentListResult, type PersistentListSequence,
  validatePersistentListResult, validatePersistentListSequence,
} from "./persistent-list-model.js";
import { runPersistentListSequenceIsolated, validatePersistentListLimits } from "./persistent-list-runtime.js";

export type PersistentListEvaluator = (sequence: PersistentListSequence, limits: Required<ExecutionLimits>, signal: AbortSignal) => Promise<unknown>;
export type PersistentListIdentityProvider = () => unknown;
type AbortCause = "deadline" | "external-signal";
type ResultLabels = Pick<PersistentListResult, "status" | "diagnostic" | "signature">;
export interface PersistentListRecordConfiguration {
  seed: number; steps: number; workerLimits: Required<ExecutionLimits>; maxElapsedMs: number;
}
export interface PersistentListReplayConfiguration { maxElapsedMs: number }
export interface PersistentListComparison {
  sameStatus: boolean; sameSignature: boolean; sameFullResult: boolean;
  sameObservation: boolean | null; sameCompiledJavaScript: boolean | null;
  sameCanonicalArtifact: boolean; sameOriginalBytes: boolean; bothComplete: boolean; matched: boolean;
}
export type PersistentListEvaluationDiagnostic = PersistentListIncompleteDiagnostic | "persistent-list-model-disagreement"
  | "persistent-list-evaluation-time-budget" | "persistent-list-evaluation-interrupted"
  | "persistent-list-evaluation-artifact-budget"
  | "persistent-list-post-identity-drift" | "persistent-list-post-identity-unavailable"
  | "persistent-list-replay-saved-incomplete" | "persistent-list-replay-result-drift";
export interface PersistentListEvaluationSummary {
  schemaVersion: "nightshade-owned-persistent-list-evaluation-1";
  mode: "record" | "replay"; scope: "owned-fixed-fixture-compiled-evaluation-only";
  identity: PersistentListIdentity;
  saved: null | { originalSha256: string; bytes: number; identity: PersistentListIdentity; limits: Required<ExecutionLimits>; status: PersistentListResult["status"]; diagnostic: string; signature: string };
  savedEnvelope: null | "not-inspected";
  configuration: { maxElapsedMs: number; workerLimits: Required<ExecutionLimits> };
  sequence: PersistentListSequence; artifact: PersistentListArtifactReference; returnedArtifact: PersistentListArtifactReference | null;
  invocation: {
    evaluatorInvoked: boolean; resultOrigin: "evaluator" | "supervisor";
    timing: { startedAtMs: number | null; finishedAtMs: number; remainingMsAtLaunch: number | null };
    abortCause: AbortCause | null; result: ResultLabels;
  };
  postIdentity: { status: "matched" | "drift"; identity: PersistentListIdentity } | { status: "unavailable"; identity: null };
  elapsedMs: number; finalAbortCause: AbortCause | null;
  comparison: PersistentListComparison | null; exactEvidenceMatched: boolean;
  outcome: { status: "passed" | "failed" | "incomplete"; diagnostics: PersistentListEvaluationDiagnostic[] };
}

const SUMMARY_BYTES = 256 * 1024, ARCHIVE_BYTES = 3 * 1024 * 1024;
function fields(value: unknown, allowed: string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new Error("Expected ordinary List evaluation configuration");
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string" || !allowed.includes(key)) throw new Error("Unexpected List evaluation configuration field");
    const descriptor = Object.getOwnPropertyDescriptor(value, key)!;
    if (!("value" in descriptor) || !descriptor.enumerable) throw new Error("Expected enumerable List evaluation data fields");
  }
  return value as Record<string, unknown>;
}
function integer(value: unknown, minimum: number, maximum: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || Object.is(value, -0) || value < minimum || value > maximum) throw new Error(`Expected integer in ${minimum}..${maximum}`);
  return value;
}
export function validatePersistentListRecordConfiguration(value: unknown): PersistentListRecordConfiguration {
  const raw = fields(value, ["seed", "steps", "workerLimits", "maxElapsedMs"]);
  if (Object.hasOwn(raw, "workerLimits") && raw.workerLimits === undefined) throw new Error("Present List workerLimits must be explicit");
  return {
    seed: integer(raw.seed, 0, 0xffffffff), steps: integer(Object.hasOwn(raw, "steps") ? raw.steps : 32, 0, 32),
    workerLimits: validatePersistentListLimits(Object.hasOwn(raw, "workerLimits") ? raw.workerLimits : PERSISTENT_LIST_LIMITS),
    maxElapsedMs: integer(Object.hasOwn(raw, "maxElapsedMs") ? raw.maxElapsedMs : 60000, 1, 60000),
  };
}
export function validatePersistentListReplayConfiguration(value: unknown = {}): PersistentListReplayConfiguration {
  const raw = fields(value, ["maxElapsedMs"]);
  return { maxElapsedMs: integer(Object.hasOwn(raw, "maxElapsedMs") ? raw.maxElapsedMs : 60000, 1, 60000) };
}
function argumentsValid(output: string, evaluate: PersistentListEvaluator, identityProvider: PersistentListIdentityProvider, signal?: AbortSignal, clock?: () => number): void {
  if (typeof output !== "string" || !output || typeof evaluate !== "function" || typeof identityProvider !== "function" || signal !== undefined && !(signal instanceof AbortSignal) || clock !== undefined && typeof clock !== "function") throw new Error("Invalid List evaluation arguments");
}
const labels = (result: PersistentListResult): ResultLabels => ({ status: result.status, diagnostic: result.diagnostic, signature: result.signature });
function elapsedClock(clock?: () => number): () => number {
  const origin = performance.now();
  let lastTime = 0;
  return () => { const value = integer(clock ? clock() : Math.floor(performance.now() - origin), lastTime, Number.MAX_SAFE_INTEGER); lastTime = value; return value; };
}

function compare(saved: PersistentListArtifactRead, actual: PersistentListArtifact): PersistentListComparison {
  const before = saved.artifact.result, after = actual.result;
  const bothComplete = before.status !== "incomplete" && after.status !== "incomplete";
  const sameFullResult = isDeepStrictEqual(before, after), sameCanonicalArtifact = isDeepStrictEqual(saved.artifact, actual);
  return {
    sameStatus: before.status === after.status, sameSignature: before.signature === after.signature, sameFullResult,
    sameObservation: bothComplete ? isDeepStrictEqual(before.observation, after.observation) : null,
    sameCompiledJavaScript: bothComplete ? before.observation.compiledJavaScriptSha256 === after.observation.compiledJavaScriptSha256 : null,
    sameCanonicalArtifact, sameOriginalBytes: saved.originalBytes.equals(Buffer.from(JSON.stringify(actual) + "\n")), bothComplete,
    matched: bothComplete && sameFullResult && sameCanonicalArtifact,
  };
}

/** Trusted in-process seams enable supervisor tests; CLI never accepts callbacks. */
export async function recordPersistentList(outputDirectory: string, configuration: unknown, evaluate: PersistentListEvaluator, identityProvider: PersistentListIdentityProvider, signal?: AbortSignal, clock?: () => number): Promise<PersistentListEvaluationSummary> {
  const config = validatePersistentListRecordConfiguration(configuration);
  argumentsValid(outputDirectory, evaluate, identityProvider, signal, clock);
  const now = elapsedClock(clock); now();
  const sequence = generatePersistentListSequence(config.seed, config.steps), identity = validatePersistentListIdentity(identityProvider());
  return evaluateCase(outputDirectory, sequence, identity, { maxElapsedMs: config.maxElapsedMs, workerLimits: config.workerLimits }, null, evaluate, identityProvider, now, signal);
}

/** Read exactly one detached case; its sibling summary is deliberately not inspected. */
export async function replayPersistentList(inputFile: string, outputDirectory: string, evaluate: PersistentListEvaluator, identityProvider: PersistentListIdentityProvider, configuration: unknown = {}, signal?: AbortSignal, clock?: () => number): Promise<PersistentListEvaluationSummary> {
  const config = validatePersistentListReplayConfiguration(configuration);
  argumentsValid(outputDirectory, evaluate, identityProvider, signal, clock);
  if (typeof inputFile !== "string" || !inputFile) throw new Error("A saved List case file is required");
  const now = elapsedClock(clock); now();
  const saved = readPersistentListArtifact(resolve(inputFile));
  const identity = validatePersistentListIdentity(identityProvider());
  const changes = persistentListIdentityChanges(saved.artifact.identity, identity);
  if (changes.length) throw new Error(`Persistent List replay identity mismatch (${changes.join(", ")})`);
  return evaluateCase(outputDirectory, saved.artifact.sequence, identity, { maxElapsedMs: config.maxElapsedMs, workerLimits: saved.artifact.limits }, saved, evaluate, identityProvider, now, signal);
}

async function evaluateCase(outputDirectory: string, sequence: PersistentListSequence, identity: PersistentListIdentity, config: PersistentListEvaluationSummary["configuration"], saved: PersistentListArtifactRead | null, evaluate: PersistentListEvaluator, identityProvider: PersistentListIdentityProvider, now: () => number, signal?: AbortSignal): Promise<PersistentListEvaluationSummary> {
  const preflightElapsedMs = now(); // Clock/config/identity refusal precedes mkdir and launch.
  const output = resolve(outputDirectory);
  mkdirSync(output, { mode: 0o700 });
  const controller = new AbortController();
  let abortCause: AbortCause | null = null;
  const abort = (cause: AbortCause): void => { if (abortCause === null) { abortCause = cause; controller.abort(); } };
  const external = () => abort("external-signal");
  signal?.addEventListener("abort", external, { once: true });
  if (signal?.aborted) external();
  const timer = setTimeout(() => abort("deadline"), Math.max(0, config.maxElapsedMs - preflightElapsedMs));
  const stopped = (at: number): AbortCause | null => { if (at >= config.maxElapsedMs) abort("deadline"); if (signal?.aborted) external(); return abortCause; };
  const interrupted = () => incompletePersistentListResult("worker-interrupted", "Owned List supervisor selected cancellation; no complete selected evaluation evidence");
  const protocol = () => incompletePersistentListResult("persistent-list-protocol", "Owned List evaluator threw or returned unqualified result data");
  try {
    let evaluatorInvoked = false, startedAtMs: number | null = null, remainingMsAtLaunch: number | null = null;
    let resultOrigin: "evaluator" | "supervisor" = "supervisor", returned: PersistentListResult | null = null;
    let selected: PersistentListResult, finishedAtMs: number;
    const before = now();
    if (stopped(before) !== null) { selected = interrupted(); finishedAtMs = before; }
    else {
      type Evaluation = { kind: "result"; result: PersistentListResult } | { kind: "protocol" } | { kind: "cancelled" };
      let accepting = true, settled: PersistentListResult | null = null;
      let cancel: (() => void) | undefined;
      try {
        const cancellation = new Promise<Evaluation>(resolve => { cancel = () => resolve({ kind: "cancelled" }); controller.signal.addEventListener("abort", cancel, { once: true }); });
        const work = Promise.resolve().then(async (): Promise<Evaluation> => {
          const launch = now();
          if (stopped(launch) !== null) return { kind: "cancelled" };
          startedAtMs = launch; remainingMsAtLaunch = config.maxElapsedMs - launch; evaluatorInvoked = true;
          try {
            // Detached arguments prevent a trusted evaluator from mutating saved comparisons.
            const value = await evaluate(validatePersistentListSequence(sequence), { ...config.workerLimits }, controller.signal);
            if (!accepting) return { kind: "cancelled" };
            const result = validatePersistentListResult(sequence, value);
            settled = result;
            return { kind: "result", result };
          } catch { return { kind: "protocol" }; }
        });
        const outcome = await Promise.race([cancellation, work]);
        accepting = false;
        finishedAtMs = now();
        if (stopped(finishedAtMs) !== null || outcome.kind === "cancelled") { selected = interrupted(); returned = outcome.kind === "result" ? outcome.result : settled; }
        else if (outcome.kind === "protocol") selected = protocol();
        else { selected = outcome.result; resultOrigin = "evaluator"; }
      } finally { accepting = false; if (cancel) controller.signal.removeEventListener("abort", cancel); }
    }
    let artifactBudget = false;
    const boundedArtifact = (result: PersistentListResult): PersistentListArtifact | null => {
      try { return makePersistentListArtifact(sequence, identity, config.workerLimits, result); }
      catch (error) {
        if (!(error instanceof Error) || error.message !== "List artifact exceeds 1 MiB") throw error;
        artifactBudget = true; return null;
      }
    };
    let actual = boundedArtifact(selected);
    if (actual === null) {
      selected = incompletePersistentListResult("persistent-list-observation-budget", "Qualified List result exceeds the bounded case artifact envelope; complete evidence could not be retained");
      resultOrigin = "supervisor";
      actual = makePersistentListArtifact(sequence, identity, config.workerLimits, selected);
    }
    const artifact = writePersistentListArtifact(resolve(output, "case.json"), actual);
    const returnedCase = returned === null ? null : boundedArtifact(returned);
    const returnedArtifact = returnedCase === null ? null : writePersistentListArtifact(resolve(output, "returned-case.json"), returnedCase);
    const invocation: PersistentListEvaluationSummary["invocation"] = {
      evaluatorInvoked, resultOrigin, timing: { startedAtMs, finishedAtMs, remainingMsAtLaunch }, abortCause, result: labels(selected),
    };
    const comparison = saved === null ? null : compare(saved, actual);
    let postIdentity: PersistentListEvaluationSummary["postIdentity"];
    try { const post = validatePersistentListIdentity(identityProvider()); postIdentity = { status: persistentListIdentityChanges(identity, post).length ? "drift" : "matched", identity: post }; }
    catch { postIdentity = { status: "unavailable", identity: null }; }
    // Evidence writes, full comparison and post-identity checks are inside the
    // deadline. This closes the evidence envelope immediately before final
    // summary assembly, serialization and durable persistence (which it describes).
    const elapsedMs = now(), finalAbortCause = stopped(elapsedMs);
    const diagnostics = new Set<PersistentListEvaluationDiagnostic>();
    if (selected.status !== "passed") diagnostics.add(selected.diagnostic);
    if (artifactBudget) diagnostics.add("persistent-list-evaluation-artifact-budget");
    if (finalAbortCause !== null) diagnostics.add(finalAbortCause === "deadline" ? "persistent-list-evaluation-time-budget" : "persistent-list-evaluation-interrupted");
    if (postIdentity.status !== "matched") diagnostics.add(postIdentity.status === "drift" ? "persistent-list-post-identity-drift" : "persistent-list-post-identity-unavailable");
    if (saved?.artifact.result.status === "incomplete") diagnostics.add("persistent-list-replay-saved-incomplete");
    if (comparison && !comparison.sameFullResult) diagnostics.add("persistent-list-replay-result-drift");
    const qualified = resultOrigin === "evaluator" && selected.status !== "incomplete" && !artifactBudget && finalAbortCause === null && postIdentity.status === "matched";
    const exactEvidenceMatched = saved !== null && qualified && comparison!.matched;
    const status = qualified && (saved === null || exactEvidenceMatched) ? selected.status : "incomplete";
    const summary: PersistentListEvaluationSummary = {
      schemaVersion: "nightshade-owned-persistent-list-evaluation-1", mode: saved === null ? "record" : "replay", scope: "owned-fixed-fixture-compiled-evaluation-only", identity,
      saved: saved === null ? null : { originalSha256: saved.sha256, bytes: saved.bytes, identity: saved.artifact.identity, limits: saved.artifact.limits, ...labels(saved.artifact.result) },
      savedEnvelope: saved === null ? null : "not-inspected", configuration: config, sequence, artifact, returnedArtifact, invocation, postIdentity,
      elapsedMs, finalAbortCause, comparison, exactEvidenceMatched, outcome: { status, diagnostics: [...diagnostics].sort() },
    };
    const bytes = Buffer.from(JSON.stringify(summary) + "\n");
    if (bytes.length > SUMMARY_BYTES || artifact.bytes + (returnedArtifact?.bytes ?? 0) + bytes.length > ARCHIVE_BYTES) throw new Error("Persistent List evaluation evidence byte budget exhausted");
    writeFileSync(resolve(output, "summary.json"), bytes, { flag: "wx", mode: 0o600, flush: true });
    const descriptor = openSync(output, "r");
    try { fsyncSync(descriptor); } finally { closeSync(descriptor); }
    return structuredClone(summary);
  } finally { clearTimeout(timer); signal?.removeEventListener("abort", external); }
}

export async function persistentListReplayMain(args = process.argv.slice(2)): Promise<number> {
  if (args.length === 1 && args[0] === "--help") {
    console.log("Owned List recording: --record --seed UINT32 --steps 0..32 --output NEW_DIRECTORY [--timeout-ms 1..60000] [--heap-mib 32..256] [--max-output-bytes 1024..1048576] [--max-elapsed-ms 1..60000]\nExact case replay: --replay CASE.json --output NEW_DIRECTORY [--max-elapsed-ms 1..60000]\nRequires pinned COMPACTC_TEST and COMPACT_RUNTIME_TEST; run from repository root. Fixed owned guarded List fixture, compiled evaluation only, four snapshot slots.\nReplay preserves saved worker limits and qualifies case evidence only; the originating recording envelope is not inspected or cleared. No proof, transaction or general contract coverage claim.\nExit 0: passing recording or exact passing case replay; 1: recorded/reproduced qualified property failure; 2: incomplete/input/evidence/identity/result drift.");
    return 0;
  }
  const allowed = ["--seed", "--steps", "--output", "--replay", "--timeout-ms", "--heap-mib", "--max-output-bytes", "--max-elapsed-ms"];
  const flags = new Map<string, string>();
  let recording = false;
  for (let index = 0; index < args.length; index++) {
    const flag = args[index];
    if (flag === "--record" && !recording) { recording = true; continue; }
    if (!allowed.includes(flag) || flags.has(flag) || !args[index + 1] || args[index + 1].startsWith("--")) throw new Error(`Invalid List evaluation argument ${flag}`);
    flags.set(flag, args[++index]);
  }
  if (!flags.has("--output") || recording === flags.has("--replay")) throw new Error("Require new --output and exactly one of --record or --replay");
  if (recording && (!flags.has("--seed") || !flags.has("--steps"))) throw new Error("List recording requires --seed and --steps");
  if (!recording && ["--seed", "--steps", "--timeout-ms", "--heap-mib", "--max-output-bytes"].some(flag => flags.has(flag))) throw new Error("List replay preserves its saved sequence and worker limits");
  const number = (flag: string, fallback: number): number => { const raw = flags.get(flag); if (raw !== undefined && !/^(0|[1-9][0-9]*)$/.test(raw)) throw new Error(`Invalid integer ${flag}`); return raw === undefined ? fallback : Number(raw); };
  const configuration = recording ? validatePersistentListRecordConfiguration({ seed: number("--seed", 0), steps: number("--steps", 32), maxElapsedMs: number("--max-elapsed-ms", 60000), workerLimits: { timeoutMs: number("--timeout-ms", PERSISTENT_LIST_LIMITS.timeoutMs), heapMiB: number("--heap-mib", PERSISTENT_LIST_LIMITS.heapMiB), maxOutputBytes: number("--max-output-bytes", PERSISTENT_LIST_LIMITS.maxOutputBytes) } }) : validatePersistentListReplayConfiguration({ maxElapsedMs: number("--max-elapsed-ms", 60000) });
  if (!process.env.COMPACTC_TEST || !process.env.COMPACT_RUNTIME_TEST) throw new Error("Pinned COMPACTC_TEST and COMPACT_RUNTIME_TEST are mandatory");
  const compiler = resolve(process.env.COMPACTC_TEST), runtime = resolve(process.env.COMPACT_RUNTIME_TEST), controller = new AbortController(), cancel = () => controller.abort();
  process.once("SIGINT", cancel); process.once("SIGTERM", cancel);
  try {
    const evaluator: PersistentListEvaluator = (sequence, limits, signal) => runPersistentListSequenceIsolated(sequence, compiler, runtime, limits, signal);
    const identity = () => persistentListBuildIdentity(compiler, runtime);
    const summary = recording ? await recordPersistentList(flags.get("--output")!, configuration, evaluator, identity, controller.signal)
      : await replayPersistentList(flags.get("--replay")!, flags.get("--output")!, evaluator, identity, configuration, controller.signal);
    console.log(`${summary.outcome.status}; ${summary.mode === "replay" ? "case evidence only; saved envelope not inspected; " : ""}${summary.outcome.diagnostics.join(", ") || "qualified case evidence"}`);
    return summary.outcome.status === "passed" ? 0 : summary.outcome.status === "failed" ? 1 : 2;
  } finally { process.removeListener("SIGINT", cancel); process.removeListener("SIGTERM", cancel); }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { process.exitCode = await persistentListReplayMain(); }
  catch (error) { console.error(error instanceof Error ? error.message : "Persistent List evaluation failed"); process.exitCode = 2; }
}
