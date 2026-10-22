// Fixed owned fixture only. Dependency injection is an in-process test seam;
// the command always uses runPersistentSequenceIsolated, never saved code.
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { ExecutionLimits } from "../../src/runtime/process.js";
import { comparePersistentResults, incompletePersistentResult, makePersistentArtifact, PERSISTENT_FILE_BYTES, persistentBuildIdentity, persistentIdentityChanges, readPersistentFile, runPersistentSequenceIsolated, validatePersistentArtifact, validatePersistentResult, type PersistentIdentity, type PersistentResult } from "./persistent-artifacts.js";
import { persistentDigest, validatePersistentSequence, type PersistentSequence } from "./persistent-model.js";
import { reducePersistentSequence, type PersistentReductionResult } from "./persistent-reduction.js";

type Limits = Required<ExecutionLimits>;
export interface PersistentReductionRunOptions { maxChecks?: number; maxElapsedMs?: number; signal?: AbortSignal }
export type OwnedPersistentEvaluator = (sequence: PersistentSequence, limits: Limits, signal: AbortSignal) => Promise<unknown>;
interface EvidenceFile { artifact: string; sha256: string; bytes: number }
interface EvaluationRecord { sequenceSha256: string; limits: Limits; evaluatorInvoked: boolean }
export interface PersistentReductionSummary {
  schemaVersion: "nightshade-owned-persistent-reduction-run-1";
  scope: "owned-fixed-fixture-compiled-evaluation-only";
  identity: PersistentIdentity;
  savedWorkerLimits: Limits;
  budget: { maxChecks: number; maxElapsedMs: number };
  input: EvidenceFile;
  originalReplay: EvidenceFile & EvaluationRecord;
  replay: ReturnType<typeof comparePersistentResults> & { matchedFailure: boolean };
  reductionStatus: "complete" | "incomplete";
  diagnostics: string[];
  reductionSignature: string | null;
  checks: number;
  changed: boolean;
  attempts: (EvidenceFile & EvaluationRecord & { originalRows: number[]; reductionSignature: string | null; preserved: boolean; reason: string })[];
  final: (EvidenceFile & { originalRows: number[]; sourceArtifact: string; caseStatus: "failed"; limits: Limits }) | null;
}

function runOptions(value: PersistentReductionRunOptions) {
  if (!value || typeof value !== "object" || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new Error("Invalid persistent reduction run options");
  for (const key of Reflect.ownKeys(value)) {
    const entry = Object.getOwnPropertyDescriptor(value, key)!;
    if (typeof key !== "string" || !["maxChecks", "maxElapsedMs", "signal"].includes(key) || !("value" in entry) || !entry.enumerable) throw new Error("Invalid persistent reduction run option");
  }
  const maxChecks = Object.hasOwn(value, "maxChecks") ? value.maxChecks! : 32;
  const maxElapsedMs = Object.hasOwn(value, "maxElapsedMs") ? value.maxElapsedMs! : 60000;
  if (!Number.isSafeInteger(maxChecks) || maxChecks < 1 || maxChecks > 256 || !Number.isSafeInteger(maxElapsedMs) || maxElapsedMs < 1 || maxElapsedMs > 60000) throw new Error("Reduction bounds: maxChecks 1..256 and maxElapsedMs 1..60000");
  if (Object.hasOwn(value, "signal") && !(value.signal instanceof AbortSignal)) throw new Error("Invalid persistent reduction run AbortSignal");
  return { maxChecks, maxElapsedMs, signal: value.signal };
}
function protocolFailure(error: unknown): PersistentResult {
  let message: unknown;
  try { message = error instanceof Error ? error.message : String(error); }
  catch { message = "Unreadable persistent reduction evaluator error"; }
  return incompletePersistentResult("persistent-protocol", typeof message === "string" ? message : "Invalid persistent reduction evaluator response");
}

/**
 * Bounded writer/orchestration, not a decoder or authenticator of saved reduction
 * summaries. Only the CLI selects the real fixed-fixture evaluator. Each saved
 * case uses the existing strict case schema and remains independently replayable.
 */
export async function writePersistentReductionRun(
  contents: Uint8Array,
  identity: PersistentIdentity,
  outputDirectory: string,
  evaluate: OwnedPersistentEvaluator,
  configuration: PersistentReductionRunOptions = {},
): Promise<PersistentReductionSummary> {
  const bounded = runOptions(configuration);
  if (!(contents instanceof Uint8Array) || contents.byteLength > PERSISTENT_FILE_BYTES) throw new Error("Persistent reduction input exceeds 1 MiB or is not bytes");
  if (typeof outputDirectory !== "string" || !outputDirectory || typeof evaluate !== "function") throw new Error("Persistent reduction requires an output directory and owned evaluator");
  const originalBytes = Buffer.from(contents);
  const previous = validatePersistentArtifact(JSON.parse(originalBytes.toString("utf8")));
  const currentIdentity = makePersistentArtifact(previous.sequence, identity, previous.limits, previous.result).identity;
  const changed = persistentIdentityChanges(previous.identity, currentIdentity);
  if (changed.length) throw new Error(`Persistent reduction requires exact build identity (${changed.join(", ")}); build comparison is not supported`);
  const saved = previous.limits;
  const output = resolve(outputDirectory);
  mkdirSync(output);
  const saveBytes = (artifact: string, bytes: Buffer): EvidenceFile => {
    if (bytes.length > PERSISTENT_FILE_BYTES) throw new Error("Persistent reduction evidence file exceeds 1 MiB");
    writeFileSync(resolve(output, artifact), bytes, { flag: "wx" });
    return { artifact, sha256: persistentDigest(bytes), bytes: bytes.length };
  };
  const save = (artifact: string, value: unknown) => saveBytes(artifact, Buffer.from(JSON.stringify(value, null, 2) + "\n"));
  const saveCase = (name: string, sequence: PersistentSequence, limits: Limits, result: PersistentResult) => save(name, makePersistentArtifact(sequence, currentIdentity, limits, result));
  const input = saveBytes("input.json", originalBytes);
  const deadline = performance.now() + bounded.maxElapsedMs;
  const controller = new AbortController();
  let timedOut = false;
  const abort = () => controller.abort();
  bounded.signal?.addEventListener("abort", abort, { once: true });
  if (bounded.signal?.aborted) abort();
  const timer = setTimeout(() => { timedOut = true; controller.abort(); }, bounded.maxElapsedMs);
  const remaining = () => Math.floor(deadline - performance.now());
  const timeout = (): PersistentResult => incompletePersistentResult("worker-timeout", "Persistent reduction total deadline exhausted");
  const interrupted = (): PersistentResult => incompletePersistentResult("worker-interrupted", "Persistent reduction was interrupted");
  const incomplete = () => timedOut || remaining() <= 0 ? timeout() : interrupted();
  const diagnostics = new Set<string>();
  const evaluations: EvaluationRecord[] = [];
  const measured = async (sequence: PersistentSequence, ceiling: number, signal: AbortSignal): Promise<PersistentResult> => {
    const model = validatePersistentSequence(sequence);
    const left = remaining();
    const limits = { ...saved, timeoutMs: left > 0 ? Math.min(saved.timeoutMs, ceiling, left) : saved.timeoutMs };
    const record: EvaluationRecord = { sequenceSha256: persistentDigest(JSON.stringify(model)), limits, evaluatorInvoked: false };
    evaluations.push(record);
    if (left <= 0 || signal.aborted) return incomplete();
    let cancel: (() => void) | undefined;
    try {
      const stopped = new Promise<PersistentResult>(resolve => { cancel = () => resolve(incomplete()); signal.addEventListener("abort", cancel, { once: true }); });
      const work = Promise.resolve().then(async () => {
        if (signal.aborted) return incomplete();
        record.evaluatorInvoked = true;
        try { return validatePersistentResult(model, await evaluate(validatePersistentSequence(model), { ...limits }, signal)); }
        catch (error) { return protocolFailure(error); }
      });
      const result = await Promise.race([stopped, work]);
      return remaining() <= 0 || signal.aborted ? incomplete() : result;
    } finally { if (cancel) signal.removeEventListener("abort", cancel); }
  };
  try {
    const replayResult = await measured(previous.sequence, saved.timeoutMs, controller.signal);
    const originalRecord = evaluations.shift()!;
    const originalReplay = { ...saveCase("original-replay.json", previous.sequence, originalRecord.limits, replayResult), ...originalRecord };
    const comparison = comparePersistentResults(previous.result, replayResult);
    const matchedFailure = previous.result.status === "failed" && replayResult.status === "failed" && comparison.sameStatus && comparison.sameSignature && comparison.sameObservation === true && comparison.sameCompiledJavaScript === true;
    let reduction: PersistentReductionResult | undefined;
    if (replayResult.status === "incomplete") diagnostics.add("persistent-reduction-original-incomplete");
    else if (!comparison.sameStatus || !comparison.sameSignature || comparison.sameObservation !== true || comparison.sameCompiledJavaScript !== true) diagnostics.add("persistent-reduction-replay-drift");
    else if (!matchedFailure) diagnostics.add("persistent-reduction-not-failed");
    const reductionRemaining = remaining();
    if (matchedFailure && reductionRemaining > 0 && !controller.signal.aborted) {
      reduction = await reducePersistentSequence(previous.sequence, replayResult, (candidate, context) => measured(candidate, context.timeoutMs, AbortSignal.any([controller.signal, context.signal])), {
        maxChecks: bounded.maxChecks, maxElapsedMs: reductionRemaining, signal: controller.signal,
      });
      for (const diagnostic of reduction.diagnostics) diagnostics.add(diagnostic);
    }
    const attempts: PersistentReductionSummary["attempts"] = [];
    let finalSequence = previous.sequence, finalResult = replayResult, finalLimits = originalRecord.limits;
    let finalRows = previous.sequence.operations.map((_, index) => index), sourceArtifact = originalReplay.artifact;
    for (const [index, attempt] of (reduction?.attempts ?? []).entries()) {
      const key = persistentDigest(JSON.stringify(attempt.sequence));
      const record = evaluations[index] ?? { sequenceSha256: key, limits: { ...saved }, evaluatorInvoked: false };
      if (record.sequenceSha256 !== key) throw new Error("Persistent reduction evaluator/audit sequence mismatch");
      const file = saveCase(`attempt-${String(index + 1).padStart(4, "0")}.json`, attempt.sequence, record.limits, attempt.result);
      attempts.push({ ...file, ...record, originalRows: [...attempt.originalRows], reductionSignature: attempt.reductionSignature, preserved: attempt.preserved, reason: attempt.reason });
      if (attempt.preserved) { finalSequence = attempt.sequence; finalResult = attempt.result; finalLimits = record.limits; finalRows = [...attempt.originalRows]; sourceArtifact = file.artifact; }
    }
    const final = matchedFailure ? { ...saveCase("final.json", finalSequence, finalLimits, finalResult), originalRows: finalRows, sourceArtifact, caseStatus: "failed" as const, limits: { ...finalLimits } } : null;
    if (timedOut || remaining() <= 0) diagnostics.add("persistent-reduction-time-budget");
    if (bounded.signal?.aborted) diagnostics.add("persistent-reduction-interrupted");
    if (matchedFailure && !reduction && !diagnostics.size) diagnostics.add("persistent-reduction-time-budget");
    const summary: PersistentReductionSummary = { schemaVersion: "nightshade-owned-persistent-reduction-run-1", scope: "owned-fixed-fixture-compiled-evaluation-only", identity: currentIdentity,
      savedWorkerLimits: { ...saved }, budget: { maxChecks: bounded.maxChecks, maxElapsedMs: bounded.maxElapsedMs }, input, originalReplay, replay: { ...comparison, matchedFailure },
      reductionStatus: diagnostics.size ? "incomplete" : "complete", diagnostics: [...diagnostics].sort(), reductionSignature: reduction?.reductionSignature ?? null,
      checks: attempts.length, changed: reduction?.changed ?? false, attempts, final };
    save("summary.json", summary);
    return structuredClone(summary);
  } finally { clearTimeout(timer); bounded.signal?.removeEventListener("abort", abort); }
}

export async function persistentReductionMain(args = process.argv.slice(2)): Promise<number> {
  if (args.length === 1 && args[0] === "--help") {
    console.log("Owned persistent failure reduction: --reduce CASE.json --output NEW_DIRECTORY [--max-checks 1..256] [--max-elapsed-ms 1..60000]\nRequires pinned COMPACTC_TEST and COMPACT_RUNTIME_TEST; run from repository root. Exact build identity and exact failed original replay are mandatory.\nExit 1: reduction complete with retained property failure; 2: incomplete/input/refusal/drift. No arbitrary source/state/adapters or failure injection.");
    return 0;
  }
  const flags = new Map<string, string>();
  for (let index = 0; index < args.length; index++) {
    const flag = args[index];
    if (!["--reduce", "--output", "--max-checks", "--max-elapsed-ms"].includes(flag) || flags.has(flag) || !args[index + 1] || args[index + 1].startsWith("--")) throw new Error(`Invalid persistent reduction argument ${flag}`);
    flags.set(flag, args[++index]);
  }
  if (!flags.has("--reduce") || !flags.has("--output")) throw new Error("Require --reduce CASE.json and new --output directory");
  const integer = (flag: string, fallback: number) => { const value = flags.get(flag); if (value !== undefined && !/^\d+$/.test(value)) throw new Error(`Invalid integer ${flag}`); return value === undefined ? fallback : Number(value); };
  const options = runOptions({ maxChecks: integer("--max-checks", 32), maxElapsedMs: integer("--max-elapsed-ms", 60000) });
  const contents = readPersistentFile(resolve(flags.get("--reduce")!));
  validatePersistentArtifact(JSON.parse(contents.toString("utf8")));
  if (!process.env.COMPACTC_TEST || !process.env.COMPACT_RUNTIME_TEST) throw new Error("Pinned COMPACTC_TEST and COMPACT_RUNTIME_TEST are mandatory");
  const compiler = resolve(process.env.COMPACTC_TEST), runtime = resolve(process.env.COMPACT_RUNTIME_TEST);
  const identity = persistentBuildIdentity(compiler, runtime);
  const controller = new AbortController(), cancel = () => controller.abort();
  process.once("SIGINT", cancel); process.once("SIGTERM", cancel);
  try {
    const summary = await writePersistentReductionRun(contents, identity, flags.get("--output")!, (sequence, limits, signal) => runPersistentSequenceIsolated(sequence, compiler, runtime, limits, signal), { maxChecks: options.maxChecks, maxElapsedMs: options.maxElapsedMs, signal: controller.signal });
    console.log(`${summary.reductionStatus}; ${summary.checks} reduction checks; ${summary.diagnostics.join(", ") || "retained failed property"}`);
    return summary.reductionStatus === "complete" ? 1 : 2;
  } finally { process.removeListener("SIGINT", cancel); process.removeListener("SIGTERM", cancel); }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { process.exitCode = await persistentReductionMain(); }
  catch (error) { console.error(error instanceof Error ? error.message : String(error)); process.exitCode = 2; }
}
