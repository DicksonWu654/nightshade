import { incompletePersistentResult, validatePersistentResult, type PersistentResult } from "./persistent-artifacts.js";
import { validatePersistentSequence, type PersistentSequence } from "./persistent-model.js";

export interface PersistentReductionOptions {
  maxChecks?: number;
  maxElapsedMs?: number;
  signal?: AbortSignal;
}
export interface PersistentEvaluationContext {
  signal: AbortSignal;
  /** Remaining overall deadline. Runtime callers must also supervise their worker. */
  timeoutMs: number;
}
export type PersistentReductionDiagnostic = "persistent-reduction-check-budget" | "persistent-reduction-time-budget" | "persistent-reduction-interrupted" | "persistent-reduction-evaluation-incomplete" | "persistent-reduction-build-drift";
export interface PersistentReductionAttempt {
  sequence: PersistentSequence;
  originalRows: number[];
  result: PersistentResult;
  reductionSignature: string | null;
  preserved: boolean;
  reason: "preserved" | "passed" | "different-property" | "compiled-build-drift" | "incomplete-evaluation" | "time-budget" | "interrupted";
}
export interface PersistentReductionResult {
  schemaVersion: "nightshade-persistent-reduction-1";
  status: "complete" | "incomplete";
  diagnostics: PersistentReductionDiagnostic[];
  sequence: PersistentSequence;
  originalRows: number[];
  result: PersistentResult;
  reductionSignature: string;
  checks: number;
  changed: boolean;
  attempts: PersistentReductionAttempt[];
}
export interface PersistentReductionCandidate { sequence: PersistentSequence; originalRows: number[] }
const diagnosticOrder: PersistentReductionDiagnostic[] = ["persistent-reduction-check-budget", "persistent-reduction-time-budget", "persistent-reduction-interrupted", "persistent-reduction-evaluation-incomplete", "persistent-reduction-build-drift"];

function options(value: PersistentReductionOptions) {
  if (!value || typeof value !== "object" || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new Error("Invalid persistent reduction options");
  for (const key of Reflect.ownKeys(value)) {
    const field = Object.getOwnPropertyDescriptor(value, key)!;
    if (typeof key !== "string" || !["maxChecks", "maxElapsedMs", "signal"].includes(key) || !("value" in field) || !field.enumerable) throw new Error("Invalid persistent reduction options field");
  }
  const maxChecks = Object.hasOwn(value, "maxChecks") ? value.maxChecks! : 32;
  const maxElapsedMs = Object.hasOwn(value, "maxElapsedMs") ? value.maxElapsedMs! : 60000;
  for (const [name, number, maximum] of [["maxChecks", maxChecks, 256], ["maxElapsedMs", maxElapsedMs, 60000]] as const) {
    if (!Number.isSafeInteger(number) || number < 1 || number > maximum) throw new Error(`Persistent reduction ${name} budget must be 1..${maximum}`);
  }
  if (Object.hasOwn(value, "signal") && !(value.signal instanceof AbortSignal)) throw new Error("Invalid persistent reduction AbortSignal");
  return { maxChecks, maxElapsedMs, signal: value.signal };
}

/** Called only after result rederivation: origin maps are reducer-owned, never input. */
export function persistentReductionProperty(candidate: PersistentReductionCandidate, result: PersistentResult): string | null {
  if (result.status !== "failed") return null;
  const row = /^persistent-model\|row:(\d+)\|operation:(accept|reject|inspect|save|restore)\|field:([a-zA-Z0-9.]+)$/.exec(result.signature);
  if (row) {
    const index = Number(row[1]);
    if (candidate.originalRows[index] === undefined || candidate.sequence.operations[index]?.kind !== row[2]) throw new Error("Invalid qualified persistent failure row");
    return `persistent-reduction-property-1|original-row:${candidate.originalRows[index]}|operation:${row[2]}|field:${row[3]}`;
  }
  const state = /^persistent-model\|field:((?:initial|final)\.[a-zA-Z0-9.]+)$/.exec(result.signature);
  if (!state) throw new Error("Unsupported qualified persistent failure property");
  return `persistent-reduction-property-1|field:${state[1]}`;
}

export function* persistentReductionCandidates(current: PersistentReductionCandidate): Generator<PersistentReductionCandidate> {
  const { sequence, originalRows } = current;
  const seen = new Set<string>();
  function candidate(operations: PersistentSequence["operations"], rows: number[]): PersistentReductionCandidate | undefined {
    const result = { sequence: validatePersistentSequence({ ...sequence, operations }), originalRows: [...rows] };
    const key = JSON.stringify(result);
    if (seen.has(key)) return undefined;
    seen.add(key);
    return result;
  }
  const empty = sequence.operations.length ? candidate([], []) : undefined;
  if (empty) yield empty;
  for (let width = Math.ceil(sequence.operations.length / 2); width >= 1; width = Math.floor(width / 2)) {
    for (let start = 0; start < sequence.operations.length; start += width) {
      const next = candidate([...sequence.operations.slice(0, start), ...sequence.operations.slice(start + width)], [...originalRows.slice(0, start), ...originalRows.slice(start + width)]);
      if (next) yield next;
    }
  }
  // All slots start initialized. An injective global rename preserves every
  // save/restore alias class; independent operand changes could merge histories.
  const used = new Set(sequence.operations.flatMap(operation => "slot" in operation ? [operation.slot] : []));
  for (const from of [...used].sort((a, b) => a - b)) {
    for (let to = 0; to < from; to++) {
      if (used.has(to)) continue;
      const next = candidate(sequence.operations.map(operation => "slot" in operation && operation.slot === from ? { ...operation, slot: to } : operation), originalRows);
      if (next) yield next;
    }
  }
}

function protocolFailure(error: unknown): PersistentResult {
  let message: unknown;
  try { message = error instanceof Error ? error.message : String(error); }
  catch { message = "Unreadable persistent evaluator exception"; }
  return incompletePersistentResult("persistent-protocol", typeof message === "string" && message ? message : "Invalid persistent evaluator result or empty exception");
}

type Evaluation = { kind: "result"; value: unknown } | { kind: "error"; error: unknown } | { kind: "time-budget" } | { kind: "interrupted" };
async function evaluateBounded(candidate: PersistentSequence, evaluate: (candidate: PersistentSequence, context: PersistentEvaluationContext) => Promise<unknown>, timeoutMs: number, signal?: AbortSignal): Promise<Evaluation> {
  if (signal?.aborted) return { kind: "interrupted" };
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let interrupted: (() => void) | undefined;
  try {
    const stop = new Promise<Evaluation>(resolve => {
      timer = setTimeout(() => { resolve({ kind: "time-budget" }); controller.abort(); }, timeoutMs);
      interrupted = () => { resolve({ kind: "interrupted" }); controller.abort(); };
      signal?.addEventListener("abort", interrupted, { once: true });
    });
    // Rejections and late completions remain handled after the deadline race.
    const work = Promise.resolve().then(() => {
      if (controller.signal.aborted) throw new Error("Persistent evaluator cancelled before invocation");
      return evaluate(structuredClone(candidate), { signal: controller.signal, timeoutMs });
    }).then<Evaluation, Evaluation>(value => ({ kind: "result", value }), error => ({ kind: "error", error }));
    return await Promise.race([stop, work]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    if (interrupted) signal?.removeEventListener("abort", interrupted);
  }
}

/**
 * Pure typed orchestration. No files, source, initial state, adapters or stored
 * code are evaluated. Callers supply the fixed-fixture evaluator. A complete
 * result means this deterministic finite local schedule finished, not a global
 * minimum, independent qualification or evidence of an identical root cause.
 */
export async function reducePersistentSequence(
  input: PersistentSequence,
  initial: PersistentResult,
  evaluate: (candidate: PersistentSequence, context: PersistentEvaluationContext) => Promise<unknown>,
  configuration: PersistentReductionOptions = {},
): Promise<PersistentReductionResult> {
  const bounded = options(configuration);
  if (typeof evaluate !== "function") throw new Error("Persistent reducer requires an evaluator");
  const original = validatePersistentSequence(input);
  let current: PersistentReductionCandidate = { sequence: original, originalRows: original.operations.map((_, index) => index) };
  let accepted = validatePersistentResult(original, initial);
  if (accepted.status !== "failed") throw new Error("Persistent reduction requires a rederived model-disagreement failure");
  const signature = persistentReductionProperty(current, accepted)!;
  const anchor = /^persistent-reduction-property-1\|original-row:(\d+)\|/.exec(signature);
  const originalAnchor = anchor ? Number(anchor[1]) : undefined;
  const compiled = accepted.observation.compiledJavaScriptSha256;
  const deadline = performance.now() + bounded.maxElapsedMs;
  const attempts: PersistentReductionAttempt[] = [];
  const diagnostics = new Set<PersistentReductionDiagnostic>();
  const seen = new Set([JSON.stringify(current)]);
  const stopped = (): boolean => {
    if (bounded.signal?.aborted) diagnostics.add("persistent-reduction-interrupted");
    if (performance.now() >= deadline) diagnostics.add("persistent-reduction-time-budget");
    return diagnostics.has("persistent-reduction-interrupted") || diagnostics.has("persistent-reduction-time-budget");
  };
  search: while (!stopped()) {
    let reduced = false;
    for (const candidate of persistentReductionCandidates(current)) {
      if (originalAnchor !== undefined && !candidate.originalRows.includes(originalAnchor)) continue;
      const key = JSON.stringify(candidate);
      if (seen.has(key)) continue;
      if (stopped()) break search;
      if (attempts.length >= bounded.maxChecks) { diagnostics.add("persistent-reduction-check-budget"); break search; }
      seen.add(key);
      const evaluation = await evaluateBounded(candidate.sequence, evaluate, Math.max(1, Math.ceil(deadline - performance.now())), bounded.signal);
      let result: PersistentResult;
      if (evaluation.kind === "time-budget") {
        diagnostics.add("persistent-reduction-time-budget");
        result = incompletePersistentResult("worker-timeout", "Persistent reduction overall deadline exhausted; evaluator abort requested");
      } else if (evaluation.kind === "interrupted") {
        diagnostics.add("persistent-reduction-interrupted");
        result = incompletePersistentResult("worker-interrupted", "Persistent reduction interrupted; evaluator abort requested");
      } else {
        try { result = evaluation.kind === "error" ? protocolFailure(evaluation.error) : validatePersistentResult(candidate.sequence, evaluation.value); }
        catch (error) { result = protocolFailure(error); }
      }
      if (result.status === "incomplete") {
        diagnostics.add("persistent-reduction-evaluation-incomplete");
        if (result.diagnostic === "worker-interrupted") diagnostics.add("persistent-reduction-interrupted");
      }
      const interrupted = stopped();
      const reductionSignature = persistentReductionProperty(candidate, result);
      let reason: PersistentReductionAttempt["reason"];
      if (diagnostics.has("persistent-reduction-interrupted")) reason = "interrupted";
      else if (interrupted) reason = "time-budget";
      else if (result.status === "incomplete") reason = "incomplete-evaluation";
      else if (result.observation.compiledJavaScriptSha256 !== compiled) { reason = "compiled-build-drift"; diagnostics.add("persistent-reduction-build-drift"); }
      else if (result.status === "passed") reason = "passed";
      else reason = reductionSignature === signature ? "preserved" : "different-property";
      const preserved = reason === "preserved";
      attempts.push({ sequence: validatePersistentSequence(candidate.sequence), originalRows: [...candidate.originalRows], result: structuredClone(result), reductionSignature, preserved, reason });
      if (interrupted) break search;
      if (preserved) { current = candidate; accepted = result; reduced = true; break; }
    }
    if (!reduced) break;
  }
  return { schemaVersion: "nightshade-persistent-reduction-1", status: diagnostics.size ? "incomplete" : "complete", diagnostics: diagnosticOrder.filter(diagnostic => diagnostics.has(diagnostic)),
    sequence: validatePersistentSequence(current.sequence), originalRows: [...current.originalRows], result: validatePersistentResult(current.sequence, accepted), reductionSignature: signature,
    checks: attempts.length, changed: JSON.stringify(current.sequence) !== JSON.stringify(original), attempts };
}
