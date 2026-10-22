/** Pure proposals for the fixed owned fixture; measured original cases determine parents. */
import { PERSISTENT_FILE_BYTES, validatePersistentArtifact } from "./persistent-artifacts.js";
import { PersistentTransitionCorpus, type PersistentArtifactReference, type PersistentCorpusAdmission, type PersistentCorpusDiagnostic, type PersistentCorpusSnapshot } from "./persistent-corpus.js";
import { persistentDigest, validatePersistentSequence, type PersistentOperation, type PersistentSequence } from "./persistent-model.js";

export const PERSISTENT_SCHEDULER = "owned-persistent-snapshot-lcg-1";
export const PERSISTENT_SCHEDULE_DEFAULTS = Object.freeze({ seed: 1, mutations: 16, maxEvaluations: 20 });
export const PERSISTENT_SCHEDULE_MAX_SLOTS = 68;
export const PERSISTENT_SCHEDULE_STOP_REASONS = Object.freeze(["persistent-campaign-interrupted", "persistent-campaign-time-budget", "persistent-campaign-evidence-budget"] as const);
export type PersistentScheduleStopReason = typeof PERSISTENT_SCHEDULE_STOP_REASONS[number];
export type PersistentScheduleDiagnostic = PersistentCorpusDiagnostic | PersistentScheduleStopReason | "persistent-schedule-protocol" | "persistent-schedule-input-budget" | "persistent-evaluation-budget";
export interface PersistentScheduleOptions { seed: number; mutations: number; maxEvaluations: number }
export type PersistentMutation =
  | { kind: "insert" | "replace"; index: number; operation: PersistentOperation }
  | { kind: "delete"; index: number }
  | { kind: "slot-edit"; index: number; before: number; after: number };
export interface PersistentDecision {
  schemaVersion: "nightshade-persistent-decision-1";
  scheduler: typeof PERSISTENT_SCHEDULER;
  ordinal: number;
  phase: "bootstrap" | "mutation";
  bootstrap: 1 | 2 | 3 | 4 | null;
  parent: { retainedIndex: number; ordinal: number; artifactSha256: string; sequenceSha256: string; operationsSha256: string } | null;
  random: { before: number; after: number; words: number[] };
  mutation: PersistentMutation | null;
  sequence: PersistentSequence;
  sequenceSha256: string;
  operationsSha256: string;
}
export interface PersistentScheduleRow {
  ordinal: number;
  status: "passed" | "failed" | "incomplete";
  diagnostic: PersistentScheduleDiagnostic | null;
  artifact: PersistentArtifactReference | null;
  caseStatus: "passed" | "failed" | "incomplete" | null;
  signature: string | null;
  admission: PersistentCorpusAdmission | null;
}
export type PersistentScheduleOutcome =
  | { status: "running"; diagnostic: "running" }
  | { status: "passed"; diagnostic: "scheduled-slots-complete" }
  | { status: "failed"; diagnostic: "persistent-model-disagreement" }
  | { status: "incomplete"; diagnostic: PersistentScheduleDiagnostic };
export interface PersistentScheduleSnapshot {
  schemaVersion: "nightshade-persistent-schedule-1";
  scheduler: typeof PERSISTENT_SCHEDULER;
  options: PersistentScheduleOptions;
  planned: number;
  proposed: number;
  recorded: number;
  pending: PersistentDecision | null;
  outcome: PersistentScheduleOutcome;
  counts: { passed: number; failed: number; incomplete: number };
  rows: PersistentScheduleRow[];
  corpus: PersistentCorpusSnapshot;
}

function record<const Keys extends readonly string[]>(value: unknown, keys: Keys): Record<Keys[number], unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new Error("persistent-schedule-protocol: expected plain data object");
  const own = Reflect.ownKeys(value);
  if (own.length !== keys.length || own.some(key => typeof key !== "string" || !keys.includes(key))) throw new Error("persistent-schedule-protocol: unexpected fields");
  for (const key of keys) {
    const property = Object.getOwnPropertyDescriptor(value, key)!;
    if (!("value" in property) || !property.enumerable) throw new Error("persistent-schedule-protocol: expected enumerable data fields");
  }
  return value as Record<Keys[number], unknown>;
}
function integer(value: unknown, maximum: number, minimum = 0): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || Object.is(value, -0) || value < minimum || value > maximum) throw new Error(`persistent-schedule-protocol: expected integer ${minimum}..${maximum}`);
  return value;
}
export function validatePersistentScheduleOptions(value: unknown): PersistentScheduleOptions {
  const raw = record(value, ["seed", "mutations", "maxEvaluations"]);
  return { seed: integer(raw.seed, 0xffffffff), mutations: integer(raw.mutations, 64), maxEvaluations: integer(raw.maxEvaluations, PERSISTENT_SCHEDULE_MAX_SLOTS, 1) };
}
function words(value: unknown): number[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length !== 6 || Reflect.ownKeys(value).length !== 7) throw new Error("persistent-schedule-protocol: six dense uint32 words required");
  const result: number[] = [];
  for (let index = 0; index < 6; index++) {
    const property = Object.getOwnPropertyDescriptor(value, index);
    if (!property || !("value" in property) || !property.enumerable) throw new Error("persistent-schedule-protocol: words must be enumerable data");
    result.push(integer(property.value, 0xffffffff));
  }
  return result;
}

/** Fixed six-word edits, no oracle, retries, names, source or alternate state. */
export function mutatePersistentSequence(input: unknown, randomWords: unknown): { sequence: PersistentSequence; mutation: PersistentMutation } {
  const sequence = validatePersistentSequence(input), random = words(randomWords);
  const slots = sequence.operations.flatMap((operation, index) => "slot" in operation ? [{ index, slot: operation.slot }] : []);
  const families: PersistentMutation["kind"][] = [];
  if (sequence.operations.length < 32) families.push("insert");
  if (sequence.operations.length) families.push("delete", "replace");
  if (slots.length) families.push("slot-edit");
  const kind = families[(random[1] >>> 16) % families.length];
  let mutation: PersistentMutation;
  if (kind === "slot-edit") {
    const selected = slots[(random[2] >>> 16) % slots.length];
    const after = (selected.slot + 1 + (random[5] >>> 16) % 3) % 4;
    mutation = { kind, index: selected.index, before: selected.slot, after };
    sequence.operations[selected.index] = { ...sequence.operations[selected.index], slot: after } as PersistentOperation;
  } else {
    const index = (random[2] >>> 16) % (sequence.operations.length + (kind === "insert" ? 1 : 0));
    if (kind === "delete") { mutation = { kind, index }; sequence.operations.splice(index, 1); }
    else {
      const operationKind = (["accept", "reject", "inspect", "save", "restore"] as const)[(random[3] >>> 16) % 5];
      const operation: PersistentOperation = operationKind === "save" || operationKind === "restore" ? { kind: operationKind, slot: (random[4] >>> 16) % 4 } : { kind: operationKind };
      mutation = { kind, index, operation: { ...operation } };
      sequence.operations.splice(index, kind === "replace" ? 1 : 0, operation);
    }
  }
  return { sequence: validatePersistentSequence(sequence), mutation };
}

function bootstrap(ordinal: 1 | 2 | 3 | 4): PersistentSequence {
  const operations: PersistentOperation[][] = [[], [{ kind: "accept" }, { kind: "inspect" }], [{ kind: "reject" }, { kind: "accept" }], [
    { kind: "restore", slot: 3 }, { kind: "accept" }, { kind: "reject" }, { kind: "accept" },
    { kind: "save", slot: 0 }, { kind: "accept" }, { kind: "save", slot: 1 },
    { kind: "restore", slot: 0 }, { kind: "accept" }, { kind: "restore", slot: 3 },
    { kind: "restore", slot: 1 }, { kind: "restore", slot: 1 }, { kind: "save", slot: 0 }, { kind: "inspect" },
  ]];
  return validatePersistentSequence({ schemaVersion: "nightshade-persistent-sequence-1", seed: ordinal, operations: operations[ordinal - 1] });
}
class InputBudget extends Error {}
const byteLength = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), "byteLength")!.get!;
function capture(value: unknown): Uint8Array {
  if (!value || typeof value !== "object" || ![Buffer.prototype, Uint8Array.prototype].includes(Object.getPrototypeOf(value))) throw new Error("Expected original artifact bytes");
  const length: number = byteLength.call(value);
  if (length > PERSISTENT_FILE_BYTES) throw new InputBudget();
  const own = Reflect.ownKeys(value);
  if (own.length !== length || own.some((key, index) => key !== String(index))) throw new Error("Decorated artifact bytes");
  const copy = new Uint8Array(length);
  Uint8Array.prototype.set.call(copy, value as Uint8Array);
  return copy;
}

/** Qualified observations select parents; this state machine itself executes nothing. */
export class PersistentSchedule {
  readonly #options: Readonly<PersistentScheduleOptions>;
  #state: number;
  #corpus: PersistentTransitionCorpus;
  #pending: PersistentDecision | null = null;
  #proposed = 0;
  #rows: PersistentScheduleRow[] = [];
  #outcome: PersistentScheduleOutcome = { status: "running", diagnostic: "running" };
  constructor(identity: unknown, workerLimits: unknown, options: unknown = PERSISTENT_SCHEDULE_DEFAULTS, corpusBudgets: unknown = {}) {
    this.#options = Object.freeze(validatePersistentScheduleOptions(options));
    this.#state = this.#options.seed;
    this.#corpus = new PersistentTransitionCorpus(identity, workerLimits, corpusBudgets);
  }
  get options(): Readonly<PersistentScheduleOptions> { return this.#options; }
  get planned(): number { return 4 + this.#options.mutations; }
  next(): PersistentDecision | undefined {
    if (this.#outcome.status !== "running") return undefined;
    if (this.#pending) return structuredClone(this.#pending);
    const ordinal = this.#rows.length + 1;
    const parents = this.#corpus.snapshot().entries;
    if (ordinal > 4 && !parents.length) { this.#outcome = { status: "incomplete", diagnostic: "persistent-schedule-protocol" }; return undefined; }
    const random = { before: this.#state, after: this.#state, words: [] as number[] };
    for (let index = 0; index < 6; index++) random.words.push(this.#state = (Math.imul(this.#state, 1664525) + 1013904223) >>> 0);
    random.after = this.#state;
    const bootstrapOrdinal = ordinal <= 4 ? ordinal as 1 | 2 | 3 | 4 : null;
    let sequence: PersistentSequence;
    let mutation: PersistentMutation | null = null;
    let parent: PersistentDecision["parent"] = null;
    if (bootstrapOrdinal !== null) sequence = bootstrap(bootstrapOrdinal);
    else {
      const retainedIndex = (random.words[0] >>> 16) % parents.length;
      const selected = parents[retainedIndex];
      parent = { retainedIndex, ordinal: selected.ordinal, artifactSha256: selected.artifactSha256, sequenceSha256: selected.sequenceSha256, operationsSha256: selected.operationsSha256 };
      ({ sequence, mutation } = mutatePersistentSequence(selected.sequence, random.words));
    }
    this.#pending = { schemaVersion: "nightshade-persistent-decision-1", scheduler: PERSISTENT_SCHEDULER, ordinal, phase: bootstrapOrdinal === null ? "mutation" : "bootstrap", bootstrap: bootstrapOrdinal,
      parent, random, mutation, sequence, sequenceSha256: persistentDigest(JSON.stringify(sequence)), operationsSha256: persistentDigest(JSON.stringify(sequence.operations)) };
    this.#proposed++;
    return structuredClone(this.#pending);
  }
  record(originalArtifactBytes: unknown): PersistentScheduleRow {
    if (!this.#pending || this.#outcome.status !== "running") throw new Error("No pending persistent decision");
    const decision = this.#pending;
    let artifact: PersistentArtifactReference | null = null;
    let row: PersistentScheduleRow;
    try {
      const bytes = capture(originalArtifactBytes);
      artifact = { sha256: persistentDigest(bytes), bytes: bytes.byteLength };
      const checked = validatePersistentArtifact(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)));
      if (JSON.stringify(checked.sequence) !== JSON.stringify(decision.sequence)) throw new Error("Artifact differs from pending sequence");
      const admission = this.#corpus.consider(bytes);
      row = { ordinal: decision.ordinal, status: admission.status === "property-failed" ? "failed" : admission.status === "incomplete" ? "incomplete" : "passed", diagnostic: admission.diagnostic,
        artifact, caseStatus: admission.caseStatus, signature: admission.signature, admission };
    } catch (error) {
      row = { ordinal: decision.ordinal, status: "incomplete", diagnostic: error instanceof InputBudget ? "persistent-schedule-input-budget" : "persistent-schedule-protocol", artifact, caseStatus: null, signature: null, admission: null };
    }
    this.#rows.push(row);
    this.#pending = null;
    if (row.status === "failed") this.#outcome = { status: "failed", diagnostic: "persistent-model-disagreement" };
    else if (row.status === "incomplete") this.#outcome = { status: "incomplete", diagnostic: row.diagnostic! };
    else if (this.#rows.length === 4 + this.#options.mutations) this.#outcome = { status: "passed", diagnostic: "scheduled-slots-complete" };
    else if (this.#rows.length === this.#options.maxEvaluations) this.#outcome = { status: "incomplete", diagnostic: "persistent-evaluation-budget" };
    return structuredClone(row);
  }
  stop(reason: PersistentScheduleStopReason): void {
    if (typeof reason !== "string" || !PERSISTENT_SCHEDULE_STOP_REASONS.includes(reason)) throw new Error("persistent-schedule-protocol: invalid external stop reason");
    if (this.#pending) throw new Error("Pending persistent decision requires an explicit case result");
    if (this.#outcome.status === "running") this.#outcome = { status: "incomplete", diagnostic: reason };
  }
  snapshot(): PersistentScheduleSnapshot {
    const counts = { passed: 0, failed: 0, incomplete: 0 };
    for (const row of this.#rows) counts[row.status]++;
    return { schemaVersion: "nightshade-persistent-schedule-1", scheduler: PERSISTENT_SCHEDULER, options: { ...this.#options }, planned: 4 + this.#options.mutations, proposed: this.#proposed, recorded: this.#rows.length,
      pending: this.#pending && structuredClone(this.#pending), outcome: { ...this.#outcome }, counts, rows: structuredClone(this.#rows), corpus: this.#corpus.snapshot() };
  }
}
