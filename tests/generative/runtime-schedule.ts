import { digest } from "./artifacts.js";
import { generateCase, renderCase, validateCase, type GeneratedCase, type Operation } from "./model.js";
import { RuntimeTransitionCorpus, type CorpusAdmission } from "./runtime-feedback.js";
import { validateRuntimeResult } from "./runtime-artifacts.js";

export const RUNTIME_SCHEDULER = "owned-checkpoint-lcg-1";
export interface ScheduleOptions { seed: number; mutations: number; maxCases: number; maxFeatures: number; maxEvaluations: number }
export const DEFAULT_SCHEDULE: Readonly<ScheduleOptions> = Object.freeze({ seed: 1, mutations: 16, maxCases: 128, maxFeatures: 512, maxEvaluations: 68 });

/** Exact data-only objects; untrusted saved metadata must not execute getters. */
export function scheduleRecord(value: unknown, keys: string[], label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new Error(`Invalid ${label}`);
  const own = Reflect.ownKeys(value);
  if (own.length !== keys.length || own.some(key => typeof key !== "string" || !keys.includes(key))) throw new Error(`Invalid ${label} fields`);
  for (const key of own) {
    const property = Object.getOwnPropertyDescriptor(value, key)!;
    if (!("value" in property) || !property.enumerable) throw new Error(`Invalid ${label} data field`);
  }
  return value as Record<string, unknown>;
}

/** Compare only the bounded structure of a freshly computed expectation. */
export function sameScheduleData(actual: unknown, expected: unknown): boolean {
  if (!expected || typeof expected !== "object") return Object.is(actual, expected);
  if (!actual || typeof actual !== "object" || Array.isArray(actual) !== Array.isArray(expected)) return false;
  if (Array.isArray(actual) ? Object.getPrototypeOf(actual) !== Array.prototype : ![Object.prototype, null].includes(Object.getPrototypeOf(actual))) return false;
  const keys = Reflect.ownKeys(expected);
  if (Reflect.ownKeys(actual).length !== keys.length) return false;
  return keys.every(key => {
    const property = Object.getOwnPropertyDescriptor(actual, key);
    return !!property && "value" in property && property.enumerable === Object.getOwnPropertyDescriptor(expected, key)!.enumerable
      && sameScheduleData(property.value, (expected as Record<PropertyKey, unknown>)[key]);
  });
}

export function validateScheduleOptions(value: unknown): ScheduleOptions {
  const raw = scheduleRecord(value, ["seed", "mutations", "maxCases", "maxFeatures", "maxEvaluations"], "schedule options");
  for (const [key, minimum, maximum] of [["seed", 0, 0xffffffff], ["mutations", 0, 64], ["maxCases", 1, 256], ["maxFeatures", 1, 4096], ["maxEvaluations", 1, 68]] as const) {
    const entry = raw[key];
    if (typeof entry !== "number" || !Number.isSafeInteger(entry) || Object.is(entry, -0) || entry < minimum || entry > maximum) throw new Error(`${key} must be ${minimum}..${maximum}`);
  }
  return { ...raw } as unknown as ScheduleOptions;
}

export type RuntimeMutation =
  | { kind: "insert" | "replace"; index: number; operation: Operation }
  | { kind: "delete"; index: number }
  | { kind: "operand"; index: number; field: "key" | "value"; before: number; after: number };

/** Six fixed PRNG words per slot; no search/retry loop and no arbitrary names. */
export function mutateRuntimeModel(input: GeneratedCase, words: readonly number[]): { model: GeneratedCase; mutation: RuntimeMutation } {
  const model = validateCase(input);
  if (!Array.isArray(words) || Object.getPrototypeOf(words) !== Array.prototype || words.length !== 6 || Reflect.ownKeys(words).length !== 7) throw new Error("Mutation requires six uint32 words");
  for (let index = 0; index < 6; index++) {
    const property = Object.getOwnPropertyDescriptor(words, index);
    if (!property || !("value" in property) || !Number.isSafeInteger(property.value) || Object.is(property.value, -0) || property.value < 0 || property.value > 0xffffffff) throw new Error("Mutation requires six uint32 words");
  }
  const operands: { index: number; field: "key" | "value"; value: number }[] = [];
  model.operations.forEach((operation, index) => {
    if ("key" in operation) operands.push({ index, field: "key", value: operation.key });
    if ("value" in operation) operands.push({ index, field: "value", value: operation.value });
  });
  const families: RuntimeMutation["kind"][] = [];
  if (model.operations.length < 32) families.push("insert");
  if (model.operations.length) families.push("delete", "replace");
  if (operands.length) families.push("operand");
  const kind = families[(words[1] >>> 16) % families.length];
  let mutation: RuntimeMutation;
  if (kind === "operand") {
    const operand = operands[(words[2] >>> 16) % operands.length];
    const boundaries = operand.field === "key" ? [0, 1, 7] : [0, 1, 255, 256, 65535];
    const sampled = words[3] % (operand.field === "key" ? 8 : 65536);
    const choices = [...new Set([...boundaries, sampled])].filter(value => value !== operand.value);
    const after = choices[(words[4] >>> 16) % choices.length];
    mutation = { kind, index: operand.index, field: operand.field, before: operand.value, after };
    model.operations[operand.index] = { ...model.operations[operand.index], [operand.field]: after } as Operation;
  } else {
    const index = (words[2] >>> 16) % (model.operations.length + (kind === "insert" ? 1 : 0));
    if (kind === "delete") { mutation = { kind, index }; model.operations.splice(index, 1); }
    else {
      const operation = generateCase(words[3], 1).operations[0];
      if ("key" in operation) operation.key = (words[4] >>> 16) % 8;
      if ("value" in operation) operation.value = [0, 1, 255, 256, 65535, words[5] >>> 16][(words[5] >>> 16) % 6];
      mutation = { kind, index, operation: structuredClone(operation) };
      model.operations.splice(index, kind === "replace" ? 1 : 0, operation);
    }
  }
  // seed retains the bootstrap ancestor; the decision transcript reproduces edits.
  return { model: validateCase(model), mutation };
}

export interface RuntimeDecision {
  schemaVersion: "nightshade-runtime-decision-1";
  scheduler: typeof RUNTIME_SCHEDULER;
  ordinal: number;
  phase: "bootstrap" | "mutation";
  parent: { ordinal: number; artifactSha256: string; sourceSha256: string } | null;
  random: { before: number; after: number; words: number[] };
  mutation: RuntimeMutation | null;
  case: GeneratedCase;
  modelSha256: string;
  sourceSha256: string;
}
export interface ScheduleRow {
  ordinal: number;
  status: "passed" | "failed" | "incomplete";
  category: string;
  resultStatus: "passed" | "failed" | "incomplete";
  signature: string;
  admission: CorpusAdmission | null;
}
export interface ScheduleOutcome { status: "running" | "passed" | "failed" | "incomplete"; category: string }
export interface ScheduleSnapshot {
  planned: number;
  completed: number;
  outcome: ScheduleOutcome;
  counts: { passed: number; failed: number; incomplete: number };
  rows: ScheduleRow[];
  corpus: ReturnType<RuntimeTransitionCorpus["snapshot"]>;
}

/** Owned proposals only. Observations are validated data, not runtime attestation. */
export class RuntimeSchedule {
  readonly options: Readonly<ScheduleOptions>;
  private state: number;
  private readonly corpus: RuntimeTransitionCorpus;
  private readonly parents: { decision: RuntimeDecision; artifactSha256: string }[] = [];
  private pending?: RuntimeDecision;
  private rows: ScheduleRow[] = [];
  private outcome: ScheduleOutcome = { status: "running", category: "running" };
  constructor(options: ScheduleOptions = { ...DEFAULT_SCHEDULE }) {
    this.options = Object.freeze(validateScheduleOptions(options));
    this.state = this.options.seed;
    this.corpus = new RuntimeTransitionCorpus(this.options.maxCases, this.options.maxFeatures);
  }
  get planned(): number { return 4 + this.options.mutations; }
  next(): RuntimeDecision | undefined {
    if (this.outcome.status !== "running") return undefined;
    if (this.pending) return structuredClone(this.pending);
    const ordinal = this.rows.length + 1;
    const random = { before: this.state, after: this.state, words: [] as number[] };
    let model: GeneratedCase;
    let mutation: RuntimeMutation | null = null;
    let parent: RuntimeDecision["parent"] = null;
    if (ordinal <= 4) model = generateCase(ordinal, 24);
    else {
      if (!this.parents.length) throw new Error("Completed bootstraps must retain a measured parent");
      for (let index = 0; index < 6; index++) random.words.push(this.state = (Math.imul(this.state, 1664525) + 1013904223) >>> 0);
      random.after = this.state;
      const selected = this.parents[(random.words[0] >>> 16) % this.parents.length];
      parent = { ordinal: selected.decision.ordinal, artifactSha256: selected.artifactSha256, sourceSha256: selected.decision.sourceSha256 };
      ({ model, mutation } = mutateRuntimeModel(selected.decision.case, random.words));
    }
    this.pending = { schemaVersion: "nightshade-runtime-decision-1", scheduler: RUNTIME_SCHEDULER, ordinal, phase: ordinal <= 4 ? "bootstrap" : "mutation",
      parent, random, mutation, case: model, modelSha256: digest(JSON.stringify(model)), sourceSha256: digest(renderCase(model)) };
    return structuredClone(this.pending);
  }
  record(value: unknown, artifactSha256: string): ScheduleRow {
    if (!this.pending || this.outcome.status !== "running") throw new Error("No pending runtime decision");
    if (!/^[a-f0-9]{64}$/.test(artifactSha256)) throw new Error("Invalid candidate artifact digest");
    const decision = this.pending;
    const result = validateRuntimeResult(decision.case, value);
    const admission = result.status === "passed" ? this.corpus.consider(decision.case, result.observation) : null;
    const status = admission?.status === "incomplete" ? "incomplete" : result.status;
    const category = admission?.diagnostic ?? result.category;
    const row: ScheduleRow = { ordinal: decision.ordinal, status, category, resultStatus: result.status, signature: result.signature, admission };
    if (admission?.status === "retained") this.parents.push({ decision: structuredClone(decision), artifactSha256 });
    this.rows.push(row);
    this.pending = undefined;
    if (status !== "passed") this.outcome = { status, category };
    else if (this.rows.length === this.planned) this.outcome = { status: "passed", category: "scheduled-slots-complete" };
    else if (this.rows.length === this.options.maxEvaluations) this.outcome = { status: "incomplete", category: "runtime-evaluation-budget" };
    return structuredClone(row);
  }
  interrupt(): void {
    if (this.pending) throw new Error("A pending candidate requires an explicit checked incomplete result");
    if (this.outcome.status === "running") this.outcome = { status: "incomplete", category: "runtime-campaign-interrupted" };
  }
  snapshot(): ScheduleSnapshot {
    const counts = { passed: 0, failed: 0, incomplete: 0 };
    for (const row of this.rows) counts[row.status]++;
    return { planned: this.planned, completed: this.rows.length, outcome: { ...this.outcome }, counts, rows: structuredClone(this.rows), corpus: this.corpus.snapshot() };
  }
}
