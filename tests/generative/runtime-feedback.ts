import { createHash } from "node:crypto";
import { expectedFlagObservations, renderCase, validateCase, type GeneratedCase } from "./model.js";

interface Atom { kind: "integer" | "boolean"; value: string }
export type Observation = Atom | Observation[];
interface Execution { flag: boolean; outcome: "evaluation-success"; result: Observation }
export interface RuntimeObservation {
  layer: "compiled-evaluation-only";
  source: "validated-owned-generated-model";
  compiler: "0.34.0";
  language: "0.26.0";
  runtime: "0.19.0";
  onchainRuntime: "4.0.0-rc.3";
  generatedSourceSha256: string;
  compiledJavaScriptSha256: string;
  fixedTime: 1700000000;
  executions: Execution[];
}

export interface RuntimeFeedback {
  schemaVersion: "nightshade-runtime-checkpoint-feedback-1";
  coverageKind: "observed-checkpoint-transitions";
  sourceSha256: string;
  compiledJavaScriptSha256: string;
  checkpoints: { flag: boolean; index: number; operation: string; features: string[] }[];
  features: string[];
}

export class RuntimeModelMismatch extends Error {
  constructor(readonly signature: string) {
    super(`Compiled observations disagree with the owned concrete model: ${signature}`);
  }
}
const sha = (value: string) => createHash("sha256").update(value).digest("hex");

function record(value: unknown, keys: string[], label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new Error(`Invalid ${label}`);
  const own = Reflect.ownKeys(value);
  if (own.length !== keys.length || own.some(key => typeof key !== "string" || !keys.includes(key))) throw new Error(`Invalid ${label} fields`);
  for (const key of keys) if (!("value" in Object.getOwnPropertyDescriptor(value, key)!)) throw new Error(`Invalid ${label} accessor`);
  return value as Record<string, unknown>;
}

function array(value: unknown, maximum: number): unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length > maximum || Reflect.ownKeys(value).length !== value.length + 1) throw new Error("Invalid bounded observation array");
  for (let index = 0; index < value.length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(value, index);
    if (!descriptor || !("value" in descriptor)) throw new Error("Invalid observation array element");
  }
  return value;
}

/** Decode and detach complete wire observations, before checking their values. */
export function validateRuntimeObservation(input: GeneratedCase, value: unknown): RuntimeObservation {
  const model = validateCase(input);
  const wire = record(value, ["layer", "source", "compiler", "language", "runtime", "onchainRuntime", "generatedSourceSha256", "compiledJavaScriptSha256", "fixedTime", "executions"], "runtime observation");
  for (const [key, expected] of Object.entries({ layer: "compiled-evaluation-only", source: "validated-owned-generated-model", compiler: "0.34.0", language: "0.26.0", runtime: "0.19.0", onchainRuntime: "4.0.0-rc.3", fixedTime: 1700000000 })) if (wire[key] !== expected) throw new Error(`Unqualified runtime observation ${key}`);
  const sourceSha256 = sha(renderCase(model));
  if (wire.generatedSourceSha256 !== sourceSha256) throw new Error("Runtime observation source/model mismatch");
  if (typeof wire.compiledJavaScriptSha256 !== "string" || !/^[a-f0-9]{64}$/.test(wire.compiledJavaScriptSha256)) throw new Error("Invalid compiled JavaScript identity");
  let nodes = 0;
  const decode = (raw: unknown, depth = 0): Observation => {
    if (++nodes > 512 || depth > 3) throw new Error("Runtime observation representation budget exhausted");
    if (Array.isArray(raw)) return array(raw, 32).map(item => decode(item, depth + 1));
    const atom = record(raw, ["kind", "value"], "runtime scalar");
    if (typeof atom.value !== "string" || atom.value.length > 80) throw new Error("Invalid runtime scalar value");
    if (atom.kind === "boolean" && ["true", "false"].includes(atom.value)) return { kind: "boolean", value: atom.value };
    if (atom.kind === "integer" && /^(?:0|-?[1-9][0-9]*)$/.test(atom.value)) return { kind: "integer", value: atom.value };
    throw new Error("Invalid runtime scalar kind/value");
  };
  const executions = array(wire.executions, 2).map((raw): Execution => {
    const execution = record(raw, ["flag", "outcome", "result"], "runtime execution");
    if (typeof execution.flag !== "boolean" || execution.outcome !== "evaluation-success") throw new Error("Missing successful runtime evaluation evidence");
    return { flag: execution.flag, outcome: "evaluation-success", result: decode(execution.result) };
  });
  if (executions.length !== 2 || new Set(executions.map(execution => execution.flag)).size !== 2) throw new Error("Runtime observations require both distinct Boolean inputs");
  executions.sort((left, right) => Number(left.flag) - Number(right.flag));
  return { layer: "compiled-evaluation-only", source: "validated-owned-generated-model", compiler: "0.34.0", language: "0.26.0",
    runtime: "0.19.0", onchainRuntime: "4.0.0-rc.3", fixedTime: 1700000000, generatedSourceSha256: sourceSha256,
    compiledJavaScriptSha256: wire.compiledJavaScriptSha256, executions };
}

/** Validate bounded wire evidence and check independent return-shape/value properties. */
export function runtimeFeedback(input: GeneratedCase, value: unknown): RuntimeFeedback {
  const model = validateCase(input);
  const wire = validateRuntimeObservation(model, value);
  const { executions } = wire;
  const expected = expectedFlagObservations(model);
  // A complete, bounded measured return with the wrong layout is a property
  // failure. Missing execution/envelope fields are protocol failures above.
  // Signatures identify the first violated property, excluding numeric operands
  // and shifting checkpoint indices so typed deletion can preserve the property.
  const fields = ["scalar", "membership", "cardinality", "saved", "unrelated"];
  for (const [at, execution] of executions.entries()) {
    const prefix = `runtime-model|flag:${execution.flag}`;
    if (!Array.isArray(execution.result) || execution.result.length !== expected[at].observations.length) throw new RuntimeModelMismatch(`${prefix}|return-layout`);
    for (const [index, row] of execution.result.entries()) {
      const site = `${prefix}|operation:${model.operations[index]?.kind ?? "read"}`;
      if (!Array.isArray(row) || row.length !== fields.length) throw new RuntimeModelMismatch(`${site}|checkpoint-layout`);
      for (const [column, atom] of row.entries()) {
        const property = `${site}|field:${fields[column]}`;
        if (Array.isArray(atom) || atom.kind !== (column === 1 ? "boolean" : "integer")) throw new RuntimeModelMismatch(`${property}|kind`);
        if (atom.value !== expected[at].observations[index][column]) throw new RuntimeModelMismatch(`${property}|value`);
      }
    }
  }

  const operations = model.operations.length ? model.operations : [{ kind: "read", key: 0 } as const];
  const relation = (before: Atom, after: Atom) => BigInt(after.value) === BigInt(before.value) ? "same" : BigInt(after.value) > BigInt(before.value) ? "up" : "down";
  const checkpoints: RuntimeFeedback["checkpoints"] = [];
  for (const execution of executions) {
    // Values below come from validated measured outputs, not expected-model rows.
    // The first checkpoint has no invented preceding runtime observation.
    const observed = execution.result as Atom[][];
    observed.forEach((current, index) => {
      const operation = operations[index];
      const size = BigInt(current[2].value);
      const features = [`checkpoint|${operation.kind}|member:${current[1].value}|size:${size === 0n ? "zero" : size === 1n ? "one" : "many"}|scalar:${current[0].value === "0" ? "zero" : "nonzero"}|saved-current:${current[3].value === current[0].value}|other:${current[4].value === "0" ? "zero" : "nonzero"}`];
      if (index) {
        const previous = observed[index - 1];
        const priorOperation = operations[index - 1];
        const key = "key" in operation ? operation.key : 0;
        const priorKey = "key" in priorOperation ? priorOperation.key : 0;
        // Membership of different queried keys is not a membership transition.
        const membership = key === priorKey ? `${previous[1].value}->${current[1].value}` : "different-query-keys";
        features.push(`edge|${priorOperation.kind}->${operation.kind}|scalar:${relation(previous[0], current[0])}|size:${size - BigInt(previous[2].value)}|saved:${relation(previous[3], current[3])}|other:${relation(previous[4], current[4])}|member:${membership}`);
      }
      checkpoints.push({ flag: execution.flag, index, operation: operation.kind, features });
    });
  }
  return { schemaVersion: "nightshade-runtime-checkpoint-feedback-1", coverageKind: "observed-checkpoint-transitions", sourceSha256: wire.generatedSourceSha256, compiledJavaScriptSha256: wire.compiledJavaScriptSha256, checkpoints, features: [...new Set(checkpoints.flatMap(checkpoint => checkpoint.features))].sort() };
}

interface CorpusEntry { model: GeneratedCase; sourceSha256: string; features: string[] }
export interface CorpusAdmission { status: "retained" | "redundant" | "incomplete"; newFeatures: string[]; diagnostic?: "runtime-corpus-budget" }

/** Finite corpus selection by measured checkpoint features, not executed edges. */
export class RuntimeTransitionCorpus {
  private readonly features = new Set<string>();
  private readonly entries: CorpusEntry[] = [];
  private exhausted = false;
  constructor(readonly maxCases = 128, readonly maxFeatures = 512) {
    if (!Number.isSafeInteger(maxCases) || maxCases < 1 || maxCases > 256 || !Number.isSafeInteger(maxFeatures) || maxFeatures < 1 || maxFeatures > 4096) throw new Error("Invalid runtime corpus budgets");
  }
  consider(input: GeneratedCase, wire: unknown): CorpusAdmission {
    const feedback = runtimeFeedback(input, wire);
    const novel = feedback.features.filter(feature => !this.features.has(feature));
    if (this.exhausted || novel.length && (this.entries.length >= this.maxCases || this.features.size + novel.length > this.maxFeatures)) {
      this.exhausted = true;
      return { status: "incomplete", newFeatures: [], diagnostic: "runtime-corpus-budget" };
    }
    if (!novel.length) return { status: "redundant", newFeatures: [] };
    this.entries.push({ model: validateCase(input), sourceSha256: feedback.sourceSha256, features: [...feedback.features] });
    for (const feature of novel) this.features.add(feature);
    return { status: "retained", newFeatures: novel };
  }
  snapshot() {
    return { schemaVersion: "nightshade-runtime-transition-corpus-1" as const, coverageKind: "observed-checkpoint-transitions" as const, budgets: { maxCases: this.maxCases, maxFeatures: this.maxFeatures }, exhausted: this.exhausted, features: [...this.features].sort(), entries: structuredClone(this.entries) };
  }
}
