/** Pure, bounded admission from original owned persistent case bytes. No execution or disk I/O. */
import type { ExecutionLimits } from "../../src/runtime/process.js";
import { PERSISTENT_FILE_BYTES, persistentIdentityChanges, validatePersistentArtifact, validatePersistentIdentity, validatePersistentLimits, type PersistentIdentity } from "./persistent-artifacts.js";
import { persistentDigest, type PersistentSequence } from "./persistent-model.js";
import { extractPersistentFeedback, persistentFeedbackDigest, PERSISTENT_COVERAGE_KIND, PERSISTENT_FEATURE_SET, type PersistentFeedback, type PersistentFeedbackDiagnostic } from "./persistent-feedback.js";

export interface PersistentCorpusBudgets { maxCases: number; maxFeatures: number; maxConsiderations: number; maxEvidenceBytes: number }
export const PERSISTENT_CORPUS_DEFAULTS: Readonly<PersistentCorpusBudgets> = Object.freeze({ maxCases: 32, maxFeatures: 512, maxConsiderations: 64, maxEvidenceBytes: 16 * 1024 * 1024 });
export const PERSISTENT_CORPUS_MAXIMA: Readonly<PersistentCorpusBudgets> = Object.freeze({ maxCases: 128, maxFeatures: 4096, maxConsiderations: 256, maxEvidenceBytes: 64 * 1024 * 1024 });
export type PersistentCorpusDiagnostic = PersistentFeedbackDiagnostic | "persistent-model-disagreement" | "persistent-corpus-budget" | "persistent-corpus-consideration-budget" | "persistent-corpus-evidence-budget" | "persistent-corpus-identity" | "persistent-corpus-compiled-build-drift" | "persistent-corpus-protocol";
export interface PersistentArtifactReference { sha256: string; bytes: number }
interface AdmissionBase {
  schemaVersion: "nightshade-persistent-admission-1";
  ordinal: number | null;
  artifact: PersistentArtifactReference | null;
}
export type PersistentCorpusAdmission = AdmissionBase & (
  | { status: "retained" | "redundant"; caseStatus: "passed"; signature: "persistent-model-checked"; feedbackSha256: string; admittedFeatureIds: string[]; diagnostic: null }
  | { status: "property-failed"; caseStatus: "failed"; signature: string; feedbackSha256: null; admittedFeatureIds: []; diagnostic: "persistent-model-disagreement" }
  | { status: "incomplete"; caseStatus: "passed" | "failed" | "incomplete" | null; signature: string | null; feedbackSha256: string | null; admittedFeatureIds: []; diagnostic: PersistentCorpusDiagnostic }
);
export interface PersistentCorpusEntry {
  ordinal: number;
  artifactSha256: string;
  artifactBytes: number;
  sequenceSha256: string;
  operationsSha256: string;
  observationSha256: string;
  feedbackSha256: string;
  featureIds: string[];
  admittedFeatureIds: string[];
  sequence: PersistentSequence;
}
export interface PersistentCorpusSnapshot {
  schemaVersion: "nightshade-persistent-transition-corpus-1";
  featureSet: typeof PERSISTENT_FEATURE_SET;
  coverageKind: typeof PERSISTENT_COVERAGE_KIND;
  identity: PersistentIdentity;
  workerLimits: Required<ExecutionLimits>;
  budgets: PersistentCorpusBudgets;
  compiledJavaScriptSha256: string | null;
  considered: number;
  evidenceBytes: number;
  terminalDiagnostic: PersistentCorpusDiagnostic | null;
  features: PersistentFeedback["features"];
  entries: PersistentCorpusEntry[];
}
export interface PersistentCorpusFold {
  scope: "offline-evidence-consistency-only";
  status: "complete" | "property-failed" | "incomplete";
  snapshot: PersistentCorpusSnapshot;
  admissions: PersistentCorpusAdmission[];
}

function record(value: unknown, keys: readonly string[], optional = false): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new Error("persistent-corpus-protocol: expected plain data object");
  const own = Reflect.ownKeys(value);
  if ((!optional && own.length !== keys.length) || own.some(key => typeof key !== "string" || !keys.includes(key))) throw new Error("persistent-corpus-protocol: unexpected fields");
  for (const key of own) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key)!;
    if (!("value" in descriptor) || !descriptor.enumerable) throw new Error("persistent-corpus-protocol: accessor or hidden field");
  }
  return value as Record<string, unknown>;
}
function array(value: unknown, maximum: number): unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length > maximum || Reflect.ownKeys(value).length !== value.length + 1) throw new Error("persistent-corpus-protocol: invalid bounded evidence array");
  for (let index = 0; index < value.length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(value, index);
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) throw new Error("persistent-corpus-protocol: sparse/accessor evidence array");
  }
  return value;
}
/** Walk only an independently regenerated bounded tree, never arbitrary saved descendants. */
function equalData(actual: unknown, expected: unknown): boolean {
  if (!expected || typeof expected !== "object") return Object.is(actual, expected);
  if (!actual || typeof actual !== "object" || Array.isArray(actual) !== Array.isArray(expected)) return false;
  if (Array.isArray(actual) ? Object.getPrototypeOf(actual) !== Array.prototype : ![Object.prototype, null].includes(Object.getPrototypeOf(actual))) return false;
  const keys = Reflect.ownKeys(expected);
  if (Reflect.ownKeys(actual).length !== keys.length) return false;
  return keys.every(key => {
    const found = Object.getOwnPropertyDescriptor(actual, key), wanted = Object.getOwnPropertyDescriptor(expected, key)!;
    return found && "value" in found && found.enumerable === wanted.enumerable && equalData(found.value, wanted.value);
  });
}
export function validatePersistentCorpusBudgets(value: unknown = {}): PersistentCorpusBudgets {
  const raw = record(value, Object.keys(PERSISTENT_CORPUS_DEFAULTS), true);
  const budgets = { ...PERSISTENT_CORPUS_DEFAULTS };
  for (const key of Object.keys(raw) as (keyof PersistentCorpusBudgets)[]) {
    const number = raw[key];
    if (typeof number !== "number" || !Number.isSafeInteger(number) || Object.is(number, -0) || number < 1 || number > PERSISTENT_CORPUS_MAXIMA[key]) throw new Error(`persistent-corpus-protocol: invalid ${key}`);
    budgets[key] = number;
  }
  return budgets;
}

const byteLength = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), "byteLength")!.get!;
/** Reject decorated byte arrays before copying; no caller conversion/accessor is invoked. */
function inputLength(value: unknown): number {
  if (!value || typeof value !== "object" || ![Buffer.prototype, Uint8Array.prototype].includes(Object.getPrototypeOf(value))) throw new Error("persistent-corpus-protocol: expected original Uint8Array or Buffer artifact bytes");
  return byteLength.call(value) as number;
}
function captureBytes(value: unknown, length: number): Uint8Array {
  const own = Reflect.ownKeys(value as object);
  if (own.length !== length || own.some((key, index) => key !== String(index))) throw new Error("persistent-corpus-protocol: decorated artifact bytes");
  const copy = new Uint8Array(length);
  Uint8Array.prototype.set.call(copy, value as Uint8Array);
  return copy;
}

/** Entries/features are admitted atomically. Terminal outcomes are sticky and do not accumulate refusal logs. */
export class PersistentTransitionCorpus {
  #identity: PersistentIdentity;
  #limits: Required<ExecutionLimits>;
  #budgets: PersistentCorpusBudgets;
  #features = new Map<string, PersistentFeedback["features"][number]>();
  #entries: PersistentCorpusEntry[] = [];
  #compiled: string | null = null;
  #considered = 0;
  #evidenceBytes = 0;
  #terminal: PersistentCorpusDiagnostic | null = null;

  constructor(identity: unknown, workerLimits: unknown, budgets: unknown = {}) {
    this.#identity = validatePersistentIdentity(identity);
    this.#limits = validatePersistentLimits(workerLimits);
    this.#budgets = validatePersistentCorpusBudgets(budgets);
  }

  consider(input: unknown): PersistentCorpusAdmission {
    const base: AdmissionBase = { schemaVersion: "nightshade-persistent-admission-1", ordinal: null, artifact: null };
    const stop = (diagnostic: PersistentCorpusDiagnostic, caseStatus: "passed" | "failed" | "incomplete" | null = null, signature: string | null = null, feedbackSha256: string | null = null): PersistentCorpusAdmission => {
      this.#terminal ??= diagnostic;
      return { ...base, status: "incomplete", caseStatus, signature, feedbackSha256, admittedFeatureIds: [], diagnostic: this.#terminal };
    };
    if (this.#terminal) return stop(this.#terminal);
    if (this.#considered >= this.#budgets.maxConsiderations) return stop("persistent-corpus-consideration-budget");
    let bytes: Uint8Array;
    try {
      const length = inputLength(input);
      if (length > PERSISTENT_FILE_BYTES || length > this.#budgets.maxEvidenceBytes - this.#evidenceBytes) return stop("persistent-corpus-evidence-budget");
      bytes = captureBytes(input, length);
    } catch { return stop("persistent-corpus-protocol"); }
    // Charge every captured case, including redundant, failed or invalid evidence.
    base.ordinal = ++this.#considered;
    base.artifact = { sha256: persistentDigest(bytes), bytes: bytes.byteLength };
    this.#evidenceBytes += bytes.byteLength;
    let artifact;
    try { artifact = validatePersistentArtifact(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes))); }
    catch { return stop("persistent-corpus-protocol"); }
    const result = artifact.result;
    if (persistentIdentityChanges(this.#identity, artifact.identity).length || !equalData(artifact.limits, this.#limits)) return stop("persistent-corpus-identity", result.status, result.signature);
    if (result.status !== "incomplete" && this.#compiled !== null && result.observation.compiledJavaScriptSha256 !== this.#compiled) return stop("persistent-corpus-compiled-build-drift", result.status, result.signature);
    const outcome = extractPersistentFeedback(artifact.sequence, result);
    if (outcome.status === "property-failed") {
      this.#terminal = "persistent-model-disagreement";
      return { ...base, status: "property-failed", caseStatus: "failed", signature: outcome.signature, feedbackSha256: null, admittedFeatureIds: [], diagnostic: "persistent-model-disagreement" };
    }
    if (outcome.status === "incomplete") return stop(outcome.diagnostic, result.status, result.signature);
    const feedback = outcome.feedback, feedbackSha256 = persistentFeedbackDigest(feedback);
    const novel: PersistentFeedback["features"] = [];
    for (const feature of feedback.features) {
      const previous = this.#features.get(feature.id);
      if (previous && !equalData(previous.descriptor, feature.descriptor)) return stop("persistent-corpus-protocol", "passed", result.signature, feedbackSha256);
      if (!previous) novel.push(feature);
    }
    if (novel.length && (this.#entries.length >= this.#budgets.maxCases || this.#features.size + novel.length > this.#budgets.maxFeatures)) return stop("persistent-corpus-budget", "passed", result.signature, feedbackSha256);
    this.#compiled ??= feedback.compiledJavaScriptSha256;
    const admittedFeatureIds = novel.map(feature => feature.id);
    if (novel.length) {
      this.#entries.push({ ordinal: base.ordinal, artifactSha256: base.artifact.sha256, artifactBytes: base.artifact.bytes,
        sequenceSha256: feedback.sequenceSha256, operationsSha256: feedback.operationsSha256, observationSha256: feedback.observationSha256, feedbackSha256,
        featureIds: feedback.features.map(feature => feature.id), admittedFeatureIds: [...admittedFeatureIds], sequence: artifact.sequence });
      for (const feature of novel) this.#features.set(feature.id, structuredClone(feature));
    }
    return { ...base, status: novel.length ? "retained" : "redundant", caseStatus: "passed", signature: "persistent-model-checked", feedbackSha256, admittedFeatureIds, diagnostic: null };
  }

  snapshot(): PersistentCorpusSnapshot {
    return structuredClone({ schemaVersion: "nightshade-persistent-transition-corpus-1", featureSet: PERSISTENT_FEATURE_SET, coverageKind: PERSISTENT_COVERAGE_KIND,
      identity: this.#identity, workerLimits: this.#limits, budgets: this.#budgets, compiledJavaScriptSha256: this.#compiled, considered: this.#considered,
      evidenceBytes: this.#evidenceBytes, terminalDiagnostic: this.#terminal,
      features: [...this.#features.values()].sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0), entries: this.#entries });
  }
}

/** Ordered original bytes, including any final budget-triggering input, are the reconstruction authority. */
export function foldPersistentCorpus(identity: unknown, workerLimits: unknown, budgets: unknown, artifacts: unknown): PersistentCorpusFold {
  const corpus = new PersistentTransitionCorpus(identity, workerLimits, budgets);
  const inputs = array(artifacts, PERSISTENT_CORPUS_MAXIMA.maxConsiderations + 1);
  const admissions: PersistentCorpusAdmission[] = [];
  for (const [index, input] of inputs.entries()) {
    const admission = corpus.consider(input);
    admissions.push(admission);
    if ((admission.status === "incomplete" || admission.status === "property-failed") && index !== inputs.length - 1) throw new Error("persistent-corpus-protocol: trailing artifacts after terminal admission");
  }
  const snapshot = corpus.snapshot();
  return { scope: "offline-evidence-consistency-only", status: snapshot.terminalDiagnostic === "persistent-model-disagreement" ? "property-failed" : snapshot.terminalDiagnostic ? "incomplete" : "complete", snapshot, admissions };
}

/** Saved metadata alone cannot restore coverage. Rebuild every decision and exact snapshot from original bytes. */
export function auditPersistentCorpus(snapshot: unknown, artifacts: unknown, admissions: unknown): PersistentCorpusFold {
  const raw = record(snapshot, ["schemaVersion", "featureSet", "coverageKind", "identity", "workerLimits", "budgets", "compiledJavaScriptSha256", "considered", "evidenceBytes", "terminalDiagnostic", "features", "entries"]);
  if (raw.schemaVersion !== "nightshade-persistent-transition-corpus-1" || raw.featureSet !== PERSISTENT_FEATURE_SET || raw.coverageKind !== PERSISTENT_COVERAGE_KIND) throw new Error("persistent-corpus-protocol: unsupported saved corpus schema");
  const expected = foldPersistentCorpus(raw.identity, raw.workerLimits, raw.budgets, artifacts);
  if (!equalData(snapshot, expected.snapshot) || !equalData(admissions, expected.admissions)) throw new Error("persistent-corpus-protocol: saved corpus or admissions differ from original evidence fold");
  return expected;
}
