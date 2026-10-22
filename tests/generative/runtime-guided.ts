// Owned model only. Audit checks saved evidence; it never executes saved source.
import { closeSync, constants, fstatSync, lstatSync, mkdirSync, openSync, opendirSync, readSync, realpathSync, writeFileSync } from "node:fs";
import { basename, dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import type { ExecutionLimits } from "../../src/runtime/process.js";
import { digest } from "./artifacts.js";
import { generateCase } from "./model.js";
import { incompleteRuntimeResult, makeRuntimeArtifact, RUNTIME_LIMITS, runRuntimeCaseIsolated, runtimeBuildIdentity, runtimeIdentityChanges, validateRuntimeArtifact, validateRuntimeLimits, type RuntimeCaseArtifact, type RuntimeIdentity } from "./runtime-artifacts.js";
import { DEFAULT_SCHEDULE, RUNTIME_SCHEDULER, RuntimeSchedule, sameScheduleData, scheduleRecord, validateScheduleOptions, type RuntimeDecision, type ScheduleOptions, type ScheduleRow } from "./runtime-schedule.js";
import { RuntimeCampaignReplay } from "./runtime-guided-replay.js";

export interface GuidedRow extends ScheduleRow { decision: string; decisionSha256: string; artifact: string; artifactSha256: string }
export interface GuidedManifest {
  schemaVersion: "nightshade-runtime-guided-1";
  purpose: "owned-checkpoint-guidance";
  coverageKind: "observed-checkpoint-transitions";
  scheduler: typeof RUNTIME_SCHEDULER;
  options: ScheduleOptions;
  identity: RuntimeIdentity;
  limits: Required<ExecutionLimits>;
  planned: number;
  completed: number;
  outcome: ReturnType<RuntimeSchedule["snapshot"]>["outcome"];
  counts: ReturnType<RuntimeSchedule["snapshot"]>["counts"];
  rows: GuidedRow[];
  corpus: ReturnType<RuntimeSchedule["snapshot"]>["corpus"];
}
export interface AuditedGuidedStep {
  decision: RuntimeDecision;
  decisionSha256: string;
  artifact: RuntimeCaseArtifact;
  artifactSha256: string;
}
export interface AuditedGuidedCampaign {
  audit: "consistent";
  executionReplay: false;
  manifest: GuidedManifest;
  manifestSha256: string;
  steps: AuditedGuidedStep[];
}
const names = (ordinal: number) => ({ decision: `${String(ordinal).padStart(4, "0")}-decision.json`, artifact: `${String(ordinal).padStart(4, "0")}.json` });

function qualifiedIdentity(identity: unknown, limits: unknown): RuntimeIdentity {
  // Reuse the exact schema-2 identity/limit validator. This unsaved shell checks
  // metadata only; it is neither a worker result nor execution evidence.
  return makeRuntimeArtifact(generateCase(1, 24), identity as RuntimeIdentity, validateRuntimeLimits(limits),
    incompleteRuntimeResult("worker-input", "Unsaved metadata validation shell; no runtime execution")).identity;
}

export function makeGuidedManifest(schedule: RuntimeSchedule, identity: RuntimeIdentity, limits: Required<ExecutionLimits>, rows: GuidedRow[]): GuidedManifest {
  const state = schedule.snapshot();
  if (state.outcome.status === "running") throw new Error("Cannot finalize a running campaign");
  if (!Array.isArray(rows) || Object.getPrototypeOf(rows) !== Array.prototype || rows.length !== state.completed || Reflect.ownKeys(rows).length !== rows.length + 1) throw new Error("Campaign row count mismatch");
  for (let index = 0; index < rows.length; index++) {
    const property = Object.getOwnPropertyDescriptor(rows, index);
    if (!property || !("value" in property) || !property.enumerable) throw new Error("Invalid campaign row data");
    const row = scheduleRecord(property.value, ["ordinal", "status", "category", "resultStatus", "signature", "admission", "decision", "decisionSha256", "artifact", "artifactSha256"], "guided row");
    const { decision, artifact } = names(index + 1);
    if (typeof row.decisionSha256 !== "string" || typeof row.artifactSha256 !== "string" || !/^[a-f0-9]{64}$/.test(row.decisionSha256) || !/^[a-f0-9]{64}$/.test(row.artifactSha256)
      || !sameScheduleData(row, { ...state.rows[index], decision, artifact, decisionSha256: row.decisionSha256, artifactSha256: row.artifactSha256 })) throw new Error("Campaign row metadata mismatch");
  }
  return { schemaVersion: "nightshade-runtime-guided-1", purpose: "owned-checkpoint-guidance", coverageKind: "observed-checkpoint-transitions", scheduler: RUNTIME_SCHEDULER,
    options: { ...schedule.options }, identity: qualifiedIdentity(identity, limits), limits: validateRuntimeLimits(limits), ...state, rows: structuredClone(rows) };
}

/** Strict bounded disk audit, with all paths derived from ordinals, never data. */
export function auditRuntimeCampaign(directory: string): AuditedGuidedCampaign {
  const root = resolve(directory);
  if (!lstatSync(root).isDirectory() || lstatSync(root).isSymbolicLink()) throw new Error("Audit requires an ordinary campaign directory");
  let bytes = 0;
  const read = (name: string, maximum: number) => {
    const path = resolve(root, name);
    if (!lstatSync(path).isFile() || lstatSync(path).isSymbolicLink()) throw new Error("Campaign evidence must be ordinary files");
    const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
    try {
      const stat = fstatSync(fd);
      if (!stat.isFile() || stat.size > maximum || bytes + stat.size > 64 * 1024 * 1024) throw new Error("Campaign evidence byte budget exhausted");
      const capacity = Math.min(maximum, 64 * 1024 * 1024 - bytes);
      const chunks: Buffer[] = [];
      let length = 0;
      // Enforce limits while reading, including a file growing after fstat.
      for (;;) {
        const chunk = Buffer.allocUnsafe(Math.min(64 * 1024, capacity + 1 - length));
        const count = readSync(fd, chunk, 0, chunk.length, null);
        if (!count) break;
        length += count;
        if (length > capacity) throw new Error("Campaign evidence byte budget exhausted");
        chunks.push(chunk.subarray(0, count));
      }
      bytes += length;
      const content = Buffer.concat(chunks, length);
      return { value: JSON.parse(content.toString("utf8")) as unknown, sha256: digest(content) };
    } finally { closeSync(fd); }
  };
  const summary = read("summary.json", 4 * 1024 * 1024);
  const raw = scheduleRecord(summary.value,
    ["schemaVersion", "purpose", "coverageKind", "scheduler", "options", "identity", "limits", "planned", "completed", "outcome", "counts", "rows", "corpus"], "guided manifest");
  if (raw.schemaVersion !== "nightshade-runtime-guided-1" || raw.purpose !== "owned-checkpoint-guidance" || raw.coverageKind !== "observed-checkpoint-transitions" || raw.scheduler !== RUNTIME_SCHEDULER) throw new Error("Unsupported guided manifest");
  const options = validateScheduleOptions(raw.options);
  const limits = validateRuntimeLimits(raw.limits);
  const identity = qualifiedIdentity(raw.identity, limits);
  const schedule = new RuntimeSchedule(options);
  if (!Array.isArray(raw.rows) || raw.rows.length > schedule.planned || raw.rows.length > options.maxEvaluations) throw new Error("Invalid campaign rows");
  const rows: GuidedRow[] = [];
  const steps: AuditedGuidedStep[] = [];
  const files = ["summary.json"];
  for (let index = 0; index < raw.rows.length; index++) {
    const row = scheduleRecord(raw.rows[index], ["ordinal", "status", "category", "resultStatus", "signature", "admission", "decision", "decisionSha256", "artifact", "artifactSha256"], "guided row");
    const expectedNames = names(index + 1);
    if (row.decision !== expectedNames.decision || row.artifact !== expectedNames.artifact) throw new Error("Invalid campaign file path/order");
    files.push(expectedNames.decision, expectedNames.artifact);
    const decision = read(expectedNames.decision, 128 * 1024);
    const artifact = read(expectedNames.artifact, 8 * 1024 * 1024);
    if (row.decisionSha256 !== decision.sha256 || row.artifactSha256 !== artifact.sha256) throw new Error("Campaign evidence digest mismatch");
    const proposed = schedule.next();
    if (!proposed || !sameScheduleData(decision.value, proposed)) throw new Error("Campaign decision/parent/random transcript mismatch");
    const checked = validateRuntimeArtifact(artifact.value);
    if (!sameScheduleData(checked.case, proposed.case) || !sameScheduleData(checked.identity, identity) || !sameScheduleData(checked.limits, limits)) throw new Error("Candidate model/identity/limits mismatch");
    const observed = schedule.record(checked.result, artifact.sha256);
    const expected = { ...observed, ...expectedNames, decisionSha256: decision.sha256, artifactSha256: artifact.sha256 };
    if (!sameScheduleData(row, expected)) throw new Error("Campaign outcome/admission mismatch");
    rows.push(expected);
    steps.push({ decision: proposed, decisionSha256: decision.sha256, artifact: checked, artifactSha256: artifact.sha256 });
  }
  // A between-worker interruption has no fabricated execution result. All
  // other early stops must follow from the checked observations or exact budget.
  if (schedule.snapshot().outcome.status === "running" && sameScheduleData(raw.outcome, { status: "incomplete", category: "runtime-campaign-interrupted" })) schedule.interrupt();
  const manifest = makeGuidedManifest(schedule, identity, limits, rows);
  if (!sameScheduleData(raw, manifest)) throw new Error("Campaign summary/counts/corpus mismatch");
  const present: string[] = [];
  const entries = opendirSync(root);
  try {
    let entry;
    while ((entry = entries.readSync())) {
      if (present.length >= files.length) throw new Error("Unexpected campaign evidence files");
      present.push(entry.name);
    }
  } finally { entries.closeSync(); }
  present.sort();
  if (!sameScheduleData(present, files.sort())) throw new Error("Unexpected or missing campaign evidence files");
  return { audit: "consistent", executionReplay: false, manifest, manifestSha256: summary.sha256, steps };
}

const save = (directory: string, name: string, value: unknown): string => {
  const text = JSON.stringify(value, null, 2) + "\n";
  writeFileSync(resolve(directory, name), text, { flag: "wx" });
  return digest(text);
};
const exitStatus = (status: string): number => status === "passed" ? 0 : status === "failed" ? 1 : 2;

async function replayCampaign(sourceDirectory: string, outputDirectory: string, compiler: string, runtime: string, compareBuild: boolean): Promise<number> {
  // Audit and retain bounded, detached evidence once. Execution never reopens a
  // mutable saved model/source file after this validation boundary.
  const saved = auditRuntimeCampaign(sourceDirectory);
  const identity = runtimeBuildIdentity(compiler, runtime);
  const changedIdentityFields = runtimeIdentityChanges(saved.manifest.identity, identity);
  if (changedIdentityFields.length && !compareBuild) throw new Error(`Campaign replay identity mismatch (${changedIdentityFields.join(", ")}); --compare-build records an explicit comparison`);
  const output = resolve(outputDirectory);
  const canonicalOutput = resolve(realpathSync(dirname(output)), basename(output));
  const withinSource = relative(realpathSync(sourceDirectory), canonicalOutput);
  if (!withinSource || !isAbsolute(withinSource) && withinSource !== ".." && !withinSource.startsWith(`..${sep}`)) throw new Error("Replay output must be outside the original campaign");
  mkdirSync(output);
  const replay = new RuntimeCampaignReplay(saved, compareBuild);
  const rows: object[] = [];
  let interrupted = false;
  const onSignal = () => { interrupted = true; };
  process.on("SIGINT", onSignal);
  process.on("SIGTERM", onSignal);
  try {
    while (replay.snapshot().outcome.status === "running") {
      if (interrupted) { replay.interrupt(); break; }
      const proposal = replay.next()!;
      const files = names(proposal.decision.ordinal);
      const decisionSha256 = save(output, files.decision, proposal.decision);
      const links = { ordinal: proposal.decision.ordinal, originalDecisionSha256: proposal.originalDecisionSha256, originalArtifactSha256: proposal.originalArtifactSha256,
        decision: files.decision, decisionSha256, sameDecision: proposal.sameDecision };
      if (!proposal.sameDecision) {
        rows.push({ ...links, artifact: null, artifactSha256: null, checked: null });
        break;
      }
      const result = await runRuntimeCaseIsolated(proposal.decision.case, compiler, runtime, saved.manifest.limits);
      const artifactSha256 = save(output, files.artifact, makeRuntimeArtifact(proposal.decision.case, identity, saved.manifest.limits, result));
      const checked = replay.record(result, artifactSha256);
      rows.push({ ...links, artifact: files.artifact, artifactSha256, checked });
      console.log(`${proposal.decision.ordinal}/${saved.steps.length} ${checked.row.resultStatus} ${replay.snapshot().outcome.category}`);
    }
    const state = replay.snapshot();
    save(output, "summary.json", { schemaVersion: "nightshade-runtime-guided-replay-1", purpose: "owned-campaign-execution-replay",
      mode: compareBuild ? "build-comparison" : "exact-replay", comparison: compareBuild, originalManifestSha256: saved.manifestSha256,
      originalIdentity: saved.manifest.identity, identity, changedIdentityFields, originalOutcome: saved.manifest.outcome,
      options: saved.manifest.options, limits: saved.manifest.limits, coverageKind: "observed-checkpoint-transitions", ...state, rows });
    return exitStatus(state.outcome.status);
  } finally { process.removeListener("SIGINT", onSignal); process.removeListener("SIGTERM", onSignal); }
}

async function main(): Promise<number> {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === "--help") {
    console.log("Owned guided compiled-evaluation campaign: --output NEW_DIRECTORY [--seed UINT32] [--mutations 0..64] [--max-evaluations 1..68] [--max-cases 1..256] [--max-features 1..4096] [--timeout-ms 1..60000]\nBootstraps: seeds 1..4, 24 operations; default 16 mutation slots. Requires pinned COMPACTC_TEST and COMPACT_RUNTIME_TEST.\nSaved evidence audit: --audit DIRECTORY (no execution or attestation).\nCampaign execution replay: --replay-campaign DIRECTORY --output NEW_DIRECTORY [--compare-build]; original limits, recorded models only.\nCase execution replay uses runtime-smoke --replay.\nExit 0: completed passing campaign/matching replay; 1: reproduced property failure; 2: incomplete/input/audit/replay drift. No arbitrary targets or adapters.");
    return 0;
  }
  const flags = new Map<string, string>();
  let compareBuild = false;
  for (let index = 0; index < args.length; index++) {
    const flag = args[index];
    if (flag === "--compare-build" && !compareBuild) { compareBuild = true; continue; }
    if (!["--output", "--audit", "--replay-campaign", "--seed", "--mutations", "--max-evaluations", "--max-cases", "--max-features", "--timeout-ms"].includes(flag)
      || flags.has(flag) || !args[index + 1] || args[index + 1].startsWith("--")) throw new Error(`Invalid guided argument ${flag}`);
    flags.set(flag, args[++index]);
  }
  if (flags.has("--audit")) {
    if (flags.size !== 1 || compareBuild) throw new Error("Audit cannot change execution settings or write a campaign");
    const checked = auditRuntimeCampaign(flags.get("--audit")!);
    console.log(JSON.stringify({ audit: checked.audit, executionReplay: false, recordedOutcome: checked.manifest.outcome, completed: checked.manifest.completed }));
    return exitStatus(checked.manifest.outcome.status);
  }
  if (compareBuild && !flags.has("--replay-campaign")) throw new Error("--compare-build applies only to campaign execution replay");
  if (!flags.has("--output") || !process.env.COMPACTC_TEST || !process.env.COMPACT_RUNTIME_TEST) throw new Error("New --output and pinned COMPACTC_TEST / COMPACT_RUNTIME_TEST are mandatory");
  if (flags.has("--replay-campaign")) {
    if (flags.size !== 2) throw new Error("Campaign replay preserves the original schedule and limits");
    return replayCampaign(flags.get("--replay-campaign")!, flags.get("--output")!, resolve(process.env.COMPACTC_TEST), resolve(process.env.COMPACT_RUNTIME_TEST), compareBuild);
  }
  const integer = (flag: string, fallback: number): number => {
    const raw = flags.get(flag);
    if (raw !== undefined && !/^(0|[1-9][0-9]*)$/.test(raw)) throw new Error(`Invalid integer ${flag}`);
    return raw === undefined ? fallback : Number(raw);
  };
  const options = validateScheduleOptions({ seed: integer("--seed", DEFAULT_SCHEDULE.seed), mutations: integer("--mutations", DEFAULT_SCHEDULE.mutations),
    maxEvaluations: integer("--max-evaluations", DEFAULT_SCHEDULE.maxEvaluations), maxCases: integer("--max-cases", DEFAULT_SCHEDULE.maxCases), maxFeatures: integer("--max-features", DEFAULT_SCHEDULE.maxFeatures) });
  const limits = validateRuntimeLimits({ ...RUNTIME_LIMITS, timeoutMs: integer("--timeout-ms", RUNTIME_LIMITS.timeoutMs) });
  const compiler = resolve(process.env.COMPACTC_TEST), runtime = resolve(process.env.COMPACT_RUNTIME_TEST);
  const identity = runtimeBuildIdentity(compiler, runtime);
  const output = resolve(flags.get("--output")!);
  mkdirSync(output);
  const schedule = new RuntimeSchedule(options);
  const rows: GuidedRow[] = [];
  let interrupted = false;
  const onSignal = () => { interrupted = true; };
  process.on("SIGINT", onSignal);
  process.on("SIGTERM", onSignal);
  try {
    while (schedule.snapshot().outcome.status === "running") {
      if (interrupted) { schedule.interrupt(); break; }
      const decision = schedule.next()!;
      const files = names(decision.ordinal);
      // Parent linkage and exact proposal are durable before execution begins.
      const decisionSha256 = save(output, files.decision, decision);
      const result = await runRuntimeCaseIsolated(decision.case, compiler, runtime, limits);
      const artifactSha256 = save(output, files.artifact, makeRuntimeArtifact(decision.case, identity, limits, result));
      const row = { ...schedule.record(result, artifactSha256), ...files, decisionSha256, artifactSha256 };
      rows.push(row);
      console.log(`${row.ordinal}/${schedule.planned} ${row.status} ${row.category}`);
    }
    const manifest = makeGuidedManifest(schedule, identity, limits, rows);
    save(output, "summary.json", manifest);
    return exitStatus(manifest.outcome.status);
  } finally { process.removeListener("SIGINT", onSignal); process.removeListener("SIGTERM", onSignal); }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { process.exitCode = await main(); }
  catch (error) { console.error(error instanceof Error ? error.message : String(error)); process.exitCode = 2; }
}
