import { deepStrictEqual } from "node:assert";
import { createHash } from "node:crypto";
import { resolve } from "node:path";
import { Dataflow, Program, detectors } from "../../src/index.js";
import { AbstractValue, AnalysisFacts } from "../../src/dataflow/index.js";
import { validateWithCompiler, CompilerValidation } from "../../src/compiler/index.js";
import { semanticPaths, withFiles } from "../helpers.js";
import { GeneratedCase, expectedFlagObservations, renderCase, validateCase } from "./model.js";
import { effectiveBudgets } from "./budgets.js";
import { informationalDetectors } from "../../src/detectors/informational.js";

export interface CheckOptions {
  compiler?: string;
  maxSteps?: number;
  maxPaths?: number;
  maxValues?: number;
}

export interface ModeObservation {
  engine: "instructions" | "expressions";
  cached: boolean;
  metrics: AnalysisFacts["metrics"];
  diagnosticCodes: string[];
  completedEntries: number;
}

export interface CheckResult {
  status: "passed" | "failed" | "incomplete" | "unqualified";
  category: string;
  signature: string;
  message?: string;
  compiler?: CompilerValidation;
  modes: ModeObservation[];
  observationSha256?: string;
}

function same(left: unknown, right: unknown): boolean {
  try { deepStrictEqual(left, right); return true; } catch { return false; }
}

const unique = (items: string[]) => [...new Set(items)].sort();
const securityDetectors = detectors.filter(detector => !informationalDetectors.some(rule => rule.id === detector.id));

export interface ObservationFailure {
  property: string;
  field: string;
  message: string;
}

/**
 * Independent value oracle for the exact generated grammar, whose only branches
 * are `if (disclose(flag))`. Provenance and writes still receive differential
 * checks; this helper does not claim an independent oracle for those domains.
 */
export function checkObservations(input: GeneratedCase, facts: AnalysisFacts): ObservationFailure | undefined {
  const item = validateCase(input);
  const failure = (property: string, field: string, message: string): ObservationFailure => ({ property, field, message });
  if (facts.failedAssertions.length) return failure("unexpected-failure", "failedAssertions", "The initialized generated fragment has no failing assertions");
  // Generated fragments exercise the exact security oracle. Informational
  // source observations are intentionally default-on for user scans, but
  // their unrelated unused-declaration notes must not invalidate this oracle.
  const findings = securityDetectors.filter(detector => detector.defaultEnabled !== false && detector.id !== "openzeppelin-preconditions").flatMap(detector => detector.run(facts));
  if (findings.length) return failure("unexpected-finding", unique(findings.map(finding => finding.detectorId)).join(","), "The generated fragment has no expected default findings");
  const expected = expectedFlagObservations(item);
  const branches = item.operations.filter(operation => operation.kind === "conditional").length;
  const coveredFlags = new Set<boolean>();
  const fields = ["scalar", "membership", "cardinality", "snapshot", "unrelated"];
  for (const path of facts.paths) {
    const decisions = path.path.filter(step => step.kind === "branch");
    if (decisions.length !== branches) return failure("branch-count", "flag", `Expected ${branches} branch decisions, got ${decisions.length}`);
    const flags = decisions.map(step => /^(?:condition|conditional) may be (true|false)$/.exec(step.label)?.[1]);
    if (flags.some(flag => flag === undefined)) return failure("branch-label", "flag", "Generated branch decision has an unrecognized label");
    if (new Set(flags).size > 1) return failure("branch-correlation", "flag", "The same Boolean input received conflicting branch decisions");
    const flag = flags[0] === "true";
    coveredFlags.add(flag);
    const observations = expected.find(outcome => outcome.flag === flag)!.observations;
    const returned = path.sinks.filter(sink => sink.kind === "exported-return");
    if (returned.length !== 1) return failure("return-count", "exported-return", `Expected one exported return, got ${returned.length}`);
    const checkpoints = returned[0].value.items;
    if (!checkpoints || checkpoints.length !== observations.length) return failure("return-shape", "checkpoints", `Expected ${observations.length} checkpoint tuples`);
    for (let checkpoint = 0; checkpoint < observations.length; checkpoint++) {
      const values = checkpoints[checkpoint].items;
      if (!values || values.length !== fields.length) return failure("return-shape", "checkpoint", `Checkpoint ${checkpoint} must contain five scalar values`);
      for (let field = 0; field < fields.length; field++) {
        const value: AbstractValue = values[field];
        const constantKind = field === 1 ? "boolean" : "integer";
        if (value.items || value.fields) return failure("return-shape", fields[field], `Checkpoint ${checkpoint}.${fields[field]} must be scalar`);
        if (value.constantKind !== constantKind) return failure("constant-kind", fields[field], `Checkpoint ${checkpoint}.${fields[field]} expected ${constantKind}, got ${value.constantKind}`);
        if (value.constant !== observations[checkpoint][field]) return failure("constant-value", fields[field], `flag=${flag}, checkpoint ${checkpoint}.${fields[field]} expected ${observations[checkpoint][field]}, got ${value.constant}`);
      }
    }
  }
  const requiredFlags = branches ? [false, true] : [false];
  if (requiredFlags.some(flag => !coveredFlags.has(flag))) return failure("missing-input-path", "flag", "No successful path represents one or more concrete flag inputs");
  return undefined;
}

/** Stable property path, omitting list indices so valid shrinking can move a defect. */
function differingField(left: unknown, right: unknown, path: string): string {
  if (same(left, right)) return path;
  if (Array.isArray(left) && Array.isArray(right)) {
    if (left.length !== right.length) return `${path}.length`;
    for (let index = 0; index < left.length; index++) if (!same(left[index], right[index])) return differingField(left[index], right[index], `${path}[]`);
  } else if (left && right && typeof left === "object" && typeof right === "object" && !(left instanceof Set) && !(right instanceof Set) && !(left instanceof Map) && !(right instanceof Map)) {
    const before = left as Record<string, unknown>;
    const after = right as Record<string, unknown>;
    for (const key of unique([...Object.keys(before), ...Object.keys(after)])) {
      if (!same(before[key], after[key])) return differingField(before[key], after[key], `${path}.${key}`);
    }
  }
  return path;
}

/** Path spelling is incidental; the error class, code and message identify it. */
export function exceptionIdentity(error: unknown, fixtureDirectory: string): { signature: string; message: string } {
  const message = (error instanceof Error ? error.message : String(error)).replaceAll(fixtureDirectory, "<fixture>");
  const exception = error as { code?: unknown; diagnostic?: { code?: unknown } } | null;
  const code = exception?.diagnostic?.code ?? exception?.code;
  const name = error instanceof Error ? `${error.constructor.name}:${error.name}` : typeof error;
  const identity = JSON.stringify({ name, code: typeof code === "string" ? code : null, message });
  return { signature: `analyzer-exception:${createHash("sha256").update(identity).digest("hex")}`, message };
}

/** Checks only the owned generated grammar, never accepts arbitrary source inputs. */
export function checkCase(input: GeneratedCase, options: CheckOptions): CheckResult {
  validateCase(input);
  const budgets = effectiveBudgets(Object.fromEntries(Object.entries(options).filter(([key]) => key !== "compiler")));
  const modes: ModeObservation[] = [];
  const result = (status: CheckResult["status"], category: string, message?: string, identity?: string): CheckResult => ({ status, category, signature: identity ? `${category}:${identity}` : category, message, modes });
  if (!options.compiler) return result("unqualified", "compiler-required", "Qualified generated checks require an explicit pinned compiler");
  let checked!: CheckResult;
  withFiles({ "main.compact": renderCase(input) }, directory => {
    const path = resolve(directory, "main.compact");
    const compiled = validateWithCompiler(options.compiler!, path);
    const finish = (value: CheckResult) => { checked = { ...value, compiler: compiled }; };
    if (!compiled.valid) {
      // The compiler adapter reports process failures and source rejection through
      // the same interface. Do not invent a semantic-rejection classification.
      finish(result("unqualified", "compiler-validation-failed", compiled.error));
      return;
    }
    try {
      const program = new Program(path);
      const facts: AnalysisFacts[] = [];
      for (const engine of ["instructions", "expressions"] as const) for (const cached of [true, false]) {
        // Enable mutation summaries explicitly in the reference cached mode too.
        const current = new Dataflow(program, budgets.maxSteps, budgets.maxPaths, budgets.maxValues, engine, cached, cached).analyze();
        facts.push(current);
        modes.push({ engine, cached, metrics: current.metrics, diagnosticCodes: unique(current.diagnostics.map(diagnostic => diagnostic.code)), completedEntries: current.completedEntries.length });
      }
      if (facts.some(fact => fact.diagnostics.length || !same(fact.completedEntries, program.entries))) {
        finish(result("incomplete", "analysis-incomplete", unique(modes.flatMap(mode => mode.diagnosticCodes)).join(", ") || "Missing completed entry"));
        return;
      }
      for (const [left, right] of [[0, 1], [2, 3]]) {
        // Full paths include traces, caller paths, ordered sinks and write guards.
        for (const field of ["paths", "failedAssertions"] as const) {
          if (!same(facts[left][field], facts[right][field])) {
            finish(result("failed", `cache-disagreement:${modes[left].engine}`, undefined, differingField(facts[left][field], facts[right][field], field)));
            return;
          }
        }
      }
      const observations = facts.map(semanticPaths);
      for (let index = 1; index < facts.length; index++) {
        const before = { paths: observations[0].map(path => JSON.parse(path) as unknown), failedAssertions: facts[0].failedAssertions };
        const after = { paths: observations[index].map(path => JSON.parse(path) as unknown), failedAssertions: facts[index].failedAssertions };
        if (!same(before, after)) {
          finish(result("failed", "engine-disagreement", undefined, differingField(before, after, "facts")));
          return;
        }
      }
      const findings = facts.map(fact => securityDetectors.flatMap(detector => detector.run(fact)));
      if (findings.some(found => !same(found, findings[0]))) {
        const different = findings.find(found => !same(found, findings[0]))!;
        finish(result("failed", "detector-disagreement", undefined, differingField(findings[0], different, "findings")));
        return;
      }
      for (let index = 0; index < facts.length; index++) {
        const failure = checkObservations(input, facts[index]);
        if (failure) {
          finish(result("failed", `concrete-model-disagreement:${modes[index].engine}:${modes[index].cached}`, failure.message, `${failure.property}:${failure.field}`));
          return;
        }
      }
      const cacheFailure = modes.find(mode => mode.cached ? mode.metrics.readSummaryHits === 0 : mode.metrics.summaryHits !== 0);
      if (cacheFailure) {
        finish(result("failed", "cache-exercise-missing", undefined, `${cacheFailure.engine}:${cacheFailure.cached ? "readSummaryHits" : "uncached.summaryHits"}`));
        return;
      }
      // Temporary paths vary between workers. This digest covers only the
      // independently checked concrete observations, not all abstract path facts.
      finish({ ...result("passed", "equivalent-and-model-checked"), observationSha256: createHash("sha256").update(JSON.stringify(expectedFlagObservations(input))).digest("hex") });
    } catch (error) {
      const exception = exceptionIdentity(error, directory);
      finish({ ...result("failed", "analyzer-exception", exception.message), signature: exception.signature });
    }
  });
  return checked;
}
