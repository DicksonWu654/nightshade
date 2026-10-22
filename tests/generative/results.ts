import type { CheckResult } from "./check.js";

type Mode = CheckResult["modes"][number];
const metricKeys = ["steps", "sources", "paths", "abstractValues", "summaryHits", "summaryEntries", "statefulSummaryHits", "readSummaryHits", "summaryEffects", "guardSubsumptions"] as const satisfies readonly (keyof Mode["metrics"])[];
const summaryMetrics = ["summaryHits", "summaryEntries", "statefulSummaryHits", "readSummaryHits", "summaryEffects"] as const;
const passingCategory = "equivalent-and-model-checked";

function record(value: unknown, required: readonly string[], optional: readonly string[], label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new Error(`Invalid ${label}: expected a plain object`);
  const allowed = [...required, ...optional];
  if (Reflect.ownKeys(value).some(key => typeof key !== "string" || !allowed.includes(key)) || required.some(key => !Object.hasOwn(value, key))) throw new Error(`Invalid ${label}: unexpected or missing fields`);
  for (const key of Object.keys(Object.getOwnPropertyDescriptors(value))) if (!("value" in Object.getOwnPropertyDescriptor(value, key)!)) throw new Error(`Invalid ${label}: accessor fields are unsupported`);
  return value as Record<string, unknown>;
}

function array(value: unknown, maximum: number, label: string): unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length > maximum || Reflect.ownKeys(value).length !== value.length + 1) throw new Error(`Invalid ${label}: expected a bounded dense array`);
  for (let index = 0; index < value.length; index++) if (!Object.getOwnPropertyDescriptor(value, index) || !("value" in Object.getOwnPropertyDescriptor(value, index)!)) throw new Error(`Invalid ${label}: expected indexed data fields`);
  return value;
}

function count(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || Object.is(value, -0)) throw new Error(`Invalid ${label}: expected a nonnegative safe integer`);
  return value;
}

function string(value: unknown, label: string, nonempty = false): string {
  if (typeof value !== "string" || nonempty && !value.trim()) throw new Error(`Invalid ${label}: expected ${nonempty ? "a nonempty" : "a"} string`);
  return value;
}

/**
 * Validate and copy a worker/stored result before using its qualification status.
 * This checks evidence shape and consistency; it does not authenticate an artifact
 * or independently establish that a compiler or analyzer actually produced it.
 */
export function validateCheckResult(value: unknown): CheckResult {
  const item = record(value, ["status", "category", "signature", "modes"], ["message", "compiler", "observationSha256"], "generated check result");
  if (!["passed", "failed", "incomplete", "unqualified"].includes(item.status as string)) throw new Error("Invalid generated check status");
  const category = string(item.category, "check category", true);
  const signature = string(item.signature, "check signature", true);
  const modes = array(item.modes, 4, "check modes").map((raw): Mode => {
    const mode = record(raw, ["engine", "cached", "metrics", "diagnosticCodes", "completedEntries"], [], "check mode");
    if (mode.engine !== "instructions" && mode.engine !== "expressions") throw new Error("Invalid mode engine");
    if (typeof mode.cached !== "boolean") throw new Error("Invalid mode cache selection");
    const sourceMetrics = record(mode.metrics, metricKeys, [], "mode metrics");
    const metrics = Object.fromEntries(metricKeys.map(key => [key, count(sourceMetrics[key], `mode metric ${key}`)])) as Mode["metrics"];
    const diagnosticCodes = array(mode.diagnosticCodes, 256, "mode diagnostics").map(code => string(code, "diagnostic code", true));
    if (new Set(diagnosticCodes).size !== diagnosticCodes.length) throw new Error("Invalid mode diagnostics: duplicate codes");
    const completedEntries = count(mode.completedEntries, "completed entries");
    if (completedEntries > 1) throw new Error("Invalid completed entries: the generated fragment has one entrypoint");
    return { engine: mode.engine, cached: mode.cached, metrics, diagnosticCodes, completedEntries };
  });
  if (new Set(modes.map(mode => `${mode.engine}:${mode.cached}`)).size !== modes.length) throw new Error("Invalid check modes: duplicate engine/cache combinations");
  const result: CheckResult = { status: item.status as CheckResult["status"], category, signature, modes };
  if (Object.hasOwn(item, "message")) result.message = item.message === undefined ? undefined : string(item.message, "check message");
  if (Object.hasOwn(item, "compiler")) {
    if (item.compiler === undefined) result.compiler = undefined;
    else {
      const compiler = record(item.compiler, ["valid", "version", "languageVersion"], ["error"], "compiler evidence");
      if (typeof compiler.valid !== "boolean") throw new Error("Invalid compiler validity");
      result.compiler = { valid: compiler.valid, version: string(compiler.version, "compiler version"), languageVersion: string(compiler.languageVersion, "compiler language version") };
      if (Object.hasOwn(compiler, "error")) result.compiler.error = compiler.error === undefined ? undefined : string(compiler.error, "compiler error");
    }
  }
  if (Object.hasOwn(item, "observationSha256")) {
    if (item.observationSha256 !== undefined && (typeof item.observationSha256 !== "string" || !/^[a-f0-9]{64}$/.test(item.observationSha256))) throw new Error("Invalid observation digest");
    result.observationSha256 = item.observationSha256 as string | undefined;
  }
  if (result.status === "passed") {
    if (category !== passingCategory || signature !== passingCategory || !result.observationSha256
      || result.compiler?.valid !== true || result.compiler.version !== "0.34.0" || result.compiler.languageVersion !== "0.26.0" || result.compiler.error !== undefined
      || modes.length !== 4 || modes.some(mode => mode.diagnosticCodes.length || mode.completedEntries !== 1
        || mode.metrics.steps === 0 || mode.metrics.paths === 0 || mode.metrics.abstractValues === 0
        || mode.cached && (mode.metrics.readSummaryHits === 0 || mode.metrics.summaryEntries === 0 || mode.metrics.summaryHits < mode.metrics.readSummaryHits + mode.metrics.statefulSummaryHits)
        || !mode.cached && summaryMetrics.some(key => mode.metrics[key] !== 0))) throw new Error("Invalid passing qualification evidence");
  }
  return result;
}
