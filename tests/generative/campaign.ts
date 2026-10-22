import { mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { runNodeModule, WorkerFailure, executionLimits, ExecutionLimits } from "../../src/runtime/process.js";
import { buildIdentity, CaseArtifact, makeArtifact, validateArtifact } from "./artifacts.js";
import { CheckOptions, CheckResult } from "./check.js";
import { GeneratedCase, generateCase, validateCase } from "./model.js";
import { reduceCase } from "./reduce.js";
import { effectiveBudgets } from "./budgets.js";
import { validateCheckResult } from "./results.js";

export async function runCaseIsolated(input: GeneratedCase, options: CheckOptions, limits: ExecutionLimits = {}): Promise<CheckResult> {
  validateCase(input);
  executionLimits(limits);
  try {
    const output = await runNodeModule(fileURLToPath(new URL("./worker.js", import.meta.url)), { case: input, options }, limits);
    return validateCheckResult(JSON.parse(output.stdout));
  } catch (error) {
    const category = error instanceof WorkerFailure ? error.code : "worker-protocol";
    return { status: "incomplete", category, signature: category, message: error instanceof Error ? error.message : String(error), modes: [] };
  }
}

function integer(value: string | undefined, fallback: number, minimum: number, maximum: number, label: string): number {
  if (value !== undefined && !/^\d+$/.test(value)) throw new Error(`${label} must be an integer`);
  const parsed = value === undefined ? fallback : Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) throw new Error(`${label} must be ${minimum}..${maximum}`);
  return parsed;
}

function save(path: string, value: unknown): void {
  writeFileSync(path, JSON.stringify(value, null, 2) + "\n", { flag: "wx" });
}

async function main(args: string[]): Promise<number> {
  if (args.includes("--help")) {
    console.log("Owned-fixture analyzer correctness campaign (run from repository root)\n--compiler PATH --output NEW_DIRECTORY [--seed UINT32 --cases 1..256 --steps 1..32]\n[--max-steps N --max-paths N --max-values N --timeout-ms N --reduce-checks 0..256]\nReplay: --compiler PATH --output NEW_DIRECTORY --replay ARTIFACT.json [--compare-build]\nSource is generated only from the bounded owned model. No arbitrary target scanning.\nExit: 0 all cases passed, 1 property/differential failure, 2 incomplete/unqualified/input failure.");
    return 0;
  }
  const flags = new Map<string, string>();
  let compareBuild = false;
  const allowed = ["--compiler", "--output", "--seed", "--cases", "--steps", "--max-steps", "--max-paths", "--max-values", "--timeout-ms", "--reduce-checks", "--replay"];
  for (let index = 0; index < args.length; index++) {
    const flag = args[index];
    if (flag === "--compare-build" && !compareBuild) { compareBuild = true; continue; }
    if (!allowed.includes(flag) || flags.has(flag) || !args[index + 1] || args[index + 1].startsWith("--")) throw new Error(`Invalid campaign argument ${flag}`);
    flags.set(flag, args[++index]);
  }
  const compiler = flags.get("--compiler") ?? process.env.COMPACTC_TEST;
  if (!compiler || !flags.has("--output")) throw new Error("A pinned compiler and a new --output directory are required");
  if (compareBuild && !flags.has("--replay")) throw new Error("--compare-build applies only to replay");
  const count = integer(flags.get("--cases"), 16, 1, 256, "cases");
  const seed = integer(flags.get("--seed"), 1, 0, 0xffffffff, "seed");
  const steps = integer(flags.get("--steps"), 12, 1, 32, "steps");
  const reductionBudget = integer(flags.get("--reduce-checks"), 32, 0, 256, "reduce-checks");
  let budgets = effectiveBudgets();
  for (const [flag, key] of [["--max-steps", "maxSteps"], ["--max-paths", "maxPaths"], ["--max-values", "maxValues"]] as const) if (flags.has(flag)) budgets[key] = integer(flags.get(flag), 1, 1, 1_000_000, flag);
  let limits: ExecutionLimits = { timeoutMs: integer(flags.get("--timeout-ms"), 60000, 1, 600000, "timeout-ms"), heapMiB: 512, maxOutputBytes: 4 * 1024 * 1024 };
  const identity = buildIdentity(resolve(compiler));
  let previous: CaseArtifact | undefined;
  if (flags.has("--replay")) {
    if (["--seed", "--cases", "--steps", "--max-steps", "--max-paths", "--max-values", "--timeout-ms"].some(flag => flags.has(flag))) throw new Error("Replay preserves recorded cases, budgets and limits");
    const path = resolve(flags.get("--replay")!);
    if (statSync(path).size > 8 * 1024 * 1024) throw new Error("Replay artifact exceeds 8 MiB");
    previous = validateArtifact(JSON.parse(readFileSync(path, "utf8")));
    const changed = Object.keys(identity).filter(key => identity[key as keyof typeof identity] !== previous!.identity[key as keyof typeof identity]);
    if (changed.length && !compareBuild) throw new Error(`Replay identity mismatch (${changed.join(", ")}); --compare-build records an explicit new-build comparison`);
    budgets = previous.budgets;
    limits = previous.limits;
  }
  const output = resolve(flags.get("--output")!);
  // Refuse overwriting past evidence, even for a nominally identical seed.
  mkdirSync(output);
  const planned = previous ? [previous.case] : Array.from({ length: count }, (_, index) => generateCase((seed + index) >>> 0, steps));
  const counts: Record<CheckResult["status"], number> = { passed: 0, failed: 0, incomplete: 0, unqualified: 0 };
  const featureCounts: Record<string, number> = {};
  const rows: { artifact: string; seed: number; status: string; category: string; signature: string; observationSha256?: string }[] = [];
  let interrupted = false;
  for (const [index, input] of planned.entries()) {
    for (const operation of input.operations) featureCounts[operation.kind] = (featureCounts[operation.kind] ?? 0) + 1;
    const result = await runCaseIsolated(input, { ...budgets, compiler: resolve(compiler) }, limits);
    const artifact = `${String(index).padStart(4, "0")}-${input.seed}.json`;
    save(resolve(output, artifact), makeArtifact(input, identity, budgets, limits, result));
    counts[result.status]++;
    rows.push({ artifact, seed: input.seed, status: result.status, category: result.category, signature: result.signature, observationSha256: result.observationSha256 });
    console.log(`${index + 1}/${planned.length} seed=${input.seed} ${result.status} ${result.category}`);
    // Only semantic/differential failures that compiled successfully can reduce.
    // Incomplete results and compiler failures are never accepted as substitutes.
    if (result.status === "failed" && result.compiler?.valid && reductionBudget > 0) {
      let retained = result;
      const reduced = await reduceCase(input, async candidate => {
        const next = await runCaseIsolated(candidate, { ...budgets, compiler: resolve(compiler) }, limits);
        const preserve = next.status === "failed" && next.compiler?.valid === true && next.signature === result.signature;
        if (preserve) retained = next;
        if (next.category === "worker-interrupted") interrupted = true;
        return preserve;
      }, reductionBudget, () => interrupted);
      save(resolve(output, `${String(index).padStart(4, "0")}-reduced.json`), { ...makeArtifact(reduced.case, identity, budgets, limits, retained), reduction: { checks: reduced.checks, exhausted: reduced.exhausted, interrupted: reduced.interrupted, changed: reduced.changed, method: "bounded typed deletion and numeric simplification; not a global minimum" } });
    }
    if (result.category === "worker-interrupted" || interrupted) { interrupted = true; break; }
  }
  const summary = {
    schemaVersion: "nightshade-generated-campaign-2", identity, completedAt: new Date().toISOString(),
    scope: "owned initialized Field/Set/scalar-snapshot fragment; no contract execution or security accuracy claim",
    coverageKind: "generated-operation-counts-and-analysis-metrics; not execution-edge coverage",
    planned: planned.length, completed: rows.length, interrupted, counts, featureCounts, rows,
    ...(previous ? { replay: { comparison: compareBuild, previousIdentity: previous.identity, previousStatus: previous.result.status, previousSignature: previous.result.signature, sameStatus: rows[0]?.status === previous.result.status, sameSignature: rows[0]?.signature === previous.result.signature, sameObservation: rows[0]?.observationSha256 && previous.result.observationSha256 ? rows[0].observationSha256 === previous.result.observationSha256 : null } } : {}),
  };
  save(resolve(output, "summary.json"), summary);
  console.log(JSON.stringify({ counts, output, completed: rows.length }));
  return interrupted || counts.incomplete || counts.unqualified ? 2 : counts.failed ? 1 : 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { process.exitCode = await main(process.argv.slice(2)); }
  catch (error) { console.error(error instanceof Error ? error.message : String(error)); process.exitCode = 2; }
}
