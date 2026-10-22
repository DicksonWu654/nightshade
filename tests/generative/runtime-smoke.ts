// Owned cases only: strict replay regenerates the bounded model, never saved source.
import { mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { digest } from "./artifacts.js";
import { generateCase } from "./model.js";
import { RuntimeTransitionCorpus } from "./runtime-feedback.js";
import { compareRuntimeResults, makeRuntimeArtifact, RUNTIME_LIMITS, runRuntimeCaseIsolated, runtimeBuildIdentity, runtimeIdentityChanges, validateRuntimeArtifact, validateRuntimeLimits, type RuntimeCaseArtifact } from "./runtime-artifacts.js";
import { reduceRuntimeCase } from "./runtime-reduce.js";

const sha = (path: string) => digest(readFileSync(path));
const save = (path: string, value: unknown) => writeFileSync(path, JSON.stringify(value, null, 2) + "\n", { flag: "wx" });

async function main(): Promise<number> {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === "--help") {
    console.log("Owned compiled-evaluation campaign: --output NEW_DIRECTORY [--timeout-ms 1..60000] [--reduce-checks 0..256]\nReplay: --output NEW_DIRECTORY --replay CASE.json [--compare-build] [--reduce-checks 0..256]\nRequires pinned COMPACTC_TEST and COMPACT_RUNTIME_TEST; run from repository root.\nFixed schedule: seeds 1..16, 24 operations, both Boolean inputs. No arbitrary targets.\nExit 0: properties passed and replay matched; 1: property failure; 2: incomplete/input/replay drift.");
    return 0;
  }
  const flags = new Map<string, string>();
  let compareBuild = false;
  for (let index = 0; index < args.length; index++) {
    const flag = args[index];
    if (flag === "--compare-build" && !compareBuild) { compareBuild = true; continue; }
    if (!["--output", "--replay", "--timeout-ms", "--reduce-checks"].includes(flag) || flags.has(flag) || !args[index + 1] || args[index + 1].startsWith("--")) throw new Error(`Invalid runtime campaign argument ${flag}`);
    flags.set(flag, args[++index]);
  }
  if (!flags.has("--output") || !process.env.COMPACTC_TEST || !process.env.COMPACT_RUNTIME_TEST) throw new Error("New --output directory and pinned compiler/runtime inputs are mandatory");
  if (compareBuild && !flags.has("--replay")) throw new Error("--compare-build applies only to replay");
  if (flags.has("--replay") && flags.has("--timeout-ms")) throw new Error("Replay preserves recorded limits");
  const integer = (flag: string, fallback: number, minimum: number, maximum: number) => {
    const raw = flags.get(flag);
    if (raw !== undefined && !/^\d+$/.test(raw)) throw new Error(`Invalid integer ${flag}`);
    const value = raw === undefined ? fallback : Number(raw);
    if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new Error(`${flag} must be ${minimum}..${maximum}`);
    return value;
  };
  const maxChecks = integer("--reduce-checks", 32, 0, 256);
  let limits = validateRuntimeLimits({ ...RUNTIME_LIMITS, timeoutMs: integer("--timeout-ms", 60000, 1, 60000) });
  const compiler = resolve(process.env.COMPACTC_TEST);
  const runtimeDirectory = resolve(process.env.COMPACT_RUNTIME_TEST);
  const identity = runtimeBuildIdentity(compiler, runtimeDirectory);
  let previous: RuntimeCaseArtifact | undefined;
  let previousArtifactSha256: string | undefined;
  let changedIdentityFields: string[] = [];
  if (flags.has("--replay")) {
    const path = resolve(flags.get("--replay")!);
    if (statSync(path).size > 8 * 1024 * 1024) throw new Error("Runtime replay artifact exceeds 8 MiB");
    const contents = readFileSync(path);
    if (contents.length > 8 * 1024 * 1024) throw new Error("Runtime replay artifact exceeds 8 MiB");
    previous = validateRuntimeArtifact(JSON.parse(contents.toString("utf8")));
    previousArtifactSha256 = digest(contents);
    changedIdentityFields = runtimeIdentityChanges(previous.identity, identity);
    if (changedIdentityFields.length && !compareBuild) throw new Error(`Runtime replay identity mismatch (${changedIdentityFields.join(", ")}); --compare-build records an explicit comparison`);
    limits = previous.limits;
  }
  const output = resolve(flags.get("--output")!);
  mkdirSync(output);
  const corpus = new RuntimeTransitionCorpus();
  const counts = { passed: 0, failed: 0, incomplete: 0 };
  const rows: object[] = [];
  const planned = previous ? [previous.case] : Array.from({ length: 16 }, (_, index) => generateCase(index + 1, 24));
  let interrupted = false;
  let reductionIncomplete = false;
  let replay: object | undefined;
  let replayMatched = true;
  for (const [index, input] of planned.entries()) {
    const result = await runRuntimeCaseIsolated(input, compiler, runtimeDirectory, limits);
    const artifact = `${String(index + 1).padStart(4, "0")}.json`;
    save(resolve(output, artifact), makeRuntimeArtifact(input, identity, limits, result));
    const admission = result.status === "passed" ? corpus.consider(input, result.observation) : undefined;
    const status = admission?.status === "incomplete" ? "incomplete" : result.status;
    const category = admission?.diagnostic ?? result.category;
    counts[status]++;
    const row: Record<string, unknown> = { artifact, sha256: sha(resolve(output, artifact)), status, category, resultStatus: result.status, signature: result.signature, admission };
    rows.push(row);
    console.log(`${index + 1}/${planned.length} ${status} ${category}`);
    if (previous) {
      const comparison = compareRuntimeResults(previous.result, result);
      replayMatched = comparison.sameStatus && comparison.sameSignature && comparison.sameObservation !== false && (compareBuild || comparison.sameCompiledJavaScript !== false);
      replay = { comparison: compareBuild, previousArtifactSha256, previousIdentity: previous.identity, changedIdentityFields, previousStatus: previous.result.status, previousSignature: previous.result.signature, ...comparison, matched: replayMatched };
    }
    if (result.status === "failed" && maxChecks) {
      const reduced = await reduceRuntimeCase(input, result, candidate => runRuntimeCaseIsolated(candidate, compiler, runtimeDirectory, limits), maxChecks, () => interrupted);
      const attempts = reduced.attempts.map((attempt, at) => {
        const name = `${String(index + 1).padStart(4, "0")}-attempt-${String(at + 1).padStart(4, "0")}.json`;
        save(resolve(output, name), makeRuntimeArtifact(attempt.model, identity, limits, attempt.result));
        return { artifact: name, sha256: sha(resolve(output, name)), preserved: attempt.preserved };
      });
      const reducedArtifact = `${String(index + 1).padStart(4, "0")}-reduced.json`;
      save(resolve(output, reducedArtifact), makeRuntimeArtifact(reduced.case, identity, limits, reduced.result));
      row.reduction = { artifact: reducedArtifact, sha256: sha(resolve(output, reducedArtifact)), checks: reduced.checks, changed: reduced.changed, exhausted: reduced.exhausted, interrupted: reduced.interrupted, attempts,
        method: "bounded typed deletion/numeric simplification preserving the first violated property; not a global minimum or proof of identical root cause" };
      interrupted ||= reduced.interrupted;
      reductionIncomplete ||= reduced.exhausted || reduced.interrupted || reduced.attempts.some(attempt => attempt.result.status === "incomplete");
    }
    if (result.category === "worker-interrupted" || interrupted) { interrupted = true; break; }
  }
  save(resolve(output, "summary.json"), {
    schemaVersion: "nightshade-owned-runtime-smoke-2", recordedAt: new Date().toISOString(), identity, limits,
    scope: "compiled evaluation of bounded owned generated cases, two Boolean inputs each; no proof or transaction qualification",
    coverageKind: "observed-checkpoint-transitions", schedule: previous ? "replay-one-model" : "fixed-seeds-1-through-16-24-operations",
    planned: planned.length, completed: rows.length, interrupted, reductionIncomplete, reductionBudget: maxChecks, counts, rows, corpus: corpus.snapshot(), replay,
  });
  return interrupted || counts.incomplete || reductionIncomplete || !replayMatched ? 2 : counts.failed ? 1 : 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { process.exitCode = await main(); }
  catch (error) { console.error(error instanceof Error ? error.message : String(error)); process.exitCode = 2; }
}
