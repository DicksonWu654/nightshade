import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { createRequire } from "node:module";
// Load the same parser modules as the worker before recording the binaries.
// The campaign otherwise imports only type declarations from the checker.
import "../../src/parser/index.js";
import { analyzerIdentity } from "../../benchmarks/identity.js";
import { SEMANTIC_PROFILE } from "../../src/semantic/profile.js";
import { CheckOptions, CheckResult } from "./check.js";
import { GeneratedCase, renderCase, validateCase } from "./model.js";
import { ExecutionLimits, executionLimits } from "../../src/runtime/process.js";
import { CheckBudgets, effectiveBudgets } from "./budgets.js";
import { validateCheckResult } from "./results.js";

export interface BuildIdentity {
  analyzerSourceSha256: string;
  harnessSourceSha256: string;
  builtJavaScriptSha256: string;
  parserRuntimeSha256: string;
  compilerSha256: string;
  compilerDistributionSha256: string;
  semanticProfile: string;
  node: string;
  platform: string;
  arch: string;
}

export interface CaseArtifact {
  schemaVersion: "nightshade-generated-artifact-2";
  purpose: "owned-fixture-analyzer-correctness";
  identity: BuildIdentity;
  case: GeneratedCase;
  source: string;
  sourceSha256: string;
  budgets: CheckBudgets;
  limits: Required<ExecutionLimits>;
  result: CheckResult;
}

export function digest(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function treeDigest(roots: string[], extension: RegExp): string {
  const hash = createHash("sha256");
  const files = roots.flatMap(root => readdirSync(root, { recursive: true }).map(String).filter(file => extension.test(file)).map(file => `${root}/${file}`));
  for (const file of files.sort()) hash.update(file).update("\0").update(readFileSync(file)).update("\0");
  return hash.digest("hex");
}

/** Run from the repository root; records source and executed build separately. */
export function buildIdentity(compiler: string): BuildIdentity {
  const require = createRequire(import.meta.url);
  const native = createHash("sha256");
  const loaded = Object.keys(require.cache).filter(file => /\.node$/.test(file));
  if (loaded.length < 2) throw new Error("Expected loaded Compact grammar and tree-sitter runtime binaries");
  const files = [...loaded, require.resolve("tree-sitter-runtime"), resolve("dist/parser/manifest.json"), resolve("dist/parser/src/node-types.json")];
  for (const file of files.sort()) native.update(relative(process.cwd(), file)).update("\0").update(readFileSync(file)).update("\0");
  const distribution = createHash("sha256");
  for (const file of ["compactc.bin", "zkir", "zkir-v3"]) distribution.update(file).update("\0").update(readFileSync(resolve(dirname(compiler), file))).update("\0");
  return {
    analyzerSourceSha256: analyzerIdentity(),
    harnessSourceSha256: digest(treeDigest(["tests/generative"], /\.ts$/) + digest(readFileSync("tests/helpers.ts")) + digest(readFileSync("benchmarks/identity.ts"))),
    builtJavaScriptSha256: digest(treeDigest(["dist/src", "dist/tests/generative"], /\.(js|node)$/) + digest(readFileSync("dist/tests/helpers.js")) + digest(readFileSync("dist/benchmarks/identity.js"))),
    parserRuntimeSha256: native.digest("hex"),
    compilerSha256: digest(readFileSync(resolve(compiler))),
    compilerDistributionSha256: distribution.digest("hex"),
    semanticProfile: SEMANTIC_PROFILE,
    node: process.version,
    platform: process.platform,
    arch: process.arch,
  };
}

export function makeArtifact(input: GeneratedCase, identity: BuildIdentity, options: Omit<CheckOptions, "compiler">, limits: ExecutionLimits, result: CheckResult): CaseArtifact {
  const source = renderCase(input);
  return { schemaVersion: "nightshade-generated-artifact-2", purpose: "owned-fixture-analyzer-correctness", identity, case: validateCase(input), source, sourceSha256: digest(source), budgets: effectiveBudgets(options), limits: executionLimits(limits), result: validateCheckResult(result) };
}

/** Replay regenerates source from the bounded model; stored source is never executed. */
export function validateArtifact(value: unknown): CaseArtifact {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Invalid generated artifact");
  const item = value as CaseArtifact;
  if (item.schemaVersion !== "nightshade-generated-artifact-2" || item.purpose !== "owned-fixture-analyzer-correctness") throw new Error("Unsupported generated artifact schema/purpose");
  const input = validateCase(item.case);
  const source = renderCase(input);
  if (item.source !== source || item.sourceSha256 !== digest(source)) throw new Error("Generated artifact source/model integrity mismatch");
  if (!item.identity || Object.keys(item.identity).sort().join() !== ["analyzerSourceSha256", "harnessSourceSha256", "builtJavaScriptSha256", "parserRuntimeSha256", "compilerSha256", "compilerDistributionSha256", "semanticProfile", "node", "platform", "arch"].sort().join()) throw new Error("Invalid artifact build identity");
  for (const [key, entry] of Object.entries(item.identity)) if (typeof entry !== "string" || !entry || key.endsWith("Sha256") && !/^[a-f0-9]{64}$/.test(entry)) throw new Error(`Invalid artifact identity ${key}`);
  if (!item.budgets || typeof item.budgets !== "object" || Array.isArray(item.budgets) || Object.keys(item.budgets).sort().join() !== ["maxSteps", "maxPaths", "maxValues"].sort().join()) throw new Error("Invalid artifact budgets");
  for (const [key, entry] of Object.entries(item.budgets)) if (!["maxSteps", "maxPaths", "maxValues"].includes(key) || !Number.isSafeInteger(entry) || entry < 1 || entry > 1_000_000) throw new Error("Invalid artifact budget");
  if (!item.limits || Object.keys(item.limits).sort().join() !== ["timeoutMs", "heapMiB", "maxOutputBytes"].sort().join()) throw new Error("Missing artifact execution limits");
  executionLimits(item.limits);
  return { ...item, case: input, budgets: effectiveBudgets(item.budgets), limits: executionLimits(item.limits), identity: { ...item.identity }, result: validateCheckResult(item.result) };
}
