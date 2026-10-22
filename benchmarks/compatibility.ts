import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { Program, Dataflow } from "../src/index.js";
import { validateWithCompiler } from "../src/compiler/index.js";
import { AnalysisError } from "../src/model.js";
import { analyzerIdentity } from "./identity.js";

const args = process.argv.slice(2);
const option = (name: string): string => {
  const index = args.indexOf(name);
  if (index < 0 || !args[index + 1]) throw new Error(`Required: ${name} VALUE`);
  return resolve(args[index + 1]);
};
const references = option("--references");
const compiler = option("--compiler");
const output = option("--output");
const revisions: Record<string, string> = { "example-counter": "273f083ab36a52407f16ec9a9796d902226e05d6", "example-bboard": "38bfac8c574abb0c5a96c9e076779716c3e88231", "compact-contracts": "ec1331cd8195694c747d291e8fc8ab6d2914a976" };
for (const [repository, revision] of Object.entries(revisions)) {
  const actual = spawnSync("git", ["-C", resolve(references, repository), "rev-parse", "HEAD"], { encoding: "utf8" });
  if (actual.status !== 0 || actual.stdout.trim() !== revision) throw new Error(`Reference revision mismatch: ${repository}`);
}
const temporary = mkdtempSync(resolve(tmpdir(), "nightshade-compatibility-"));
try {
  const ownable = resolve(temporary, "ownable.compact");
  const pausable = resolve(temporary, "pausable.compact");
  const access = resolve(references, "compact-contracts/contracts/src/access/Ownable");
  const pause = resolve(references, "compact-contracts/contracts/src/security/Pausable");
  writeFileSync(ownable, `pragma language_version >= 0.26.0; import "${access}" prefix Ownable_; export circuit check(): [] { Ownable_assertOnlyOwner(); }`);
  writeFileSync(pausable, `pragma language_version >= 0.26.0; import "${pause}" prefix Pausable_; export circuit check(): [] { Pausable_assertNotPaused(); }`);
  const fixtures = [
    { name: "counter", repository: "example-counter", path: resolve(references, "example-counter/contract/src/counter.compact") },
    { name: "bboard", repository: "example-bboard", path: resolve(references, "example-bboard/contract/src/bboard.compact") },
    { name: "Ownable check composition", repository: "compact-contracts", path: ownable },
    { name: "Pausable check composition", repository: "compact-contracts", path: pausable },
  ];
  const rows = fixtures.map(fixture => {
    const compilerResult = validateWithCompiler(compiler, fixture.path);
    try {
      const program = new Program(fixture.path);
      const facts = new Dataflow(program).analyze();
      return { name: fixture.name, revision: revisions[fixture.repository], sourceSha256: createHash("sha256").update(readFileSync(fixture.path)).digest("hex"), compiler: compilerResult, files: program.files.size, circuits: program.functions.size, entrypoints: program.entries.length, completed: facts.completedEntries.length, diagnostics: facts.diagnostics.map(diagnostic => ({ code: diagnostic.code, message: diagnostic.message, line: diagnostic.location.line })) };
    } catch (error) {
      return { name: fixture.name, revision: revisions[fixture.repository], compiler: compilerResult, diagnostics: [error instanceof AnalysisError ? { code: error.diagnostic.code, message: error.diagnostic.message, line: error.diagnostic.location.line } : { code: "analysis-error", message: String(error) }] };
    }
  });
  const report = { version: "compatibility-1", analyzerSourceAndLockSha256: analyzerIdentity(), measuredAt: new Date().toISOString(), scope: "Structural and abstract-analysis completion only; detectors are not run; no security labels or vulnerability claims", compositions: { Ownable: "assertOnlyOwner wrapper", Pausable: "assertNotPaused wrapper" }, rows };
  writeFileSync(output, JSON.stringify(report, null, 2) + "\n");
  console.log(JSON.stringify(rows, null, 2));
} finally { rmSync(temporary, { recursive: true, force: true }); }
