import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Dataflow, Program, resolvePolicies, scanFile, type AnalysisFacts } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { openzeppelinPreconditions, OZ_POLICY_REVISION } from "../src/detectors/openzeppelin.js";
import { BUILTIN_POLICIES, validatePolicies, type BuiltinPolicy } from "../src/policies.js";
import { readConfiguration } from "../src/config.js";
import { withFiles, semanticPaths } from "./helpers.js";

const external = process.env.OZ_COMPACT_TEST;
const searchPaths = external ? [resolve(external, "contracts/src")] : [];
const options = { searchPaths, policies: { builtins: [...BUILTIN_POLICIES] }, detectors: [openzeppelinPreconditions.id] };
const manifest = JSON.parse(readFileSync("tests/corpus/manifest.json", "utf8")).builtins as {
  revision: string; detector: string; cases: { name: string; policy: BuiltinPolicy; line: number }[];
};
function compile(file: string, paths = searchPaths): void {
  if (process.env.COMPACTC_TEST) {
    const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file, paths);
    assert.equal(compiled.valid, true, compiled.error);
  }
}
// Traversal order may allocate distinct wildcard snapshot numbers in the two
// engines. Preserve their equality relationships via a bijective alpha rename.
function comparablePaths(facts: AnalysisFacts): string[] {
  const identities = new Map<string, string>();
  return semanticPaths(facts).map(path => JSON.stringify(JSON.parse(path), (key, value: unknown) => {
    if (key !== "identity" || typeof value !== "string") return value;
    return value.replace(/^snapshot:\d+:/, id => {
      if (!identities.has(id)) identities.set(id, `snapshot:${identities.size}:`);
      return identities.get(id)!;
    });
  }));
}
function compare(file: string, expectedLines: number[], paths = searchPaths): void {
  compile(file, paths);
  const program = new Program(file, paths), policies = resolvePolicies(program, options.policies);
  let prior: AnalysisFacts | undefined;
  for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
    const facts = new Dataflow(program, 20000, 256, 50000, engine, cached, cached, "equivalent-states", true).analyze();
    assert.deepEqual(facts.diagnostics, []);
    assert.deepEqual(facts.completedEntries, program.entries);
    assert.deepEqual(openzeppelinPreconditions.run(facts, policies).map(finding => finding.location.line), expectedLines);
    if (prior) {
      assert.deepEqual(facts.callReaches, prior.callReaches);
      assert.deepEqual(comparablePaths(facts), comparablePaths(prior));
    }
    prior = facts;
  }
  const result = scanFile(file, { ...options, searchPaths: paths });
  assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
  assert.deepEqual(result.findings.map(finding => finding.location.line), expectedLines);
  assert.ok(result.findings.every(finding => finding.metadata.libraryRevision === OZ_POLICY_REVISION));
  assert.ok(!scanFile(file, { searchPaths: paths }).coverage.detectors.includes(openzeppelinPreconditions.id), "Ordinary default scans stay opt-out");
}
for (const item of manifest.cases) for (const label of ["positive", "corrected", "lookalike"]) {
  test(`OZ ${item.name}: compiler-valid ${label}`, { skip: label !== "lookalike" && !external }, () => {
    assert.equal(manifest.revision, OZ_POLICY_REVISION);
    compare(resolve(`tests/corpus/builtins/${item.name}-${label}.compact`), label === "positive" ? [item.line] : [], label === "lookalike" ? [] : searchPaths);
  });
}

test("built-in policy configuration is explicit and strict", () => {
  withFiles({ "nightshade.json": JSON.stringify({ version: 1, policies: options.policies }) }, directory => {
    assert.deepEqual(readConfiguration(resolve(directory, "nightshade.json")).options.policies, options.policies);
  });
  const span = { file: "config", start: 0, end: 0, line: 1, column: 1, endLine: 1, endColumn: 1 };
  assert.throws(() => validatePolicies({ builtins: ["ownable"] }, span), /Unknown built-in policy/);
  assert.throws(() => validatePolicies({ builtins: "openzeppelin-ownable" }, span), /Unknown built-in policy/);
  assert.throws(() => validatePolicies({ builtins: new Array(1) }, span), /Unknown built-in policy/);
});

test("call observations survive later caller aborts, leaf caching and callback invocation", () => {
  withFiles({ "main.compact": `circuit leaf(value: Boolean): Boolean { return value; }
circuit guard(value: Boolean): Boolean { assert(value, "guard"); return leaf(value); }
circuit wrapper(value: Boolean): Boolean { return guard(value); }
export circuit entry(flag: Boolean): [] {
  leaf(true); leaf(true);
  if (flag) { wrapper(true); assert(false, "later"); }
  else { wrapper(false); }
}
export circuit callback(): Vector<1, Boolean> { return map(guard, [true]); }` }, directory => {
    const file = resolve(directory, "main.compact"); compile(file, []);
    const program = new Program(file);
    let prior: AnalysisFacts | undefined;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 20000, 256, 50000, engine, cached, cached, "equivalent-states", true).analyze();
      assert.deepEqual(facts.diagnostics, []);
      const wrapper = [...program.functions.values()].find(fn => fn.symbol.name === "wrapper")!;
      const shared = facts.callReaches!.find(reach => reach.owner === wrapper.symbol.id)!;
      assert.equal(shared.maySucceed, true);
      assert.equal(shared.failure!.message, '"guard"');
      assert.equal(facts.paths.filter(path => program.symbols.get(path.entry)!.name === "entry").length, 0);
      if (prior) assert.deepEqual(facts.callReaches, prior.callReaches);
      prior = facts;
    }
    assert.equal(new Dataflow(program).analyze().callReaches, undefined);
    const limited = new Dataflow(program, 20000, 256, 1, "instructions", true, true, "equivalent-states", true).analyze();
    assert.ok(limited.diagnostics.some(diagnostic => diagnostic.code === "value-budget"));
    assert.deepEqual(openzeppelinPreconditions.run(limited, resolvePolicies(program, options.policies)), []);
  });
});

const ownableHeader = `import CompactStandardLibrary;\nimport "access/Ownable" prefix O_;\n`;
test("Ownable constructor-only use is checked per invocation context and through aliases", { skip: !external }, () => {
  withFiles({ "main.compact": ownableHeader + `circuit shared(): [] { O_initialize(left<Bytes<32>, ContractAddress>(pad(32, "owner"))); }
constructor() { shared(); }
export circuit entry(): [] { shared(); }` }, directory => {
    const file = resolve(directory, "main.compact"); compare(file, [3]);
    assert.deepEqual(scanFile(file, options).findings[0].callPath, ["entry", "shared", "initialize"]);
  });
  withFiles({ "main.compact": ownableHeader + `export { O_initialize };` }, directory => compare(resolve(directory, "main.compact"), [2]));
});

test("Initializable composition checks resolved owned imports without reproducing compiler aliasing", { skip: !external }, () => {
  withFiles({ "main.compact": `module Wrapper {
  import "security/Initializable" prefix I_;
  export circuit init(): [] { I_initialize(); }
}
import Wrapper prefix W_;
export circuit entry(): [] { W_init(); }` }, directory => compare(resolve(directory, "main.compact"), [2]));
  withFiles({ "main.compact": `module Initializable { export circuit initialize(): [] {} }
module Wrapper { import Initializable prefix I_; export circuit init(): [] { I_initialize(); } }
import Wrapper prefix W_; export circuit entry(): [] { W_init(); }` }, directory => compare(resolve(directory, "main.compact"), [], []));
});

test("path-dependent library guards and successful calls before abort remain quiet", { skip: !external }, () => {
  withFiles({ "main.compact": `import "security/Pausable" prefix P_;
export circuit entry(flag: Boolean): [] {
  if (disclose(flag)) { P__pause(); }
  P__pause();
}
export circuit later(): [] { P__pause(); assert(false, "later"); }` }, directory => compare(resolve(directory, "main.compact"), []));
});

test("incomplete and unselected callers cannot turn a shared call into a universal rejection", { skip: !external }, () => {
  withFiles({ "main.compact": `import "security/Pausable" prefix P_;
circuit shared(): [] { P__pause(); }
export circuit bad(): [] { P__pause(); shared(); }
export circuit good(): [] { for (const i of 0..30) { disclose(i); } shared(); }` }, directory => {
    const file = resolve(directory, "main.compact"); compile(file);
    const program = new Program(file, searchPaths), policies = resolvePolicies(program, options.policies);
    const bad = program.entries.find(entry => program.symbols.get(entry)!.name === "bad")!;
    const subset = new Dataflow(program, 20000, 256, 50000, "instructions", true, true, "equivalent-states", true).analyzeSubset([bad]);
    assert.deepEqual(openzeppelinPreconditions.run(subset, policies), []);
    const incomplete = new Dataflow(program, 80, 256, 50000, "instructions", true, true, "equivalent-states", true).analyze();
    assert.ok(incomplete.diagnostics.length);
    assert.deepEqual(openzeppelinPreconditions.run(incomplete, policies), []);
  });
});

test("modified upstream dependencies and source lookalikes are not trusted", { skip: !external }, () => {
  const ownable = readFileSync(resolve(searchPaths[0], "access/Ownable.compact"), "utf8");
  const utils = readFileSync(resolve(searchPaths[0], "utils/Utils.compact"), "utf8");
  const source = ownableHeader + `export circuit entry(): [] { O_initialize(left<Bytes<32>, ContractAddress>(pad(32, "owner"))); }`;
  for (const changed of ["ownable", "dependency"]) withFiles({ "main.compact": source,
    "access/Ownable.compact": ownable + (changed === "ownable" ? "\n// changed\n" : ""),
    "utils/Utils.compact": utils + (changed === "dependency" ? "\n// changed\n" : ""),
  }, directory => compare(resolve(directory, "main.compact"), [], [directory]));
});

// This owned triplet qualifies import-policy recall only. Compiler acceptance
// does not establish shared storage, and these tests execute no contract runtime.
for (const label of ["positive", "corrected", "lookalike"] as const) {
  test(`Initializable two-module composition: compiler-valid ${label}`, { skip: label === "positive" && !external }, () => {
    const file = resolve(`tests/corpus/builtins/initializable-composition-${label}.compact`);
    const paths = label === "positive" ? searchPaths : [];
    compare(file, label === "positive" ? [4, 8] : [], paths);
    const report = scanFile(file, { ...options, searchPaths: paths });
    assert.deepEqual(report.findings.map(item => item.metadata.precondition), label === "positive" ? ["top-level-single-importer", "top-level-single-importer"] : []);
    assert.deepEqual(report.findings.map(item => item.metadata.importers), label === "positive" ? [2, 2] : []);
  });
}
