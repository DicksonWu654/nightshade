import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile, resolvePolicies, type AnalysisFacts } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { inconsistentAccessControl as rule } from "../src/detectors/access-control.js";
import { predicateEvidence, predicateSourceKey, trustedPreimageSources } from "../src/dataflow/predicates.js";
import { accessTargets } from "../src/semantic/access-targets.js";
import { analyzeCounterPredicates } from "../src/analysis/counter-scan.js";
import { withFiles } from "./helpers.js";

const modes = ["instructions", "expressions"] as const;
const preamble = `import CompactStandardLibrary;
export ledger owner: Bytes<32>;
export ledger alternate: Bytes<32>;
export ledger publicInput: Bytes<32>;
export ledger stored: Field;
witness secret(): Bytes<32>;
circuit guard(): [] { assert(persistentHash<Bytes<32>>(secret()) == owner, "owner"); }
`;
const peers = `export circuit first(next: Field): [] { guard(); stored = disclose(next); }
export circuit second(next: Field): [] { guard(); stored = disclose(next); }
`;
function compile(file: string): void {
  if (process.env.COMPACTC_TEST) {
    const result = validateWithCompiler(process.env.COMPACTC_TEST, file);
    assert.equal(result.valid, true, result.error);
  }
}
function fixture(source: string, check: (program: Program) => void): void {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact"); compile(file); check(new Program(file, [], directory));
  });
}
function flow(program: Program, engine: typeof modes[number] = "instructions", cached = true, steps = 40000) {
  return new Dataflow(program, steps, 256, 50000, engine, cached, cached, "equivalent-states", false, true, "all-private");
}
function compare(program: Program, expected: string[], inspect?: (facts: AnalysisFacts) => void): void {
  let baseline: unknown;
  for (const engine of modes) for (const cached of [false, true]) {
    const facts = flow(program, engine, cached).analyze();
    const findings = rule.run(facts);
    assert.deepEqual(facts.diagnostics, []);
    assert.deepEqual(facts.completedEntries, program.entries);
    assert.deepEqual(findings.map(finding => finding.metadata.entry).sort(), expected.slice().sort());
    baseline ??= findings; assert.deepEqual(findings, baseline, JSON.stringify({ engine, cached }));
    inspect?.(facts);
  }
}

test("caller convention manifest: compiler-valid positive, corrected and ignored-guard lookalike", () => {
  const manifest = JSON.parse(readFileSync("tests/corpus/manifest.json", "utf8"));
  for (const row of manifest.accessConvention.cases) {
    const file = resolve("tests/corpus", row.file); compile(file);
    compare(new Program(file), row.lines.length ? ["missing"] : []);
    for (const experimentalCounterQueries of [false, true]) {
      const scan = scanFile(file, { experimentalCounterQueries, detectors: [rule.id] });
      assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics));
      assert.deepEqual(scan.findings.filter(finding => finding.detectorId === rule.id).map(finding => finding.location.line), row.lines);
      const defaults = scanFile(file, { experimentalCounterQueries });
      assert.equal(defaults.status, "complete", JSON.stringify(defaults.diagnostics));
      assert.ok(defaults.findings.every(finding => finding.detectorId !== rule.id));
    }
  }
});

test("witness and parameter preimages share a convention; aggregate publicness survives hashing, effects and liveness", () => {
  for (const condition of ["sk == publicInput", "[sk] == [publicInput]"]) for (const late of [false, true]) {
    fixture(`${preamble}
export circuit first(next: Field): [] { guard(); stored = disclose(next); }
export circuit second(next: Field, key: Bytes<32>): [] { assert(persistentHash<Bytes<32>>(key) == owner, "owner"); stored = disclose(next); }
export circuit publicPreimage(next: Field, sk: Bytes<32>): [] {
  ${late ? "" : `assert(${condition}, "public");`}
  const digest = persistentHash<Bytes<32>>(sk);
  assert(digest == owner, "digest"); stored = disclose(next);
  ${late ? `assert(${condition}, "public");` : ""}
}`, program => compare(program, ["publicPreimage"], facts => {
      const path = facts.paths.find(path => facts.program.symbols.get(path.entry)!.name === "publicPreimage")!;
      const evidence = predicateEvidence(path, 10000);
      assert.equal(evidence.complete, true);
      const preimages = evidence.equalities.flatMap(({ equality }) => trustedPreimageSources(equality));
      if (late) assert.equal(preimages.length, 1, "the earlier digest keeps its exact private source");
      assert.ok(preimages.every(source => evidence.publicValues.has(predicateSourceKey(source, path))));
    }));
  }
});

test("alternate keys, parameter inputs, branch checks and atomic late authentication remain quiet", () => {
  fixture(`${preamble}${peers}
export circuit alternateCheck(next: Field, key: Bytes<32>, flag: Boolean): [] {
  stored = disclose(next);
  if (disclose(flag)) { assert(persistentHash<Bytes<32>>(key) == owner, "owner"); }
  else { assert(persistentHash<Bytes<32>>(key) == alternate, "alternate authority"); }
}`, program => compare(program, []));
});

test("branch-local authorization is not a must guard of the unguarded effect history", () => {
  fixture(`${preamble}${peers}
export circuit partial(next: Field, flag: Boolean): [] {
  if (disclose(flag)) { guard(); }
  stored = disclose(next);
}`, program => compare(program, ["partial"]));
});

test("public preimages on a mutually exclusive non-writing history cannot contaminate an authenticated writer", () => {
  fixture(`${preamble}${peers}
export circuit conditional(next: Field, key: Bytes<32>, flag: Boolean): [] {
  if (disclose(flag)) { assert([key] == [publicInput], "public path without a write"); }
  else { assert(persistentHash<Bytes<32>>(key) == owner, "caller"); stored = disclose(next); }
}`, program => compare(program, []));
});

test("ignored comparison and self-written trusted data cannot authenticate", () => {
  for (const guard of ["const ignored = persistentHash<Bytes<32>>(sk) == owner;",
    "owner = disclose(persistentHash<Bytes<32>>(sk)); assert(persistentHash<Bytes<32>>(sk) == owner, \"self\");"]) {
    fixture(`${preamble}${peers}
export circuit missing(next: Field, sk: Bytes<32>): [] { ${guard} stored = disclose(next); }
`, program => compare(program, ["missing"]));
  }
});

test("retained old owner snapshot and unrelated aggregate component preserve real private authentication", () => {
  fixture(`${preamble}${peers}
export circuit snapshot(next: Field, sk: Bytes<32>, unused: Bytes<32>): [] {
  const old = owner; const digest = persistentHash<Bytes<32>>(sk);
  assert([unused] == [publicInput], "different component");
  owner = default<Bytes<32>>;
  assert(digest == old, "old authority"); stored = disclose(next);
}`, program => compare(program, []));
});

test("nested stateful summary replay cannot multiply writers or lose caller/effect sites", () => {
  fixture(`${preamble}${peers}
circuit mutate(next: Field): [] { stored = disclose(next); }
circuit wrapper(next: Field): [] { mutate(next); }
export circuit missing(next: Field): [] { wrapper(next); wrapper(next); }
`, program => compare(program, ["missing"], facts => {
    const finding = rule.run(facts)[0];
    assert.equal(finding.metadata.writerCount, 3);
    assert.equal((finding.metadata.effectCallSites as unknown[]).length, 3);
  }));
});

test("strict majority excludes constructors and dead writers, and requires two distinct guarded entries", () => {
  fixture(`${preamble}${peers}
constructor() { stored = 0 as Field; }
export circuit missing(next: Field): [] { stored = disclose(next); }
export circuit disabled(next: Field): [] { stored = disclose(next); assert(false, "disabled"); }
`, program => compare(program, ["missing"], facts => assert.equal(rule.run(facts)[0].metadata.writerCount, 3)));
  fixture(`${preamble}${peers}
export circuit publicFirst(next: Field): [] { stored = disclose(next); }
export circuit publicSecond(next: Field): [] { stored = disclose(next); }
`, program => compare(program, []));
  fixture(`${preamble}
export circuit first(next: Field): [] { guard(); stored = disclose(next); stored = disclose(next); stored = disclose(next); }
export circuit publicFirst(next: Field): [] { stored = disclose(next); }
export circuit publicSecond(next: Field): [] { stored = disclose(next); }
`, program => compare(program, []));
});

test("an intentional public minority is a documented false-positive shape, never a proven privilege violation", () => {
  fixture(`${preamble}${peers}
// Deliberate application policy: anyone may reset this shared field.
export circuit publicReset(): [] { stored = 0 as Field; }
`, program => compare(program, ["publicReset"], facts => {
    const finding = rule.run(facts)[0];
    assert.equal(finding.confidence, "low");
    assert.equal(finding.metadata.authenticationIntent, "unknown");
    assert.equal(finding.metadata.reviewRequired, true);
  }));
});

test("raw witness conventions remain explicitly weaker than secret-preimage checks", () => {
  fixture(`${preamble}
circuit raw(): [] { assert(secret() == owner, "raw"); }
export circuit first(next: Field): [] { raw(); stored = disclose(next); }
export circuit second(next: Field): [] { raw(); stored = disclose(next); }
export circuit missing(next: Field): [] { stored = disclose(next); }
`, program => compare(program, ["missing"], facts => assert.equal(rule.run(facts)[0].metadata.convention, "raw-witness")));
});

test("a private value mixed with ledger data is not a public preimage", () => {
  fixture(`import CompactStandardLibrary;
export ledger owner: Bytes<32>;
export ledger publicOffset: Field;
export ledger stored: Field;
witness secret(): Field;
circuit guard(): [] { assert(persistentHash<Field>(secret()) == owner, "owner"); }
${peers}
export circuit mixed(next: Field, other: Field): [] {
  const key = secret();
  assert(key == other + publicOffset, "private relation");
  assert(persistentHash<Field>(key) == owner, "owner");
  stored = disclose(next);
}`, program => compare(program, []));
});

test("an actual budget stop before a potential write cannot manufacture a majority", () => {
  fixture(`${preamble}${peers}
witness choice(): Boolean;
circuit burn(value: Field): Field { assert(choice(), "work"); return value; }
export circuit missing(next: Field): [] { stored = disclose(next); }
export circuit incompleteBeforeWrite(next: Field): [] {
  map(burn, default<Vector<64, Field>>); stored = disclose(next);
}`, program => {
    for (const engine of modes) for (const cached of [false, true]) {
      const facts = flow(program, engine, cached, 160).analyze();
      const incomplete = program.entries.find(entry => program.symbols.get(entry)!.name === "incompleteBeforeWrite")!;
      assert.ok(!facts.completedEntries.includes(incomplete));
      assert.ok(!facts.paths.some(path => path.entry === incomplete));
      assert.equal(facts.completedEntries.length, 3);
      assert.deepEqual(rule.run(facts), []);
      assert.ok(facts.diagnostics.some(diagnostic => diagnostic.code === "caller-convention-incomplete"));
    }
  });
});

test("modeled value-moving operations use actual runtime effects", () => {
  fixture(`${preamble}
circuit transferValue(): [] { sendUnshielded(default<Bytes<32>>, 2, left<ContractAddress,UserAddress>(kernel.self())); }
export circuit first(): [] { guard(); transferValue(); }
export circuit second(): [] { guard(); transferValue(); }
export circuit missing(): [] { transferValue(); }
`, program => compare(program, ["missing"], facts => assert.equal(rule.run(facts)[0].metadata.target, "claimUnshieldedCoinSpend")));
});

test("incomplete potential writers block their group even when no write was reached", () => {
  fixture(`${preamble}${peers}
export circuit missing(next: Field): [] { stored = disclose(next); }
export circuit unknown(next: Field): [] { stored = disclose(next); }
`, program => {
    const facts = flow(program).analyzeSubset(program.entries.filter(entry => program.symbols.get(entry)!.name !== "unknown"));
    assert.deepEqual(rule.run(facts), []);
    assert.ok(facts.diagnostics.some(diagnostic => diagnostic.code === "caller-convention-incomplete"));
    const partialScope = new Dataflow(program).analyze();
    assert.deepEqual(rule.run(partialScope), []);
    assert.ok(partialScope.diagnostics.some(diagnostic => diagnostic.code === "predicate-evidence-unavailable"));
    assert.equal(accessTargets(program, 1).complete, false);
    const bounded = flow(program, "instructions", true, 1).analyze();
    assert.deepEqual(rule.run(bounded), []);
    assert.ok(bounded.diagnostics.length > 0);
  });
});

test("predicate decomposition exhaustion returns no partial convention findings", () => {
  fixture(`${preamble}${peers}
export circuit missing(next: Field): [] { stored = disclose(next); }
`, program => {
    const facts = flow(program).analyze();
    const predicate = facts.paths[0].predicates![0];
    for (let i = 0; i < 70; i++) predicate.value = { flows: [], ledger: new Set(), type: "Boolean", negated: predicate.value };
    assert.deepEqual(rule.run(facts), []);
    assert.ok(facts.diagnostics.some(diagnostic => diagnostic.code === "predicate-analysis-budget"));
  });
});

test("unguarded Counter siblings require exact convention evidence; they cannot get a no-witness certificate", () => {
  fixture(`${preamble}
export ledger count: Counter;
export circuit first(): [] { guard(); count.resetToDefault(); }
export circuit second(): [] { guard(); count.increment(1); }
export circuit missing(): [] { count.resetToDefault(); }
`, program => {
    const result = analyzeCounterPredicates(new Dataflow(program), resolvePolicies(program), [rule.id]);
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.deepEqual(result.findings.filter(finding => finding.detectorId === rule.id).map(finding => finding.metadata.entry), ["missing"]);
    assert.equal(result.exact!.facts.predicateScope, "all-private");
    assert.ok(result.coverage.filter(row => row.detector === rule.id).every(row => row.method === "exact"));
    assert.equal(result.certificates.filter(row => row.detector === rule.id).length, 0);
  });
});
