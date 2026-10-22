import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { readFileSync } from "node:fs";
import { Dataflow, Program, scanFile, atomicUpdateObservations } from "../src/index.js";
import { resolvePolicies, validatePolicies, type Policies } from "../src/policies.js";
import { checkpointSplitsAtomicUpdate as rule } from "../src/detectors/atomic-updates.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const policies: Policies = { atomicUpdates: [{ circuit: "entry", ledgers: ["primary", "mirror"] }] };
const declarations = "import CompactStandardLibrary; export ledger primary: Field; export ledger mirror: Field; export ledger padding: Field;\n";
function fixture(body: string, inspect: (program: Program, file: string) => void, extras = ""): void {
  withFiles({ "main.compact": declarations + extras + `\nexport circuit entry(value: Field, flag: Boolean): [] { ${body} }` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    inspect(new Program(file), file);
  });
}
function factsFor(program: Program, engine: "instructions" | "expressions", cached: boolean, steps = 40000, values = 50000) {
  const entry = program.entries.find(id => program.symbols.get(id)!.name === "entry")!;
  return new Dataflow(program, steps, 256, values, engine, cached, cached,
    "equivalent-states", false, false, "all", false, false, false, false).analyzeAtomicUpdateEntry(entry);
}
function agreement(program: Program, reasons: string[]) {
  const selected = resolvePolicies(program, policies);
  let oracle: unknown;
  for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
    const facts = factsFor(program, engine, cached);
    assert.deepEqual(facts.diagnostics, []);
    const observed = rule.run(facts, selected);
    assert.deepEqual(facts.diagnostics, []);
    assert.deepEqual(observed.map(item => item.metadata.reason).sort(), reasons.sort());
    assert.ok(observed.every(item => item.severity === "low" && item.confidence === "high"));
    oracle ??= observed; assert.deepEqual(observed, oracle, `${engine}/${cached}`);
  }
}

test("declared Cell co-update reports the checkpoint boundary without changing default selection", () => {
  fixture("primary=disclose(value);kernel.checkpoint();mirror=disclose(value);", (program, file) => {
    agreement(program, ["partial-group-prefix"]);
    const report = scanFile(file, { detectors: [rule.id], policies });
    assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
    assert.equal(report.findings.length, 1);
    assert.ok(report.coverage.rules!.every(row => row.status === "complete"));
    const normal = scanFile(file);
    assert.ok(!normal.findings.some(item => item.detectorId === rule.id));
    assert.ok(!normal.coverage.detectors.includes(rule.id));
    const noPolicy = scanFile(file, { detectors: [rule.id] });
    assert.equal(noPolicy.findings.length, 0);
    assert.ok(noPolicy.coverage.rules!.every(row => row.status === "not-applicable"));
  });
});

test("co-written corrections, unrelated staged writes and unreached boundaries stay quiet", () => {
  for (const body of [
    "primary=disclose(value);mirror=disclose(value);kernel.checkpoint();",
    "primary=disclose(value);mirror=disclose(value);kernel.checkpoint();padding=disclose(value);",
    "kernel.checkpoint();primary=disclose(value);mirror=disclose(value);",
    "primary=disclose(value);mirror=disclose(value);if(false){kernel.checkpoint();}",
    "primary=disclose(value);mirror=disclose(value);",
    // No complete co-update on this history; not an always-write-all policy.
    "primary=disclose(value);kernel.checkpoint();padding=disclose(value);",
  ]) fixture(body, program => agreement(program, []));
});

test("mutually exclusive writes never manufacture a complete co-update", () => {
  fixture("if(disclose(flag)){primary=disclose(value);kernel.checkpoint();}else{kernel.checkpoint();mirror=disclose(value);}", program => agreement(program, []));
});

test("grouped findings retain alternate write sites and guards as separate real routes", () => {
  fixture("primary=disclose(value);kernel.checkpoint();if(disclose(flag)){mirror=3 as Field;}else{mirror=4 as Field;}", program => {
    agreement(program, ["partial-group-prefix"]);
    const observed = rule.run(factsFor(program, "instructions", true), resolvePolicies(program, policies));
    const routes = observed[0].metadata.invocationSites as { writes: { ledger: string; location: { start: number } }[]; predicates: { truth: boolean }[] }[];
    assert.equal(routes.length, 2);
    const mirror = program.activeSymbols().find(symbol => symbol.kind === "ledger" && symbol.name === "mirror")!.id;
    assert.equal(new Set(routes.map(route => route.writes.find(write => write.ledger === mirror)!.location.start)).size, 2);
    assert.deepEqual(routes.map(route => route.predicates.at(-1)!.truth).sort(), [false, true]);
    assert.equal(observed[0].metadata.historyGrouping, "alternative-linked-histories");
  });
});

test("repeated writes distinguish mixed final revisions and retain early partial groups", () => {
  fixture("primary=disclose(value);mirror=disclose(value);kernel.checkpoint();primary=7 as Field;", program => agreement(program, ["mixed-final-write-prefix"]));
  fixture("primary=disclose(value);kernel.checkpoint();primary=7 as Field;mirror=disclose(value);", program => agreement(program, ["partial-group-prefix"]));
  fixture("primary=disclose(value);mirror=disclose(value);kernel.checkpoint();primary=7 as Field;mirror=8 as Field;", program => agreement(program, []));
});

test("equal committed outcomes retain both physical boundaries and helper occurrences", () => {
  fixture("primary=disclose(value);kernel.checkpoint();kernel.checkpoint();mirror=disclose(value);", program => {
    agreement(program, ["partial-group-prefix", "partial-group-prefix"]);
    const facts = factsFor(program, "instructions", true);
    assert.equal(facts.paths.length, 2); // Existing flat outcome deduplication is preserved.
    const full = facts.paths.find(path => path.checkpointOutcomes)!;
    assert.deepEqual(full.checkpointOutcomes!.map(item => item.ordinal), [0, 1]);
    assert.notEqual(full.checkpointOutcomes![0].location.start, full.checkpointOutcomes![1].location.start);
    assert.deepEqual(full.checkpointOutcomes![0].history.writes, full.checkpointOutcomes![1].history.writes);
  });
  fixture("primary=disclose(value);mark();mark();mirror=disclose(value);", program => {
    agreement(program, ["partial-group-prefix"]);
    const findings = rule.run(factsFor(program, "instructions", true), resolvePolicies(program, policies));
    const invocations = findings[0].metadata.invocationSites as { ordinal: number; callSites: { start: number }[] }[];
    assert.deepEqual(invocations.map(item => item.ordinal), [0, 1]);
    assert.notDeepEqual(invocations[0].callSites, invocations[1].callSites);
  }, "circuit mark():[]{kernel.checkpoint();}");
});

test("full-proof witness guards survive prefix linkage; unprovable continuations supply no prefixes", () => {
  fixture('primary=disclose(value);mark();assert(disclose(authorized()),"proof gate");mirror=disclose(value);', program => {
    agreement(program, ["partial-group-prefix"]);
    const facts = factsFor(program, "instructions", true), full = facts.paths.find(path => path.checkpointOutcomes)!;
    assert.deepEqual(full.checkpointOutcomes![0].history.predicates, full.predicates);
    assert.ok(full.predicates!.some(predicate => predicate.value.flows.some(flow => flow.source.kind === "witness")));
  }, "witness authorized():Boolean;circuit mark():[]{kernel.checkpoint();}");
  fixture('primary=disclose(value);kernel.checkpoint();assert(false,"cannot prove");mirror=disclose(value);', program => {
    agreement(program, []); assert.deepEqual(factsFor(program, "instructions", true).paths, []);
  });
});

test("native namesakes and zero-iteration callback boundaries do not create prefixes", () => {
  fixture("primary=disclose(value);fake_checkpoint();mirror=disclose(value);", program => agreement(program, []),
    "module Fake{export circuit checkpoint():[]{return [];}}import Fake prefix fake_;");
  fixture("primary=disclose(value);map(mark,default<Vector<0,Field>>);mirror=disclose(value);", program => agreement(program, []),
    "circuit mark(value:Field):Field{kernel.checkpoint();return value;}");
  fixture("primary=disclose(value);map(mark,[1 as Field,2 as Field]);mirror=disclose(value);", program => agreement(program, ["partial-group-prefix"]),
    "circuit mark(value:Field):Field{kernel.checkpoint();return value;}");
});

test("missing exact evidence, truncated links and exhausted allowances never certify a clean rule result", () => {
  fixture("primary=disclose(value);kernel.checkpoint();mirror=disclose(value);", (program, file) => {
    const selected = resolvePolicies(program, policies), ordinary = new Dataflow(program).analyze();
    assert.equal(atomicUpdateObservations(ordinary, selected).diagnostics[0].code, "atomic-update-evidence-unavailable");
    const exhausted = factsFor(program, "instructions", true, 1);
    assert.ok(exhausted.diagnostics.some(issue => issue.code === "analysis-budget"));
    assert.equal(atomicUpdateObservations(exhausted, selected).observations.length, 0);
    const facts = factsFor(program, "instructions", true);
    const missing = factsFor(program, "instructions", true);
    delete missing.paths.find(path => path.checkpointOutcomes)!.checkpointOutcomes;
    assert.equal(atomicUpdateObservations(missing, selected).diagnostics[0].code, "atomic-update-evidence-unavailable");
    const truncated = factsFor(program, "instructions", true);
    truncated.paths.find(path => path.checkpointOutcomes)!.checkpointOutcomes!.length = 0;
    assert.equal(atomicUpdateObservations(truncated, selected).diagnostics[0].code, "atomic-update-evidence-unavailable");
    const ordinal = factsFor(program, "instructions", true);
    ordinal.paths.find(path => path.checkpointOutcomes)!.checkpointOutcomes![0].ordinal = 1;
    assert.equal(atomicUpdateObservations(ordinal, selected).diagnostics[0].code, "atomic-update-evidence-unavailable");
    facts.checkpointEvidence!.maxSteps = facts.metrics.steps;
    assert.equal(atomicUpdateObservations(facts, selected).diagnostics[0].code, "atomic-update-evidence-unavailable");
    const report = scanFile(file, { detectors: [rule.id], policies, maxValues: 1 });
    assert.equal(report.status, "incomplete");
    assert.ok(report.diagnostics.length);
    assert.ok(report.coverage.rules!.some(row => row.status === "incomplete"));
  });
});

test("policy groups resolve distinct ordinary Cells and reject malformed or ADT selectors", () => {
  fixture("primary=disclose(value);mirror=disclose(value);", program => {
    const selected = resolvePolicies(program, policies);
    assert.equal(new Set(selected.atomicUpdates![0].ledgers).size, 2);
    assert.equal(resolvePolicies(program, { atomicUpdates: [...policies.atomicUpdates!, { circuit: "entry", ledgers: ["mirror", "primary"] }] }).atomicUpdates!.length, 1);
    for (const ledgers of [["primary"], ["primary", "primary"], ["primary", "typo"], ["primary", "counter"]])
      assert.throws(() => resolvePolicies(program, { atomicUpdates: [{ circuit: "entry", ledgers }] }));
    assert.throws(() => validatePolicies({ atomicUpdates: [{ circuit: "entry", ledgers: ["primary", "primary"] }] }, program.rootSource.ast.span));
    assert.deepEqual(validatePolicies(policies, program.rootSource.ast.span), policies);
  }, "ledger counter:Counter;");
});

test("realistic owned Counter positive/corrected/lookalike triples are compiler-valid", () => {
  for (const kind of ["positive", "corrected", "lookalike"]) {
    const file = resolve(`tests/corpus/known-bugs/counter-checkpoint-atomic-${kind}.compact`);
    assert.match(readFileSync(file, "utf8"), /round.increment\(1\)/);
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const report = scanFile(file, { detectors: [rule.id], policies: { atomicUpdates: [{ circuit: "increment", ledgers: ["primary", "mirror"] }] } });
    assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
    assert.deepEqual(report.findings.map(item => item.location.line), kind === "positive" ? [32] : []);
  }
});
