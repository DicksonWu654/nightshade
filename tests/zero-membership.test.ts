import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile, scanFileIsolated } from "../src/index.js";
import { zeroMembershipObservations } from "../src/analysis/zero-membership.js";
import { zeroAmountInitialMembership as rule } from "../src/detectors/zero-membership.js";
import { resolvePolicies, validatePolicies, type Policies } from "../src/policies.js";
import { human, sarif } from "../src/reporting/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const policies: Policies = { zeroAmountMembership: [{ circuit: "run", amount: "amount", map: "balances" }] };
const header = `pragma language_version >= 0.26.0;
import CompactStandardLibrary;
export ledger balances: Map<Bytes<32>, Uint<64>>;
`;
const lookup = `const old = balances.lookup(disclose(key)); balances.insert(disclose(key), disclose((old + amount) as Uint<64>));`;
const entry = (body: string) => `export circuit run(key: Bytes<32>, amount: Uint<64>, other: Bytes<32>): [] { ${body} }`;

function check(body: string, expected: number, incomplete = false, prefix = header) {
  withFiles({ "main.compact": prefix + body }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(file), resolved = resolvePolicies(program, policies), relation = resolved.zeroAmountMembership![0];
    let oracle: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyzeZeroEntry(relation.circuit, relation.amount);
      const findings = (facts.diagnostics.length ? [] : rule.run(facts, resolved)).sort((a, b) => a.fingerprint.localeCompare(b.fingerprint));
      assert.equal(findings.length, expected, JSON.stringify(facts.diagnostics));
      assert.equal(!!facts.diagnostics.length, incomplete, JSON.stringify(facts.diagnostics));
      assert.equal(facts.metrics.statefulSummaryHits, 0); assert.equal(facts.metrics.readSummaryHits, 0);
      for (const finding of findings) {
        assert.equal(finding.severity, "low"); assert.equal(finding.confidence, "high");
        assert.equal(finding.metadata.declaredAmount, "0"); assert.equal(finding.metadata.helperAmountZero, "not-claimed");
        assert.equal(finding.metadata.initiallyMissing, "not-proven");
      }
      const outcome = { findings, codes: facts.diagnostics.map(issue => issue.code) };
      oracle ??= outcome; assert.deepEqual(outcome, oracle, `${engine}/${cached}`);
    }
    const result = scanFile(file, { policies, detectors: [rule.id] });
    assert.equal(result.status, incomplete ? "incomplete" : "complete", JSON.stringify(result.diagnostics));
    assert.equal(result.coverage.baselineStatus, "complete", JSON.stringify(result.diagnostics));
    assert.deepEqual(result.findings.sort((a, b) => a.fingerprint.localeCompare(b.fingerprint)), (oracle as { findings: unknown }).findings);
    assert.ok(result.diagnostics.every(issue => issue.scope?.detectorId === rule.id));
  });
}

test("declared zero requires initial lookup or asserted membership, including saved query before insertion", () => {
  check(entry(lookup), 1);
  check(entry(`assert(balances.member(disclose(key)), "present"); if (disclose(amount) > 0) { ${lookup} }`), 1);
  check(entry(`const was = balances.member(disclose(key)); balances.insertDefault(disclose(key)); assert(was, "initial"); ${lookup}`), 1);
  check(entry(`assert(balances.member(disclose(key)) == true, "present");`), 1);
  check(entry(`assert(!(!balances.member(disclose(key))), "present");`), 1);
  check(entry(`const permit = disclose(other) == pad(32, "permit"); assert(balances.member(disclose(key)) == permit, "relation"); assert(permit, "required");`), 0, true);
});

test("zero bypass, optional lookup, discarded predicate and prior insertion stay quiet", () => {
  check(entry(`if (disclose(amount) > 0) { ${lookup} }`), 0);
  check(entry(`if (balances.member(disclose(key))) { ${lookup} }`), 0);
  check(entry(`const present = balances.member(disclose(key));`), 0);
  check(entry(`balances.insertDefault(disclose(key)); ${lookup}`), 0);
  check(entry(`if (!balances.member(disclose(key))) { balances.insertDefault(disclose(key)); } ${lookup}`), 0);
  check(entry(`assert(balances.member(disclose(key)) || disclose(other) == pad(32, "bypass"), "optional");`), 0);
});

test("helper arguments keep their actual offsets and repeated zero/nonzero invocation operands", () => {
  const helper = `circuit consume(key: Bytes<32>, amount: Uint<64>): [] { ${lookup} }`;
  check(helper + entry(`consume(key, (amount + 1) as Uint<64>); consume(key, amount);`), 1);
  check(helper + entry(`consume(key, 1);`), 1);
  check(helper + entry(`consume(key, disclose(amount)); consume(other, 1);`), 0, true);
  check(`circuit readOnly(key: Bytes<32>, amount: Uint<64>): [] { const old = balances.lookup(disclose(key)); }`
    + entry(`readOnly(key, amount); readOnly(other, 1);`), 2);
  check(`circuit consume(key: Bytes<32>, amount: Uint<64>): [] { if (disclose(amount) > 0) { ${lookup} } }` + entry(`consume(key, amount);`), 0);
});

test("nested Maps retain outer and inner dependencies and distinguish local setup", () => {
  const nested = header.replace("Map<Bytes<32>, Uint<64>>", "Map<Bytes<32>, Map<Bytes<32>, Uint<64>>>");
  check(entry(`const old = balances.lookup(disclose(key)).lookup(disclose(other));`), 2, false, nested);
  check(entry(`balances.lookup(disclose(key)).insertDefault(disclose(other)); const old = balances.lookup(disclose(key)).lookup(disclose(other));`), 1, false, nested);
  check(entry(`balances.insertDefault(disclose(key)); balances.lookup(disclose(key)).insertDefault(disclose(other)); const old = balances.lookup(disclose(key)).lookup(disclose(other));`), 0, false, nested);
  const nestedSet = header.replace("Map<Bytes<32>, Uint<64>>", "Map<Bytes<32>, Set<Bytes<32>>>");
  check(entry(`assert(balances.lookup(disclose(key)).member(disclose(other)), "set member");`), 1, false, nestedSet);
  check(entry(`const was = balances.lookup(disclose(key)).member(disclose(other)); balances.insertDefault(disclose(key)); assert(was, "old inner");`), 2, false, nested);
  check(entry(`const was = balances.lookup(disclose(key)).member(disclose(other)); balances.insertDefault(disclose(key)); assert(was, "old inner"); const old = balances.lookup(disclose(key)).lookup(disclose(other));`), 0, true, nested);
  check(entry(`balances.resetToDefault(); balances.insertDefault(disclose(key)); balances.lookup(disclose(key)).insertDefault(disclose(other)); const old = balances.lookup(disclose(key)).lookup(disclose(other));`), 0, false, nested);
  const counter = header.replace("Map<Bytes<32>, Uint<64>>", "Map<Bytes<32>, Counter>");
  check(entry(`balances.lookup(disclose(key)).increment(1); assert(balances.member(disclose(key)), "still present");`), 1, false, counter);
  check(entry(`assert(balances.member(disclose(key)), "Field zero");`).replace("amount: Uint<64>", "amount: Field"), 1);
});

test("may-alias writes and stale membership cannot establish a current lookup origin", () => {
  check(entry(`balances.insertDefault(disclose(other)); ${lookup}`), 0, true);
  check(entry(`const was = balances.member(disclose(key)); balances.remove(disclose(other)); assert(was, "old"); ${lookup}`), 0, true);
  check(entry(`balances.remove(disclose(key)); ${lookup}`), 0, true);
  check(entry(`balances.resetToDefault(); ${lookup}`), 0, true);
  check(entry(`balances.resetToDefault(); balances.insertDefault(disclose(key)); ${lookup}`), 0);
  check(entry(`balances.insertDefault(pad(32, "unrelated")); const old = balances.lookup(pad(32, "selected"));`), 1);
});

test("direct nonzero guards certify a zero rejection only when ordinary invocations survive", () => {
  check(entry(`assert(amount > 0, "nonzero"); ${lookup}`), 0);
  check(entry(`assert(0 < disclose(amount), "nonzero"); ${lookup}`), 0);
  check(entry(`assert(amount > 0, "nonzero"); assert(false, "unrelated failure");`), 0, true);
  check(entry(`assert(false, "unrelated failure"); ${lookup}`), 0, true);
  check(entry(`assert(amount > 0, "nonzero"); assert(amount == 0, "contradiction");`), 0, true);
  check(entry(`assert((amount * 0) > 0, "vacuous"); ${lookup}`), 0, true);
  check(entry(`kernel.checkpoint(); assert(amount > 0, "nonzero");`), 0, true);
});

test("other no-zero-success and reached checkpoints stay rule-scoped unavailable", () => {
  check(entry(`kernel.checkpoint(); ${lookup}`), 0, true);
  check(entry(`${lookup} kernel.checkpoint();`), 0, true);
});

test("zero specialization never changes ordinary analysis or silently selects a helper", () => {
  withFiles({ "main.compact": header + `circuit hidden(amount: Uint<64>): [] {}` + entry(lookup) }, directory => {
    const file = resolve(directory, "main.compact"), program = new Program(file), relation = resolvePolicies(program, policies).zeroAmountMembership![0];
    const flow = new Dataflow(program), before = new Dataflow(program).analyze();
    flow.analyzeZeroEntry(relation.circuit, relation.amount);
    assert.deepEqual(flow.analyze(), new Dataflow(program).analyze());
    assert.equal(before.zeroEntry, undefined);
    const ordinary = new Dataflow(program).analyze();
    assert.equal(zeroMembershipObservations(ordinary, resolvePolicies(program, policies)).observations.length, 0);
    assert.throws(() => flow.analyzeZeroEntry(program.activeSymbols().find(symbol => symbol.name === "hidden")!.id, relation.amount), /exported/);
    assert.equal(scanFile(file).findings.some(finding => finding.detectorId === rule.id), false);
    assert.equal(scanFile(file, { detectors: [rule.id] }).status, "complete");
    assert.equal(scanFile(file, { detectors: [rule.id] }).findings.length, 0);
  });
});

test("bounded consumer, paths and values cannot turn unavailable zero evidence into clean", () => {
  withFiles({ "main.compact": header + entry(`if (disclose(other) == pad(32, "branch")) { balances.insertDefault(disclose(key)); } ${lookup}`) }, directory => {
    const file = resolve(directory, "main.compact"), program = new Program(file), resolved = resolvePolicies(program, policies), relation = resolved.zeroAmountMembership![0];
    const facts = new Dataflow(program).analyzeZeroEntry(relation.circuit, relation.amount);
    facts.zeroEntry!.maxSteps = facts.metrics.steps;
    const observation = zeroMembershipObservations(facts, resolved);
    assert.equal(observation.observations.length, 0); assert.equal(observation.diagnostics[0].code, "zero-membership-unavailable");
    for (const limits of [{ maxSteps: 2 }, { maxValues: 2 }, { maxPaths: 1 }]) {
      const report = scanFile(file, { policies, detectors: [rule.id], ...limits });
      assert.equal(report.status, "incomplete"); assert.deepEqual(report.findings, []);
    }
  });
});

test("policy schema rejects ambiguity, helpers, nonnumeric inputs and invalid Map selection", () => {
  withFiles({ "main.compact": header + `export ledger scalar: Field; circuit hidden(amount: Uint<64>): [] {}` + entry(lookup) }, directory => {
    const program = new Program(resolve(directory, "main.compact")), location = program.rootSource.ast.span;
    assert.deepEqual(validatePolicies(policies, location), policies);
    assert.equal(resolvePolicies(program, { zeroAmountMembership: [...policies.zeroAmountMembership!, ...policies.zeroAmountMembership!] }).zeroAmountMembership!.length, 1);
    for (const invalid of [{ zeroAmountMembership: [{}] }, { zeroAmountMembership: Array(1) }, { zeroAmountMembership: Array(65).fill(policies.zeroAmountMembership![0]) }, { zeroAmountMembership: [{ ...policies.zeroAmountMembership![0], map: "" }] }])
      assert.throws(() => validatePolicies(invalid, location));
    for (const override of [{ circuit: "hidden" }, { amount: "other" }, { map: "scalar" }, { map: "missing" }])
      assert.throws(() => resolvePolicies(program, { zeroAmountMembership: [{ ...policies.zeroAmountMembership![0], ...override }] }));
  });
});

test("missing snapshots, wrong epochs and multiple zero policies never erase unavailable evidence", () => {
  const source = header + entry(lookup).replace("other: Bytes<32>", "other: Bytes<32>, fee: Uint<64>");
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact"), program = new Program(file), resolved = resolvePolicies(program, policies), relation = resolved.zeroAmountMembership![0];
    for (const malformed of ["missing-key", "wrong-epoch", "bad-position"]) {
      const facts = new Dataflow(program).analyzeZeroEntry(relation.circuit, relation.amount);
      const lookup = facts.paths[0].operations!.find(operation => operation.kind === "map-lookup")!;
      if (malformed === "missing-key") lookup.membership!.key = undefined;
      if (malformed === "wrong-epoch") lookup.membership!.revision++;
      if (malformed === "bad-position") lookup.writesBefore = NaN;
      const observed = zeroMembershipObservations(facts, resolved);
      assert.deepEqual(observed.observations, []); assert.equal(observed.diagnostics[0].code, "zero-membership-unavailable");
    }
    const multiple = { zeroAmountMembership: [...policies.zeroAmountMembership!, { circuit: "run", amount: "fee", map: "balances" }] };
    const report = scanFile(file, { policies: multiple, detectors: [rule.id] });
    assert.equal(report.status, "complete"); assert.equal(report.findings.length, 2);
    const first = new Dataflow(program).analyzeZeroEntry(relation.circuit, relation.amount); rule.run(first, resolved);
    const baselineSteps = report.metrics.steps - report.ruleObservationWork!.reduce((sum, work) => sum + work.metrics.steps, 0);
    const constrained = scanFile(file, { policies: multiple, detectors: [rule.id], maxSteps: Math.max(first.metrics.steps, baselineSteps) + 1 });
    assert.equal(constrained.coverage.baselineStatus, "complete"); assert.equal(constrained.status, "incomplete");
    assert.equal(constrained.coverage.rules!.find(row => row.detectorId === rule.id)!.status, "incomplete");
    assert.ok(constrained.diagnostics.every(issue => issue.scope?.detectorId === rule.id));
    assert.match(human(constrained), /incomplete/i); assert.ok(sarif(constrained));
  });
});

test("owned real Counter positive/corrected/lookalike seed and JSON/SARIF/human coverage", () => {
  const manifest = JSON.parse(readFileSync("tests/corpus/known-bugs.json", "utf8")).cases.find((seed: { detector: string }) => seed.detector === rule.id);
  for (const [file, lines] of [[manifest.file, manifest.expectedLines], [manifest.corrected, []], [manifest.lookalike, []]]) {
    const filename = resolve("tests/corpus", file);
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, filename); assert.equal(compiled.valid, true, compiled.error);
    }
    const result = scanFile(filename, { policies: manifest.policies, detectors: [rule.id] });
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.deepEqual(result.findings.map(finding => finding.location.line), lines);
    assert.ok(result.coverage.rules!.every(row => row.status !== "incomplete"));
    assert.match(human(result, { verbose: true }), /zero-amount-initial-membership/);
    assert.ok(sarif(result));
  }
});

test("zero Map policy keeps its static contract on pinned historical and newer profiles", () => {
  const profiles = [["0.30.0", process.env.COMPACTC_030_TEST], ["0.31.1", process.env.COMPACTC_031_TEST],
    ["0.33.0-rc.2", process.env.COMPACTC_033_RC2_TEST], ["0.35.0", process.env.COMPACTC_035_TEST]] as const;
  for (const [version, compiler] of profiles) for (const kind of ["positive", "corrected", "lookalike"]) {
    const file = resolve(`tests/corpus/known-bugs/counter-zero-membership-${kind}.compact`);
    if (compiler) { const compiled = validateWithCompiler(compiler, file, [], 30000, 2, version); assert.equal(compiled.valid, true, compiled.error); }
    const selected: Policies = { zeroAmountMembership: [{ circuit: "credit", amount: "amount", map: "balances" }] };
    const report = scanFile(file, { compilerVersion: version, policies: selected, detectors: [rule.id] });
    assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
    assert.deepEqual(report.findings.map(finding => finding.location.line), kind === "positive" ? [31] : []);
  }
});


test("owned nested allowance boundary agrees through selected and supervised APIs", async () => {
  const selected: Policies = { zeroAmountMembership: [{ circuit: "spend", amount: "amount", map: "allowances" }] };
  for (const kind of ["positive", "corrected", "lookalike"] as const) {
    const file = resolve(`tests/corpus/synthetic-regressions/state16/zero-amount-initial-membership-case-3-${kind}.compact`);
    const direct = scanFile(file, { policies: selected, detectors: [rule.id] });
    assert.equal(direct.status, "complete", JSON.stringify(direct.diagnostics));
    assert.deepEqual(direct.findings.map(finding => finding.location.line), kind === "positive" ? [11, 12] : []);
    const worker = await scanFileIsolated(file, { policies: selected, detectors: [rule.id] });
    assert.equal(worker.status, direct.status); assert.deepEqual(worker.findings, direct.findings);
    assert.deepEqual(worker.coverage, direct.coverage);
    if (kind === "lookalike") {
      const program = new Program(file), relation = resolvePolicies(program, selected).zeroAmountMembership![0];
      for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
        const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyzeZeroEntry(relation.circuit, relation.amount);
        assert.equal(facts.paths.length, 0); assert.equal(facts.failedAssertions.length, 1);
        assert.equal(facts.failedAssertions[0].location.line, 13);
        assert.equal(facts.zeroEntry!.rejection?.kind, "direct-nonzero-input");
        assert.ok(facts.zeroEntry!.rejection!.ordinarySuccesses > 0);
        assert.deepEqual(zeroMembershipObservations(facts, resolvePolicies(program, selected)).diagnostics, []);
        facts.completedEntries = [];
        assert.equal(zeroMembershipObservations(facts, resolvePolicies(program, selected)).diagnostics[0].code, "zero-membership-unavailable");
      }
    }
  }
});


test("zero rejection never certifies exhausted ordinary evidence or a missing failure", () => {
  withFiles({ "main.compact": header + entry(`assert(amount > 0, "nonzero"); ${lookup}`) }, directory => {
    const file = resolve(directory, "main.compact"), program = new Program(file), resolved = resolvePolicies(program, policies);
    const relation = resolved.zeroAmountMembership![0];
    const facts = new Dataflow(program).analyzeZeroEntry(relation.circuit, relation.amount);
    assert.ok(facts.zeroEntry!.rejection);
    facts.failedAssertions = [];
    assert.equal(zeroMembershipObservations(facts, resolved).diagnostics[0].code, "zero-membership-unavailable");
    for (const limits of [{ maxSteps: facts.metrics.steps - 1 }, { maxValues: facts.metrics.abstractValues - 1 }]) {
      const result = scanFile(file, { policies, detectors: [rule.id], ...limits });
      assert.equal(result.status, "incomplete"); assert.deepEqual(result.findings, []);
    }
  });
});
