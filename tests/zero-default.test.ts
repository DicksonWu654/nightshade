import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile } from "../src/index.js";
import { exactMapDebits, mapDebitAmountCandidates } from "../src/dataflow/map-debit.js";
import { initialMapRequirements } from "../src/dataflow/zero-membership.js";
import { zeroDefaultGetterCertificate } from "../src/dataflow/zero-default.js";
import { zeroDefaultScope } from "../src/semantic/zero-default-targets.js";
import { observeZeroDefault } from "../src/analysis/zero-default-observation.js";
import { zeroDefaultGetterMembershipReview as rule } from "../src/detectors/zero-default.js";
import { withFiles } from "./helpers.js";

const fixture = (name: string) => resolve(`tests/corpus/drafts/allowance42/${name}.compact`);
const frozen = (name: string) => resolve(`tests/corpus/synthetic-regressions/state16/zero-amount-initial-membership-case-3-${name}.compact`);

test("owned single/nested missing-zero getter triplets retain the source obligation", () => {
  for (const name of ["direct-positive", "nested-positive", "key-depth-mismatch"]) {
    const result = scanFile(fixture(name), { detectors: [rule.id] });
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].severity, "info");
    assert.equal(result.findings[0].metadata.applicationPolicy, "not-inferred");
    assert.equal(result.findings[0].metadata.crossInvocationEquality, "not-claimed");
    assert.ok((result.findings[0].metadata.sourceKeyBinding as unknown[]).length >= 1);
    assert.equal(scanFile(fixture(name)).findings.some(finding => finding.detectorId === rule.id), false);
  }
  for (const name of ["direct-corrected", "nested-corrected", "direct-zero-rejection", "nested-zero-rejection", "all-zero-bypass",
    "same-name-unrelated-roots", "unrelated-root", "helper-composition", "getter-rejects-absence", "nonzero-fallback", "nested-nonzero-inner-fallback",
    "wrong-member-key", "wrong-fallback-key", "wrong-inner-member-key", "inner-constant-key"]) {
    const result = scanFile(fixture(name), { detectors: [rule.id] });
    assert.equal(result.status, "complete", `${name}: ${JSON.stringify(result.diagnostics)}`);
    assert.equal(result.findings.length, 0, name);
  }
  for (const [name, expected] of [["positive", 1], ["corrected", 0], ["lookalike", 0]] as const) {
    const result = scanFile(frozen(name), { detectors: [rule.id] });
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.equal(result.findings.length, expected);
  }
});

test("exact certificates agree across instruction/reference and cached/uncached execution", () => {
  const program = new Program(frozen("positive"));
  const getter = program.entries.find(id => program.symbols.get(id)?.name === "allowance")!;
  const spender = program.entries.find(id => program.symbols.get(id)?.name === "spend")!;
  let reference: unknown;
  for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
    const flow = new Dataflow(program, 40000, 256, 50000, engine, cached, cached);
    const getterFacts = flow.analyzeMapDebitCandidates(getter);
    const certificate = zeroDefaultGetterCertificate(getterFacts, getter);
    assert.ok(certificate, `${engine}/${cached}`);
    const ordinary = flow.analyzeMapDebitCandidates(spender);
    const amounts = mapDebitAmountCandidates(ordinary, spender, 40000 - ordinary.metrics.steps);
    assert.equal(amounts.length, 1);
    const facts = flow.analyzeZeroMapDebitEntry(spender, amounts[0]);
    facts.zeroDefaultEvidence = { getters: [certificate] };
    assert.deepEqual(facts.diagnostics, []);
    const findings = rule.run(facts);
    assert.equal(findings.length, 1, JSON.stringify(facts.diagnostics));
    assert.deepEqual(facts.diagnostics, []);
    reference ??= findings;
    assert.deepEqual(findings, reference, `${engine}/${cached}`);
    assert.deepEqual(rule.run(new Dataflow(program).analyzeSubset([spender])), []);
  }
});

const header = `pragma language_version >= 0.26.0; import CompactStandardLibrary;
export ledger values: Map<Bytes<32>, Uint<64>>;
export circuit get(key: Bytes<32>): Uint<64> {
 if (values.member(disclose(key))) return values.lookup(disclose(key));
 return 0 as Uint<64>;
}`;
const decrement = `const prior = values.lookup(disclose(key));
values.insert(disclose(key), disclose((prior - disclose(amount)) as Uint<64>));`;

test("full zero bypass and supplied membership cannot certify initial membership", () => {
  for (const body of [`if (disclose(flag)) return; assert(values.member(disclose(key)), "member"); ${decrement}`,
    `values.insert(disclose(key), 1 as Uint<64>); ${decrement}`,
    `assert(values.member(disclose(key)), "member"); const prior = values.lookup(disclose(key)); values.insert(disclose(other), disclose((prior - disclose(amount)) as Uint<64>));`]) {
    withFiles({ "main.compact": `${header} export circuit spend(key: Bytes<32>, other: Bytes<32>, amount: Uint<64>, flag: Boolean): [] { ${body} }` }, directory => {
      const result = scanFile(resolve(directory, "main.compact"), { detectors: [rule.id] });
      assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
      assert.equal(result.findings.length, 0);
    });
  }
});

test("lost membership evidence and shared budgets remain incomplete", () => {
  const program = new Program(frozen("positive"));
  const getter = program.entries.find(id => program.symbols.get(id)?.name === "allowance")!;
  const spender = program.entries.find(id => program.symbols.get(id)?.name === "spend")!;
  const certificate = zeroDefaultGetterCertificate(new Dataflow(program).analyzeMapDebitCandidates(getter), getter)!;
  const amount = program.functions.get(spender)!.declaration.parameters.find(parameter => parameter.name === "amount")!.symbol!;
  const facts = new Dataflow(program).analyzeZeroMapDebitEntry(spender, amount);
  facts.zeroDefaultEvidence = { getters: [certificate] };
  facts.paths[0].predicates = undefined;
  assert.deepEqual(rule.run(facts), []);
  assert.ok(facts.diagnostics.some(diagnostic => diagnostic.code === "zero-default-evidence-unavailable"));
  for (const maxSteps of [25, 250]) {
    const result = scanFile(frozen("positive"), { detectors: [rule.id], maxSteps });
    assert.equal(result.status, "incomplete");
    assert.equal(result.findings.length, 0);
    assert.ok(result.diagnostics.length);
    assert.ok(result.coverage.rules?.some(row => row.detectorId === rule.id && row.status === "incomplete"));
  }
});

test("an unrelated ordered getter condition cannot establish absent-to-zero semantics", () => {
  const gated = header.replace("get(key: Bytes<32>)", "get(key: Bytes<32>, gate: Uint<64>)")
    .replace("return 0 as Uint<64>;", "assert(disclose(gate) > 0, \"gate\"); return 0 as Uint<64>;");
  withFiles({ "main.compact": `${gated} export circuit spend(key: Bytes<32>, amount: Uint<64>): [] {
 assert(values.member(disclose(key)), "member"); ${decrement} }` }, directory => {
    const result = scanFile(resolve(directory, "main.compact"), { detectors: [rule.id] });
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.equal(result.findings.length, 0);
  });
});

test("existing explicit membership policy retains its own independent evidence", () => {
  const options = { policies: { zeroAmountMembership: [{ circuit: "spend", amount: "amount", map: "allowances" }] } };
  const existing = scanFile(frozen("positive"), { ...options, detectors: ["zero-amount-initial-membership"] });
  const combined = scanFile(frozen("positive"), { ...options, detectors: ["zero-amount-initial-membership", rule.id] });
  assert.equal(existing.status, "complete"); assert.equal(combined.status, "complete");
  assert.deepEqual(combined.findings.filter(finding => finding.detectorId === "zero-amount-initial-membership"), existing.findings);
  assert.equal(combined.findings.filter(finding => finding.detectorId === rule.id).length, 1);
});

test("preparation retention exhausts its shared value budget before observing entries", () => {
  const program = new Program(fixture("nested-positive"));
  const plan = zeroDefaultScope(program);
  assert.equal(plan.complete, true);
  assert.ok(plan.values > plan.getters.length + plan.spenders.length);
  for (const maxValues of [1, plan.values - 1, plan.values]) {
    const observed = observeZeroDefault(program, rule, { maxValues });
    assert.deepEqual(observed.findings, []);
    assert.equal(observed.work.metrics.sources, 0);
    assert.ok(observed.work.metrics.abstractValues > maxValues);
    assert.ok(observed.diagnostics.some(issue => issue.code === "zero-default-preparation-values"));
    assert.ok(observed.coverage.every(row => row.status === "incomplete" && row.evidence === "unavailable"));
  }
  const ordinary = observeZeroDefault(program, rule, {});
  assert.deepEqual(ordinary.diagnostics, []);
  assert.equal(ordinary.findings.length, 1);
  assert.ok(ordinary.work.metrics.abstractValues >= plan.values);
});

test("pattern/prefix/certificate value boundaries account every retained dimension", () => {
  let priorCost = 0;
  for (const name of ["direct-positive", "nested-positive"]) {
    const program = new Program(fixture(name));
    const getter = program.entries.find(id => program.symbols.get(id)?.name === "allowance")!;
    const ordinary = new Dataflow(program).analyzeMapDebitCandidates(getter);
    const startingValues = ordinary.metrics.abstractValues;
    const certificate = zeroDefaultGetterCertificate(ordinary, getter);
    assert.ok(certificate);
    const retained = ordinary.metrics.abstractValues - startingValues;
    assert.ok(retained > priorCost); priorCost = retained;
    for (const [additional, success] of [[retained - 1, false], [retained, true]] as const) {
      const tight = new Dataflow(program).analyzeMapDebitCandidates(getter);
      tight.mapDebitEvidence!.maxValues = tight.metrics.abstractValues + additional;
      if (success) assert.deepEqual(zeroDefaultGetterCertificate(tight, getter), certificate);
      else assert.throws(() => zeroDefaultGetterCertificate(tight, getter), /shared work\/value allowance/);
      assert.equal(tight.metrics.abstractValues, ordinary.metrics.abstractValues);
    }
  }
});

test("selected initialRequirements exclude distinct same-root gates and retain implicit lookup evidence", () => {
  const metadataFile = (name: string) => fixture(`metadata-cases/${name}`);
  for (const [name, lines] of [["same-root-unrelated-required-positive", [13, 14]], ["same-root-unrelated-required-quiet", [15, 16]]] as const) {
    const result = scanFile(metadataFile(name), { detectors: [rule.id] });
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.equal(result.findings.length, 1);
    const requirements = result.findings[0].metadata.initialRequirements as { line: number }[];
    assert.equal(requirements.length, 2);
    assert.deepEqual(requirements.map(span => span.line).sort((left, right) => left - right), lines);
  }
  const bypass = scanFile(metadataFile("same-root-unrelated-required-zero-bypass"), { detectors: [rule.id] });
  assert.equal(bypass.status, "complete", JSON.stringify(bypass.diagnostics));
  assert.deepEqual(bypass.findings, []);
});

test("unresolved callable closure cannot certify structural absence", () => {
  for (const mutate of [(program: Program) => program.functions.get(program.entries[0])!.calls.add("owned-model-test::unresolved"),
    (program: Program) => {
      const node = program.functions.get(program.entries[0])!.cfg.nodes.find(node => node.expr)!;
      node.expr = { ...node.expr!, kind: "call", symbol: undefined, args: [] };
    }]) {
    const program = new Program(fixture("direct-positive"));
    mutate(program);
    const plan = zeroDefaultScope(program);
    assert.equal(plan.complete, false);
    assert.equal("reason" in plan && plan.reason, "unresolved");
    const observed = observeZeroDefault(program, rule, {});
    assert.deepEqual(observed.findings, []);
    assert.ok(observed.diagnostics.some(issue => issue.code === "zero-default-target-unavailable"));
    assert.ok(observed.coverage.every(row => row.status === "incomplete"));
  }
});

test("shared initial membership and exact debit helper retention obey tight value allowances", () => {
  const program = new Program(frozen("positive"));
  const entry = program.entries.find(id => program.symbols.get(id)?.name === "spend")!;
  const amount = program.functions.get(entry)!.declaration.parameters.find(parameter => parameter.name === "amount")!.symbol!;
  const map = [...program.symbols.values()].find(symbol => symbol.kind === "ledger" && symbol.name === "allowances")!.id;
  const facts = new Dataflow(program).analyzeZeroMapDebitEntry(entry, amount);
  const helpers = [(charge: (work?: number, values?: number) => boolean) =>
    [...initialMapRequirements(facts, facts.paths[0], map, charge, message => { throw new Error(message); }).values()].map(item => item.location.line),
    (charge: (work?: number, values?: number) => boolean) =>
      exactMapDebits(facts, facts.paths[0], amount, charge, () => { charge(0, 5); }, false).map(item => item.write.location.line)];
  for (const helper of helpers) {
    let work = 0, values = 0;
    const charge = (units = 1, retained = 0) => { work += units; values += retained; return true; };
    const expected = helper(charge);
    assert.ok(expected.length >= 2); assert.ok(work > 0); assert.ok(values > 2);
    const retained = values;
    for (const budget of [1, retained - 1, retained]) {
      let spent = 0;
      const bounded = (_units = 1, count = 0) => {
        spent += count;
        if (spent > budget) throw new Error("owned shared helper value budget exhausted");
        return true;
      };
      if (budget < retained) assert.throws(() => helper(bounded), /value budget exhausted/);
      else assert.deepEqual(helper(bounded), expected);
    }
  }
  const ordinary = new Dataflow(program).analyzeMapDebitCandidates(entry);
  ordinary.mapDebitEvidence!.maxValues = ordinary.metrics.abstractValues + 1;
  assert.throws(() => mapDebitAmountCandidates(ordinary, entry, 40000 - ordinary.metrics.steps), /value allowance exhausted/);
});
