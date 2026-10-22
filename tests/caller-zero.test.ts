import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile } from "../src/index.js";
import { callerKeyZeroEntryReview as rule } from "../src/detectors/caller-zero.js";
import { callerZeroAmountCandidates, callerZeroObservations } from "../src/dataflow/caller-zero.js";
import { requiredDistinctSelectors } from "../src/dataflow/selector-proof.js";
import type { AbstractValue, SuccessfulPredicate } from "../src/dataflow/index.js";
import { withFiles } from "./helpers.js";
import { validateWithCompiler } from "./compiler-fixtures.js";

const header = `pragma language_version >= 0.26.0;
import CompactStandardLibrary;
export ledger values: Map<Bytes<32>, Uint<64>>;
`;
const insert = `values.insert(disclose(key), disclose(amount));`;
const entry = (body: string) => `export circuit run(key: Bytes<32>, other: Bytes<32>, amount: Uint<64>): [] { ${body} }`;
function check(body: string, expected: number, incomplete = false, prefix = header) {
  withFiles({ "main.compact": prefix + body }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(file), id = program.entries.find(id => program.symbols.get(id)?.name === "run")!;
    const amount = program.functions.get(id)!.declaration.parameters.find(parameter => parameter.name === "amount")!.symbol!;
    let oracle: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyzeZeroEntry(id, amount);
      const findings = facts.diagnostics.length ? [] : rule.run(facts);
      assert.equal(findings.length, expected, JSON.stringify(facts.diagnostics));
      assert.equal(!!facts.diagnostics.length, incomplete, JSON.stringify(facts.diagnostics));
      const outcome = { findings, codes: facts.diagnostics.map(issue => issue.code) };
      oracle ??= outcome; assert.deepEqual(outcome, oracle, `${engine}/${cached}`);
      for (const finding of findings) {
        assert.equal(finding.severity, "info"); assert.equal(finding.confidence, "high");
        assert.equal(finding.metadata.declaredAmount, "0"); assert.equal(finding.metadata.initiallyMissing, "not-proven");
        assert.equal(finding.metadata.newEntry, "not-proven");
      }
    }
    const result = scanFile(file, { detectors: [rule.id] });
    assert.equal(result.findings.length, expected, JSON.stringify(result.diagnostics));
    assert.equal(result.status, incomplete ? "incomplete" : "complete", JSON.stringify(result.diagnostics));
    assert.equal(scanFile(file).findings.some(finding => finding.detectorId === rule.id), false);
  });
}

test("surviving zero insertion and intentional zero APIs retain the exact source relationship", () => {
  check(entry(insert), 1);
  check(entry(`if (disclose(amount) == 0) { ${insert} }`), 1);
  check(entry(`if (disclose(amount) > 0) { ${insert} }`), 0);
  check(entry(`if (values.member(disclose(key))) {} else { ${insert} }`), 1);
  check(entry(`if (values.member(disclose(key))) { ${insert} }`), 0);
});

test("required literal domains and positive amounts are quiet", () => {
  check(entry(`assert(disclose(key) == pad(32, "fixed"), "domain"); ${insert}`), 0);
  check(entry(`assert(disclose(key) == pad(32, "a") || disclose(key) == pad(32, "b"), "domain"); ${insert}`), 0);
  check(entry(`if (disclose(key) == pad(32, "fixed")) { ${insert} }`), 0);
  check(entry(`assert(disclose(key) == disclose(other), "same caller inputs"); ${insert}`), 1);
  check(entry(`assert(disclose(key) == disclose(other), "alias"); assert(disclose(other) == pad(32, "fixed"), "domain"); ${insert}`), 0);
  check(entry(`assert(disclose(other) == pad(32, "a") || disclose(other) == pad(32, "b"), "domain"); assert(disclose(key) == disclose(other), "alias"); ${insert}`), 0);
  check(entry(`assert(disclose(key) != pad(32, "fixed"), "exclusion"); ${insert}`), 1);
  check(entry(`assert(disclose(amount) > 0, "positive"); ${insert}`), 0);
});

test("exact initial membership excludes existing-only updates while unrelated may-alias membership does not", () => {
  check(entry(`assert(values.member(disclose(key)), "existing"); ${insert}`), 0);
  check(entry(`const old = values.lookup(disclose(key)); ${insert}`), 0);
  check(entry(`assert(values.member(disclose(other)), "other entry"); ${insert}`), 1);
  check(entry(`assert(values.member(disclose(other)), "existing"); assert(disclose(key) == disclose(other), "same key"); ${insert}`), 0);
  check(entry(`const was = values.member(disclose(key)); values.insertDefault(disclose(key)); assert(was, "existing"); ${insert}`), 0);
  check(entry(`values.insertDefault(disclose(key)); assert(values.member(disclose(key)), "supplied"); ${insert}`), 1);
});

test("writes must survive successful completion and helper amounts retain actual operands", () => {
  check(entry(`${insert} values.remove(disclose(key));`), 0);
  check(entry(`${insert} values.resetToDefault();`), 0);
  check(entry(`${insert} values.insert(disclose(key), 1);`), 0);
  check(entry(`${insert} values.remove(disclose(other));`), 0);
  const helper = `circuit save(key: Bytes<32>, amount: Uint<64>): [] { ${insert} }`;
  check(helper + entry(`save(key, amount);`), 1);
  check(helper + entry(`save(key, (amount + 1) as Uint<64>);`), 0);
  check(helper + entry(`save(key, amount); save(key, 1);`), 0);
  check(helper + entry(`save(key, 1); save(key, amount);`), 1);
  check(helper + entry(`save(key, amount); values.remove(disclose(key)); save(key, amount);`), 1);
});

test("literal-zero APIs match without inventing an amount parameter", () => {
  for (const cleanup of [false, true]) withFiles({ "main.compact": header + `export circuit record(key: Bytes<32>): [] {
    values.insert(disclose(key), 0); ${cleanup ? "values.remove(disclose(key));" : ""} }` }, directory => {
    const file = resolve(directory, "main.compact"), program = new Program(file);
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyzeCallerZeroCandidates(program.entries[0]);
      assert.deepEqual(callerZeroAmountCandidates(facts, program.entries[0], 40000), []);
      assert.equal(rule.run(facts).length, cleanup ? 0 : 1);
      assert.deepEqual(facts.diagnostics, []);
    }
    const result = scanFile(file, { detectors: [rule.id] });
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.equal(result.findings.length, cleanup ? 0 : 1);
    assert.equal(result.findings[0]?.metadata.amountIdentity, undefined);
  });
});

test("required distinct selectors preserve insertion across direct and helper writes", () => {
  const distinct = `assert(disclose(key) != disclose(other), "distinct");`;
  check(entry(`${distinct} ${insert} values.remove(disclose(other));`), 1);
  check(entry(`${insert} values.remove(disclose(other)); ${distinct}`), 1);
  check(entry(`${distinct} ${insert} values.insert(disclose(other), 1);`), 1);
  const helper = `circuit removeOther(other: Bytes<32>): [] { values.remove(disclose(other)); }`;
  check(helper + entry(`${distinct} ${insert} removeOther(other);`), 1);
  check(helper + entry(`${insert} removeOther(other);`), 0);
  check(helper + entry(`${insert} removeOther(key);`), 0);
  // One exact successful history requires disequality; the other does not.
  // This existential rule may report the former without merging histories.
  check(entry(`assert(disclose(key) != disclose(other) || disclose(amount) == 0, "alternative"); ${insert} values.remove(disclose(other));`), 1);
  check(entry(`${distinct} ${insert} values.resetToDefault();`), 0);
});

test("selector proof intersects Boolean alternatives and charges bounded work", () => {
  const left: AbstractValue = { flows: [], ledger: new Set(), identity: "left", type: "Bytes<32>" };
  const right: AbstractValue = { flows: [], ledger: new Set(), identity: "right", type: "Bytes<32>" };
  const comparison: AbstractValue = { flows: [], ledger: new Set(), type: "Boolean", comparison: { left, right, operator: "!=" } };
  const unrelated: AbstractValue = { flows: [], ledger: new Set(), identity: "flag", type: "Boolean" };
  const predicate = (value: AbstractValue) => [{ value, truth: true }] as SuccessfulPredicate[];
  const unavailable = (message: string): never => { throw new Error(message); };
  let work = 0, values = 0;
  const charge = (steps: number, retained: number) => { work += steps; values += retained; return true; };
  assert.equal(requiredDistinctSelectors(left, right, predicate(comparison), charge, unavailable), true);
  assert.ok(work > 0 && values > 0);
  assert.equal(requiredDistinctSelectors(left, right, predicate({ flows: [], ledger: new Set(), type: "Boolean",
    predicateAlternatives: [comparison, unrelated] }), charge, unavailable), false);
  assert.equal(requiredDistinctSelectors(left, { ...right, region: { root: "map", path: ["key:*"], type: "Bytes<32>" } },
    predicate(comparison), charge, unavailable), false);
  assert.throws(() => requiredDistinctSelectors(left, right, predicate(comparison), () => { throw new Error("budget"); }, unavailable), /budget/);
  assert.throws(() => requiredDistinctSelectors(left, right, predicate(comparison), () => false, unavailable), /allowance/);
});

test("owned lifecycle controls retain their source-first insertion sites", () => {
  for (const [fixture, lines] of [
    ["survives.compact", [8]], ["remove-exact.compact", []],
    ["remove-exact-helper.compact", []], ["remove-other-key-lookalike.compact", [13]],
  ] as const) {
    const file = resolve("tests/corpus/drafts/caller-zero41", fixture);
    const program = new Program(file), id = program.entries[0];
    const amount = program.functions.get(id)!.declaration.parameters.find(parameter => parameter.name === "amount")!.symbol!;
    let oracle: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyzeZeroEntry(id, amount);
      if (fixture === "remove-other-key-lookalike.compact") for (const limit of ["maxSteps", "maxValues"] as const) {
        const limited = { ...facts, metrics: { ...facts.metrics }, zeroEntry: { ...facts.zeroEntry!,
          [limit]: limit === "maxSteps" ? facts.metrics.steps : facts.metrics.abstractValues } };
        const result = callerZeroObservations(limited);
        assert.deepEqual(result.observations, []);
        assert.equal(result.diagnostics[0]?.code, "caller-zero-evidence-unavailable");
      }
      const findings = rule.run(facts);
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(findings.map(finding => finding.location.line), lines);
      oracle ??= findings; assert.deepEqual(findings, oracle);
    }
  }
});

test("ordinary discovery selects actual insertion origins and respects zero-iteration callback order", () => {
  const helper = `circuit save(key: Bytes<32>, amount: Uint<64>): Uint<64> { ${insert} return amount; }`;
  check(helper + entry(`map(save, [key], [amount]);`), 1);
  check(helper + entry(`map(save, [key, key], [amount, 1 as Uint<64>]);`), 0);
  check(helper + entry(`map(save, [key, key], [1 as Uint<64>, amount]);`), 1);
  check(helper + entry(`map(save, default<Vector<0, Bytes<32>>>, default<Vector<0, Uint<64>>>);`), 0);
  withFiles({ "main.compact": header + `export circuit run(key: Bytes<32>, amount: Uint<64>, fee: Uint<64>): [] {
    assert(fee > 1, "unrelated amount"); ${insert} }` }, directory => {
    const file = resolve(directory, "main.compact"), program = new Program(file), id = program.entries[0];
    const amount = program.functions.get(id)!.declaration.parameters.find(parameter => parameter.name === "amount")!.symbol!;
    const flow = new Dataflow(program), before = flow.analyze();
    const ordinary = flow.analyzeCallerZeroCandidates(id);
    assert.deepEqual(callerZeroAmountCandidates(ordinary, id, 40000), [amount]);
    assert.throws(() => callerZeroAmountCandidates(ordinary, id, 0), /allowance/);
    assert.deepEqual(flow.analyze(), before);
    assert.deepEqual(rule.run(before), []); assert.deepEqual(before.diagnostics, []);
    const selected = scanFile(file, { detectors: [rule.id] });
    assert.equal(selected.status, "complete", JSON.stringify(selected.diagnostics));
    assert.equal(selected.findings.length, 1);
  });
});

test("missing exact evidence, checkpoints, failed zero histories and budgets remain diagnostic", () => {
  check(entry(`${insert} kernel.checkpoint();`), 0, true);
  check(entry(`assert(false, "unrelated"); ${insert}`), 0, true);
  withFiles({ "main.compact": header + entry(insert) }, directory => {
    const file = resolve(directory, "main.compact"), program = new Program(file), id = program.entries[0];
    const amount = program.functions.get(id)!.declaration.parameters.find(parameter => parameter.name === "amount")!.symbol!;
    const ordinary = new Dataflow(program).analyze();
    assert.equal(callerZeroObservations(ordinary).diagnostics.length, 1);
    const facts = new Dataflow(program).analyzeZeroEntry(id, amount);
    assert.equal(callerZeroObservations({ ...facts, collectionEvidence: undefined }).diagnostics.length, 1);
    assert.equal(callerZeroObservations({ ...facts, paths: facts.paths.map(path => ({ ...path, predicates: undefined })) }).diagnostics.length, 1);
    assert.equal(callerZeroObservations(facts, 1).diagnostics.length, 1);
    const result = scanFile(file, { detectors: [rule.id], maxSteps: 1 });
    assert.equal(result.status, "incomplete"); assert.equal(result.findings.length, 0);
  });
});
