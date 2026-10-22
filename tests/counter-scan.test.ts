import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { analyzeCounterPredicates } from "../src/analysis/counter-scan.js";
import { qualifyCounterDetectors } from "../src/analysis/counter-certificates.js";
import { Dataflow } from "../src/dataflow/index.js";
import { detectors } from "../src/detectors/index.js";
import { Program } from "../src/semantic/index.js";
import { resolvePolicies, type ResolvedPolicies } from "../src/policies.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { informationalDetectors } from "../src/detectors/informational.js";
import { withFiles } from "./helpers.js";

const qualified = { skip: !process.env.COMPACTC_TEST ? "Requires pinned COMPACTC_TEST" : false };
// Built-in library policies are opt-in; the ordinary predicate contract stays unchanged.
const all = detectors.filter(detector => detector.defaultEnabled !== false && detector.id !== "openzeppelin-preconditions").map(detector => detector.id);
// Retain opt-in review and convention certificates alongside default rules.
const extraCertificates = ["inconsistent-access-control", "zero-amount-unshielded-send", "merkle-insert-without-dedupe"];
const withConventions = detectors.filter(detector => all.includes(detector.id) || extraCertificates.includes(detector.id)).map(detector => detector.id);
const sourceOnlyIds = new Set([...informationalDetectors.map(detector => detector.id), "ignored-validation-result", "discarded-comparison", "discarded-shielded-send-result", "missing-role-bootstrap", "caller-supplied-deadline", "freshness-bound-caller-time"]);
const policyIds = ["declared-secret-publication", "unguarded-sensitive-state-write"];
const body = (name: string, size: number, reset: boolean, returned: boolean) => `export circuit ${name}(unused: Field, ${Array.from({ length: size }, (_, i) => `flag${i}: Boolean`).join(",")}): [] {
${reset ? "count.resetToDefault();" : ""}
${Array.from({ length: size }, (_, i) => `if (disclose(flag${i})) { count.increment(${i % 2 ? 65535 : 0}); }`).join("\n")}
${returned ? "return [];" : ""}}
`;
const source = (size: number, reset = true, returned = true) => `pragma language_version 0.26.0;
import CompactStandardLibrary;
export ledger count: Counter;
export ledger phase: Uint<8>;
circuit guard(): [] { assert(true, "fixture guard"); }
circuit helper(value: Field): Field { return value + 1; }
${body("entry", size, reset, returned)}`;
function fixture(text: string, compile: boolean, check: (program: Program) => void) {
  withFiles({ "main.compact": text }, directory => {
    const file = resolve(directory, "main.compact");
    if (compile) { const result = validateWithCompiler(process.env.COMPACTC_TEST!, file); assert.equal(result.valid, true, result.error); }
    check(new Program(file));
  });
}
const id = (program: Program, name: string) => program.entries.find(entry => program.functions.get(entry)!.symbol.name === name)!;
function policies(program: Program, size: number): ResolvedPolicies {
  return resolvePolicies(program, { secrets: [{ circuit: "entry", parameter: "unused" }, ...Array.from({ length: size }, (_, i) => ({ circuit: "entry", parameter: `flag${i}` }))],
    authorization: [{ state: "count", guard: "guard" }], transitions: [{ state: "phase", from: "0", to: "1" }],
    workBudgets: [{ circuit: "entry", maxUnits: 1 }, { circuit: "helper", maxUnits: 1 }] });
}
const sorted = <T extends { fingerprint: string }>(values: T[]) => [...values].sort((a, b) => a.fingerprint.localeCompare(b.fingerprint));

for (let size = 1; size <= 8; size++) test(`${size}-choice internal predicate scan matches defaults plus opt-in reviews and conventions in all four modes`, qualified, () => {
  fixture(source(size, size % 2 === 0, size % 2 !== 0), true, program => {
    const configured = policies(program, size);
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const flow = new Dataflow(program, 20000, 256, 50000, engine, cached, cached);
      const exact = flow.analyze();
      const expected = detectors.filter(detector => withConventions.includes(detector.id)).flatMap(detector => detector.run(exact, configured));
      assert.deepEqual(exact.diagnostics, []);
      const result = analyzeCounterPredicates(flow, configured, withConventions);
      assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
      assert.deepEqual(sorted(result.findings), sorted(expected));
      assert.deepEqual(result.exact!.entries, []);
      assert.deepEqual(result.exact!.facts.paths, []);
      assert.deepEqual(result.exact!.facts.completedEntries, []);
      assert.equal(result.certificates.length, 19);
      assert.equal(result.certificates.find(row => row.detector === "redundant-self-shielded-receive")?.reason, "no-token-operations");
      assert.equal(result.certificates.find(row => row.detector === "zero-amount-unshielded-send")?.reason, "no-token-operations");
      assert.equal(result.certificates.find(row => row.detector === "zero-amount-set-consumption-review")?.reason, "no-token-operations");
      assert.equal(result.certificates.find(row => row.detector === "merkle-insert-without-dedupe")?.reason, "no-merkle-inserts");
      assert.equal(result.certificates.find(row => row.detector === "field-recomposition-range-review")?.reason, "no-field-arithmetic");
      assert.equal(result.certificates.find(row => row.detector === "publicly-derivable-encryption-secret")?.reason, "no-hash-inputs");
      assert.equal(result.certificates.find(row => row.detector === "public-key-membership-authorization")?.reason, "no-witnesses");
      assert.equal(result.certificates.find(row => row.detector === "duplicate-shielded-mint")?.reason, "no-token-operations");
      assert.equal(result.certificates.find(row => row.detector === "either-payload-mismatch")?.reason,"no-either-receivers");
      assert.equal(result.certificates.find(row => row.detector === "low-entropy-hash-disclosure")?.reason,"no-hash-inputs");
      assert.equal(result.certificates.find(row => row.detector === "identity-signature-key")?.reason, "no-signature-verification");
      assert.equal(result.certificates.find(row => row.detector === "inconsistent-access-control")?.reason, "no-caller-convention");
      assert.equal(result.certificates.find(row => row.detector === "merkle-membership-not-enforced")?.reason, "no-merkle-proofs");
      assert.equal(result.certificates.find(row => row.detector === "merkle-leaf-binding-review")?.reason, "no-merkle-proofs");
      assert.deepEqual(result.coverage.map(row => row.detector), withConventions);
      assert.ok(result.coverage.every(row => row.entry === id(program, "entry") && row.root === program.root && row.status === "covered"));
      assert.deepEqual(result.workPolicies.map(row => row.status), ["covered", "covered"]);
      assert.deepEqual(flow.analyze().paths, exact.paths);
    }
  });
});

test("leaf-binding absence is entry-local and Merkle calls still refuse Counter qualification", () => {
  fixture(`import CompactStandardLibrary;
export ledger count: Counter;
witness pathFor(): MerkleTreePath<0, Field>;
export circuit counted(flag: Boolean): [] {
  if (disclose(flag)) { count.increment(1); }
}
export circuit withProof(flag: Boolean): [] {
  if (disclose(flag)) { count.increment(1); }
  merkleTreePathRoot<0, Field>(pathFor());
}`, Boolean(process.env.COMPACTC_TEST), program => {
    const configured = resolvePolicies(program);
    const closed = qualifyCounterDetectors(program, id(program, "counted"), ["merkle-leaf-binding-review"], configured);
    assert.equal(closed.status, "eligible");
    if (closed.status === "eligible") assert.deepEqual(closed.certificates.map(row => [row.detector, row.reason]),
      [["merkle-leaf-binding-review", "no-merkle-proofs"]]);
    assert.equal(qualifyCounterDetectors(program, id(program, "withProof"), ["merkle-leaf-binding-review"], configured).status, "ineligible");
  });
});

test("unchanged ten-branch workload has complete scoped predicates while default exact paths stay incomplete", qualified, () => {
  const text = `import CompactStandardLibrary; export ledger count: Counter; export circuit entry(${Array.from({ length: 10 }, (_, index) => `flag${index}: Boolean`).join(",")}): [] { ${Array.from({ length: 10 }, (_, index) => `if (disclose(flag${index})) { count.increment(1); }`).join(" ")} }`;
  fixture(text, true, program => {
    const configured = resolvePolicies(program, { secrets: Array.from({ length: 10 }, (_, index) => ({ circuit: "entry", parameter: `flag${index}` })), authorization: [{ state: "count", guard: "entry" }] });
    const flow = new Dataflow(program);
    const result = analyzeCounterPredicates(flow, configured);
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.equal(result.findings.filter(item => item.detectorId === policyIds[0]).length, 55);
    assert.equal(result.findings.filter(item => item.detectorId === policyIds[1]).length, 10);
    const expected = Array.from({ length: 10 }, (_, site) => Array.from({ length: site + 1 }, (_, source) => `flag${source}:${text.indexOf("count.increment(1)", text.indexOf(`if (disclose(flag${site}))`))}`)).flat().sort();
    assert.deepEqual(result.findings.filter(item => item.detectorId === policyIds[0]).map(item => `${/Secret (\w+) influences/.exec(item.message)![1]}:${item.location.start}`).sort(), expected);
    assert.equal(result.coverage.length, all.length);
    assert.ok(result.coverage.every(row => row.status === "covered"));
    assert.deepEqual(result.exact!.facts.completedEntries, []);
    assert.equal(result.work.query.witnesses, 10);
    assert.ok(result.work.query.transferSteps <= 20000);
    const exact = flow.analyze();
    assert.deepEqual(exact.completedEntries, []);
    assert.ok(exact.diagnostics.some(item => item.code === "analysis-budget"));
  });
});

test("mixed entries and constructors use genuine exact fallback without source or guard contamination", qualified, () => {
  fixture(source(2) + 'constructor() { phase = 0; } export circuit other(value: Field): Field { guard(); return disclose(value); }', true, program => {
    const configured = resolvePolicies(program, { secrets: [{ circuit: "entry", parameter: "flag0" }, { circuit: "other", parameter: "value" }], authorization: [{ state: "count", guard: "guard" }], transitions: [{ state: "phase", from: "0", to: "0" }] });
    const flow = new Dataflow(program);
    const exact = flow.analyze();
    const expected = detectors.filter(detector => all.includes(detector.id)).flatMap(detector => detector.run(exact, configured));
    const result = analyzeCounterPredicates(flow, configured);
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.equal(result.exact!.entries.length, 2);
    assert.ok(result.exact!.facts.paths.every(path => path.entry !== id(program, "entry")));
    assert.deepEqual(result.exact!.facts.completedEntries, result.exact!.entries);
    assert.deepEqual(sorted(result.findings), sorted(expected));
    assert.ok(result.coverage.filter(row => row.entry === id(program, "other") && sourceOnlyIds.has(row.detector)).every(row => row.method === "source-work"));
    assert.equal(result.coverage.find(row => row.entry === id(program, "other") && row.detector === "discarded-shielded-send-result")?.method, "source-work");
    assert.ok(result.coverage.filter(row => row.entry === id(program, "other") && row.detector !== "circuit-work-budget" && !sourceOnlyIds.has(row.detector)).every(row => row.method === "exact"));
  });
});

test("a covered entry cannot hide incomplete exact fallback or unavailable helper work", () => {
  fixture(source(2) + 'export circuit expensive(values: Vector<8, Field>): [] {} circuit hidden(): [] { hidden(); }', false, program => {
    const configured = resolvePolicies(program, { workBudgets: [{ circuit: "hidden", maxUnits: 100 }] });
    const result = analyzeCounterPredicates(new Dataflow(program, 20000, 256, 4), configured);
    assert.equal(result.status, "incomplete");
    assert.ok(result.diagnostics.some(item => item.code === "value-budget"));
    assert.ok(result.diagnostics.some(item => item.code === "work-estimate-unavailable"));
    assert.ok(result.coverage.some(row => row.entry === id(program, "expensive") && row.status === "incomplete"));
    assert.equal(result.workPolicies[0].status, "incomplete");
  });
  fixture(source(2) + 'circuit hidden(): [] { hidden(); }', false, program => {
    const result = analyzeCounterPredicates(new Dataflow(program), resolvePolicies(program, { workBudgets: [{ circuit: "hidden", maxUnits: 100 }] }));
    assert.equal(result.status, "incomplete");
    assert.deepEqual(result.exact!.entries, []);
    assert.ok(result.diagnostics.some(item => item.code === "work-estimate-unavailable"));
    assert.equal(result.workPolicies[0].status, "incomplete");
  });
});

test("call/assertion/continuation lookalikes fall back; absence certificates never inherit unsupported predicates", qualified, () => {
  for (const suffix of ['guard();', 'assert(disclose(flag0), "later");', 'count.read();']) fixture(source(2).replace('return [];', `${suffix} return [];`), true, program => {
    const configured = policies(program, 2);
    const flow = new Dataflow(program);
    const exact = flow.analyze();
    const expected = detectors.filter(detector => all.includes(detector.id)).flatMap(detector => detector.run(exact, configured));
    const result = analyzeCounterPredicates(flow, configured);
    assert.deepEqual(result.exact!.entries, program.entries);
    assert.deepEqual(result.certificates, []);
    assert.deepEqual(sorted(result.findings), sorted(expected));
  });
  fixture(source(2), true, program => {
    assert.equal(qualifyCounterDetectors(program, id(program, "entry"), ["future-detector"], resolvePolicies(program)).status, "ineligible");
    const configured = resolvePolicies(program);
    configured.transitions.push({ state: [...program.symbols.values()].find(item => item.kind === "ledger" && item.name === "count")!.id, from: "*", to: "*" });
    const result = analyzeCounterPredicates(new Dataflow(program), configured, ["forbidden-state-transition"]);
    assert.equal(result.status, "incomplete");
    assert.ok(result.diagnostics.some(item => item.code === "counter-transition-policy"));
    assert.throws(() => resolvePolicies(program, { transitions: [{ state: "count", from: "0", to: "1" }] }));
  });
});

test("scan, extraction, consumer and shared cross-entry budgets remain explicit", () => {
  fixture(source(2) + body("second", 2, false, false), false, program => {
    const configured = policies(program, 2), flow = new Dataflow(program);
    for (const limits of [{ maxEntries: 1 }, { maxCoverageRows: 1 }, { maxPreparationWork: 1 }, { maxFindings: 1 },
      { consumer: { maxPolicies: 1 } }, { consumer: { query: { region: { maxBranches: 1 } } } },
      { consumer: { query: { maxWitnesses: 2 } } }, { consumer: { query: { maxTransferSteps: 1 } } }, { consumer: { maxFindingWork: 1 } }]) {
      const result = analyzeCounterPredicates(flow, configured, all, limits);
      assert.equal(result.status, "incomplete", JSON.stringify(limits));
      assert.ok(result.diagnostics.length);
    }
    const one = analyzeCounterPredicates(flow, configured, policyIds, { consumer: { query: { maxWitnesses: 2 } } });
    assert.ok(one.coverage.some(row => row.entry === id(program, "entry") && row.status === "covered"));
    assert.ok(one.coverage.some(row => row.entry === id(program, "second") && row.status === "incomplete"));
    assert.equal(one.work.query.witnesses, 2);
    assert.throws(() => analyzeCounterPredicates(flow, configured, []));
    assert.throws(() => analyzeCounterPredicates(flow, configured, Array(1)));
    assert.throws(() => analyzeCounterPredicates(flow, configured, ["future-detector"]));
    assert.throws(() => analyzeCounterPredicates(flow, configured, [policyIds[0], policyIds[0]]));
  });
  fixture(source(1) + 'export circuit other(value: Field): [] {}', false, program => {
    const configured = resolvePolicies(program);
    const one = analyzeCounterPredicates(new Dataflow(program), configured, policyIds);
    assert.equal(one.status, "complete");
    const globalValues = one.exact!.facts.metrics.abstractValues + one.work.query.transferValues;
    assert.equal(analyzeCounterPredicates(new Dataflow(program, 20000, 256, globalValues), configured, policyIds).status, "complete");
    const short = analyzeCounterPredicates(new Dataflow(program, 20000, 256, globalValues - 1), configured, policyIds);
    assert.equal(short.status, "incomplete", "Query allocations must share the original value allowance after exact fallback");
  });
});

test("exact subset validates canonical entries, preserves Program order and a single aggregate value allowance", () => {
  fixture('circuit hidden(): [] {} export circuit first(value: Field): Field { return disclose(value); } export circuit second(value: Field): Field { return disclose(value); }', false, program => {
    const before = [...program.entries], first = id(program, "first"), second = id(program, "second");
    const flow = new Dataflow(program);
    assert.deepEqual(flow.analyzeSubset([second, first]).paths, flow.analyze().paths);
    assert.deepEqual(flow.analyzeSubset([second]).completedEntries, [second]);
    assert.ok(flow.analyzeSubset([second]).paths.every(path => path.entry === second));
    assert.deepEqual(flow.analyzeSubset([]).paths, []);
    assert.deepEqual(program.entries, before);
    const helper = [...program.symbols.values()].find(item => item.name === "hidden" && item.kind === "circuit")!.id;
    for (const entries of [[first, first], ["first"], [helper], Array(1)]) assert.throws(() => flow.analyzeSubset(entries));
    const getter = [first];
    Object.defineProperty(getter, "0", { get() { assert.fail("entry getter evaluated"); } });
    assert.throws(() => flow.analyzeSubset(getter));
    const bounded = new Dataflow(program, 20000, 256, 1).analyzeSubset([second, first]);
    assert.ok(bounded.diagnostics.some(item => item.code === "value-budget"));
    assert.deepEqual(bounded.completedEntries, [first]);
  });
});

test("structural-only selection and library-only input preserve their narrow coverage scope", () => {
  fixture(source(10), false, program => {
    const result = analyzeCounterPredicates(new Dataflow(program, 1, 1, 1), resolvePolicies(program), ["ledger-bound-preimage-publication", "predictable-commitment-randomness", "impossible-assertion"]);
    assert.equal(result.status, "complete");
    assert.equal(result.work.query.witnesses, 0);
    assert.deepEqual(result.exact!.facts.completedEntries, []);
    assert.deepEqual(result.findings, []);
    assert.ok(result.coverage.every(row => row.method === "structural-absence"));
  });
  fixture('module Library { export circuit helper(): [] {} }', false, program => {
    const result = analyzeCounterPredicates(new Dataflow(program), resolvePolicies(program));
    assert.equal(result.status, "complete");
    assert.deepEqual(result.coverage, []);
    assert.deepEqual(result.exact!.facts.completedEntries, []);
  });
});

test("duplicate work policies retain multiplicity and later exact callers retain last-wins policy evidence", qualified, () => {
  fixture(source(1) + 'export circuit later(flag: Boolean): [] { entry(0 as Field, flag); }', true, program => {
    const configured = resolvePolicies(program, { authorization: [{ state: "count", guard: "guard" }],
      workBudgets: [{ circuit: "entry", maxUnits: 1 }, { circuit: "entry", maxUnits: 2 }] });
    const flow = new Dataflow(program);
    const exact = flow.analyze();
    const expected = detectors.filter(detector => all.includes(detector.id)).flatMap(detector => detector.run(exact, configured));
    const result = analyzeCounterPredicates(flow, configured);
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.deepEqual(sorted(result.findings), sorted(expected));
    const work = result.findings.filter(finding => finding.detectorId === "circuit-work-budget");
    assert.equal(work.length, 2);
    assert.equal(work[0].fingerprint, work[1].fingerprint);
    assert.deepEqual(work.map(finding => finding.metadata.budget), [1, 2]);
    assert.ok(result.findings.filter(finding => finding.detectorId === "unguarded-sensitive-state-write").every(finding => finding.callPath.join("/") === "later/entry"));
  });
});

test("approved derived forms, unused inputs and unrelated scalar policies produce covered empty findings", qualified, () => {
  fixture(source(3), true, program => {
    const configured = resolvePolicies(program, { secrets: [{ circuit: "entry", parameter: "flag0", allowedForms: ["derived"] }, { circuit: "entry", parameter: "unused" }],
      authorization: [{ state: "phase", guard: "guard" }], transitions: [{ state: "phase", from: "0", to: "1" }] });
    const result = analyzeCounterPredicates(new Dataflow(program), configured);
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.deepEqual(result.findings.filter(finding => !sourceOnlyIds.has(finding.detectorId)), []);
    assert.ok(result.findings.some(finding => sourceOnlyIds.has(finding.detectorId)));
    assert.ok(result.coverage.every(row => row.status === "covered"));
  });
});
