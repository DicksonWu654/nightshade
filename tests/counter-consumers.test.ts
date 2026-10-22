import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow } from "../src/dataflow/index.js";
import { counterPolicyFindings } from "../src/detectors/counter-consumers.js";
import { secretPublication, unguardedWrite } from "../src/detectors/rules.js";
import { type Finding } from "../src/detectors/types.js";
import { resolvePolicies } from "../src/policies.js";
import { Program } from "../src/semantic/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const qualified = { skip: !process.env.COMPACTC_TEST ? "Requires pinned COMPACTC_TEST" : false };
const ids = ["declared-secret-publication", "unguarded-sensitive-state-write"] as const;
const source = (size: number, reset = true) => `pragma language_version 0.26.0; import CompactStandardLibrary; export ledger count: Counter; export ledger other: Counter;
circuit guard(): [] { assert(true, "owned guard fixture"); }
export circuit entry(unused: Field, ${Array.from({ length: size }, (_, i) => `flag${i}: Boolean`).join(",")}): [] {
${reset ? "count.resetToDefault();" : ""}
${Array.from({ length: size }, (_, i) => `if (disclose(flag${i})) { count.increment(${i % 2 ? 65535 : 0}); }`).join("\n")}
return []; }
`;
const sorted = (findings: Finding[]) => [...findings].sort((a, b) => a.fingerprint.localeCompare(b.fingerprint));
function fixture(size: number, reset: boolean, compile: boolean, check: (program: Program) => void) {
  withFiles({ "main.compact": source(size, reset) }, directory => {
    const file = resolve(directory, "main.compact");
    if (compile) { const compiled = validateWithCompiler(process.env.COMPACTC_TEST!, file); assert.equal(compiled.valid, true, compiled.error); }
    check(new Program(file));
  });
}
function policies(program: Program, size: number) {
  return resolvePolicies(program, { secrets: [{ circuit: "entry", parameter: "unused" }, ...Array.from({ length: size }, (_, i) => ({ circuit: "entry", parameter: `flag${i}` }))], authorization: [{ state: "count", guard: "guard" }, { state: "other", guard: "guard" }] });
}
for (let size = 1; size <= 8; size++) test(`${size}-diamond query-backed policy consumers match complete exact findings in all four modes`, qualified, () => {
  fixture(size, true, true, program => {
    const configured = policies(program, size);
    let baseline: Finding[] | undefined;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const flow = new Dataflow(program, 20000, 256, 50000, engine, cached, cached);
      const exact = flow.analyze();
      assert.deepEqual(exact.diagnostics, []);
      const expected = sorted([...secretPublication.run(exact, configured), ...unguardedWrite.run(exact, configured)]);
      const queried = counterPolicyFindings(flow, program.entries[0], configured, ids);
      assert.equal(queried.status, "complete", JSON.stringify(queried, (_, value) => typeof value === "bigint" ? String(value) : value));
      if (queried.status !== "complete") throw new Error(JSON.stringify(queried));
      assert.deepEqual(sorted(queried.findings), expected);
      assert.equal(queried.findings.length, size * (size + 1) / 2 + size + 1);
      assert.equal(queried.coverage.representedAssignments, 1n << BigInt(size));
      assert.equal(queried.coverage.scope, "selected-policy-predicates");
      assert.equal(queried.witnesses.length, size);
      assert.equal("completedEntries" in queried, false);
      if (baseline) assert.deepEqual(expected, baseline);
      baseline = expected;
    }
  });
});

test("ten diamonds complete only the supported policy predicates within unchanged transfer budgets", qualified, () => {
  fixture(10, false, true, program => {
    const flow = new Dataflow(program);
    const queried = counterPolicyFindings(flow, program.entries[0], policies(program, 10), ids);
    assert.equal(queried.status, "complete", JSON.stringify(queried, (_, value) => typeof value === "bigint" ? String(value) : value));
    if (queried.status !== "complete") throw new Error(JSON.stringify(queried));
    assert.equal(queried.findings.length, 65);
    assert.equal(queried.coverage.representedAssignments, 1024n);
    assert.ok(queried.work.query.transferSteps <= 20000);
    assert.ok(queried.work.query.transferValues <= 50000);
    assert.ok(queried.work.query.witnesses <= 256);
    const exact = flow.analyze();
    assert.deepEqual(exact.completedEntries, []);
    assert.ok(exact.diagnostics.some(item => item.code === "analysis-budget"));
    const expectedPairs = Array.from({ length: 10 }, (_, sink) => Array.from({ length: sink + 1 }, (_, source) => `flag${source}:${sink + 1}`)).flat().sort();
    const incrementLines = Array.from({ length: 10 }, (_, i) => 5 + i);
    const observedPairs = queried.findings.filter(item => item.detectorId === ids[0]).map(item => {
      const name = /Secret (\w+) influences/.exec(item.message)![1];
      return `${name}:${incrementLines.indexOf(item.location.line) + 1}`;
    }).sort();
    assert.deepEqual(observedPairs, expectedPairs);
  });
});

test("approved derived flows, unused inputs, other ledger policies and duplicate policy order stay consistent", qualified, () => {
  fixture(3, true, true, program => {
    const flow = new Dataflow(program);
    for (const configured of [
      resolvePolicies(program, { secrets: [{ circuit: "entry", parameter: "flag0", allowedForms: ["derived"] }, { circuit: "entry", parameter: "unused" }], authorization: [{ state: "other", guard: "guard" }] }),
      resolvePolicies(program, { secrets: [{ circuit: "entry", parameter: "flag0", allowedForms: ["derived"] }, { circuit: "entry", parameter: "flag0" }], authorization: [] }),
      resolvePolicies(program, { secrets: [{ circuit: "entry", parameter: "flag0" }, { circuit: "entry", parameter: "flag0", allowedForms: ["derived"] }], authorization: [{ state: "count", guard: "guard" }, { state: "count", guard: "guard" }] }),
    ]) {
      const exact = flow.analyze();
      const queried = counterPolicyFindings(flow, program.entries[0], configured, ids);
      assert.equal(queried.status, "complete");
      if (queried.status !== "complete") throw new Error(JSON.stringify(queried));
      assert.deepEqual(sorted(queried.findings), sorted([...secretPublication.run(exact, configured), ...unguardedWrite.run(exact, configured)]));
    }
  });
});

test("consumer policy, matching-work, findings and query exhaustion cannot return complete absence or partial findings", () => {
  fixture(3, true, false, program => {
    const flow = new Dataflow(program);
    for (const limits of [{ maxPolicies: 1 }, { maxFindingWork: 1 }, { maxFindings: 1 }, { query: { maxQueryWork: 1 } }, { query: { maxWitnesses: 1 } }, { query: { maxTransferSteps: 1 } }]) {
      const result = counterPolicyFindings(flow, program.entries[0], policies(program, 3), ids, limits);
      assert.equal(result.status, "incomplete");
      assert.equal("findings" in result, false);
    }
    assert.throws(() => counterPolicyFindings(flow, program.entries[0], policies(program, 3), ["forbidden-state-transition"] as never));
  });
});
