import assert from "node:assert/strict";
import { resolve } from "node:path";
import { readFileSync } from "node:fs";
import test from "node:test";
import { Dataflow, Program, scanFile, scanFileIsolated, type AnalysisFacts } from "../src/index.js";
import { zeroConsumptionFindings, zeroAmountSetConsumptionReview } from "../src/detectors/zero-consumption.js";
import { requiredAbsenceBeforeSurvivingInsertion } from "../src/dataflow/collection-consumption.js";
import { ZERO_CONSUMPTION_RULE } from "../src/semantic/zero-consumption-targets.js";
import { ZERO_SEND_TARGET } from "../src/semantic/zero-send-targets.js";
import { withFiles } from "./helpers.js";
import { validateWithCompiler } from "./compiler-fixtures.js";

function observed(program: Program, engine: "instructions" | "expressions", cached: boolean): AnalysisFacts {
  return new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, false,
    "all", false, true, false, false, false, false, false, false, false, true, new Set([ZERO_SEND_TARGET])).analyze();
}

const header = `import CompactStandardLibrary;
ledger used: Set<Field>; ledger other: Set<Field>; ledger values: Map<Field,Field>;
witness nonce(): Field;
`;
const send = `sendUnshielded(default<Bytes<32>>, disclose(amount), right<ContractAddress,UserAddress>(default<UserAddress>));`;
function check(body: string, expected: number, extra = "", inspect?: (facts: AnalysisFacts) => void) {
  withFiles({ "main.compact": `${header}${extra} export circuit run(amount: Uint<64>, key: Field, otherKey: Field, flag: Boolean): [] { ${body} }` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiler = validateWithCompiler(process.env.COMPACTC_TEST, file, [], 30000, 2, "0.34.0");
      assert.equal(compiler.valid, true, compiler.error);
    }
    const program = new Program(file);
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = observed(program, engine, cached);
      assert.deepEqual(facts.diagnostics, []);
      assert.equal(zeroConsumptionFindings(facts).length, expected);
      assert.deepEqual(facts.diagnostics, []);
      inspect?.(facts);
    }
    const result = scanFile(file, { detectors: [ZERO_CONSUMPTION_RULE] });
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.equal(result.findings.length, expected);
  });
}

test("owned compiler-accepted consumption controls preserve both engines and cache modes", () => {
  const corpus = JSON.parse(readFileSync("tests/corpus/manifest.json", "utf8")).zeroAmountSetConsumptionReview40 as {
    cases: { file: string; lines: number[] }[];
  };
  for (const fixture of corpus.cases) {
    const file = resolve("tests/corpus", fixture.file), program = new Program(file);
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = observed(program, engine, cached);
      assert.deepEqual(zeroConsumptionFindings(facts).map(item => item.location.line), fixture.lines, fixture.file);
      assert.deepEqual(facts.diagnostics, []);
    }
    const scan = scanFile(file, { detectors: [ZERO_CONSUMPTION_RULE] });
    assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics));
    assert.deepEqual(scan.findings.map(item => item.location.line), fixture.lines);
  }
  assert.equal(zeroAmountSetConsumptionReview.defaultEnabled, true);
});

test("default direct and supervised scans retain the informational consumption review and quiet controls", async () => {
  for (const fixture of ["positive", "corrected", "standalone-zero-lookalike"]) {
    const file = resolve(`tests/corpus/drafts/consumption40/${fixture}.compact`);
    const selected = scanFile(file, { detectors: [ZERO_CONSUMPTION_RULE] });
    const expected = JSON.parse(JSON.stringify(selected.findings));
    assert.equal(expected.length, fixture === "positive" ? 1 : 0);
    for (const report of [scanFile(file), await scanFileIsolated(file)]) {
      assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
      assert.ok(report.coverage.detectors.includes(ZERO_CONSUMPTION_RULE));
      const findings = report.findings.filter(item => item.detectorId === ZERO_CONSUMPTION_RULE);
      assert.deepEqual(JSON.parse(JSON.stringify(findings)), expected);
      assert.ok(findings.every(item => item.severity === "info" && item.metadata.deployedImpact === "not-proven"));
    }
  }
});

test("exact enforced prefix excludes late queries, late guards and late same-key insertions", () => {
  check(`assert(!used.member(disclose(key)), "fresh"); ${send} used.insert(disclose(key));`, 0);
  check(`const absent = !used.member(disclose(key)); used.insert(disclose(key)); assert(absent, "late guard"); ${send}`, 0);
  check(`assert(!used.member(disclose(key)), "fresh"); used.insert(disclose(otherKey)); ${send} used.insert(disclose(key));`, 0);
  check(`assert(!used.member(disclose(key)), "fresh"); used.insert(disclose(otherKey)); used.insert(disclose(key)); ${send}`, 0);
});

test("revision invalidation and later destruction cannot be rescued by reinsertion", () => {
  check(`const absent = !used.member(disclose(key)); used.resetToDefault(); assert(absent, "old revision"); used.insert(disclose(key)); ${send}`, 0);
  check(`assert(!used.member(disclose(key)), "fresh"); used.insert(disclose(key)); ${send} used.remove(disclose(key)); used.insert(disclose(key));`, 0);
  check(`assert(!used.member(disclose(key)), "fresh"); used.insert(disclose(key)); ${send} used.resetToDefault(); used.insert(disclose(key));`, 0);
  check(`assert(!used.member(disclose(key)), "fresh"); used.insert(disclose(key)); used.insert(disclose(otherKey)); ${send}`, 1);
});

test("ordinary histories retain required absence, exact key equality and successful abort continuations", () => {
  check(`used.member(disclose(key)); used.insert(disclose(key)); ${send}`, 0);
  check(`if (disclose(flag)) { assert(!used.member(disclose(key)), "fresh"); used.insert(disclose(key)); } else { ${send} }`, 0);
  check(`assert(!used.member(disclose(key)), "fresh"); assert(key == otherKey, "same"); used.insert(disclose(otherKey)); ${send}`, 1);
  check(`assert(!used.member(disclose(key)), "fresh"); used.insert(disclose(key)); ${send} assert(false, "abort");`, 0);
  check(`assert(!used.member(disclose(key)), "fresh"); used.insert(disclose(key)); ${send} assert(amount > 0, "atomic positivity");`, 0);
  check(`const a = values.lookup(disclose(key)); const b = values.lookup(disclose(otherKey)); assert(!used.member(a), "fresh"); used.insert(b); ${send}`, 0);
});

test("stateful helper replay preserves each query, argument and insertion order", () => {
  // Same source sites are grouped in reporting. Both invocation certificates
  // must nevertheless survive the cached and ordinary histories independently.
  check(`const first = nonce(); const second = nonce(); consume(first); consume(second); ${send}`, 1,
    `circuit consume(id: Field): [] { assert(!used.member(disclose(id)), "fresh"); used.insert(disclose(id)); }`, facts => {
      for (const path of facts.paths) {
        const insertions = path.operations!.flatMap((op, index) => op.kind === "collection-write" && op.name === "insert" ? [index] : []);
        assert.equal(insertions.length, 2);
        for (const index of insertions) {
          const result = requiredAbsenceBeforeSurvivingInsertion(path, index);
          assert.equal(result.complete, true);
          assert.equal(result.queries.length, 1);
        }
      }
    });
});

test("send argument evaluation consumes before the canonical invocation boundary", () => {
  check(`sendUnshielded(default<Bytes<32>>, disclose(consumeAmount(amount, key)), right<ContractAddress,UserAddress>(default<UserAddress>));`, 1,
    `circuit consumeAmount(amount: Uint<64>, id: Field): Uint<64> { assert(!used.member(disclose(id)), "fresh"); used.insert(disclose(id)); return amount; }`);
});

test("missing histories, exact addresses and exhausted matching allowances diagnose incompleteness", () => {
  withFiles({ "main.compact": `${header} export circuit run(amount: Uint<64>, key: Field): [] { assert(!used.member(disclose(key)), "fresh"); used.insert(disclose(key)); ${send} }` }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    for (const alter of [
      (facts: AnalysisFacts) => { delete facts.paths[0].operations; },
      (facts: AnalysisFacts) => { delete facts.paths[0].operations!.find(op => op.kind === "circuit-invocation")!.operationsBefore; },
      (facts: AnalysisFacts) => { delete facts.collectionEvidence; },
      (facts: AnalysisFacts) => { delete facts.paths[0].predicates; },
      (facts: AnalysisFacts) => { Reflect.deleteProperty(facts.paths[0].predicates![0], "operationsBefore"); },
      (facts: AnalysisFacts) => {
        const receiver = facts.paths[0].operations!.find(op => op.kind === "collection-query")!.args[0];
        receiver.region = { ...receiver.region!, path: ["key:*"], collectionSelectors: [] };
      },
    ]) {
      const facts = observed(program, "instructions", true); alter(facts);
      assert.deepEqual(zeroConsumptionFindings(facts), []);
      assert.ok(facts.diagnostics.some(issue => issue.scope?.detectorId === ZERO_CONSUMPTION_RULE));
    }
    const facts = observed(program, "instructions", true);
    assert.deepEqual(zeroConsumptionFindings(facts, 1), []);
    assert.ok(facts.diagnostics.some(issue => issue.scope?.detectorId === ZERO_CONSUMPTION_RULE));
    const path = observed(program, "instructions", true).paths[0];
    assert.equal(requiredAbsenceBeforeSurvivingInsertion(path, 0, 0).complete, false);
    assert.equal(scanFile(program.root, { detectors: [ZERO_CONSUMPTION_RULE], maxSteps: 1 }).status, "incomplete");
  });
});
