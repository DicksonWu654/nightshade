import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { readFileSync } from "node:fs";
import { Dataflow, Program, scanFile, detectors } from "../src/index.js";
import { destructiveListReset as rule } from "../src/detectors/list-reset.js";
import { acknowledgedListReset } from "../src/dataflow/list-reset.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const header = `import CompactStandardLibrary;
export ledger queues: Map<Uint<8>,List<Field>>;
export ledger other: Map<Uint<8>,List<Field>>;
export ledger items: List<Field>;
export ledger epoch: Counter;
`;
function fixture(body: string, expected: string[], inspect?: (facts: ReturnType<Dataflow["analyze"]>) => void) {
  withFiles({ "main.compact": header + body }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(file);
    let oracle: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, true, "all").analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      const findings = rule.run(facts);
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(findings.map(f => f.metadata.entry).sort(), expected);
      oracle ??= findings;
      assert.deepEqual(findings, oracle, `${engine}/${cached}`);
      inspect?.(facts);
    }
    const scan = scanFile(file, { detectors: [rule.id] });
    assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics));
    assert.deepEqual(scan.findings.map(f => f.metadata.entry).sort(), expected);
  });
}

test("whole List reset and default Map List replacement need acknowledgment review", () => {
  fixture(`
export circuit plain(): [] { items.resetToDefault(); }
export circuit keyed(key: Uint<8>): [] { assert(queues.member(disclose(key)), "exists"); queues.insert(disclose(key),default<List<Field>>); }
export circuit defaultSlot(key: Uint<8>): [] { queues.insertDefault(disclose(key)); }
`, ["defaultSlot", "keyed", "plain"], facts => {
    for (const finding of rule.run(facts)) {
      assert.equal(finding.severity, "low"); assert.equal(finding.confidence, "medium");
      assert.equal(finding.metadata.reviewRequired, true);
      assert.equal(finding.metadata.customEpochOrDigest, "not-analyzed");
    }
  });
});

test("same List count, empty-list and exact absent-slot initializers stay quiet", () => {
  fixture(`
constructor() { items.resetToDefault(); }
export circuit count(key: Uint<8>, expected: Uint<64>): [] {
  assert(queues.lookup(disclose(key)).length() as Field == expected as Field, "count"); queues.insertDefault(disclose(key));
}
export circuit empty(): [] { assert(items.isEmpty(), "empty"); items.resetToDefault(); }
export circuit zero(): [] { assert(items.length() == 0, "zero"); items.resetToDefault(); }
export circuit initialized(key: Uint<8>): [] { if (!queues.member(disclose(key))) { queues.insertDefault(disclose(key)); } }
export circuit absentEquality(key: Uint<8>): [] { assert(queues.member(disclose(key)) == false, "absent"); queues.insertDefault(disclose(key)); }
`, []);
});

test("wrong key, wrong list, ignored and optional count checks cannot acknowledge a reset", () => {
  fixture(`
export circuit wrongKey(key: Uint<8>, another: Uint<8>, expected: Uint<64>): [] {
  assert(queues.lookup(disclose(another)).length() as Field == expected as Field, "other count"); queues.insertDefault(disclose(key));
}
export circuit wrongList(key: Uint<8>, expected: Uint<64>): [] {
  assert(other.lookup(disclose(key)).length() as Field == expected as Field, "other list"); queues.insertDefault(disclose(key));
}
export circuit ignored(expected: Uint<64>): [] { items.length() as Field == expected as Field; items.resetToDefault(); }
export circuit optional(check: Boolean, expected: Uint<64>): [] {
  if (disclose(check)) { assert(items.length() as Field == expected as Field, "count"); } items.resetToDefault();
}
export circuit tautology(): [] { const count = items.length(); assert(count == count, "same count"); items.resetToDefault(); }
export circuit wrongAbsence(key: Uint<8>, another: Uint<8>): [] {
  assert(!queues.member(disclose(another)), "other absent"); queues.insertDefault(disclose(key));
}
`, ["ignored", "optional", "tautology", "wrongAbsence", "wrongKey", "wrongList"]);
});

test("revision invalidation prevents saved count from acknowledging intervening appends", () => {
  fixture(`
export circuit stale(expected: Uint<64>): [] {
  const count = items.length(); assert(count as Field == expected as Field, "before append");
  items.pushFront(9 as Field); items.resetToDefault();
}
export circuit afterReset(expected: Uint<64>): [] { items.resetToDefault(); assert(items.length() as Field == expected as Field, "after reset"); }
export circuit lateSaved(expected: Uint<64>): [] {
  const count = items.length(); items.resetToDefault(); assert(count as Field == expected as Field, "saved immutable count");
}
export circuit alias(key: Uint<8>, expected: Uint<64>): [] {
  const copied = key; assert(queues.lookup(disclose(copied)).length() as Field == expected as Field, "same key"); queues.insertDefault(disclose(key));
}
`, ["afterReset", "stale"]);
});

test("helper replay retains current count, revision and exact invocation evidence", () => {
  fixture(`
circuit count(): Uint<64> { return items.length(); }
circuit clear(expected: Uint<64>): [] { assert(count() as Field == expected as Field, "count"); items.resetToDefault(); }
export circuit replay(first: Uint<64>, second: Uint<64>): [] { clear(first); items.pushFront(3 as Field); clear(second); }
export circuit unguarded(): [] { erase(); items.pushFront(4 as Field); erase(); }
circuit erase(): [] { items.resetToDefault(); }
`, ["unguarded"], facts => {
    const found = rule.run(facts)[0];
    assert.equal((found.metadata.affectedHistories as unknown[]).length, 2);
    assert.ok((found.metadata.affectedHistories as { invocationSites: unknown[] }[]).every(history => history.invocationSites.length >= 2));
  });
});

test("custom epoch checks and intentional purges remain explicit opt-in reviews", () => {
  fixture(`export circuit purge(expectedEpoch: Field): [] { assert(epoch as Field == expectedEpoch, "epoch"); items.resetToDefault(); }`, ["purge"]);
});

test("missing selector/full-predicate evidence and query allowance fail explicitly", () => {
  fixture(`export circuit entry(): [] { items.resetToDefault(); }`, ["entry"], facts => {
    const path = facts.paths[0], write = path.writes[0];
    assert.equal(acknowledgedListReset(write, path, 0).complete, false);
    assert.equal(acknowledgedListReset({ ...write, before: { ...write.before, region: { ...write.before.region!, path: ["key:*"] } } }, path).complete, false);
    const missing = { ...facts, diagnostics: [] as typeof facts.diagnostics, predicateScope: "witness" as const };
    assert.deepEqual(rule.run(missing), []);
    assert.equal(missing.diagnostics[0]?.code, "list-reset-evidence-unavailable");
    assert.equal(missing.diagnostics[0]?.scope?.kind, "rule");
  });
});

test("owned Counter history seeds compile, and the review remains opt-in", () => {
  assert.equal(detectors.find(detector => detector.id === rule.id)?.defaultEnabled, false);
  for (const name of ["positive", "corrected", "lookalike"]) {
    const file = resolve(`tests/corpus/known-bugs/counter-list-reset-${name}.compact`);
    if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, file).valid, true);
    const scan = scanFile(file, { detectors: [rule.id] });
    assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics));
    assert.equal(scan.findings.length, name === "positive" ? 1 : 0);
    assert.equal(scanFile(file).findings.some(finding => finding.detectorId === rule.id), false);
  }
  const manifest = JSON.parse(readFileSync("tests/corpus/manifest.json", "utf8")).listReset;
  assert.equal(manifest.detector, rule.id);
  assert.equal(manifest.optIn, true);
  assert.equal(manifest.cases.length, 3);
  const seeds = JSON.parse(readFileSync("tests/corpus/known-bugs.json", "utf8"));
  assert.equal(seeds.cases.find((seed: { id: string }) => seed.id === "counter-list-reset")?.detector, rule.id);
});
