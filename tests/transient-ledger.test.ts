import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile } from "../src/index.js";
import { transientLedgerObservations } from "../src/analysis/transient-ledger.js";
import { transientDigestToLedger as rule } from "../src/detectors/transient-ledger.js";
import { transientDependencies, MAX_TRANSIENT_ORIGINS } from "../src/dataflow/transient-origins.js";
import { transientScope } from "../src/semantic/transient-targets.js";
import { human, sarif } from "../src/reporting/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const header = `pragma language_version >= 0.26.0; import CompactStandardLibrary;
export ledger saved: Field; export ledger stable: Bytes<32>; export ledger rounds: Counter;
export ledger entries: Map<Field, Field>; export ledger members: Set<Field>;
`;
const run = (body: string) => `export circuit run(x: Field, y: Field, rand: Field): [] { ${body} }`;

function observe(program: Program, engine: "instructions" | "expressions", cached: boolean) {
  return new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, false, "all", false, false, false, false,
    false, false, false, false, false, false, undefined, true).analyze();
}

function check(source: string, expected: number, incomplete = false) {
  withFiles({ "main.compact": header + source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiler = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiler.valid, true, compiler.error);
    }
    const program = new Program(file);
    let oracle: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = observe(program, engine, cached);
      const findings = rule.run(facts, { secrets: [], authorization: [], transitions: [], workBudgets: [] }).sort((a, b) => a.fingerprint.localeCompare(b.fingerprint));
      assert.equal(findings.length, expected, JSON.stringify(facts.diagnostics));
      assert.equal(!!facts.diagnostics.length, incomplete, JSON.stringify(facts.diagnostics));
      for (const item of findings) {
        assert.equal(item.severity, "low"); assert.equal(item.confidence, "high");
        assert.equal(item.metadata.upgradeFailure, "not-proven");
      }
      const outcome = { findings, codes: facts.diagnostics.map(issue => issue.code) };
      oracle ??= outcome; assert.deepEqual(outcome, oracle, `${engine}/${cached}`);
    }
    const report = scanFile(file, { detectors: [rule.id] });
    assert.equal(report.coverage.baselineStatus, "complete", JSON.stringify(report.diagnostics));
    assert.equal(report.status, incomplete ? "incomplete" : "complete", JSON.stringify(report.diagnostics));
    assert.deepEqual(report.findings.sort((a, b) => a.fingerprint.localeCompare(b.fingerprint)), (oracle as { findings: unknown }).findings);
    assert.ok(report.diagnostics.every(issue => issue.scope?.detectorId === rule.id));
    assert.equal(scanFile(file).findings.some(item => item.detectorId === rule.id), false);
  });
}

test("transient digests persist independently of private flows, including constants, commitment and outer persistent hash", () => {
  check(run(`saved = disclose(transientHash<Field>(x));`), 1);
  check(run(`saved = transientHash<Field>(7 as Field);`), 1);
  check(run(`saved = disclose(transientCommit<Field>(x, rand));`), 1);
  check(run(`stable = disclose(persistentHash<Field>(transientHash<Field>(x)));`), 1);
  check(run(`stable = disclose(persistentCommit<Field>(transientCommit<Field>(x, rand), pad(32, "opening")));`), 1);
  check(run(`saved = disclose(transientHash<Field>(x) + y);`), 1);
});

test("transparent helpers, cached mutations, retained snapshots and aggregate projections preserve exact data origins", () => {
  check(`circuit digest(x: Field): Field { return transientHash<Field>(x); }
    circuit store(x: Field): [] { saved = disclose(digest(x)); }
    ${run(`store(x); store(y);`)}`, 1);
  check(run(`const old = transientHash<Field>(x); saved = disclose(old); saved = 0 as Field; stable = disclose(persistentHash<Field>(old));`), 1);
  check(`struct Pair { first: Field; second: Field; }
    ${run(`const p = Pair { first: transientHash<Field>(x), second: y }; saved = disclose(p.first);`)}`, 1);
  check(`struct Pair { first: Field; second: Field; }
    ${run(`const p = Pair { first: transientHash<Field>(x), second: y }; saved = disclose(p.second);`)}`, 0);
  check(run(`const hashes = map((v: Field): Field => transientHash<Field>(v), [x, y]); saved = disclose(hashes[0]);`), 1);
  check(run(`const values = map((v: Field): Field => transientHash<Field>(v), [] as Vector<0, Field>); rounds.increment(1);`), 0);
});

test("Map keys and values persist, while exact replacement, removal and enclosing reset kill prior derivations", () => {
  check(run(`entries.insert(disclose(transientHash<Field>(x)), disclose(y));`), 1);
  check(run(`entries.insert(1 as Field, disclose(transientHash<Field>(x)));`), 1);
  check(run(`entries.insert(1 as Field, disclose(transientHash<Field>(x))); entries.insert(1 as Field, 0 as Field);`), 0);
  check(run(`entries.insert(1 as Field, disclose(transientHash<Field>(x))); entries.remove(1 as Field);`), 0);
  check(run(`entries.insert(disclose(transientHash<Field>(x)), disclose(y)); entries.resetToDefault();`), 0);
  check(run(`saved = disclose(transientHash<Field>(x)); saved = 0 as Field;`), 0);
  check(run(`saved = disclose(transientHash<Field>(x)); saved.resetToDefault();`), 0);
  check(run(`members.insert(disclose(transientHash<Field>(x)));`), 1);
  check(run(`members.insert(disclose(transientHash<Field>(x))); members.resetToDefault();`), 0);
});

test("consistency guards, control-only writes, application outputs, persistent primitives and arbitrary witness results stay quiet", () => {
  check(run(`assert(transientHash<Field>(x) == transientHash<Field>(y), "consistent"); rounds.increment(1);`), 0);
  check(run(`if (disclose(transientHash<Field>(x) == transientHash<Field>(y))) { saved = 1 as Field; } else { saved = 2 as Field; }`), 0);
  check(`export circuit run(x: Field): Field { return disclose(transientHash<Field>(x)); }`, 0);
  check(run(`stable = disclose(persistentHash<Field>(x));`), 0);
  check(`witness opaque(x: Field): Field; ${run(`saved = disclose(opaque(transientHash<Field>(x)));`)}`, 0);
  withFiles({ "main.compact": `pragma language_version >= 0.26.0; export ledger saved: Field;
    circuit transientHash(x: Field): Field { return x; } export circuit run(x: Field): [] { saved = disclose(transientHash(x)); }` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, file).valid, true);
    const result = scanFile(file, { detectors: [rule.id] }); assert.equal(result.status, "complete"); assert.deepEqual(result.findings, []);
  });
});

test("possible aliases and unsupported collection lifetimes remain rule-scoped incomplete", () => {
  check(run(`entries.insert(disclose(x), disclose(transientHash<Field>(y))); entries.insert(disclose(y), 0 as Field);`), 0, true);
  check(run(`members.insert(disclose(transientHash<Field>(x))); members.remove(7 as Field);`), 0, true);
  check(run(`members.insert(disclose(transientHash<Field>(x))); members.remove(7 as Field); members.resetToDefault();`), 0);
});

test("origin/consumer budgets and missing exact evidence never certify clean", () => {
  withFiles({ "main.compact": header + run(`saved = disclose(transientHash<Field>(x));`) }, directory => {
    const file = resolve(directory, "main.compact"), program = new Program(file), facts = observe(program, "instructions", true);
    assert.equal(transientLedgerObservations(facts, 1).diagnostics.length, 1);
    const absent = { ...facts, transientEvidence: undefined };
    assert.equal(transientLedgerObservations(absent).diagnostics.length, 1);
    const value = facts.paths[0].writes[0].after;
    const origins = Array.from({ length: MAX_TRANSIENT_ORIGINS + 1 }, (_, index) => ({ ...value, transientOrigins: [{ ...value.transientOrigins![0], location: { ...value.transientOrigins![0].location, start: index } }] }));
    const full = transientDependencies(origins);
    assert.equal(full.transientOriginsUnavailable, true); assert.equal(full.transientOrigins, undefined);
    facts.paths[0].writes[0].after = { ...value, ...full };
    assert.equal(transientLedgerObservations(facts).diagnostics.length, 1);
    assert.equal(transientScope(program, program.entries[0], 1).complete, false);
    for (const options of [{ maxSteps: 1 }, { maxValues: 1 }]) {
      const report = scanFile(file, { detectors: [rule.id], ...options }); assert.equal(report.status, "incomplete");
    }
  });
});

test("compiler-grounded real Counter seed, quiet controls and review output", () => {
  const seed = JSON.parse(readFileSync("tests/corpus/known-bugs.json", "utf8")).cases.find((item: { id: string }) => item.id === "counter-transient-ledger");
  for (const [relative, expected] of [[seed.file, seed.expectedLines], [seed.corrected, []], [seed.lookalike, []]]) {
    const file = resolve("tests/corpus", relative);
    for (const compiler of [process.env.COMPACTC_TEST, process.env.COMPACTC_030_TEST, process.env.COMPACTC_031_TEST, process.env.COMPACTC_033_RC2_TEST, process.env.COMPACTC_035_TEST].filter(Boolean)) {
      const result = validateWithCompiler(compiler!, file); assert.equal(result.valid, true, result.error);
    }
    const report = scanFile(file, { detectors: [rule.id] });
    assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
    assert.deepEqual(report.findings.map(item => item.location.line), expected);
    assert.ok(report.coverage.rules!.every(row => row.status !== "incomplete"));
    assert.ok(human(report)); assert.ok(sarif(report));
  }
});
