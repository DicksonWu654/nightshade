import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile } from "../src/index.js";
import { splitWitnessIdentity as rule } from "../src/detectors/split-identity.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";
const header = `import CompactStandardLibrary;
export ledger owner: Bytes<32>;
export ledger entries: Map<Bytes<32>, Uint<8>>;
witness first(): Bytes<32>;
witness second(): Bytes<32>;
circuit identity(value: Bytes<32>): Bytes<32> { return persistentHash<Bytes<32>>(value); }
`;
function check(body: string, expected: string[]) {
  withFiles({ "main.compact": header + body }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) { const result = validateWithCompiler(process.env.COMPACTC_TEST, file); assert.equal(result.valid, true, result.error); }
    const program = new Program(file); let baseline: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, false, "all", false, true, false, false, false, false, true).analyze();
      assert.deepEqual(facts.diagnostics, []);
      const findings = rule.run(facts); assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual([...new Set(findings.map(item => item.metadata.entry))].sort(), expected.sort());
      baseline ??= findings; assert.deepEqual(findings, baseline);
    }
    for (const experimentalCounterQueries of [false, true]) {
      const result = scanFile(file, { detectors: [rule.id], experimentalCounterQueries });
      assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
      assert.deepEqual([...new Set(result.findings.map(item => item.metadata.entry))].sort(), expected.sort());
    }
  });
}
test("independent composed digest identities report while digest/secret equality binds", () => check(`
export circuit independent(): [] { const a = identity(first()); const b = identity(second()); assert(a == owner, "guard"); entries.insert(disclose(b), 1); }
export circuit digestBound(): [] { const a = identity(first()); const b = identity(second()); assert(a == owner, "guard"); entries.insert(disclose(b), 1); assert(a == b, "binding"); }
export circuit inputBound(): [] { const a = first(); const b = second(); assert(identity(a) == owner, "guard"); assert(a == b, "binding"); entries.insert(disclose(identity(b)), 1); }
export circuit shared(): [] { const a = identity(first()); assert(a == owner, "guard"); entries.insert(disclose(a), 1); }
export circuit publicKey(key: Bytes<32>): [] { assert(identity(first()) == owner, "guard"); entries.insert(disclose(key), 1); }
export circuit unguarded(): [] { const a = identity(first()); entries.insert(disclose(identity(second())), 1); }
`, ["independent"]));
test("same witness declaration fresh calls stay independent; transitive constraints bind", () => check(`
export circuit fresh(): [] { const a = identity(first()); const b = identity(first()); assert(a == owner, "guard"); entries.insert(disclose(b), 1); }
export circuit transitive(): [] { const a = identity(first()); const b = identity(second()); const c = identity(first()); assert(a == owner, "guard"); assert(a == c, "one"); assert(c == b, "two"); entries.insert(disclose(b), 1); }
export circuit aborted(): [] { assert(identity(first()) == owner, "guard"); entries.insert(disclose(identity(second())), 1); assert(false, "abort"); }
`, ["fresh"]));
test("missing observers remains rule-scoped incomplete", () => {
  withFiles({ "main.compact": header + `export circuit entry(): [] { assert(identity(first()) == owner,"guard"); entries.insert(disclose(identity(second())),1); }` }, directory => {
    const facts = new Dataflow(new Program(resolve(directory,"main.compact"))).analyze();
    assert.deepEqual(rule.run(facts), []);
    assert.ok(facts.diagnostics.some(issue => issue.scope?.detectorId === rule.id));
  });
});
test("intentional independent beneficiary retains the same static observation", () => check(`
export circuit intentionalDelegation(): [] { assert(identity(first()) == owner, "administrator"); entries.insert(disclose(identity(second())), 1); }
export circuit preview(): Bytes<32> { assert(identity(first()) == owner, "administrator"); return disclose(identity(second())); }
`, ["intentionalDelegation"]));
test("experimental Counter absence has a closed no-witness certificate", () => {
  withFiles({ "main.compact": `import CompactStandardLibrary; export ledger count: Counter; export circuit entry(flag: Boolean): [] { if (disclose(flag)) { count.increment(1); } }` }, directory => {
    const result = scanFile(resolve(directory, "main.compact"), { detectors: [rule.id], experimentalCounterQueries: true });
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.deepEqual(result.findings, []);
  });
});
test("absence of native digests needs no observation evidence", () => {
  withFiles({ "main.compact": "import CompactStandardLibrary; ledger items: List<Field>; export circuit entry(): [] { assert(!items.isEmpty(), \"present\"); items.popFront(); }" }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    for (const engine of ["instructions", "expressions"] as const) {
      const facts = new Dataflow(program, 20000, 256, 50000, engine).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(rule.run(facts), []);
      assert.deepEqual(facts.diagnostics, []);
    }
  });
});
