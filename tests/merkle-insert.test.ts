import assert from "node:assert/strict";
import { resolve } from "node:path";
import test from "node:test";
import { scanFile, Program, Dataflow } from "../src/index.js";
import { merkleInsertFindings } from "../src/detectors/merkle-insert.js";
import { MERKLE_INSERT_OBSERVER, MERKLE_INSERT_RULE } from "../src/semantic/merkle-targets.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const header = `import CompactStandardLibrary;
export ledger tree: MerkleTree<4, Field>;
export ledger seen: Set<Field>;
export ledger unrelated: Set<Field>;
circuit absent(value: Field): [] { assert(!seen.member(value), "duplicate"); }
circuit remember(value: Field): [] { seen.insert(value); }
export circuit probe(value: Field, other: Field, flag: Boolean): [] {`;
function inspect(source: string, expected: number) {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file, [], 30000, 2, "0.34.0");
      assert.equal(compiled.valid, true, compiled.error);
    }
    for (const experimentalCounterQueries of [false, true]) {
      const scan = scanFile(file, { detectors: [MERKLE_INSERT_RULE], experimentalCounterQueries });
      assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics));
      assert.equal(scan.findings.length, expected, source);
      assert.deepEqual(scan.diagnostics, []);
      for (const item of scan.findings) assert.equal(item.metadata.capacityExhaustion, "not-proven");
    }
    const program = new Program(file);
    for (const [engine, cached] of [["instructions", true], ["instructions", false], ["expressions", false]] as const) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, false,
        "all", false, true, false, false, false, false, false, false, false, false,
        new Set([MERKLE_INSERT_OBSERVER])).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.equal(merkleInsertFindings(facts).length, expected, source);
      assert.deepEqual(facts.diagnostics, []);
    }
  });
}
const check = (body: string, expected: number) => inspect(`${header}${body}}`, expected);

test("owned bounded Merkle insertion triplet detects the previously measured gap", () => {
  for (const variant of ["positive", "corrected", "lookalike"]) {
    const file = resolve(`tests/corpus/known-bugs/counter-merkle-insert-dedupe-${variant}.compact`);
    if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, file).valid, true);
    for (const experimentalCounterQueries of [false, true]) {
      const scan = scanFile(file, { detectors: [MERKLE_INSERT_RULE], experimentalCounterQueries });
      assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics));
      assert.deepEqual(scan.findings.map(item => item.location.line), variant === "positive" ? [31] : []);
    }
    assert.equal(scanFile(file).findings.some(item => item.detectorId === MERKLE_INSERT_RULE), false);
  }
});

test("exact absence and surviving remembering writes support helper aliases and equality", () => {
  check(`const saved = disclose(value); absent(saved); tree.insert(saved); remember(saved);`, 0);
  check(`const saved = disclose(value); absent(saved); remember(saved); tree.insert(saved);`, 0);
  check(`assert(value == other, "equal"); absent(disclose(other)); tree.insert(disclose(value)); remember(disclose(other));`, 0);
  check(`const saved = disclose(value); const missing = !seen.member(saved); assert(missing == true, "absent"); tree.insert(saved); remember(saved);`, 0);
});

test("unrelated, ignored, late and stale guards cannot certify per-insertion dedupe", () => {
  check(`tree.insert(disclose(value));`, 1);
  check(`absent(disclose(other)); tree.insert(disclose(value)); remember(disclose(value));`, 1);
  check(`const ignored = seen.member(disclose(value)); tree.insert(disclose(value)); remember(disclose(value));`, 1);
  check(`tree.insert(disclose(value)); absent(disclose(value)); remember(disclose(value));`, 1);
  check(`absent(disclose(value)); seen.resetToDefault(); tree.insert(disclose(value)); remember(disclose(value));`, 1);
  check(`absent(disclose(value)); tree.insert(disclose(value)); remember(disclose(value)); seen.remove(disclose(value));`, 1);
  check(`absent(disclose(value)); tree.insert(disclose(value)); unrelated.insert(disclose(value));`, 1);
});

test("exclusive histories and repeated insertions cannot share missing guards", () => {
  check(`if (disclose(flag)) { absent(disclose(value)); } tree.insert(disclose(value)); remember(disclose(value));`, 1);
  check(`absent(disclose(value)); tree.insert(disclose(value)); tree.insert(disclose(value)); remember(disclose(value));`, 1);
  check(`absent(disclose(value)); tree.insert(disclose(value)); if (disclose(flag)) { remember(disclose(value)); }`, 1);
  const helper = header.replace('export circuit probe', 'circuit append(value: Field): [] { tree.insert(value); }\nexport circuit probe');
  inspect(`${helper}absent(disclose(value)); append(disclose(value)); append(disclose(value)); remember(disclose(value));}`, 1);
  inspect(`${helper}absent(disclose(value)); append(disclose(value)); remember(disclose(value)); absent(disclose(other)); append(disclose(other)); remember(disclose(other));}`, 0);
});

test("receiver selectors are immutable and wildcard may-alias is never equality", () => {
  const source = (key: string) => `import CompactStandardLibrary;
export ledger tree: MerkleTree<4, Field>;
export ledger collections: Map<Field, Set<Field>>;
export circuit probe(a: Field, b: Field, value: Field): [] {
  assert(!collections.lookup(disclose(a)).member(disclose(value)), "absent");
  tree.insert(disclose(value));
  collections.lookup(disclose(${key})).insert(disclose(value));
}`;
  inspect(source("a"), 0);
  inspect(source("b"), 1);
  inspect(source("b").replace('assert(!collections', 'assert(a == b, "same receiver"); assert(!collections'), 0);
  const rememberFirst = source("b").replace('tree.insert(disclose(value));\n  ', '')
    .replace('collections.lookup(disclose(b)).insert(disclose(value));', 'collections.lookup(disclose(b)).insert(disclose(value)); tree.insert(disclose(value));');
  inspect(rememberFirst.replace('assert(!collections', 'assert(a == b, "same receiver"); assert(!collections'), 0);
  inspect(rememberFirst, 1);
});

test("indexed replacement and constructor setup are outside sequential repeat review", () => {
  inspect(`import CompactStandardLibrary;
export ledger tree: MerkleTree<4, Field>;
constructor() { tree.insert(1 as Field); }
export circuit replace(value: Field): [] { tree.insertIndex(disclose(value), 0); }`, 0);
});

test("missing exact evidence and exhausted allowances remain rule-scoped incomplete", () => {
  withFiles({ "main.compact": `${header}tree.insert(disclose(value));}` }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const facts = new Dataflow(program).analyze();
    assert.deepEqual(merkleInsertFindings(facts), []);
    assert.ok(facts.diagnostics.some(item => item.scope?.detectorId === MERKLE_INSERT_RULE));
    const scan = scanFile(program.root, { detectors: [MERKLE_INSERT_RULE], maxSteps: 1 });
    assert.equal(scan.status, "incomplete");
    assert.ok(scan.diagnostics.some(item => item.scope?.detectorId === MERKLE_INSERT_RULE));
    const exact = new Dataflow(program, 40000, 256, 50000, "instructions", true, true, "equivalent-states", false, false,
      "all", false, true, false, false, false, false, false, false, false, false, new Set([MERKLE_INSERT_OBSERVER])).analyze();
    assert.equal(merkleInsertFindings(exact).length, 1);
    assert.deepEqual(merkleInsertFindings(exact, 0), []);
    assert.ok(exact.diagnostics.some(item => item.scope?.detectorId === MERKLE_INSERT_RULE));
    const retained = new Dataflow(program, 40000, 256, 1, "instructions", true, true, "equivalent-states", false, false,
      "all", false, true, false, false, false, false, false, false, false, false, new Set([MERKLE_INSERT_OBSERVER])).analyze();
    assert.ok(retained.diagnostics.length);
    assert.deepEqual(retained.completedEntries, []);
  });
});
