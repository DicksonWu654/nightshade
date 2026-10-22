import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { Dataflow, Program, scanFile } from "../src/index.js";
import { sarif } from "../src/reporting/index.js";
import { buildCFG } from "../src/cfg/index.js";

const corpus = resolve("tests/corpus");
const manifest = JSON.parse(readFileSync(resolve(corpus, "manifest.json"), "utf8")) as { detector: string; cases: { file: string; lines: number[] }[] };

for (const fixture of manifest.cases) {
  test(`corpus: ${fixture.file}`, () => {
    const result = scanFile(resolve(corpus, fixture.file), { compiler: process.env.COMPACTC_TEST });
    assert.deepEqual(result.diagnostics, []);
    assert.equal(result.status, "complete");
    assert.deepEqual(result.findings.map(finding => finding.location.line), fixture.lines);
    assert.ok(result.findings.every(finding => finding.detectorId === manifest.detector));
  });
}

const prefix = `pragma language_version >= 0.26.0;
import CompactStandardLibrary;
export ledger ownerHash: Bytes<32>;
export ledger published: Field;
witness ownerSecret(): Field;
constructor(initialHash: Bytes<32>) { ownerHash = disclose(initialHash); }
`;
const check = 'assert(persistentHash<Field>(secret) == ownerHash, "not authorized");';

function withFiles(files: Record<string, string>, callback: (directory: string) => void): void {
  const directory = mkdtempSync(resolve(tmpdir(), "nightshade-test-"));
  try {
    for (const [name, source] of Object.entries(files)) writeFileSync(resolve(directory, name), source);
    callback(directory);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

function expectBody(body: string, findings: number): void {
  withFiles({ "main.compact": `${prefix}export circuit update(flag: Boolean): [] { const secret = ownerSecret(); ${body} }` }, directory => {
    const result = scanFile(resolve(directory, "main.compact"));
    assert.deepEqual(result.diagnostics, []);
    assert.equal(result.findings.filter(finding => finding.detectorId === manifest.detector).length, findings);
  });
}

test("return prevents a later publication", () => expectBody(`${check} if (true) return []; published = disclose(secret);`, 0));
test("known false branch is not analyzed as reachable", () => expectBody(`${check} if (false) { published = disclose(secret); }`, 0));
test("a failed assertion discards pending ledger effects", () => expectBody(`${check} published = disclose(secret); assert(false, "abort");`, 0));
test("lexical shadowing does not inherit the outer source", () => expectBody(`${check} { const secret = 0 as Field; published = secret; }`, 0));
test("a shadow scope does not overwrite the outer source", () => expectBody(`${check} { const secret = 0 as Field; } published = disclose(secret);`, 1));
test("literal zero-iteration loops do not publish", () => expectBody(`${check} for (const counter of 0..0) { published = disclose(secret); }`, 0));
test("bounded loops retain witness provenance", () => expectBody(`${check} for (const counter of 0..2) { published = disclose(secret); }`, 1));
test("boolean disjunction does not manufacture a hash constraint", () => expectBody('assert(true || persistentHash<Field>(secret) == ownerHash, "ok"); published = disclose(secret);', 0));
test("optional left-hand equality is not a mandatory constraint", () => expectBody('assert(persistentHash<Field>(secret) == ownerHash || true, "ok"); published = disclose(secret);', 0));
test("boolean conjunction retains the mandatory hash constraint", () => expectBody('assert(true && persistentHash<Field>(secret) == ownerHash, "ok"); published = disclose(secret);', 1));
test("early return keeps checks off other paths", () => expectBody(`if (disclose(flag)) { ${check} return []; } published = disclose(secret);`, 0));
test("tuple projections preserve only the selected source", () => expectBody(`${check} const pair = [secret, 0 as Field]; published = disclose(pair[1]);`, 0));
test("tuple projections preserve raw identity", () => expectBody(`${check} const pair = [secret, 0 as Field]; published = disclose(pair[0]);`, 1));
test("self-written hash is not treated as a trusted preexisting ledger binding", () => expectBody(`ownerHash = disclose(persistentHash<Field>(secret)); ${check} published = disclose(secret);`, 0));

test("relative, selected, aliased and prefixed module imports resolve calls", () => {
  withFiles({
    "main.compact": `${prefix}import { identity as pass } from "Helper" prefix H_; export circuit update(): [] { const secret = ownerSecret(); ${check} published = disclose(H_pass(secret)); }`,
    "Helper.compact": "module Helper { export circuit identity(value: Field): Field { return value; } }",
  }, directory => {
    const result = scanFile(resolve(directory, "main.compact"));
    assert.deepEqual(result.diagnostics, []);
    assert.equal(result.findings.length, 1);
    assert.equal(result.scanned.length, 3);
    assert.ok(result.scanned.some(file => file.endsWith("/stdlib/standard-library.compact")));
    assert.ok(result.findings[0].trace.some(step => step.location.file.endsWith("Helper.compact")));
  });
});

test("imported exports are entrypoints only when re-exported", () => {
  withFiles({
    "main.compact": 'import { publish as entry } from "Helper"; export { entry };',
    "Helper.compact": `module Helper { ${prefix}export circuit publish(): [] { const secret = ownerSecret(); ${check} published = disclose(secret); } }`,
  }, directory => {
    const result = scanFile(resolve(directory, "main.compact"));
    assert.deepEqual(result.diagnostics, []);
    assert.equal(result.findings.length, 1);
  });
});

test("symbol identity prevents a user-defined hash function being treated as intrinsic", () => {
  withFiles({ "main.compact": `export ledger ownerHash: Bytes<32>; export ledger published: Field; witness ownerSecret(): Field; circuit persistentHash(value: Field): Bytes<32> { return pad(32, ""); } export circuit update(): [] { const secret = ownerSecret(); assert(persistentHash(secret) == ownerHash, "ok"); published = disclose(secret); }` }, directory => {
    const result = scanFile(resolve(directory, "main.compact"));
    assert.deepEqual(result.diagnostics, []);
    assert.equal(result.findings.length, 0);
  });
});

test("call graph and transitive state effects are queryable", () => {
  const program = new Program(resolve(corpus, "vulnerable/interprocedural.compact"));
  const update = [...program.functions.values()].find(fn => fn.symbol.name === "update")!;
  const publish = [...program.functions.values()].find(fn => fn.symbol.name === "publish")!;
  assert.ok(update.calls.has(publish.symbol.id));
  assert.ok([...update.readsState].some(id => id.endsWith("::ownerHash")));
  assert.ok([...update.writesState].some(id => id.endsWith("::published")));
  assert.ok(program.findCallers(publish.symbol.id).includes(update));
  assert.ok(program.findStateWriters([...update.writesState][0]).includes(update));
  assert.ok(update.cfg.isReachable(update.cfg.entry, update.cfg.exit));
});

test("resource exhaustion is explicit and never reported as complete", () => {
  const program = new Program(resolve(corpus, "vulnerable/direct.compact"));
  const facts = new Dataflow(program, 1).analyze();
  assert.ok(facts.diagnostics.some(item => item.code === "analysis-budget"));
});

test("CFG expansion has an independent size budget", () => {
  const program = new Program(resolve(corpus, "vulnerable/direct.compact"));
  const fn = [...program.functions.values()].find(fn => fn.symbol.name === "update")!;
  assert.throws(() => buildCFG(fn.declaration.body!, 4), /CFG expansion budget/);
});

test("fingerprints do not depend on checkout directory", () => {
  const source = readFileSync(resolve(corpus, "vulnerable/direct.compact"), "utf8");
  const fingerprints: string[] = [];
  for (let iteration = 0; iteration < 2; iteration++) withFiles({ "main.compact": source }, directory => fingerprints.push(scanFile(resolve(directory, "main.compact")).findings[0].fingerprint));
  assert.equal(fingerprints[0], fingerprints[1]);
});

test("enum references resolve by enum name rather than first variant", () => {
  withFiles({ "main.compact": "export enum State { OPEN, CLOSED } export ledger state: State; export circuit close(): [] { state = State.CLOSED; }" }, directory => {
    const result = scanFile(resolve(directory, "main.compact"));
    assert.deepEqual(result.diagnostics, []);
    assert.equal(result.entrypoints.length, 1);
  });
});

test("unresolved calls and parser recovery fail visibly", () => {
  for (const [source, code] of [["export circuit broken(): [] { mystery(); }", "unresolved-symbol"], ["export circuit broken(: [] {", "parse-error"]]) {
    withFiles({ "main.compact": source }, directory => {
      const result = scanFile(resolve(directory, "main.compact"));
      assert.equal(result.status, "incomplete");
      assert.equal(result.diagnostics[0].code, code);
    });
  }
});

test("generic argument mismatches and missing imports are explicit coverage errors", () => {
  for (const [source, code] of [["module Generic<T> {} import Generic;", "generic-arity"], ['import "Missing";', "unresolved-import"]]) {
    withFiles({ "main.compact": source }, directory => {
      const result = scanFile(resolve(directory, "main.compact"));
      assert.equal(result.status, "incomplete");
      assert.equal(result.diagnostics[0].code, code);
    });
  }
});

test("UTF-8 offsets and UTF-16 columns remain accurate after non-ASCII text", () => {
  const source = `${prefix}export circuit update(): [] { const secret = ownerSecret(); assert(persistentHash<Field>(secret) == ownerHash, "é 🌙"); published = disclose(secret); }`;
  withFiles({ "main.compact": source }, directory => {
    const finding = scanFile(resolve(directory, "main.compact")).findings[0];
    const expectedIndex = source.indexOf("published =");
    assert.equal(finding.location.start, Buffer.byteLength(source.slice(0, expectedIndex)));
    assert.equal(finding.location.column, expectedIndex - source.lastIndexOf("\n", expectedIndex));
    assert.equal(Buffer.from(source).subarray(finding.location.start, finding.location.end).toString(), "published = disclose(secret)");
  });
});

test("SARIF contains locations, rule identity, trace and incompleteness", () => {
  const result = scanFile(resolve(corpus, "vulnerable/direct.compact"));
  const output = sarif(result) as { version: string; runs: { results: { ruleId: string; codeFlows: unknown[] }[]; columnKind: string }[] };
  assert.equal(output.version, "2.1.0");
  assert.equal(output.runs[0].results[0].ruleId, manifest.detector);
  assert.equal(output.runs[0].columnKind, "utf16CodeUnits");
  assert.equal(output.runs[0].results[0].codeFlows.length, 1);
});

test("CLI JSON, SARIF, shorthand, detector listing and exit status", () => {
  const run = (...args: string[]) => spawnSync(process.execPath, [resolve("dist/src/cli.js"), ...args], { encoding: "utf8" });
  assert.equal(run("detector", "list").status, 0);
  const vulnerable = run(resolve(corpus, "vulnerable/direct.compact"), "--json");
  assert.equal(vulnerable.status, 1);
  assert.equal(JSON.parse(vulnerable.stdout).findings.length, 1);
  assert.equal(run("scan", resolve(corpus, "safe/hash-only.compact")).status, 0);
  const missing = run("does-not-exist", "--sarif");
  assert.equal(missing.status, 2);
  assert.equal(JSON.parse(missing.stdout).runs[0].invocations[0].executionSuccessful, false);
});
