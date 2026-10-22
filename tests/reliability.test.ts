import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";
import { isNoEntrypointsNotice } from "../src/model.js";

test("bounded malformed-input mutations produce reports, not exceptions", () => {
  const valid = "export circuit entry(flag: Boolean): Boolean { return flag; }";
  const variants = Array.from({ length: valid.length }, (_, index) => valid.slice(0, index));
  for (const source of variants) withFiles({ "main.compact": source }, directory => {
    const result = scanFile(resolve(directory, "main.compact"));
    assert.ok(["complete", "incomplete"].includes(result.status));
    if (result.diagnostics.some(issue => !isNoEntrypointsNotice(issue, result.coverage.noEntrypointRoots))) assert.equal(result.status, "incomplete");
    else if (result.diagnostics.length) {
      assert.equal(result.status, "complete");
      assert.deepEqual(result.entrypoints, []);
      assert.deepEqual(result.coverage.noEntrypointRoots, [resolve(directory, "main.compact")]);
    }
  });
});

test("aggregate budget exhaustion remains explicit", () => {
  withFiles({ "main.compact": "export circuit entry(values: Vector<8, Vector<8, Field>>): [] {}" }, directory => {
    const result = scanFile(resolve(directory, "main.compact"), { maxValues: 8 });
    assert.equal(result.status, "incomplete");
    assert.ok(result.diagnostics.some(diagnostic => diagnostic.code === "value-budget"));
    assert.equal(result.coverage.completedEntries.length, 0);
  });
});

test("step exhaustion does not diagnose a path shortage", () => {
  const cases = [
    { source: "export circuit entry(): [] {}", steps: 1, paths: 256, message: "Analysis step budget exhausted; results are incomplete" },
    { source: "export circuit entry(flag: Boolean): Boolean { return disclose(flag) ? true : false; }", steps: 20000, paths: 1, message: "Abstract path budget exhausted; results are incomplete" },
  ];
  for (const item of cases) withFiles({ "main.compact": item.source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(file);
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, item.steps, item.paths, 50000, engine, cached, cached).analyze();
      assert.deepEqual(facts.completedEntries, []);
      assert.deepEqual(facts.diagnostics.map(diagnostic => [diagnostic.code, diagnostic.message]), [["analysis-budget", item.message]]);
    }
  });
});

test("metamorphic formatting and local renaming preserve preimage findings", () => {
  const source = readFileSync("tests/corpus/vulnerable/direct.compact", "utf8");
  const variants = [source, source.replaceAll("secret", "localValue"), `/* preface 🌙 */\n${source}`, source.replaceAll(";", ";\n"), source.replace("const secret", "{ const unused = 0; } const secret")];
  for (const variant of variants) withFiles({ "main.compact": variant }, directory => {
    const result = scanFile(resolve(directory, "main.compact"));
    assert.deepEqual(result.diagnostics, []);
    assert.equal(result.findings.filter(finding => finding.detectorId === "ledger-bound-preimage-publication").length, 1);
  });
});

test("branch work exhaustion cannot look like a complete analysis", () => {
  const parameters = Array.from({ length: 10 }, (_, index) => `flag${index}: Boolean`).join(",");
  const branches = Array.from({ length: 10 }, (_, index) => `if (flag${index}) { count += 1; }`).join(" ");
  withFiles({ "main.compact": `import CompactStandardLibrary; export ledger count: Counter; export circuit entry(${parameters}): [] { ${branches} }` }, directory => {
    const result = scanFile(resolve(directory, "main.compact"), { maxPaths: 16 });
    assert.equal(result.status, "incomplete");
    assert.ok(result.diagnostics.some(diagnostic => diagnostic.code === "analysis-budget"));
  });
});

test("equivalent paths merge after dead condition variables leave scope", () => {
  const parameters = Array.from({ length: 20 }, (_, index) => `flag${index}: Boolean`).join(",");
  const branches = Array.from({ length: 20 }, (_, index) => `if (flag${index}) { disclose(flag${index}); }`).join(" ");
  withFiles({ "main.compact": `export circuit entry(${parameters}): [] { ${branches} }` }, directory => {
    const result = scanFile(resolve(directory, "main.compact"), { maxPaths: 64 });
    assert.deepEqual(result.diagnostics, []);
    assert.equal(result.metrics.paths, 1);
    assert.ok(result.metrics.steps < 200);
  });
});

test("liveness keeps values captured by a later anonymous circuit", () => {
  withFiles({ "main.compact": "export circuit entry(secret: Field, flag: Boolean): Field { if (flag) { disclose(flag); } const result = map((item: Field): Field => secret, [0 as Field]); return disclose(result[0]); }" }, directory => {
    const result = scanFile(resolve(directory, "main.compact"), { policies: { secrets: [{ circuit: "entry", parameter: "secret" }] } });
    assert.deepEqual(result.diagnostics, []);
    assert.equal(result.findings.filter(finding => finding.detectorId === "declared-secret-publication").length, 1);
  });
});

test("reserved compiler identifiers are rejected despite grammar acceptance", () => {
  for (const source of ["export circuit public(): [] {}", "struct Box { private: Field; }", "module class {}", "export circuit entry(): [] { const await = 1; }"]) withFiles({ "main.compact": source }, directory => {
    const report = scanFile(resolve(directory, "main.compact"));
    assert.equal(report.status, "incomplete");
    assert.ok(report.diagnostics.some(diagnostic => diagnostic.code === "reserved-identifier" || diagnostic.code === "parse-error"));
  });
});
