import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { Program, scanFile, scanFileIsolated } from "../src/index.js";
import { closedCapacityScope } from "../src/semantic/closed-capacity.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { sha256 } from "./synthetic-regression-fixtures.js";
import { withFiles } from "./helpers.js";

const group = JSON.parse(readFileSync("tests/corpus/manifest.json", "utf8")).closedMembershipCapacity55 as {
  detector: string; cases: { file: string; sha256: string; lines: number[] }[];
};
for (const item of group.cases) test(`source-closed capacity boundary: ${item.file}`, () => {
  const file = resolve("tests/corpus", item.file);
  assert.equal(sha256(readFileSync(file)), item.sha256);
  if (process.env.COMPACTC_TEST) {
    const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file, [], 30000, 3);
    assert.equal(compiled.valid, true, compiled.error);
  }
  const report = scanFile(file, { detectors: [group.detector], compilerVersion: "0.34.0", zkirVersion: 3 });
  assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
  assert.deepEqual(report.findings.map(finding => finding.location.line), item.lines);
  for (const finding of report.findings) {
    assert.equal(finding.severity, "info");
    assert.equal(finding.metadata.noPostConstructorWriter, true);
    assert.equal(finding.metadata.allConfigurations, "unproven");
    assert.equal(finding.metadata.runtimeImmutability, "unproven");
  }
});

test("closed capacity source closure honors whole-root may-effects and unresolved targets", () => {
  withFiles({ "main.compact": `import CompactStandardLibrary; export ledger members: Set<Bytes<32>>;
    constructor(seed: Bytes<32>) { members.insert(disclose(seed)); }
    export circuit act(a: Bytes<32>): [] { assert(members.member(disclose(a)), "member"); }` }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const entry = program.entries.find(id => id.endsWith("::act"))!;
    const root = [...program.symbols.values()].find(symbol => symbol.kind === "ledger")!.id;
    assert.equal(closedCapacityScope(program, () => {}).writers.has(root), false);
    // Compact does not permit a Set value as an ordinary argument for root
    // assignment. Keep the conservative model boundary explicit nonetheless.
    program.functions.get(entry)!.writesState.add(root);
    assert.equal(closedCapacityScope(program, () => {}).writers.has(root), true);
    program.functions.get(entry)!.calls.add("missing-callable");
    assert.throws(() => closedCapacityScope(program, () => {}), /unresolved/);
  });
});

test("source-closed capacity supervised reporting preserves the direct observation", async () => {
  const file = resolve("tests/corpus/drafts/closed-capacity55/closed-one-vs-two.compact");
  const options = { detectors: [group.detector], compilerVersion: "0.34.0" as const, zkirVersion: 3 as const };
  const direct = scanFile(file, options), supervised = await scanFileIsolated(file, options);
  assert.equal(supervised.status, "complete", JSON.stringify(supervised.diagnostics));
  assert.deepEqual(supervised.findings, direct.findings);
  assert.deepEqual(supervised.coverage.rules, direct.coverage.rules);
});
