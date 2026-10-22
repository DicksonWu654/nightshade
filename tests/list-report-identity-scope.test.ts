import assert from "node:assert/strict";
import test from "node:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Dataflow, Program, scanFile } from "../src/index.js";
import { retainedListGrowth } from "../src/dataflow/list-growth.js";
import { ReportIdentityKeys } from "../src/reporting/identity-keys.js";

const header = "import CompactStandardLibrary;export ledger records:Map<Bytes<32>,List<Bytes<32>>>;";
const params = "recipient:Bytes<32>,color:Bytes<32>,amount:Uint<128>,memo:Bytes<32>";
const body = "const dest=persistentHash<Bytes<32>>(recipient);sendUnshielded(disclose(color),disclose(amount),right<ContractAddress,UserAddress>(UserAddress{bytes:disclose(dest)}));records.lookup(disclose(dest)).pushFront(disclose(memo));";
const source = header + ["first", "second"].map(name => `export circuit ${name}(${params}):[]{${body}}`).join("\n");

test("List report identities distinguish separate entry passes and survive relocation", context => {
  const temporary = mkdtempSync(join(tmpdir(), "ns-list-report-"));
  try {
    const short = join(temporary, "s");
    let long = temporary;
    while (long.length < 320) long = join(long, "long-checkout-0123456789-abcdef");
    const reports = [short, long].map(directory => {
      mkdirSync(directory, { recursive: true });
      const file = join(directory, "main.compact"); writeFileSync(file, source);
      const program = new Program(file), raw: string[] = [];
      for (const entry of program.entries) {
        const facts = new Dataflow(program).analyzeZeroTransferListEntry(entry);
        assert.deepEqual(facts.diagnostics, []);
        retainedListGrowth(facts, item => raw.push(item.address));
      }
      assert.equal(raw.length, 2);
      assert.equal(new Set(raw).size, 2, "analysis receivers must be distinct");
      const runs = [0, 1].map(() => {
        const result = scanFile(file, { detectors: ["zero-transfer-retained-list-review"] });
        assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
        assert.equal(result.findings.length, 2);
        const reported = result.findings.map(item => item.metadata?.selectedAddress);
        assert.equal(new Set(reported).size, 2, "different entries must not restart the same report token namespace");
        return JSON.parse(JSON.stringify({ status: result.status, coverage: result.coverage,
          diagnostics: result.diagnostics, findings: result.findings,
          metrics: Object.fromEntries(Object.entries(result.metrics).filter(([key]) => !key.endsWith("Ms"))),
          ruleObservationWork: result.ruleObservationWork }).replaceAll(directory, "<ROOT>"));
      });
      assert.deepEqual(runs[1], runs[0], "a new scan must reproduce the same token assignment");
      context.diagnostic(JSON.stringify({ pathLength: directory.length, raw: raw.length, distinctReported: 2 }));
      return runs[0];
    });
    assert.deepEqual(reports[1], reports[0]);
  } finally { rmSync(temporary, { recursive: true, force: true }); }
});

test("report-key tables retain raw distinctions across every construction in one scan", () => {
  const temporary = mkdtempSync(join(tmpdir(), "ns-report-scope-"));
  try {
    const file = join(temporary, "main.compact");
    writeFileSync(file, "export circuit entry(value:Field):Field{return value;}");
    const program = new Program(file);
    const table = () => new ReportIdentityKeys(program, "test-rule", program.rootSource.ast.span);
    const first = table(), second = table();
    const left = "hash-derived:" + "a".repeat(64), right = "hash-derived:" + "b".repeat(64);
    assert.notEqual(first.key(left), second.key(right));
    assert.equal(first.key(left), second.key(left));
    assert.equal(first.key(right), second.key(right));
    assert.equal(first.domain(left), second.domain(left));
    assert.notEqual(first.domain(left), second.domain(right));
    assert.equal(first.opaqueIdentity(left), second.opaqueIdentity(left));
    assert.notEqual(first.opaqueIdentity(left), second.opaqueIdentity(right));
    assert.notEqual(first.opaqueIdentity(left), first.domain(left));
  } finally { rmSync(temporary, { recursive: true, force: true }); }
});
