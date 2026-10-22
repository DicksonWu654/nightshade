import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { Dataflow, Program, scanFile } from "../src/index.js";
import { shieldedContractRecipientReview as rule, contractRecipientReviewPass } from "../src/detectors/contract-recipient.js";
import { observeContractRecipient } from "../src/analysis/contract-recipient-observation.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const draft = (name: string) => resolve("tests/corpus/drafts/contract-recipient45", `${name}.compact`);
const frozen = (name: string) => resolve("tests/corpus/synthetic-regressions/privacy16/contract-recipient-claim", `${name}.compact`);
const source = readFileSync(draft("positive"), "utf8");

test("owned contract recipient surfaces compile with the supported offline compiler", { skip: !process.env.COMPACTC_TEST }, () => {
  for (const name of readdirSync("tests/corpus/drafts/contract-recipient45").filter(name => name.endsWith(".compact"))) {
    const result = validateWithCompiler(process.env.COMPACTC_TEST!, resolve("tests/corpus/drafts/contract-recipient45", name), [], 30000, 2, "0.34.0");
    assert.equal(result.valid, true, `${name}: ${result.error}`);
  }
});

test("core triplet and distinct self/account controls preserve exact canonical operands", () => {
  for (const name of ["positive", "explicit-contract", "qualified-send", "helper-forwarding", "distinct-tag-guard", "prefixed-import"]) {
    const result = scanFile(draft(name), { detectors: [rule.id] });
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.equal(result.findings.length, 1, name);
    const finding = result.findings[0];
    assert.equal(finding.severity, "info");
    assert.equal(finding.metadata.activeArm, "right");
    assert.equal(finding.metadata.nonSelf, "enforced-exact-immutable-bytes-relation");
    assert.equal(finding.metadata.claimPresence, "not-inferred");
    assert.equal(finding.metadata.transactionRejection, "not-inferred");
    assert.equal(finding.metadata.fullRecordRecallCredit, false);
    assert.equal(finding.location.file, draft(name));
  }
  for (const name of ["corrected", "lookalike", "self-recipient", "account-recipient", "late-account-guard", "aborts-after-send", "zero-iteration-callback"]) {
    const result = scanFile(draft(name), { detectors: [rule.id] });
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.deepEqual(result.findings, [], name);
  }
  assert.equal(rule.defaultEnabled, false);
  assert.equal(scanFile(draft("positive")).findings.some(finding => finding.detectorId === rule.id), false);
});

test("frozen lookalike has the same source obligation and cannot earn full-record credit", () => {
  for (const [name, count] of [["positive", 1], ["corrected", 0], ["lookalike", 1]] as const) {
    const result = scanFile(frozen(name), { detectors: [rule.id] });
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.equal(result.findings.length, count, name);
  }
});

test("ordinary and tag-specialized histories agree across engines and caches", () => {
  for (const name of ["positive", "corrected", "self-recipient", "helper-forwarding", "late-account-guard", "prefixed-import", "zero-iteration-callback"]) {
    const program = new Program(draft(name)), entry = program.entries[0];
    const parameter = program.functions.get(entry)!.declaration.parameters.find(part => part.name === "recipient")?.symbol;
    for (const specialized of [undefined, ...(parameter ? [parameter] : [])]) {
      let expected: unknown;
      for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
        const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyzeContractRecipientEntry(entry, specialized);
        const findings = contractRecipientReviewPass(facts, true);
        assert.deepEqual(facts.diagnostics, [], `${name}/${engine}/${cached}`);
        expected ??= findings;
        assert.deepEqual(findings, expected, `${name}/${engine}/${cached}`);
      }
    }
  }
});

test("a sibling receiver guard and a visible receive do not certify claim composition", () => {
  const withReceive = source.replace("  return sendImmediateShielded", "  receiveShielded(disclose(coin));\n  return sendImmediateShielded");
  withFiles({ "main.compact": withReceive }, directory => {
    const result = scanFile(resolve(directory, "main.compact"), { detectors: [rule.id] });
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.equal(result.findings.length, 1);
  });
  withFiles({ "main.compact": source.replaceAll("pay", "dispatch").replaceAll("recipient", "destination").replaceAll("coin", "asset") }, directory => {
    const result = scanFile(resolve(directory, "main.compact"), { detectors: [rule.id] });
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.equal(result.findings.length, 1);
  });
});

test("opaque recipients, lost original evidence and exhausted allowances refuse findings", () => {
  const opaque = scanFile(draft("opaque-recipient"), { detectors: [rule.id] });
  assert.equal(opaque.status, "incomplete"); assert.deepEqual(opaque.findings, []);
  assert.ok(opaque.diagnostics.some(issue => issue.code === "contract-recipient-evidence-unavailable"));
  const program = new Program(draft("positive")), entry = program.entries[0];
  const parameter = program.functions.get(entry)!.declaration.parameters[1].symbol!;
  for (const lose of [(facts: ReturnType<Dataflow["analyze"]>) => { facts.paths[0].predicates = undefined; },
    (facts: ReturnType<Dataflow["analyze"]>) => { facts.paths[0].operations!.pop(); },
    (facts: ReturnType<Dataflow["analyze"]>) => { facts.contractRecipientEvidence!.histories++; },
    (facts: ReturnType<Dataflow["analyze"]>) => { facts.contractRecipientEvidence!.maxValues = facts.metrics.abstractValues + 1; }]) {
    const facts = new Dataflow(program).analyzeContractRecipientEntry(entry, parameter);
    lose(facts);
    assert.deepEqual(rule.run(facts), []);
    assert.ok(facts.diagnostics.some(issue => issue.code === "contract-recipient-evidence-unavailable"));
  }
  for (const limits of [{ maxSteps: 1 }, { maxSteps: 80 }, { maxValues: 1 }, { maxValues: 80 }, { maxPaths: 1 }]) {
    const result = scanFile(draft("positive"), { detectors: [rule.id], ...limits });
    assert.equal(result.status, "incomplete", JSON.stringify(limits));
    assert.deepEqual(result.findings, []);
    assert.ok(result.coverage.rules!.some(row => row.detectorId === rule.id && row.status === "incomplete"));
  }
  const unavailable = observeContractRecipient(program, rule, {}, new Set());
  assert.deepEqual(unavailable.findings, []);
  assert.equal(unavailable.coverage[0].status, "incomplete");
  const unqualified = scanFile(draft("positive"), { detectors: [rule.id], compilerVersion: "0.35.0" });
  assert.equal(unqualified.status, "incomplete"); assert.deepEqual(unqualified.findings, []);
});

test("standalone ordinary facts refuse pending raw tags and entry passes share path admission", () => {
  const program = new Program(draft("positive")), entry = program.entries[0];
  const parameter = program.functions.get(entry)!.declaration.parameters[1].symbol!;
  const ordinary = new Dataflow(program).analyzeContractRecipientEntry(entry);
  assert.deepEqual(rule.run(ordinary), []);
  assert.ok(ordinary.diagnostics.some(issue => issue.message.includes("separately completed right-arm specialization")));
  const pending = new Dataflow(program).analyzeContractRecipientEntry(entry);
  const deferred = contractRecipientReviewPass(pending, true);
  assert.deepEqual(pending.diagnostics, []);
  assert.deepEqual(deferred.pendingParameters, [parameter]);
  assert.deepEqual(pending.contractRecipientEvidence!.pendingTagParameters, [parameter]);
  const right = new Dataflow(program).analyzeContractRecipientEntry(entry, parameter);
  assert.deepEqual(right.diagnostics, []);
  const limit = Math.max(pending.paths.length, right.paths.length);
  assert.ok(pending.paths.length + right.paths.length > limit);
  // Baseline and both individual passes fit; the combined observer admission
  // cannot fit in that same unchanged allowance.
  assert.equal(new Dataflow(program, 40000, limit, 50000).analyze().completedEntries.includes(entry), true);
  assert.deepEqual(new Dataflow(program, 40000, limit, 50000).analyzeContractRecipientEntry(entry).diagnostics, []);
  assert.deepEqual(new Dataflow(program, 40000, limit, 50000).analyzeContractRecipientEntry(entry, parameter).diagnostics, []);
  const exhausted = observeContractRecipient(program, rule, { maxPaths: limit });
  assert.deepEqual(exhausted.findings, []);
  assert.equal(exhausted.coverage[0].status, "incomplete");
  assert.ok(exhausted.diagnostics.some(issue => issue.message.includes("shared entry path allowance")));
});

test("multiple native send operands complete every named tag specialization", () => {
  const pair = `pragma language_version >= 0.26.0;
import CompactStandardLibrary;
export circuit pay(first: ShieldedCoinInfo, second: ShieldedCoinInfo, one: Either<ZswapCoinPublicKey, ContractAddress>, two: Either<ZswapCoinPublicKey, ContractAddress>): [] {
  sendImmediateShielded(disclose(first), disclose(one), 1);
  sendImmediateShielded(disclose(second), disclose(two), 1);
}`;
  withFiles({ "main.compact": pair }, directory => {
    const file = resolve(directory, "main.compact"), program = new Program(file), entry = program.entries[0];
    const facts = new Dataflow(program).analyzeContractRecipientEntry(entry);
    const pass = contractRecipientReviewPass(facts, true);
    assert.deepEqual(pass.pendingParameters, program.functions.get(entry)!.declaration.parameters.slice(2).map(part => part.symbol));
    assert.deepEqual(facts.diagnostics, []);
    const result = scanFile(file, { detectors: [rule.id] });
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.deepEqual(result.findings.map(finding => finding.location.line), [4, 5]);
  });
});

test("canonical checkpoints and unresolved effects cannot certify quiet coverage", () => {
  for (const effect of ["kernel.checkpoint();", "missingEffect();"]) {
    withFiles({ "main.compact": source.replace("  return sendImmediateShielded", `  ${effect}\n  return sendImmediateShielded`) }, directory => {
      const result = scanFile(resolve(directory, "main.compact"), { detectors: [rule.id] });
      assert.equal(result.status, "incomplete"); assert.deepEqual(result.findings, []);
    });
  }
});
