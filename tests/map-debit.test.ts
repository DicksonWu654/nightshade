import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile, scanFileIsolated } from "../src/index.js";
import { mapDebitAmountCandidates } from "../src/dataflow/map-debit.js";
import { zeroAmountUnguardedMapDebitReview as rule } from "../src/detectors/map-debit.js";
import { withFiles } from "./helpers.js";

const debitFixture = (kind: string) => resolve(`tests/corpus/synthetic-regressions/state16/zero-amount-unguarded-map-debit-review-case-2-${kind}.compact`);
const header = `pragma language_version >= 0.26.0;
import CompactStandardLibrary;
export ledger balances: Map<Bytes<32>, Uint<64>>;
`;
const entry = (body: string) => `${header}export circuit debit(key: Bytes<32>, other: Bytes<32>, amount: Uint<64>): [] {
${body}
}`;
const debit = `const prior = balances.lookup(disclose(key));
balances.insert(disclose(key), disclose((prior - disclose(amount)) as Uint<64>));`;

function scanSource(body: string, expected: number, status = "complete") {
  withFiles({ "main.compact": entry(body) }, directory => {
    const file = resolve(directory, "main.compact");
    const result = scanFile(file, { detectors: [rule.id] });
    assert.equal(result.status, status, JSON.stringify(result.diagnostics));
    assert.equal(result.findings.length, expected, JSON.stringify(result.diagnostics));
    assert.equal(scanFile(file).findings.some(finding => finding.detectorId === rule.id), false);
  });
}

test("frozen map-debit source lookup is the sole debit finding and controls are quiet", () => {
  for (const [kind, expected] of [["positive", 1], ["corrected", 0], ["lookalike", 0]] as const) {
    const result = scanFile(debitFixture(kind), { detectors: [rule.id] });
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.equal(result.findings.length, expected);
    if (expected) {
      assert.equal(result.findings[0].location.line, 7);
      assert.equal(result.findings[0].severity, "info");
      assert.equal(result.findings[0].metadata.membershipBeforeLookup, "unknown");
      assert.equal(result.findings[0].metadata.initiallyMissing, "not-proven");
    }
  }
});

test("exact membership and prior insertion suppress only their own entry", () => {
  scanSource(`assert(balances.member(disclose(key)), "existing"); ${debit}`, 0);
  scanSource(`assert(balances.member(disclose(other)), "other"); ${debit}`, 1);
  scanSource(`balances.insert(disclose(key), 1 as Uint<64>); ${debit}`, 0);
  scanSource(`const unused = balances.lookup(disclose(key)); ${debit}`, 0);
  scanSource(`const prior = balances.lookup(disclose(key)); assert(balances.member(disclose(key)), "late"); balances.insert(disclose(key), disclose((prior - disclose(amount)) as Uint<64>));`, 1);
});

test("actual zero debit amount and exact subtraction select the candidate", () => {
  scanSource(`if (disclose(amount) > 0) { ${debit} }`, 0);
  scanSource(`const prior = balances.lookup(disclose(key)); balances.insert(disclose(key), disclose((prior + disclose(amount)) as Uint<64>));`, 0);
  scanSource(`const prior = balances.lookup(disclose(key)); balances.insert(disclose(key), disclose((prior - 0 as Uint<64>) as Uint<64>));`, 1);
  scanSource(`const prior = balances.lookup(disclose(key)); balances.insert(disclose(other), disclose((prior - disclose(amount)) as Uint<64>));`, 0);
});

test("ordinary candidate and zero history agree across instruction/reference and cache modes", () => {
  const program = new Program(debitFixture("positive"));
  const exported = program.entries.find(id => program.symbols.get(id)?.name === "update")!;
  let reference: unknown;
  for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
    const ordinary = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyzeMapDebitCandidates(exported);
    const amounts = mapDebitAmountCandidates(ordinary, exported, 40000 - ordinary.metrics.steps);
    assert.equal(amounts.length, 1);
    const zero = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyzeZeroMapDebitEntry(exported, amounts[0]);
    assert.deepEqual(ordinary.diagnostics, []); assert.deepEqual(zero.diagnostics, []);
    const result = rule.run(zero);
    assert.equal(result.length, 1);
    reference ??= result;
    assert.deepEqual(result, reference, `${engine}/${cached}`);
    assert.deepEqual(rule.run(new Dataflow(program).analyzeSubset([exported])), []);
  }
});

test("repeated helper calls bind each actual entry amount", () => {
  const source = `${header}circuit applyDebit(key: Bytes<32>, amount: Uint<64>): [] {
  if (disclose(amount) == 0 as Uint<64>) {
    const prior = balances.lookup(disclose(key));
    balances.insert(disclose(key), disclose((prior - amount) as Uint<64>));
  }
}
export circuit batch(first: Bytes<32>, second: Bytes<32>, firstAmount: Uint<64>, secondAmount: Uint<64>): [] {
  applyDebit(disclose(first), disclose(firstAmount));
  applyDebit(disclose(second), disclose(secondAmount));
}`;
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact"), program = new Program(file);
    const exported = program.entries.find(id => program.symbols.get(id)?.name === "batch")!;
    let reference: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const ordinary = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyzeMapDebitCandidates(exported);
      const amounts = mapDebitAmountCandidates(ordinary, exported, 40000 - ordinary.metrics.steps);
      assert.equal(amounts.length, 2);
      const findings = amounts.flatMap(amount => {
        const zero = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyzeZeroMapDebitEntry(exported, amount);
        assert.deepEqual(zero.diagnostics, []);
        return rule.run(zero);
      });
      assert.equal(findings.length, 2);
      assert.equal(new Set(findings.map(finding => finding.fingerprint)).size, 2);
      reference ??= findings;
      assert.deepEqual(findings, reference, `${engine}/${cached}`);
    }
    const scanned = scanFile(file, { detectors: [rule.id] });
    assert.equal(scanned.status, "complete"); assert.equal(scanned.findings.length, 2);
  });
});

test("worker scan retains the selected rule result", async () => {
  const result = await scanFileIsolated(debitFixture("positive"), { detectors: [rule.id] });
  assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
  assert.deepEqual(result.findings.map(finding => finding.location.line), [7]);
});

test("an independent existing review keeps its complete finding object", () => {
  const source = entry(`balances.insert(disclose(other), disclose(amount)); ${debit}`)
    .replace("export ledger balances:", "export ledger values: Map<Bytes<32>, Uint<64>>;\nexport ledger balances:")
    .replace("balances.insert(disclose(other), disclose(amount));", "values.insert(disclose(other), disclose(amount));");
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    const existing = scanFile(file, { detectors: ["caller-key-zero-entry-review"] });
    const combined = scanFile(file, { detectors: ["caller-key-zero-entry-review", rule.id] });
    assert.equal(existing.status, "complete"); assert.equal(combined.status, "complete");
    assert.equal(existing.findings.length, 1);
    assert.deepEqual(combined.findings.filter(finding => finding.detectorId === "caller-key-zero-entry-review"), existing.findings);
    assert.equal(combined.findings.filter(finding => finding.detectorId === rule.id).length, 1);
  });
});

test("exhausted baseline or relation work remains an incomplete scan", () => {
  for (const maxSteps of [25, 250]) {
    const result = scanFile(debitFixture("positive"), { detectors: [rule.id], maxSteps });
    assert.equal(result.status, "incomplete");
    assert.equal(result.findings.length, 0);
    assert.ok(result.diagnostics.length > 0);
    assert.ok(result.coverage.rules?.some(row => row.detectorId === rule.id && row.status === "incomplete"));
  }
});

test("checkpoint and failed invocation evidence stays diagnostic", () => {
  for (const [body, code] of [[`${debit} kernel.checkpoint();`, "zero-entry-checkpoint-unavailable"],
    [`${debit} assert(false, "stop");`, "map-debit-candidates-unavailable"]] as const) {
    withFiles({ "main.compact": entry(body) }, directory => {
      const result = scanFile(resolve(directory, "main.compact"), { detectors: [rule.id] });
      assert.equal(result.status, "incomplete"); assert.equal(result.findings.length, 0);
      assert.ok(result.diagnostics.some(issue => issue.code === code), JSON.stringify(result.diagnostics));
    });
  }
});

test("legitimate empty dedicated history has explicit operations", () => {
  withFiles({ "main.compact": entry(`if (disclose(amount) > 0) { ${debit} }`) }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const exported = program.entries.find(id => program.symbols.get(id)?.name === "debit")!;
    const amount = program.functions.get(exported)!.declaration.parameters.find(parameter => parameter.name === "amount")!.symbol!;
    const facts = new Dataflow(program).analyzeZeroMapDebitEntry(exported, amount);
    assert.equal(facts.diagnostics.length, 0);
    assert.ok(facts.paths.length > 0);
    assert.ok(facts.paths.every(path => Array.isArray(path.operations)));
    assert.deepEqual(rule.run(facts), []);
    assert.deepEqual(facts.diagnostics, []);
  });
});

test("malformed dedicated operation and write snapshots never become clean absences", () => {
  const program = new Program(debitFixture("positive"));
  const exported = program.entries.find(id => program.symbols.get(id)?.name === "update")!;
  const amount = program.functions.get(exported)!.declaration.parameters.find(parameter => parameter.name === "amount")!.symbol!;
  const broken = (change: (path: NonNullable<ReturnType<Dataflow["analyzeZeroMapDebitEntry"]>["paths"]>[number]) => void) => {
    const facts = new Dataflow(program).analyzeZeroMapDebitEntry(exported, amount);
    assert.equal(facts.diagnostics.length, 0);
    const path = { ...facts.paths[0], operations: facts.paths[0].operations?.map(operation => ({ ...operation,
      args: operation.args.slice(), membership: operation.membership && { ...operation.membership } })),
      writes: facts.paths[0].writes.map(write => ({ ...write })) };
    change(path);
    facts.paths = [path];
    assert.deepEqual(rule.run(facts), []);
    assert.ok(facts.diagnostics.some(issue => issue.code === "map-debit-evidence-unavailable"), JSON.stringify(facts.diagnostics));
  };
  broken(path => { delete path.operations; });
  broken(path => { delete (path as { writes?: unknown }).writes; });
  broken(path => { delete path.operations!.find(operation => operation.kind === "map-lookup" && operation.result.mapDebitLookupOrigin)!.membership; });
  broken(path => { path.operations!.find(operation => operation.kind === "map-lookup" && operation.result.mapDebitLookupOrigin)!.args = []; });
  broken(path => { delete path.operations!.find(operation => operation.kind === "map-lookup" && operation.result.mapDebitLookupOrigin)!.result.mapDebitLookupOrigin; });
  broken(path => { path.operations!.find(operation => operation.kind === "collection-write" && operation.name === "insert")!.args.length = 2; });
  broken(path => { path.operations!.find(operation => operation.kind === "collection-write" && operation.name === "insert")!.writesBefore = 999; });
  broken(path => {
    const operation = path.operations!.find(item => item.kind === "collection-write" && item.name === "insert")!;
    const position = operation.writesBefore!;
    path.writes[position] = { ...path.writes[position], location: { ...path.writes[position].location, start: path.writes[position].location.start + 1 } };
  });
  broken(path => {
    const operation = path.operations!.find(item => item.kind === "collection-write" && item.name === "insert")!;
    const position = operation.writesBefore!;
    path.writes[position] = { ...path.writes[position], callSites: [operation.location] };
  });
});
