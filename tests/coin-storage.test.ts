import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile, type AnalysisFacts } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles, semanticPaths } from "./helpers.js";

function compare(source: string, check: (facts: AnalysisFacts) => void): void {
  withFiles({ "main.compact": `import CompactStandardLibrary;\n${source}` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(file);
    let expected: AnalysisFacts | undefined;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 20000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      check(facts);
      if (expected) assert.deepEqual(semanticPaths(facts), semanticPaths(expected));
      else expected = facts;
    }
  });
}

test("coin writes preserve payloads, checked transaction index identity and retained snapshots", () => {
  compare(`ledger first: QualifiedShieldedCoinInfo;
ledger second: QualifiedShieldedCoinInfo;
circuit put(coin: ShieldedCoinInfo, recipient: Either<ZswapCoinPublicKey,ContractAddress>): [] { first.writeCoin(coin,recipient); }
export circuit entry(coin: ShieldedCoinInfo, recipient: Either<ZswapCoinPublicKey,ContractAddress>): Boolean {
  const c = disclose(coin); const r = disclose(recipient);
  put(c,r); const saved = first;
  second.writeCoin(c,r);
  put(ShieldedCoinInfo { ...c, value: 9 },r);
  assert(first.value == 9, "replacement");
  assert(second.value == saved.value, "preserved snapshot");
  return saved.mt_index == second.mt_index;
}`, facts => {
    assert.equal(facts.paths.length, 1);
    assert.deepEqual(facts.failedAssertions, []);
    const path = facts.paths[0];
    assert.equal(path.sinks.find(sink => sink.kind === "exported-return")!.value.constant, "true");
    const ops = path.operations!.filter(operation => operation.kind === "coin-qualification");
    assert.equal(ops.length, 3);
    assert.equal(ops[0].result.fields!.mt_index.identity, ops[1].result.fields!.mt_index.identity);
    assert.notEqual(ops[0].result.fields!.mt_index.identity, ops[2].result.fields!.mt_index.identity);
    assert.equal(ops[0].result.fields!.mt_index.constant, undefined, "Unknown transaction index is not invented");
    assert.ok(ops[0].result.fields!.nonce.flows.some(flow => flow.source.name === "coin" && flow.form === "raw"));
    assert.ok(ops[0].result.fields!.mt_index.flows.some(flow => flow.source.name === "recipient"));
    assert.equal(path.writes.length, 3);
    const sink = path.sinks.find(sink => sink.name === "first.writeCoin")!;
    assert.deepEqual(new Set(sink.value.flows.map(flow => flow.source.name)), new Set(["coin", "recipient"]));
    const nodes = facts.program.instructionCFG(facts.program.entries[0]).nodes;
    assert.ok(nodes.some(node => node.instruction?.kind === "evaluate" && node.instruction.expression.name === "writeCoin" && node.instruction.effects.includes("state-write")));
  });
});

test("qualified Map and List writes reuse collection updates and retain guarded operation histories", () => {
  compare(`ledger coins: Map<Field,QualifiedShieldedCoinInfo>;
ledger queue: List<QualifiedShieldedCoinInfo>;
ledger unique: Set<QualifiedShieldedCoinInfo>;
circuit authorize(permission: Boolean): [] { assert(permission,"permission required"); }
export circuit entry(permission: Boolean,flag: Boolean,coin: ShieldedCoinInfo): QualifiedShieldedCoinInfo {
  authorize(disclose(permission));
  const c = disclose(coin); const r = right<ZswapCoinPublicKey,ContractAddress>(kernel.self());
  coins.resetToDefault(); queue.resetToDefault(); unique.resetToDefault();
  if (disclose(flag)) { coins.insertCoin(1 as Field,c,r); }
  else { coins.insertCoin(1 as Field,c,r); coins.insertCoin(2 as Field,c,r); }
  assert(coins.member(1 as Field), "inserted");
  queue.pushFrontCoin(c,r); unique.insertCoin(c,r);
  assert(!queue.isEmpty(), "pushed"); assert(!unique.isEmpty(), "inserted coin");
  const saved = coins.lookup(1 as Field);
  coins.remove(1 as Field);
  assert(!coins.member(1 as Field), "removed");
  assert(queue.head().value.mt_index == saved.mt_index, "same transaction lookup");
  return disclose(saved);
}`, facts => {
    assert.equal(facts.paths.length, 2);
    assert.deepEqual(facts.failedAssertions, []);
    assert.deepEqual(facts.paths.map(path => path.operations!.filter(op => op.kind === "coin-qualification").length).sort(), [3,4]);
    for (const path of facts.paths) {
      const operation = path.operations!.find(op => op.kind === "coin-qualification")!;
      assert.ok(operation.control.some(value => value.flows.some(flow => flow.source.name === "flag")));
      assert.ok(operation.guards.some(guard => guard.endsWith("authorize")));
      assert.ok(path.sinks.find(sink => sink.kind === "exported-return")!.value.fields!.nonce.flows.some(flow => flow.source.name === "coin"));
    }
  });
});

test("coin method lookalikes cannot qualify a different stored type", () => {
  withFiles({ "main.compact": `import CompactStandardLibrary;
ledger value: ShieldedCoinInfo;
export circuit entry(coin: ShieldedCoinInfo): [] { value.writeCoin(disclose(coin),right<ZswapCoinPublicKey,ContractAddress>(kernel.self())); }` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, file).valid, false);
    assert.equal(scanFile(file).diagnostics[0]?.code, "unsupported-state-operation");
  });
});

test("coin operation resource exhaustion cannot report complete", () => {
  withFiles({ "main.compact": `import CompactStandardLibrary;
ledger value: QualifiedShieldedCoinInfo;
export circuit entry(coin: ShieldedCoinInfo): [] { value.writeCoin(disclose(coin),right<ZswapCoinPublicKey,ContractAddress>(kernel.self())); }` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, file).valid, true);
    const program = new Program(file);
    for (const engine of ["instructions", "expressions"] as const) {
      const facts = new Dataflow(program,20000,256,1,engine).analyze();
      assert.deepEqual(facts.completedEntries, []);
      assert.ok(facts.diagnostics.some(diagnostic => diagnostic.code.endsWith("budget")));
    }
  });
});

test("coin qualification never equates values read through a shared wildcard region", () => {
  compare(`ledger source: Map<Field,ShieldedCoinInfo>;
ledger first: QualifiedShieldedCoinInfo;
ledger second: QualifiedShieldedCoinInfo;
export circuit entry(a: Field,b: Field): Boolean {
  const x = source.lookup(disclose(a)); const y = source.lookup(disclose(b));
  const recipient = right<ZswapCoinPublicKey,ContractAddress>(kernel.self());
  first.writeCoin(x,recipient); second.writeCoin(y,recipient);
  return first.mt_index == second.mt_index;
}`, facts => {
    assert.equal(facts.paths.length, 1);
    const path = facts.paths[0];
    assert.equal(path.sinks.find(sink => sink.kind === "exported-return")!.value.constant, undefined);
    const [first, second] = path.operations!.filter(operation => operation.kind === "coin-qualification").map(operation => operation.result.fields!.mt_index.identity);
    assert.ok(first === undefined || second === undefined || first !== second, "Separate snapshots cannot inherit equality from the wildcard region");
  });
});
