import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, resolvePolicies, type AnalysisFacts } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { predictableCommitment } from "../src/detectors/rules.js";
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

test("Kernel self and initial balances remain correlated across sends and nested helper calls", () => {
  compare(`
circuit balance(color: Bytes<32>): Uint<128> { return unshieldedBalance(color); }
export circuit entry(color: Bytes<32>): Boolean {
  const before = balance(disclose(color)); const self = kernel.self();
  receiveUnshielded(disclose(color), 3);
  sendUnshielded(disclose(color), 2, left<ContractAddress,UserAddress>(self));
  const after = balance(disclose(color));
  assert(before == after, "initial balance remains fixed");
  if (before == 0) { assert(unshieldedBalanceLt(disclose(color),1), "shared context for comparisons"); }
  return self == kernel.self();
}`, facts => {
    assert.ok(facts.paths.length > 0);
    assert.deepEqual(facts.failedAssertions, []);
    for (const path of facts.paths) {
      assert.equal(path.sinks.find(sink => sink.kind === "exported-return")!.value.constant, "true");
      const operations = path.operations!;
      assert.ok(operations.some(operation => operation.kind === "kernel-write" && operation.name === "claimUnshieldedCoinSpend"));
      const balances = operations.filter(operation => operation.name === "balance");
      assert.equal(balances.length, 2);
      assert.equal(balances[0].result.identity, balances[1].result.identity);
      assert.equal(path.writes.length, 0, "Transaction effects are not persistent storage writes");
    }
  });
});

test("native wallet operations preserve ordered arguments and distinguish mutually exclusive histories", () => {
  compare(`witness coin(): ShieldedCoinInfo;
export circuit entry(flag: Boolean): [] {
  const input = coin();
  const recipient = right<ZswapCoinPublicKey,ContractAddress>(kernel.self());
  if (disclose(flag)) { createZswapOutput(input,recipient); }
  else { createZswapOutput(input,recipient); createZswapOutput(input,recipient); }
}`, facts => {
    const histories = facts.paths.map(path => path.operations!.filter(operation => operation.kind === "native-witness"));
    assert.deepEqual(histories.map(operations => operations.length).sort(), [1, 2]);
    for (const operations of histories) for (const operation of operations) {
      assert.ok(operation.args[0].fields!.nonce.flows.some(flow => flow.source.name === "coin"));
      assert.ok(operation.control.some(value => value.flows.some(flow => flow.source.name === "flag")));
    }
  });
});

test("only the documented public Kernel arguments become public sinks", () => {
  compare(`witness comm(): Field;
export circuit entry(address: Bytes<32>, point: Bytes<32>): [] {
  kernel.claimContractCall(disclose(address),disclose(point),comm());
}`, facts => {
    const path = facts.paths[0];
    const operation = path.operations!.find(operation => operation.name === "claimContractCall")!;
    assert.ok(operation.args[2].flows.some(flow => flow.source.name === "comm"));
    const sink = path.sinks.find(sink => sink.name === "kernel.claimContractCall")!;
    assert.deepEqual(new Set(sink.value.flows.map(flow => flow.source.name)), new Set(["address", "point"]));
  });
});

test("parsed sendShielded retains native effects, change arithmetic and self-recipient correlation", () => {
  compare(`export circuit entry(input: QualifiedShieldedCoinInfo): ShieldedSendResult {
  assert(input.value == 5, "test amount");
  const recipient = right<ZswapCoinPublicKey,ContractAddress>(kernel.self());
  return disclose(sendShielded(disclose(input),recipient,3));
}`, facts => {
    assert.equal(facts.paths.length, 1);
    const path = facts.paths[0];
    const returned = path.sinks.find(sink => sink.kind === "exported-return")!.value;
    assert.equal(returned.fields!.sent.fields!.value.constant, "3");
    assert.equal(returned.fields!.change.fields!.is_some.constant, "true");
    assert.equal(returned.fields!.change.fields!.value.fields!.value.constant, "2");
    assert.deepEqual(path.operations!.filter(operation => operation.kind !== "kernel-read").map(operation => operation.name),
      ["createZswapInput", "claimZswapNullifier", "createZswapOutput", "claimZswapCoinSpend", "claimZswapCoinReceive", "createZswapOutput", "claimZswapCoinSpend", "claimZswapCoinReceive"]);
  });
});

test("pinned token derivation is quiet while a same-named user commitment still reports", () => {
  compare(`import { tokenType as libraryTokenType } from CompactStandardLibrary;
circuit tokenType(secret: Field): Bytes<32> { return persistentCommit<Field>(secret,pad(32,"midnight:derive_token")); }
export circuit token(domain: Bytes<32>,address: ContractAddress): Bytes<32> { return disclose(libraryTokenType(domain,address)); }
export circuit user(secret: Field): Bytes<32> { return disclose(tokenType(secret)); }`, facts => {
    const findings = predictableCommitment.run(facts, resolvePolicies(facts.program));
    assert.equal(findings.length, 1);
    assert.deepEqual(findings[0].callPath, ["user"]);
  });
});

test("checkpoint prefixes are exact histories and operation budgets remain explicitly incomplete", () => {
  withFiles({ "main.compact": "import CompactStandardLibrary; export circuit entry(): [] { kernel.checkpoint(); }" }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, file).valid, true);
    const program = new Program(file);
    for (const engine of ["instructions", "expressions"] as const) {
      const facts = new Dataflow(program, 20000, 256, 50000, engine).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      // The effect-free prefix commits the same outcome as the full history.
      assert.equal(facts.paths.length, 1);
    }
  });
  withFiles({ "main.compact": "import CompactStandardLibrary; export circuit entry(): [] { for (const i of 0..8) { kernel.self(); } }" }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, file).valid, true);
    const facts = new Dataflow(new Program(file), 20000, 256, 5).analyze();
    assert.ok(facts.diagnostics.some(diagnostic => ["effect-budget", "value-budget"].includes(diagnostic.code)));
    assert.deepEqual(facts.completedEntries, []);
  });
});

const writesOf = (facts: AnalysisFacts) => facts.paths.map(path => path.writes.map(write => write.ledger.split("::").at(-1)).join(",")).sort();
test("a trailing checkpoint write keeps later pure proof checks without later effects", () => {
  compare(`export ledger stored: Field;
export ledger padding: Bytes<32>;
witness authorized(): Boolean;
circuit padTransaction(): [] { kernel.checkpoint(); padding = pad(32, "pad"); }
export circuit entry(value: Field): Field {
  stored = disclose(value);
  padTransaction();
  assert(disclose(authorized()), "late check");
  return disclose(value);
}`, facts => {
    assert.deepEqual(writesOf(facts), ["stored", "stored,padding"]);
    const prefix = facts.paths.find(path => path.writes.length === 1)!, full = facts.paths.find(path => path.writes.length === 2)!;
    // The later pure assertion is required for the full proof, including prefixes.
    // Later writes and the exported return are separate fallible effects.
    assert.deepEqual(prefix.predicates, full.predicates);
    assert.ok(prefix.path.some(step => step.label === "assertion required by the full proof across kernel checkpoint"));
    assert.ok(!prefix.sinks.some(sink => sink.kind === "exported-return"));
    assert.ok(full.sinks.some(sink => sink.kind === "exported-return"));
    assert.ok(full.predicates!.some(predicate => predicate.value.flows.some(flow => flow.source.kind === "witness")));
  });
});

test("each reached checkpoint commits its own prefix; unprovable continuations commit nothing", () => {
  compare(`export ledger first: Field;
export ledger second: Field;
export ledger third: Field;
circuit mark(): [] { kernel.checkpoint(); }
export circuit twice(value: Field): [] {
  first = disclose(value); mark(); second = disclose(value); mark(); third = disclose(value);
}
export circuit impossible(value: Field): [] {
  first = disclose(value); kernel.checkpoint(); assert(false, "never provable");
}
export circuit branch(value: Field, flag: Boolean): [] {
  first = disclose(value);
  if (disclose(flag)) { kernel.checkpoint(); second = disclose(value); } else { third = disclose(value); }
}`, facts => {
    const byEntry = (name: string) => writesOf({ ...facts, paths: facts.paths.filter(path => facts.program.symbols.get(path.entry)!.name === name) });
    assert.deepEqual(byEntry("twice"), ["first", "first,second", "first,second,third"]);
    assert.deepEqual(byEntry("impossible"), []);
    assert.deepEqual(byEntry("branch"), ["first", "first,second", "first,third"]);
  });
});


test("committed prefixes retain the entry path allowance and pure hash-selector proof constraints", () => {
  withFiles({ "main.compact": `import CompactStandardLibrary;
export ledger first: Field; export ledger second: Field; export ledger third: Field;
export circuit entry(value: Field): [] {
  first = disclose(value); kernel.checkpoint();
  second = disclose(value); kernel.checkpoint();
  third = disclose(value);
}` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) { const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file); assert.equal(compiled.valid, true, compiled.error); }
    const program = new Program(file);
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 20000, 2, 50000, engine, cached, cached).analyze();
      assert.deepEqual(facts.completedEntries, []);
      assert.deepEqual(facts.paths, []);
      assert.ok(facts.diagnostics.some(diagnostic => diagnostic.code === "analysis-budget" && diagnostic.message.includes("checkpoint histories")));
    }
  });
  withFiles({ "main.compact": `import CompactStandardLibrary;
export ledger root: Bytes<32>;
export circuit entry(a: Bytes<32>, b: Bytes<32>, selector: Boolean): [] {
  const chosen = selector ? persistentHash<Vector<2, Bytes<32>>>([a,b]) : persistentHash<Vector<2, Bytes<32>>>([b,a]);
  assert(chosen == persistentHash<Vector<2, Bytes<32>>>([a,b]), "known hash");
  kernel.checkpoint();
  assert(selector, "later selector");
}` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) { const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file); assert.equal(compiled.valid, true, compiled.error); }
    const program = new Program(file);
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 20000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(facts.completedEntries, program.entries);
      assert.deepEqual(facts.diagnostics, []);
      assert.ok(facts.paths.every(path => path.predicates!.some(predicate => predicate.location.line === 7)));
    }
  });
});
