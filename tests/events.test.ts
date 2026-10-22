import assert from "node:assert/strict";
import test from "node:test";
import { symlinkSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { Dataflow, Program, scanFile, type AnalysisFacts } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const eventNames = ["ShieldedSpend", "ShieldedReceive", "ShieldedMint", "ShieldedBurn", "UnshieldedSpend", "UnshieldedReceive", "UnshieldedMint", "UnshieldedBurn", "Paused", "Unpaused", "Misc"];
const allEvents = `import CompactStandardLibrary;
export circuit all(): [] { ${eventNames.map(name => `emit(default<${name}>);`).join("\n")} }`;
const withoutMetrics = ({ program, metrics, ...facts }: AnalysisFacts) => ({ ...facts,
  paths: facts.paths.map(path => ({ ...path, path: path.path.map(step => step.kind === "branch" ? { ...step, label: step.label.match(/(?:true|false)$/)?.[0] ?? step.label } : step) })) });

function compile(file: string, valid = true): void {
  if (!process.env.COMPACTC_TEST) return;
  const result = validateWithCompiler(process.env.COMPACTC_TEST, file);
  assert.equal(result.valid, valid, result.error);
}

function compare(source: string, check: (facts: AnalysisFacts) => void): void {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    compile(file);
    const program = new Program(file);
    let expected: AnalysisFacts | undefined;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const analyzer = new Dataflow(program, 40000, 256, 50000, engine, cached, cached);
      const facts = analyzer.analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      check(facts);
      if (expected) assert.deepEqual(withoutMetrics(facts), withoutMetrics(expected));
      else expected = facts;
      assert.deepEqual(analyzer.analyze(), facts);
    }
  });
}

test("all eleven native events retain wire identity, order, payload schemas and empty results", () => {
  compare(allEvents, facts => {
    const path = facts.paths[0];
    assert.deepEqual(path.operations!.map(operation => operation.name), eventNames);
    assert.deepEqual(path.operations!.map(operation => operation.event), eventNames.map((name, tag) => ({ name, version: 1, tag })));
    assert.ok(path.operations!.every(operation => operation.kind === "event" && operation.args.length === 1 && operation.result.items?.length === 0));
    assert.deepEqual(path.sinks.filter(sink => sink.kind === "event").map(sink => sink.name), eventNames);
    assert.deepEqual(path.writes, [], "Logs are not persistent ledger writes");
    assert.deepEqual(Object.keys(path.operations![1].args[0].fields!), ["commitment", "ciphertext", "contractAddress"]);
    const graph = facts.program.instructionCFG(path.entry);
    assert.equal(graph.nodes.filter(node => node.instruction?.effects.includes("event")).length, 11);
  });
});

const ordered = `import CompactStandardLibrary;
witness secret(): Bytes<32>;
circuit authorize(allowed: Boolean): [] { assert(allowed, "allowed"); }
circuit payload(value: Bytes<32>): ShieldedSpend {
  emit(Unpaused {});
  return ShieldedSpend {nullifier: value};
}
circuit publishValue(value: Bytes<32>): [] { return emit(payload(value)); }
export circuit entry(flag: Boolean, allowed: Boolean): [] {
  authorize(disclose(allowed));
  const value = secret();
  if (disclose(flag)) { publishValue(disclose(value)); publishValue(disclose(value)); }
  else { publishValue(disclose(value)); }
  emit(Paused {});
}`;
test("nested and repeated emits retain caller guards, argument effects, control and private provenance", () => {
  compare(ordered, facts => {
    assert.equal(facts.paths.length, 2);
    assert.deepEqual(facts.paths.map(path => path.operations!.map(operation => operation.name)).sort((a, b) => a.length - b.length), [
      ["Unpaused", "ShieldedSpend", "Paused"], ["Unpaused", "ShieldedSpend", "Unpaused", "ShieldedSpend", "Paused"],
    ]);
    const guard = [...facts.program.functions.values()].find(fn => fn.symbol.name === "authorize")!.symbol.id;
    for (const path of facts.paths) for (const operation of path.operations!) {
      assert.ok(operation.guards.includes(guard));
      if (operation.name === "Paused") continue;
      assert.ok(operation.control.some(value => value.flows.some(flow => flow.source.name === "flag")));
      if (operation.name === "ShieldedSpend") {
        assert.ok(operation.args[0].fields!.nullifier.flows.some(flow => flow.source.name === "secret"));
        assert.deepEqual(operation.callPath.map(id => facts.program.symbols.get(id)!.name), ["entry", "publishValue"]);
      }
    }
    for (const path of facts.paths) {
      const sink = path.sinks.find(sink => sink.kind === "event" && sink.name === "ShieldedSpend")!;
      assert.deepEqual(new Set(sink.value.flows.map(flow => flow.source.name)), new Set(["flag", "secret"]));
      assert.ok(sink.value.flows.find(flow => flow.source.name === "secret")!.trace.some(step => step.kind === "event"));
      assert.ok(path.sinks.find(sink => sink.kind === "event" && sink.name === "Unpaused")!.value.flows.some(flow => flow.source.name === "flag"), "An empty event still discloses its control");
    }
  });
});

test("event operands keep current storage snapshots across cache invalidation", () => {
  compare(`import CompactStandardLibrary;
export ledger stored: Bytes<32>;
circuit read(): Bytes<32> { return stored; }
circuit publish(): [] { emit(ShieldedSpend {nullifier: read()}); }
export circuit entry(first: Bytes<32>, second: Bytes<32>): [] {
  stored = disclose(first); publish(); publish();
  stored = disclose(second); publish();
}`, facts => {
    assert.deepEqual(facts.paths[0].operations!.map(operation => operation.args[0].fields!.nullifier.flows.map(flow => flow.source.name)), [["first"], ["first"], ["second"]]);
    assert.equal(facts.paths[0].writes.length, 2);
  });
});

const rejection = `import CompactStandardLibrary;
circuit payload(allowed: Boolean): ShieldedSpend { assert(allowed, "payload guard"); return default<ShieldedSpend>; }
export circuit before(allowed: Boolean): [] { emit(payload(allowed)); }
export circuit after(allowed: Boolean): [] { emit(default<ShieldedSpend>); assert(allowed, "after guard"); }
export circuit reject(): [] { emit(payload(false)); }
export circuit rejectLater(): [] { emit(default<ShieldedSpend>); assert(false, "later reject"); }`;
test("event effects only survive successful payload evaluation and successful entry paths", () => {
  compare(rejection, facts => {
    assert.deepEqual(facts.paths.map(path => facts.program.symbols.get(path.entry)!.name), ["before", "after"]);
    assert.ok(facts.paths.every(path => path.operations?.length === 1));
    assert.equal(facts.failedAssertions.length, 2);
  });
});

test("event names and exact ordered schemas survive imports and same-shaped user declarations", () => {
  for (const source of [
    `import {ShieldedSpend as Log} from CompactStandardLibrary; export circuit entry(): [] { return emit(Log {nullifier: default<Bytes<32>>}); }`,
    `struct Misc {name: Bytes<32>, payload: Bytes<256>} export circuit entry(): [] { emit(default<Misc>); }`,
    `struct Paused {} export circuit entry(): [] { emit(Paused {}); }`,
    `import CompactStandardLibrary; circuit empty(): Paused { return Paused {}; } export circuit entry(): [] { emit(empty()); }`,
  ]) compare(source, facts => assert.equal(facts.paths[0].operations?.length, 1));
});

test("compiler-invalid event lookalikes, field schemas, arity and reserved bindings reject", () => {
  for (const source of [
    `struct Custom {name: Bytes<32>, payload: Bytes<256>} export circuit entry(): [] { emit(default<Custom>); }`,
    `struct Misc {name: Bytes<32>, payload: Bytes<255>} export circuit entry(): [] { emit(default<Misc>); }`,
    `struct Misc {payload: Bytes<256>, name: Bytes<32>} export circuit entry(): [] { emit(default<Misc>); }`,
    `new type Name = Bytes<32>; struct Misc {name: Name, payload: Bytes<256>} export circuit entry(): [] { emit(default<Misc>); }`,
    `export circuit entry(): [] { emit(1); }`,
    `import CompactStandardLibrary; export circuit entry(): [] { emit(Paused {}, Unpaused {}); }`,
    `export circuit emit(): [] {}`,
  ]) withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    compile(file, false);
    const report = scanFile(file);
    assert.equal(report.status, "incomplete");
    assert.ok(["invalid-event-type", "parse-error", "reserved-identifier"].includes(report.diagnostics[0].code), JSON.stringify(report.diagnostics));
  });
});

test("constructors and pure circuits reject direct, nested, unreachable and zero-iteration emits", () => {
  for (const body of ["emit(Paused {});", "helper();", "if(false) { helper(); }", "for(const i of 0..0) { helper(); }", "map(callback, []);"]) {
    for (const declaration of ["constructor()", "export pure circuit entry(): []"]) {
      withFiles({ "main.compact": `import CompactStandardLibrary;
circuit helper(): [] { emit(Paused {}); }
circuit callback(v: Boolean): [] { return helper(); }
${declaration} { ${body} }` }, directory => {
        const file = resolve(directory, "main.compact");
        compile(file, false);
        assert.ok(["constructor-event", "pure-event"].includes(scanFile(file).diagnostics[0].code));
      });
    }
  }
});

test("potentially effectful empty payloads are explicitly incomplete across the compiler erasure gap", () => {
  for (const body of ["assert(false, \"erased\");", "emit(Unpaused {});", "stored = 1 as Field;"]) {
    withFiles({ "main.compact": `import CompactStandardLibrary; export ledger stored: Field;
circuit payload(): Paused { ${body} return Paused {}; }
export circuit entry(): [] { emit(payload()); }` }, directory => {
      const file = resolve(directory, "main.compact");
      compile(file);
      const report = scanFile(file);
      assert.equal(report.status, "incomplete");
      assert.equal(report.diagnostics[0].code, "unsupported-empty-event-effects");
      assert.deepEqual(report.coverage.completedEntries, []);
    });
  }
});

const emptyPayload = `circuit emptyPayload(): Paused { emit(Unpaused {}); return Paused {}; }`;
const materialized = `export circuit materialized(): [] { const saved = emptyPayload(); emit(saved); }`;
test("materializing an empty payload before emitting retains its earlier effects", () => {
  compare(`import CompactStandardLibrary; ${emptyPayload} ${materialized}`, facts => {
    assert.deepEqual(facts.paths[0].operations!.map(operation => operation.name), ["Unpaused", "Paused"]);
  });
});

test("event retention and step exhaustion remain explicitly incomplete in both engines", () => {
  withFiles({ "main.compact": allEvents }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    for (const engine of ["instructions", "expressions"] as const) for (const [steps, values] of [[2, 50000], [40000, 5]]) {
      const facts = new Dataflow(program, steps, 256, values, engine).analyze();
      assert.ok(facts.diagnostics.some(diagnostic => ["analysis-budget", "effect-budget", "value-budget"].includes(diagnostic.code)));
      assert.deepEqual(facts.completedEntries, []);
    }
  });
});

test("existing detectors treat event payloads and empty-event control as public sinks", () => {
  withFiles({ "main.compact": `import CompactStandardLibrary;
witness secret(): Field;
export circuit entry(flag: Boolean): [] {
  emit(ShieldedSpend {nullifier: disclose(persistentCommit<Field>(secret(),default<Bytes<32>>))});
  if (disclose(flag)) { emit(Paused {}); }
}` }, directory => {
    const file = resolve(directory, "main.compact");
    compile(file);
    const report = scanFile(file, { policies: { secrets: [{ circuit: "entry", parameter: "flag" }] } });
    assert.equal(report.status, "complete");
    assert.equal(report.findings.filter(finding => finding.detectorId === "predictable-commitment-randomness").length, 1);
    assert.equal(report.findings.filter(finding => finding.detectorId === "declared-secret-publication").length, 1);
  });
});

test("pinned runtime confirms event order, tags, return value and argument/entry rejection", { skip: !process.env.COMPACT_RUNTIME_TEST ? "Requires pinned runtime" : false }, () => {
  assert.ok(process.env.COMPACTC_TEST);
  withFiles({ "main.compact": allEvents + ordered.replace("import CompactStandardLibrary;", "") + rejection.replace("import CompactStandardLibrary;", "").replaceAll("payload", "guardedPayload") + emptyPayload + materialized + "export circuit erased(): [] { emit(emptyPayload()); }" }, directory => {
    const compiled = spawnSync(process.env.COMPACTC_TEST!, ["--skip-zk", resolve(directory, "main.compact"), resolve(directory, "compiled")], { encoding: "utf8", timeout: 30000 });
    assert.equal(compiled.status, 0, compiled.stderr);
    symlinkSync(resolve(process.env.COMPACT_RUNTIME_TEST!, "node_modules"), resolve(directory, "node_modules"), "dir");
    writeFileSync(resolve(directory, "run.mjs"), `import assert from 'node:assert/strict';
import * as r from '@midnight-ntwrk/compact-runtime';
import {Contract} from './compiled/contract/index.js';
const contract = new Contract({secret: context => [context.privateState, new Uint8Array(32).fill(7)]});
const initial = await contract.initialState(r.createConstructorContext({},'0'.repeat(64)));
const context = name => r.createCircuitContext(name,r.dummyContractAddress(),'0'.repeat(64),initial.currentContractState,{});
const all = await contract.circuits.all(context('all'));
assert.deepEqual(all.result, []);
assert.deepEqual(all.context.events.map(event => event.eventType), ['shielded-spend','shielded-receive','shielded-mint','shielded-burn','unshielded-spend','unshielded-receive','unshielded-mint','unshielded-burn','paused','unpaused','misc']);
assert.ok(all.context.events.every(event => event.version === 1));
for (const flag of [false,true]) {
 const input = context('entry');
 const result = await contract.circuits.entry(input,flag,true);
 assert.deepEqual(result.result, []);
 assert.deepEqual(result.context.events.map(event => event.eventType), flag ? ['unpaused','shielded-spend','unpaused','shielded-spend','paused'] : ['unpaused','shielded-spend','paused']);
 assert.deepEqual(input.events, [], 'Evaluation does not publish into the caller snapshot');
}
for (const name of ['before','after']) {
 const input = context(name);
 await assert.rejects(contract.circuits[name](input,false), /failed assert/);
 assert.deepEqual(input.events, []);
 assert.equal((await contract.circuits[name](context(name),true)).context.events.length,1);
}
for (const name of ['reject','rejectLater']) await assert.rejects(contract.circuits[name](context(name)), /failed assert/);
assert.deepEqual((await contract.circuits.materialized(context('materialized'))).context.events.map(event => event.eventType), ['unpaused','paused']);
assert.deepEqual((await contract.circuits.erased(context('erased'))).context.events.map(event => event.eventType), ['paused']);
`);
    const run = spawnSync(process.execPath, [resolve(directory, "run.mjs")], { encoding: "utf8", timeout: 30000 });
    assert.equal(run.status, 0, run.stderr);
  });
});
