import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { Dataflow, Program, scanFile, type AnalysisFacts } from "../src/index.js";
import { reInitialization as rule } from "../src/detectors/initialization.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { semanticPaths, withFiles } from "./helpers.js";

function fixture(source: string, expected: string[], inspect?: (facts: AnalysisFacts, cached: boolean) => void): void {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiler = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiler.valid, true, compiler.error);
    }
    const program = new Program(file);
    let prior: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", true, true, "all", false, false, true).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      const findings = rule.run(facts);
      assert.deepEqual(findings.map(finding => finding.metadata.entry).sort(), expected.slice().sort());
      const paths = facts.initialization!.map(row => ({ entry: row.entry, first: row.firstSuccesses, second: row.secondSuccesses,
        pairs: row.pairs.map(pair => ({ histories: semanticPaths({ ...facts, paths: [...pair.construction ? [pair.construction] : [], pair.first, pair.second] }),
          changes: pair.changes.map(change => change.ledger) })) }));
      const current = { findings, paths };
      prior ??= current; assert.deepEqual(current, prior);
      inspect?.(facts, cached);
    }
    for (const experimentalCounterQueries of [false, true]) {
      const result = scanFile(file, { detectors: [rule.id], experimentalCounterQueries });
      assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
      assert.deepEqual(result.findings.map(finding => finding.metadata.entry).sort(), expected.slice().sort());
    }
  });
}

const header = `import CompactStandardLibrary;
ledger done: Boolean;
ledger authorized: Boolean;
export ledger payload: Field;
constructor() { authorized = true; }
circuit firstUse(): [] { assert(!done, "already initialized"); }
circuit authorize(): [] { assert(authorized, "authorized"); }
`;

test("consecutive initialization uses actual storage, fresh inputs and fresh guards", () => {
  fixture(readFileSync(resolve("tests/runtime-fixtures/initialization.compact"), "utf8"), ["initialize_repeatable", "initialize_restored", "initialize_freshInput", "initialize_conditionalGuard", "initialize_conditionalAuthorization"], facts => {
    for (const row of facts.initialization!) {
      const name = facts.program.symbols.get(row.entry)!.name;
      assert.equal(row.firstSuccesses, 1, name);
      assert.equal(row.secondSuccesses, ["initialize_corrected", "initialize_late"].includes(name) ? 0 : 1, name);
      if (name !== "initialize_conditionalAuthorization") continue;
      const pair = row.pairs[0];
      const hasGuard = (part: typeof pair.first) => part.writes.some(write => write.guards.some(id => facts.program.symbols.get(id)?.name === "authorize"));
      assert.equal(hasGuard(pair.first), true); assert.equal(hasGuard(pair.second), false);
      const old = pair.changes.find(change => facts.program.symbols.get(change.ledger)!.name === "payload")!.before;
      const next = pair.changes.find(change => facts.program.symbols.get(change.ledger)!.name === "payload")!.after;
      assert.deepEqual(old.flows.map(flow => flow.source.sequenceStep), [1]);
      assert.deepEqual(next.flows.map(flow => flow.source.sequenceStep), [2]);
      assert.notEqual(old.identity, next.identity);
      assert.equal(next.preexistingLedger, undefined, "prior writes never certify trusted preexisting data");
    }
  });
});

test("constructor reachability and branch pairs are retained without mixing histories", () => {
  fixture(`import CompactStandardLibrary;
ledger done: Boolean;
export ledger payload: Field;
constructor(flag: Boolean) { done = disclose(flag); }
circuit save(value: Field): [] { payload = disclose(value); }
export circuit initialize_guarded(value: Field): [] { assert(!done, "first"); done = true; save(value); }
export circuit initialize_branch(value: Field, restore: Boolean): [] { assert(!done, "first"); done = true; save(value); if (disclose(restore)) { done = false; } }
`, ["initialize_branch"], facts => {
    const row = facts.initialization!.find(row => facts.program.symbols.get(row.entry)!.name === "initialize_branch")!;
    assert.equal(row.firstSuccesses, 2);
    assert.equal(row.secondSuccesses, 2);
    for (const pair of row.pairs) {
      const flag = pair.first.writes.filter(write => facts.program.symbols.get(write.ledger)!.name === "done").at(-1)!;
      assert.equal(flag.after.constant, "false", "second call must use the actual first post-state");
      assert.ok(pair.construction);
    }
  });
});

test("sequence rejection does not contaminate ordinary assertion or call evidence", () => {
  withFiles({ "main.compact": `${header} export circuit initialize(value: Field): [] { firstUse(); done = true; payload = disclose(value); }` }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const ordinary = new Dataflow(program, 40000, 256, 50000, "instructions", true, true, "equivalent-states", true, true, "all").analyze();
    const sequence = new Dataflow(program, 40000, 256, 50000, "instructions", true, true, "equivalent-states", true, true, "all", false, false, true).analyze();
    assert.deepEqual(sequence.assertionReaches, ordinary.assertionReaches);
    assert.deepEqual(sequence.callReaches, ordinary.callReaches);
    assert.deepEqual(sequence.failedAssertions, ordinary.failedAssertions);
    assert.deepEqual(semanticPaths(sequence), semanticPaths(ordinary));
    assert.deepEqual(sequence.initialization!.map(row => row.secondSuccesses), [0]);
    assert.deepEqual(scanFile(program.root, { detectors: [rule.id, "impossible-assertion"] }).findings, []);
  });
});

test("transitive and aggregate equalities distinguish final values from allocation metadata", () => {
  fixture(`import CompactStandardLibrary;
struct Pair { first: Field; second: Field; }
ledger done: Boolean;
ledger saved: Pair;
export circuit initialize(value: Pair, intermediate: Pair): [] {
  if (done) { assert(value == intermediate, "alias"); assert(intermediate == saved, "same"); }
  saved = disclose(value); done = true;
}`, []);
});

test("witnesses are fresh on each invocation and stored private provenance retains its step", () => {
  fixture(`${header}
witness next(): Field;
export circuit initialize(): [] { const value = next(); if (done) { assert(value != payload, "fresh"); } payload = disclose(value); done = true; }
`, ["initialize"], facts => {
    const pair = facts.initialization![0].pairs[0];
    const change = pair.changes.find(change => facts.program.symbols.get(change.ledger)!.name === "payload")!;
    assert.equal(change.before.flows[0].source.kind, "witness");
    assert.equal(change.before.flows[0].source.sequenceStep, 1);
    assert.equal(change.after.flows[0].source.sequenceStep, 2);
    assert.notEqual(change.before.flows[0].source.id, change.after.flows[0].source.id);
    assert.deepEqual([...pair.first.witnessCalls!.values()], [1]);
    assert.deepEqual([...pair.second.witnessCalls!.values()], [1]);
  });
});

test("imported initializer helpers and same-invocation read-summary reuse keep the guard", () => {
  fixture(`import CompactStandardLibrary;
module Setup {
  export ledger done: Boolean;
  export ledger payload: Field;
  circuit read(): Boolean { return done; }
  circuit repeatedRead(): Boolean { const a = read(); const b = read(); assert(a == b, "same"); return a; }
  export circuit initialize(value: Field): [] { assert(!repeatedRead(), "first"); done = true; payload = disclose(value); }
}
import Setup prefix S_;
export { S_initialize };
`, [], (facts, cached) => { if (cached) assert.ok(facts.metrics.readSummaryHits > 0, "exercise actual read-summary replay"); });
});

test("ordinary analysis and consecutive calls share one entry step allowance", () => {
  withFiles({ "main.compact": `import CompactStandardLibrary; ledger value: Field; export circuit initialize(input: Field): [] { value = disclose(input); }` }, directory => {
    const file = resolve(directory, "main.compact");
    const ordinary = scanFile(file, { detectors: ["impossible-assertion"] });
    assert.equal(ordinary.status, "complete");
    const maxSteps = ordinary.metrics.steps + 1;
    assert.equal(scanFile(file, { detectors: ["impossible-assertion"], maxSteps }).status, "complete");
    const sequence = scanFile(file, { detectors: [rule.id], maxSteps });
    assert.equal(sequence.status, "incomplete");
    assert.deepEqual(sequence.findings, []);
    assert.ok(sequence.diagnostics.some(diagnostic => diagnostic.code === "analysis-budget"));
  });
});

test("sequence budgets and unsupported context/storage effects remain incomplete", () => {
  const samples = [
    { source: `${header} export circuit initialize(value: Field): [] { payload = disclose(value); }`, options: { maxSteps: 20 }, diagnostic: "analysis-budget" },
    { source: `${header} export circuit initialize(value: Field): [] { payload = disclose(value); }`, options: { maxValues: 1 }, diagnostic: "value-budget" },
    { source: `${header} export circuit initialize(value: Field, choice: Boolean): [] { if (disclose(choice)) { payload = disclose(value); } else { payload = 1 as Field; } }`, options: { maxPaths: 2 }, diagnostic: "analysis-budget" },
    { source: `import CompactStandardLibrary; ledger values: Map<Field,Field>; export circuit initialize(): [] { values.insert(1 as Field, 1 as Field); }`, options: {}, diagnostic: "initialization-state-unsupported" },
    { source: `import CompactStandardLibrary; ledger count: Field; export circuit initialize(): [] { count = 1 as Field; sendUnshielded(default<Bytes<32>>, 1, right<ContractAddress,UserAddress>(default<UserAddress>)); }`, options: {}, diagnostic: "initialization-effect-unsupported" },
  ];
  for (const sample of samples) withFiles({ "main.compact": sample.source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) { const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file); assert.equal(compiled.valid, true, compiled.error); }
    const report = scanFile(file, { detectors: [rule.id], ...sample.options });
    assert.equal(report.status, "incomplete", JSON.stringify(report));
    assert.deepEqual(report.findings, []);
    assert.ok(report.diagnostics.some(item => item.code === sample.diagnostic), JSON.stringify(report.diagnostics));
  });
});

test("initialization corpus pairs and intentional idempotent lookalike", () => {
  for (const [kind, expected] of [["vulnerable/re-initialization", ["initialize"]], ["safe/re-initialization", []], ["safe/re-initialization-lookalike", []]] as const)
    fixture(readFileSync(resolve(`tests/corpus/${kind}.compact`), "utf8"), [...expected]);
  const file = resolve("tests/corpus/vulnerable/re-initialization.compact");
  assert.equal(scanFile(file).findings.some(finding => finding.detectorId === rule.id), false, "name-based intent stays opt-in");
  const facts = new Dataflow(new Program(file)).analyze();
  assert.deepEqual(rule.run(facts), []);
  assert.ok(facts.diagnostics.some(diagnostic => diagnostic.code === "initialization-evidence-unavailable"));
});

test("Counter initializer comparison uses final scalar contents, including resets and restored values", () => {
  fixture(`import CompactStandardLibrary;
export ledger count: Counter;
ledger done: Boolean;
constructor() { count.increment(9); }
circuit increment(): [] { count.increment(1); }
export circuit initialize_repeatable(): [] { increment(); increment(); }
export circuit initialize_corrected(): [] { assert(!done, "first use"); done = true; increment(); }
export circuit initialize_reset(): [] { count.resetToDefault(); }
export circuit initialize_restore(): [] { count.increment(1); count.decrement(1); }
export circuit initialize_zero(): [] { count.increment(0); count.decrement(0); }
export circuit initialize_fixed(): [] { count.resetToDefault(); count.increment(7); }
`, ["initialize_repeatable"], facts => {
    const repeat = facts.initialization!.find(row => facts.program.symbols.get(row.entry)!.name === "initialize_repeatable")!;
    const change = repeat.pairs[0].changes[0];
    assert.equal(facts.program.symbols.get(change.ledger)!.name, "count");
    assert.equal(change.before.constant, "11"); assert.equal(change.after.constant, "13");
    assert.equal(repeat.pairs[0].first.writes.length, 2);
    assert.equal(repeat.pairs[0].second.writes.length, 2);
    const corrected = facts.initialization!.find(row => facts.program.symbols.get(row.entry)!.name === "initialize_corrected")!;
    assert.equal(corrected.secondSuccesses, 0);
  });
});

test("unknown constructor Counter payloads retain zero-update identity and fresh invocation dependencies", () => {
  fixture(`import CompactStandardLibrary;
export ledger count: Counter;
constructor(initial: Uint<16>) { count.increment(disclose(initial)); count.increment(7); }
witness amount(): Uint<16>;
export circuit initialize_zero(): [] { count.increment(0); count.decrement(0); }
export circuit initialize_restore(): [] { count.increment(1); count.decrement(1); }
export circuit initialize_changed(): [] { count.increment(2); count.decrement(1); }
export circuit initialize_dynamic(): [] { count.increment(disclose(amount())); }
`, ["initialize_changed", "initialize_dynamic"], facts => {
    const dynamic = facts.initialization!.find(row => facts.program.symbols.get(row.entry)!.name === "initialize_dynamic")!;
    const change = dynamic.pairs[0].changes[0];
    assert.deepEqual([...new Set(change.before.flows.map(flow => flow.source.sequenceStep))].sort(), [0, 1]);
    assert.deepEqual([...new Set(change.after.flows.map(flow => flow.source.sequenceStep))].sort(), [0, 1, 2]);
    const zero = facts.initialization!.find(row => facts.program.symbols.get(row.entry)!.name === "initialize_zero")!;
    assert.equal(zero.pairs[0].changes.length, 0);
    assert.equal(zero.pairs[0].first.writes.length, 2, "No-op value identity does not remove effect history");
    assert.equal(zero.pairs[0].second.writes.length, 2);
  });
});

test("canonical Counter aliases and private branches retain separate consecutive histories", () => {
  fixture(`import { Counter as Count } from CompactStandardLibrary;
export ledger count: Count;
export circuit initialize(choice: Boolean): [] { if (disclose(choice)) { count.increment(1); } }
`, ["initialize"], facts => {
    const row = facts.initialization![0];
    assert.equal(row.firstSuccesses, 2); assert.equal(row.secondSuccesses, 4);
    assert.equal(row.pairs.filter(pair => pair.changes.length).length, 2);
    for (const pair of row.pairs.filter(pair => pair.changes.length)) {
      const change = pair.changes[0];
      assert.equal(BigInt(change.after.constant!) - BigInt(change.before.constant!), 1n);
    }
  });
});

test("Counter underflow removes failed second calls and budgets still withhold incomplete findings", () => {
  const source = `import CompactStandardLibrary;
export ledger count: Counter;
constructor() { count.increment(1); }
export circuit initialize(): [] { count.decrement(1); }`;
  fixture(source, [], facts => {
    assert.equal(facts.initialization![0].firstSuccesses, 1);
    assert.equal(facts.initialization![0].secondSuccesses, 0);
  });
  withFiles({ "main.compact": source }, directory => {
    const result = scanFile(resolve(directory, "main.compact"), { detectors: [rule.id], maxSteps: 1 });
    assert.equal(result.status, "incomplete"); assert.deepEqual(result.findings, []);
  });
});

test("opaque defaults are stable, while an inactive optional payload can still change", () => {
  fixture(`import CompactStandardLibrary;
export ledger text: Opaque<"string">;
export ledger bytes: Opaque<"Uint8Array">;
export ledger optional: Maybe<Opaque<"string">>;
witness value(): Opaque<"string">;
export circuit initialize_defaults(): [] {
  text = default<Opaque<"string">>;
  bytes = default<Opaque<"Uint8Array">>;
  optional = none<Opaque<"string">>();
}
export circuit initialize_inactive(): [] {
  optional = Maybe<Opaque<"string">> { is_some: false, value: disclose(value()) };
}
`, ["initialize_inactive"]);
});

test("real board deferred initialization detects the repeatable Counter mutation and preserves its controls", () => {
  for (const [label, expected] of [["positive", ["initialize"]], ["corrected", []], ["lookalike", []]] as const) {
    fixture(readFileSync(resolve(`tests/corpus/known-bugs/bboard-repeatable-initialize-${label}.compact`), "utf8"), [...expected], facts => {
      if (label !== "positive") return;
      const change = facts.initialization![0].pairs[0].changes;
      assert.deepEqual(change.map(item => facts.program.symbols.get(item.ledger)!.name), ["sequence"]);
      assert.equal(change[0].before.constant, "1"); assert.equal(change[0].after.constant, "2");
    });
  }
});

test("[timing] Counter restoration and opaque defaults agree with pinned compiled evaluation", {
  skip: !process.env.COMPACT_RUNTIME_TEST || !process.env.COMPACTC_TEST ? "Requires pinned compiler/runtime" : false,
}, async () => {
  const directory = mkdtempSync(resolve(tmpdir(), "nightshade-counter-defaults-"));
  try {
    writeFileSync(resolve(directory, "package.json"), '{"private":true,"type":"module"}\n');
    const modules = resolve(process.env.COMPACT_RUNTIME_TEST!, "node_modules");
    symlinkSync(modules, resolve(directory, "node_modules"), "dir");
    const file = resolve(directory, "main.compact");
    writeFileSync(file, `import CompactStandardLibrary;
export ledger count: Counter;
export ledger text: Maybe<Opaque<"string">>;
export ledger bytes: Opaque<"Uint8Array">;
constructor(initial: Uint<16>) { count.increment(disclose(initial)); }
export circuit initialize(): [] {
  count.increment(1); count.increment(0); count.decrement(1); count.decrement(0);
  text = none<Opaque<"string">>(); bytes = default<Opaque<"Uint8Array">>;
}`);
    const compiler = (args: string[]) => {
      const result = spawnSync(process.env.COMPACTC_TEST!, args, { encoding: "utf8", timeout: 30000 });
      assert.equal(result.status, 0, String(result.error ?? result.stderr));
      return result.stdout.trim();
    };
    assert.equal(compiler(["--version"]), "0.34.0");
    assert.equal(compiler(["--runtime-version"]), "0.19.0");
    compiler(["--skip-zk", file, resolve(directory, "compiled")]);
    const runtime = await import(pathToFileURL(resolve(modules, "@midnight-ntwrk/compact-runtime/dist/index.js")).href);
    const { Contract, ledger } = await import(pathToFileURL(resolve(directory, "compiled/contract/index.js")).href);
    assert.equal(runtime.versionString, "0.19.0");
    for (const initial of [0n, 1n, 65535n]) {
      const contract = new Contract({});
      const initialized = await contract.initialState(runtime.createConstructorContext({}, "0".repeat(64)), initial);
      let state = initialized.currentContractState.data;
      for (let call = 0; call < 2; call++) {
        const context = runtime.createCircuitContext("initialize", runtime.dummyContractAddress(), "0".repeat(64), state,
          initialized.currentPrivateState, undefined, undefined, undefined, 1700000000);
        const result = await contract.circuits.initialize(context);
        state = result.context.callContext.currentQueryContext.state;
        assert.equal(ledger(state).count, initial);
        assert.deepEqual(ledger(state).text, { is_some: false, value: "" });
        assert.deepEqual(ledger(state).bytes, new Uint8Array());
      }
    }
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("[timing] initialization agrees with pinned local compiled evaluation", {
  skip: !process.env.COMPACT_RUNTIME_TEST || !process.env.COMPACTC_TEST ? "Requires pinned compiler/runtime" : false,
}, async () => {
  const directory = mkdtempSync(resolve(tmpdir(), "nightshade-initialization-runtime-"));
  try {
    writeFileSync(resolve(directory, "package.json"), '{"private":true,"type":"module"}\n');
    const modules = resolve(process.env.COMPACT_RUNTIME_TEST!, "node_modules");
    symlinkSync(modules, resolve(directory, "node_modules"), "dir");
    const compiler = (args: string[]) => {
      const result = spawnSync(process.env.COMPACTC_TEST!, args, { encoding: "utf8", timeout: 30000, maxBuffer: 1024 * 1024 });
      assert.equal(result.status, 0, String(result.error ?? result.stderr));
      return result.stdout.trim();
    };
    assert.equal(compiler(["--version"]), "0.34.0");
    assert.equal(compiler(["--runtime-version"]), "0.19.0");
    compiler(["--skip-zk", resolve("tests/runtime-fixtures/initialization.compact"), resolve(directory, "compiled")]);
    const runtime = await import(pathToFileURL(resolve(modules, "@midnight-ntwrk/compact-runtime/dist/index.js")).href);
    const { Contract, ledger } = await import(pathToFileURL(resolve(directory, "compiled/contract/index.js")).href);
    assert.equal(runtime.versionString, "0.19.0");
    const samples: [string, bigint[], bigint[], boolean][] = [
      ["corrected", [1n], [2n], false], ["late", [1n], [2n], false],
      ["repeatable", [1n], [2n], true], ["restored", [1n], [2n], true],
      ["freshInput", [1n], [2n], true], ["freshInput", [1n], [1n], false],
      ["conditionalGuard", [1n], [2n], true], ["conditionalAuthorization", [1n], [2n], true],
      ["idempotent", [], [], true], ["restorePayload", [1n], [2n], true],
      ["equal", [1n], [1n], true], ["equal", [1n], [2n], false],
    ];
    for (const [suffix, firstArgs, secondArgs, secondSucceeds] of samples) {
      const contract = new Contract({});
      const initialized = await contract.initialState(runtime.createConstructorContext({}, "0".repeat(64)));
      let state = initialized.currentContractState.data;
      for (const [at, args] of [firstArgs, secondArgs].entries()) {
        const input = state.toString();
        const name = `initialize_${suffix}`;
        const context = runtime.createCircuitContext(name, runtime.dummyContractAddress(), "0".repeat(64), state,
          initialized.currentPrivateState, undefined, undefined, undefined, 1700000000);
        let success = false;
        try {
          const out = await contract.circuits[name](context, ...args);
          state = out.context.callContext.currentQueryContext.state;
          success = true;
        } catch (error) {
          assert.equal((error as Error).name, "CompactError");
          assert.match((error as Error).message, /failed assert: (already initialized|first use|change|same)/);
        }
        assert.equal(context.callContext.currentQueryContext.state.toString(), input, "evaluating a call must not mutate its input snapshot");
        assert.equal(success, at === 0 || secondSucceeds, name);
      }
      if (["idempotent", "restorePayload"].includes(suffix)) assert.equal(ledger(state).payload, 0n);
    }
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
