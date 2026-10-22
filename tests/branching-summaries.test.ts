import assert from "node:assert/strict";
import { resolve } from "node:path";
import test from "node:test";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { BranchMutationEligibility } from "../src/analysis/summaries.js";
import { Dataflow, Program } from "../src/index.js";
import { semanticPaths, withFiles } from "./helpers.js";

type Facts = ReturnType<Dataflow["analyze"]>;
const globals = "export ledger first: Field; export ledger second: Field; export ledger enabled: Boolean;";
const arms = "if (disclose(flag)) { first = disclose(value); } else { second = disclose(value); }";
function source(entry: string, body = arms, extra = "", parameters = "a: Uint<8>, b: Uint<8>, value: Field"): string {
  return `${globals} ${extra} circuit select(flag: Boolean,value: Field): [] { ${body} } export circuit entry(${parameters}): [] { ${entry} }`;
}
function compare(text: string, check: (cached: Facts, expanded: Facts, program: Program, engine: string) => void): void {
  withFiles({ "main.compact": text }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) { const compiled = validateWithCompiler(process.env.COMPACTC_TEST, path); assert.equal(compiled.valid, true, compiled.error); }
    const program = new Program(path); let reference: string[] | undefined;
    const select = [...program.functions.values()].find(fn => fn.symbol.name === "select")!;
    assert.equal(new BranchMutationEligibility(program).allows(select.symbol.id), true);
    for (const engine of ["instructions", "expressions"] as const) {
      const cached = new Dataflow(program, 20000, 256, 50000, engine, true, true).analyze();
      const expanded = new Dataflow(program, 20000, 256, 50000, engine, false, false).analyze();
      assert.deepEqual(cached.diagnostics, []); assert.deepEqual(expanded.diagnostics, []);
      assert.deepEqual(cached.paths, expanded.paths); assert.deepEqual(cached.failedAssertions, expanded.failedAssertions);
      assert.deepEqual(cached.completedEntries, expanded.completedEntries);
      const semantic = semanticPaths(cached); if (reference) assert.deepEqual(semantic, reference); reference = semantic;
      assert.ok(cached.metrics.statefulSummaryHits > 0, `${engine} must actually replay the branching helper`);
      assert.ok(cached.metrics.summaryEntries <= 256); assert.ok(cached.metrics.summaryEffects <= 4096);
      check(cached, expanded, program, engine);
    }
  });
}

test("actual unknown-two-arm summaries preserve separate histories and all four engine/cache modes", () => compare(source("const flag = (a + 1) < (b + 1); select(flag,value); select(flag,value);"), (cached, expanded, program) => {
  assert.equal(cached.metrics.statefulSummaryHits, 2); assert.equal(cached.metrics.summaryEntries, 1);
  // Arithmetic-derived operands still lack immutable equality identities. These
  // four abstract histories exercise both cached arms, not four concrete executions.
  assert.equal(cached.paths.length, 4);
  const histories = cached.paths.map(path => path.writes.map(write => program.symbols.get(write.ledger)!.name).join(",")).sort();
  assert.deepEqual(histories, ["first,first", "first,second", "second,first", "second,second"]);
  assert.ok(cached.metrics.steps <= expanded.metrics.steps);
  assert.ok(cached.paths.every(path => path.writes.every(write => write.after.flows.some(flow => flow.source.name === "value"))));
}));

test("identity-bearing ordered predicates preserve two feasible histories across repeated helpers", () => {
  withFiles({ "main.compact": source("const flag = a < b; select(flag,value); select(flag,value);") }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) { const result = validateWithCompiler(process.env.COMPACTC_TEST, file); assert.equal(result.valid, true, result.error); }
    const program = new Program(file);
    let expected: string[] | undefined;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 20000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.paths.map(path => path.writes.map(write => program.symbols.get(write.ledger)!.name).join(",")).sort(), ["first,first", "second,second"]);
      if (expected) assert.deepEqual(semanticPaths(facts), expected);
      else expected = semanticPaths(facts);
    }
  });
});

test("void helper joins retain both caller predicates and branch-specific guards", () => {
  withFiles({ "main.compact": `pragma language_version >= 0.26.0;
export ledger saved: Field;
circuit yes(flag: Boolean): [] { assert(flag, "yes"); }
circuit no(flag: Boolean): [] { assert(!flag, "no"); }
circuit guard(flag: Boolean): [] { if (flag) yes(flag); else no(flag); }
export circuit entry(flag: Boolean): Field {
  guard(flag);
  if (disclose(flag)) { saved = 1 as Field; return 1 as Field; }
  saved = 0 as Field; return 0 as Field;
}` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) { const result = validateWithCompiler(process.env.COMPACTC_TEST, file); assert.equal(result.valid, true, result.error); }
    const program = new Program(file);
    let expected: string[] | undefined;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 20000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.equal(facts.paths.length, 2);
      assert.deepEqual(facts.paths.map(path => path.sinks.find(sink => sink.kind === "exported-return")!.value.constant).sort(), ["0", "1"]);
      for (const path of facts.paths) {
        const write = path.writes[0];
        const guards = write.guards.map(id => program.symbols.get(id)!.name);
        const truth = write.after.constant === "1";
        assert.ok(guards.includes(truth ? "yes" : "no"));
        assert.ok(!guards.includes(truth ? "no" : "yes"));
        assert.ok(write.after.flows.some(flow => flow.source.name === "flag"));
      }
      if (expected) assert.deepEqual(semanticPaths(facts), expected);
      else expected = semanticPaths(facts);
    }
  });
});

test("larger ordered arms reuse branch summaries with less charged work", () => compare(source("const flag = (a + 1) < (b + 1); select(flag,value); select(flag,value);", `if (disclose(flag)) { ${"first = disclose(value);".repeat(8)} } else { ${"second = disclose(value);".repeat(8)} }`), (cached, expanded) => {
  assert.equal(cached.metrics.statefulSummaryHits, 2); assert.ok(cached.metrics.steps < expanded.metrics.steps);
  assert.ok(cached.paths.every(path => path.writes.length === 16));
}));

test("branch replay recomputes current before-values after caller overwrites", () => compare(source("const flag = (a + 1) < (b + 1); select(flag,value); first = default<Field>; second = default<Field>; select(flag,value);"), cached => {
  assert.equal(cached.paths.length, 4);
  assert.ok(cached.paths.every(path => path.writes.at(-1)!.before.constant === "0"));
  assert.ok(cached.paths.every(path => path.writes.at(-1)!.after.flows.some(flow => flow.source.name === "value")));
}));

test("shared identity-free prefix writes execute once before replay forks", () => compare(source("const flag = (a + 1) < (b + 1); select(flag,value); select(flag,value); prepared = prepared;", "prepared = default<Field>; if (disclose(flag)) { first = default<Field>; } else { second = default<Field>; }", "export ledger prepared: Field;"), (cached, _expanded) => {
  assert.equal(cached.metrics.statefulSummaryHits, 2);
  assert.equal(cached.paths.length, 4);
  assert.ok(cached.paths.every(path => path.writes.at(-1)!.before.constant === "0"));
}));

test("current caller completion guards survive or invalidate on their own selected writes", () => compare(source("const flag = (a + 1) < (b + 1); select(flag,value); const saved = guard(); select(flag,value);", "if (disclose(flag)) { enabled = false; first = disclose(value); } else { second = disclose(value); }", "circuit guard(): Boolean { return enabled; }"), (cached, _expanded, program) => {
  const guard = [...program.functions.values()].find(fn => fn.symbol.name === "guard")!.symbol.id;
  for (const path of cached.paths) {
    const last = path.writes.at(-1)!;
    if (program.symbols.get(last.ledger)!.name === "first") {
      assert.ok(path.writes.at(-2)!.guards.includes(guard)); assert.equal(last.guards.includes(guard), false);
    } else assert.ok(last.guards.includes(guard));
  }
}));

test("nested callers rebase cached branch write and completion paths", () => compare(source("select(true,default<Field>); wrapper();", arms, "circuit wrapper(): [] { select(true,default<Field>); }", ""), (cached, _expanded, program) => {
  assert.equal(cached.paths.length, 1); assert.equal(cached.metrics.statefulSummaryHits, 1);
  assert.deepEqual(cached.paths[0].writes[1].callPath.map(id => program.symbols.get(id)!.name), ["entry", "wrapper", "select"]);
}));

test("ambient private control is retained separately from callee branch conditions", () => compare(source("if (disclose(outer)) { select(true,value); select(true,value); } else { select(false,value); select(false,value); }", arms, "", "outer: Boolean,value: Field"), cached => {
  assert.equal(cached.paths.length, 2);
  assert.ok(cached.paths.every(path => path.writes.every(write => write.after.flows.some(flow => flow.source.name === "outer"))));
}));

test("caller rejection after actual branch replay removes all successful publications", () => compare(source('const flag = (a + 1) < (b + 1); select(flag,value); select(flag,value); assert(false,"owned stop");'), cached => {
  assert.deepEqual(cached.paths, []); assert.ok(cached.failedAssertions.length > 0);
}));

test("known true and false keys cannot exchange effects between arms", () => compare(source("select(true,value); select(true,value); select(false,value); select(false,value);", arms, "", "value: Field"), (cached, _expanded, program) => {
  assert.equal(cached.paths.length, 1); assert.equal(cached.metrics.statefulSummaryHits, 2);
  assert.deepEqual(cached.paths[0].writes.map(write => program.symbols.get(write.ledger)!.name), ["first", "first", "second", "second"]);
}));

test("saturated branch journals fall back for both arms without dropping effects", () => {
  const text = source("const flag = (a + 1) < (b + 1); select(flag,value); select(flag,value);", `if (disclose(flag)) { ${"first = disclose(value);".repeat(70)} } else { ${"second = disclose(value);".repeat(70)} }`);
  withFiles({ "main.compact": text }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) { const result = validateWithCompiler(process.env.COMPACTC_TEST, path); assert.equal(result.valid, true, result.error); }
    const program = new Program(path), select = [...program.functions.values()].find(fn => fn.symbol.name === "select")!;
    assert.equal(new BranchMutationEligibility(program).allows(select.symbol.id), true);
    for (const engine of ["instructions", "expressions"] as const) {
      const cached = new Dataflow(program, 20000, 256, 50000, engine, true, true).analyze();
      const expanded = new Dataflow(program, 20000, 256, 50000, engine, false, false).analyze();
      assert.deepEqual(cached.diagnostics, []); assert.deepEqual(cached.paths, expanded.paths);
      assert.equal(cached.metrics.statefulSummaryHits, 0); assert.equal(cached.metrics.summaryEntries, 0);
      assert.ok(cached.paths.every(path => path.writes.length === 140));
    }
  });
});

test("path and value exhaustion on a cold branch cannot seed a successful partial summary", () => {
  withFiles({ "main.compact": source("const flag = (a + 1) < (b + 1); select(flag,value); select(flag,value);") }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    for (const engine of ["instructions", "expressions"] as const) for (const [paths, values, code] of [[1, 50000, "analysis-budget"], [256, 3, "value-budget"]] as const) {
      const cached = new Dataflow(program, 20000, paths, values, engine, true, true).analyze();
      const expanded = new Dataflow(program, 20000, paths, values, engine, false, false).analyze();
      assert.ok(cached.diagnostics.some(diagnostic => diagnostic.code === code)); assert.deepEqual(cached.diagnostics, expanded.diagnostics);
      assert.deepEqual(cached.completedEntries, []); assert.deepEqual(cached.paths, expanded.paths);
      assert.equal(cached.metrics.summaryEntries, 0); assert.equal(cached.metrics.statefulSummaryHits, 0);
    }
  });
});

test("guard-cover interpretation conservatively bypasses branch summary recording", () => {
  withFiles({ "main.compact": source("const flag = (a + 1) < (b + 1); select(flag,value); select(flag,value);") }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const cached = new Dataflow(program, 20000, 256, 50000, "instructions", true, true, "guard-cover").analyze();
    const expanded = new Dataflow(program, 20000, 256, 50000, "instructions", false, false, "guard-cover").analyze();
    assert.deepEqual(cached.diagnostics, []); assert.deepEqual(cached.paths, expanded.paths); assert.equal(cached.metrics.statefulSummaryHits, 0);
  });
});

test("deduplicated unknown arms cannot seed a summary claiming both observed choices", () => {
  withFiles({ "main.compact": source("const flag = (a + 1) < (b + 1); select(flag,value); select(flag,value);", "first = disclose(value); if (disclose(flag)) {} else {} second = disclose(value);") }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) { const result = validateWithCompiler(process.env.COMPACTC_TEST, path); assert.equal(result.valid, true, result.error); }
    const program = new Program(path);
    for (const engine of ["instructions", "expressions"] as const) {
      const cached = new Dataflow(program, 20000, 256, 50000, engine, true, true).analyze();
      const expanded = new Dataflow(program, 20000, 256, 50000, engine, false, false).analyze();
      assert.deepEqual(cached.diagnostics, []); assert.deepEqual(cached.paths, expanded.paths);
      assert.equal(cached.paths.length, 1); assert.equal(cached.metrics.statefulSummaryHits, 0); assert.equal(cached.metrics.summaryEntries, 0);
    }
  });
});

test("join cleanup uses current caller references instead of restoring recorded constraint maps", () => {
  const text = source('assert(remember,"owned"); enabled = disclose(remember); select(true,value); enabled = false; assert(remember,"owned"); select(true,value);', arms, "", "remember: Boolean,value: Field");
  withFiles({ "main.compact": text }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) { const result = validateWithCompiler(process.env.COMPACTC_TEST, path); assert.equal(result.valid, true, result.error); }
    const program = new Program(path);
    for (const engine of ["instructions", "expressions"] as const) {
      const run = (summaries: boolean) => {
        const dataflow = new Dataflow(program, 20000, 256, 50000, engine, summaries, summaries);
        // Observe internal constraint lifetime on an owned compiler-valid case.
        // This is a transfer regression, not a separate execution attestation.
        const observable = dataflow as unknown as { invoke: (...args: unknown[]) => { state: { known: Map<string, unknown> } }[] };
        const invoke = observable.invoke.bind(observable), snapshots: string[][][] = [];
        observable.invoke = (...args) => {
          const results = invoke(...args);
          if ((args[0] as { symbol: { name: string } }).symbol.name === "select") snapshots.push(results.map(result => [...result.state.known.keys()].sort()));
          return results;
        };
        return { facts: dataflow.analyze(), snapshots };
      };
      const cached = run(true), expanded = run(false);
      assert.deepEqual(cached.facts.diagnostics, []); assert.deepEqual(cached.facts.paths, expanded.facts.paths);
      assert.deepEqual(cached.snapshots, expanded.snapshots); assert.equal(cached.facts.metrics.statefulSummaryHits, 1);
      assert.equal(cached.snapshots.length, 2); assert.equal(cached.snapshots[0][0].length, 1); assert.deepEqual(cached.snapshots[1][0], []);
    }
  });
});

test("shared entry saturation declines new branch caches while retaining earlier usable entries", () => compare(source(`${Array.from({ length: 257 }, (_, index) => `select(false,${index} as Field);`).join("")} select(false,0 as Field);`, "if (disclose(flag)) { first = disclose(value); }", "", ""), cached => {
  assert.equal(cached.metrics.summaryEntries, 256); assert.equal(cached.metrics.statefulSummaryHits, 1);
  assert.equal(cached.paths.length, 1); assert.deepEqual(cached.paths[0].writes, []);
}));

test("shared retained-effect saturation falls back without truncating later writes", () => compare(source(`${Array.from({ length: 200 }, (_, index) => `select(true,${index} as Field);`).join("")} select(true,0 as Field);`, `if (disclose(flag)) { ${"first = disclose(value);".repeat(8)} }`, "", ""), cached => {
  assert.ok(cached.metrics.summaryEntries < 200); assert.equal(cached.metrics.statefulSummaryHits, 1);
  assert.ok(cached.metrics.summaryEffects <= 4096); assert.ok(cached.metrics.summaryEffects > 4000);
  assert.equal(cached.paths[0].writes.length, 201 * 8);
}));

test("actual branch cache hits still terminate with explicit step exhaustion", () => {
  withFiles({ "main.compact": source("const flag = (a + 1) < (b + 1); select(flag,value); select(flag,value);", `if (disclose(flag)) { ${"first = disclose(value);".repeat(8)} } else { ${"second = disclose(value);".repeat(8)} }`) }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    for (const engine of ["instructions", "expressions"] as const) {
      let exercised = false;
      for (let steps = 50; steps <= 400; steps += 10) {
        const facts = new Dataflow(program, steps, 256, 50000, engine, true, true).analyze();
        if (!facts.metrics.statefulSummaryHits || !facts.diagnostics.some(diagnostic => diagnostic.code === "analysis-budget")) continue;
        assert.deepEqual(facts.completedEntries, []); exercised = true; break;
      }
      assert.ok(exercised, `${engine} must exhaust after a real branch cache hit`);
    }
  });
});

test("warmed branching helpers cannot bypass nested call-depth checks", () => {
  const chain = Array.from({ length: 31 }, (_, index) => `circuit chain${index}(): [] { ${index === 30 ? "select(true,default<Field>)" : `chain${index + 1}()`}; }`).join("\n");
  withFiles({ "main.compact": source("select(true,default<Field>); chain0();", arms, chain, "") }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) { const result = validateWithCompiler(process.env.COMPACTC_TEST, path); assert.equal(result.valid, true, result.error); }
    const program = new Program(path);
    for (const engine of ["instructions", "expressions"] as const) {
      const cached = new Dataflow(program, 20000, 256, 50000, engine, true, true).analyze();
      const expanded = new Dataflow(program, 20000, 256, 50000, engine, false, false).analyze();
      assert.ok(cached.diagnostics.some(diagnostic => diagnostic.code === "call-depth"));
      assert.deepEqual(cached.diagnostics, expanded.diagnostics); assert.deepEqual(cached.paths, expanded.paths); assert.deepEqual(cached.completedEntries, []);
      assert.equal(cached.metrics.statefulSummaryHits, 0); assert.equal(cached.metrics.summaryEntries, 1);
    }
  });
});

test("cached empty returns preserve final-call alternatives and write provenance without inventing returned data", () => compare(source("const flag = (a + 1) < (b + 1); select(flag,value); return select(flag,value);", arms + " return [];"), (cached, _expanded) => {
  assert.equal(cached.paths.length, 4);
  assert.ok(cached.paths.every(path => path.sinks.at(-1)!.kind === "exported-return"));
  // [] carries no data. Control still reaches the actual public ledger writes.
  for (const path of cached.paths) {
    assert.deepEqual(path.sinks.at(-1)!.value.items, []);
    assert.deepEqual(path.sinks.at(-1)!.value.flows, []);
    const writes = path.sinks.filter(sink => sink.kind === "ledger-write");
    assert.equal(writes.length, 2);
    for (const sink of writes) assert.deepEqual([...new Set(sink.value.flows.map(flow => flow.source.name))].sort(), ["a", "b", "value"]);
  }
}));

test("public scalar return after branch replay preserves current storage and implicit-flow provenance", () => compare(source("const flag = (a + 1) < (b + 1); select(flag,value); first = default<Field>; select(flag,value); return first;").replace("export circuit entry(a: Uint<8>, b: Uint<8>, value: Field): []", "export circuit entry(a: Uint<8>, b: Uint<8>, value: Field): Field"), (cached, _expanded, program) => {
  assert.equal(cached.paths.length, 4);
  for (const path of cached.paths) {
    const returned = path.sinks.at(-1)!;
    assert.equal(returned.kind, "exported-return");
    assert.deepEqual(returned.callPath.map(id => program.symbols.get(id)!.name), ["entry"]);
    if (program.symbols.get(path.writes.at(-1)!.ledger)!.name === "first") {
      assert.deepEqual([...new Set(returned.value.flows.map(flow => flow.source.name))].sort(), ["a", "b", "value"]);
      assert.equal(returned.value.constant, undefined);
    } else {
      assert.deepEqual(returned.value.flows, []);
      assert.equal(returned.value.constant, "0");
    }
  }
}));

for (const [name, argument, parameters] of [
  ["live ledger argument", "enabled", "value: Field"],
  ["negated scalar metadata", "!flag", "flag: Boolean,value: Field"],
  ["comparison metadata", "a == b", "a: Field,b: Field,value: Field"],
] as const) test(`runtime branch admission falls back for ${name}`, () => {
  withFiles({ "main.compact": source(`select(${argument},value); select(${argument},value);`, arms, "", parameters) }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) { const result = validateWithCompiler(process.env.COMPACTC_TEST, path); assert.equal(result.valid, true, result.error); }
    const program = new Program(path);
    for (const engine of ["instructions", "expressions"] as const) {
      const cached = new Dataflow(program, 20000, 256, 50000, engine, true, true).analyze();
      const expanded = new Dataflow(program, 20000, 256, 50000, engine, false, false).analyze();
      assert.deepEqual(cached.diagnostics, []); assert.deepEqual(cached.paths, expanded.paths); assert.deepEqual(cached.failedAssertions, expanded.failedAssertions);
      assert.equal(cached.metrics.statefulSummaryHits, 0);
    }
  });
});
