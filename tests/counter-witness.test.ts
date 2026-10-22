import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, type SuccessfulPath } from "../src/dataflow/index.js";
import { Program } from "../src/semantic/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const qualified = { skip: !process.env.COMPACTC_TEST ? "Requires pinned COMPACTC_TEST" : false };
const source = (size: number, reset = true, terminal = false) => `pragma language_version 0.26.0; import CompactStandardLibrary; export ledger count: Counter;
export circuit entry(${Array.from({ length: size }, (_, i) => `flag${i}: Boolean`).join(",")}): [] {
${reset ? "count.resetToDefault();" : ""}
${Array.from({ length: size }, (_, i) => `if (disclose(flag${i})) count.increment(${i % 3 === 0 ? 0 : i + 1});`).join("\n")}
${terminal ? "return [];" : ""}}
`;
function fixture(text: string, compile: boolean, check: (program: Program) => void) {
  withFiles({ "main.compact": text }, directory => {
    const file = resolve(directory, "main.compact");
    if (compile) { const result = validateWithCompiler(process.env.COMPACTC_TEST!, file); assert.equal(result.valid, true, result.error); }
    const program = new Program(file);
    check(program);
  });
}

/** Rename only allocator-generated write IDs, preserving their equality relation.
 * Source allocation is entry-scoped for selection; rename IDs consistently,
 * retaining source origin fields and every equality/distinctness relationship.
 * Every trace/guard, constant, region/revision and user datum remains.
 */
function observation(path: SuccessfulPath): unknown {
  const ids = new Map<string, string>();
  const sources = new Map<string, string>();
  const visit = (value: unknown, field?: string): unknown => {
    if (field === "identity" && typeof value === "string" && /^write:\d+$/.test(value)) {
      if (!ids.has(value)) ids.set(value, `write:${ids.size}`);
      return ids.get(value);
    }
    if (field === "source" && value && typeof value === "object") {
      const source = value as { id: string };
      if (!sources.has(source.id)) sources.set(source.id, `source:${sources.size}`);
      return { ...source, id: sources.get(source.id) };
    }
    if (value instanceof Set) return [...value].sort();
    if (Array.isArray(value)) return value.map(item => visit(item));
    if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => [key, visit(item, key)]));
    return value;
  };
  return visit(path);
}
const choices = (path: SuccessfulPath) => path.path.filter(step => step.kind === "branch").map(step => step.label === "condition may be true");

for (let size = 1; size <= 8; size++) test(`${size}-diamond selected witnesses preserve every exact observation in all four modes`, qualified, () => {
  fixture(source(size, true, size % 2 === 0), true, program => {
    let baseline: Map<string, unknown> | undefined;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const flow = new Dataflow(program, 20000, 256, 50000, engine, cached, cached);
      const facts = flow.analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.equal(facts.paths.length, 2 ** size);
      const current = new Map<string, unknown>();
      for (const path of facts.paths) {
        const assignment = choices(path);
        const selected = flow.selectCounterWitness(path.entry, assignment);
        assert.equal(selected.status, "selected");
        if (selected.status !== "selected") throw new Error(JSON.stringify(selected));
        assert.equal("completedEntries" in selected, false);
        assert.equal("paths" in selected, false);
        assert.deepEqual(selected.decisions, assignment);
        assert.deepEqual(observation(selected.path), observation(path));
        assert.deepEqual(selected.path.writes.map(write => write.location), selected.projection.operations.map(operation => operation.location));
        current.set(JSON.stringify(assignment), observation(selected.path));
      }
      assert.equal(current.size, 2 ** size);
      if (baseline) assert.deepEqual(current, baseline);
      baseline = current;
      // The same object must return to ordinary full analysis after selection.
      const again = flow.analyze();
      assert.deepEqual(again.diagnostics, []);
      assert.deepEqual(again.paths.map(observation), facts.paths.map(observation));
    }
  });
});

test("1024 selected histories use ordinary transfers and a separate arithmetic oracle; full default analysis stays incomplete", qualified, () => {
  fixture(source(10), true, program => {
    const flow = new Dataflow(program);
    const bounded = flow.analyze();
    assert.ok(bounded.diagnostics.some(item => item.code === "analysis-budget"));
    assert.deepEqual(bounded.completedEntries, []);
    for (let bits = 0; bits < 1024; bits++) {
      const assignment = Array.from({ length: 10 }, (_, i) => Boolean(bits & (1 << i)));
      const result = flow.selectCounterWitness(program.entries[0], assignment);
      assert.equal(result.status, "selected");
      if (result.status !== "selected") throw new Error(JSON.stringify(result));
      assert.deepEqual(choices(result.path), assignment);
      let expected = 0n;
      const rows: { before: string | undefined; after: string }[] = [{ before: undefined, after: "0" }];
      for (let i = 0; i < assignment.length; i++) if (assignment[i]) {
        const before = expected;
        expected += BigInt(i % 3 === 0 ? 0 : i + 1);
        rows.push({ before: String(before), after: String(expected) });
      }
      assert.deepEqual(result.path.writes.map(write => ({ before: write.before.constant, after: write.after.constant })), rows);
      assert.equal(result.metrics.paths, 1);
    }
    assert.ok(flow.analyze().diagnostics.some(item => item.code === "analysis-budget"));
  });
});

test("unknown incoming storage, unused parameters and a second entry do not contaminate selected evaluation", qualified, () => {
  fixture(source(3, false).replace("flag0: Boolean", "unused: Field, flag0: Boolean") + "export circuit unrelated(): [] { count.resetToDefault(); }", true, program => {
    for (const engine of ["instructions", "expressions"] as const) {
      const flow = new Dataflow(program, 20000, 256, 50000, engine);
      const entry = program.entries.find(id => program.functions.get(id)!.symbol.name === "entry")!;
      const selected = flow.selectCounterWitness(entry, [true, false, true]);
      assert.equal(selected.status, "selected");
      if (selected.status !== "selected") throw new Error(JSON.stringify(selected));
      assert.ok(selected.path.writes.every(write => write.before.constant === undefined && write.after.constant === undefined));
      assert.ok(selected.path.writes.every(write => write.callPath.length === 1 && write.callPath[0] === entry));
      assert.ok(selected.path.writes.every(write => write.after.flows.every(item => item.source.name !== "unused")));
      assert.equal(flow.analyze().completedEntries.length, 2);
    }
  });
});

test("extraction, graph, projection, transfer, path and value limits remain explicit, without a successful prefix", () => {
  fixture(source(3), false, program => {
    const entry = program.entries[0];
    const cases: [Dataflow, Parameters<Dataflow["selectCounterWitness"]>[2], string][] = [
      [new Dataflow(program), { region: { maxBranches: 1 } }, "counter-region-budget"],
      [new Dataflow(program), { maxGraphNodes: 1 }, "correlated-graph-budget"],
      [new Dataflow(program), { maxProjectionWork: 1 }, "correlated-projection-budget"],
      [new Dataflow(program, 1), {}, "analysis-budget"],
      [new Dataflow(program, 20000, 0), {}, "analysis-budget"],
      [new Dataflow(program, 20000, 256, 1), {}, "value-budget"],
    ];
    for (const [flow, limits, code] of cases) {
      const result = flow.selectCounterWitness(entry, [true, true, true], limits);
      assert.equal(result.status, "incomplete");
      if (result.status !== "incomplete") throw new Error(JSON.stringify(result));
      assert.ok(result.diagnostics.some(item => item.code === code), JSON.stringify(result));
      assert.equal("path" in result, false);
    }
    const flow = new Dataflow(program, 20000, 1);
    assert.equal(flow.selectCounterWitness(entry, [true, false, true]).status, "selected");
    assert.ok(flow.analyze().diagnostics.some(item => item.code === "analysis-budget"));
  });
});

test("unsupported continuations refuse selection; malformed decisions cannot activate branch filtering", () => {
  for (const suffix of ['assert(disclose(flag0), "later");', "count.decrement(1);", "count.read();"]) fixture(source(2).replace(/}\n$/, `${suffix}}\n`), false, program => {
    const result = new Dataflow(program).selectCounterWitness(program.entries[0], [true, false]);
    assert.equal(result.status, "ineligible");
  });
  fixture(source(2), false, program => {
    const flow = new Dataflow(program);
    for (const decisions of [[], [true], [false, true, false], Array(2), [true, 1]]) assert.throws(() => flow.selectCounterWitness(program.entries[0], decisions as boolean[]));
    const getter = [true, false];
    Object.defineProperty(getter, "0", { get() { assert.fail("decision getter executed"); } });
    assert.throws(() => flow.selectCounterWitness(program.entries[0], getter));
    assert.equal(flow.analyze().paths.length, 4);
    assert.equal(flow.selectCounterWitness("missing", [true, false]).status, "ineligible");
  });
});

test("selected observations detach from later analysis and preserve write identity equality under normalization", () => {
  fixture(source(2), false, program => {
    const flow = new Dataflow(program);
    const selected = flow.selectCounterWitness(program.entries[0], [true, true]);
    assert.equal(selected.status, "selected");
    if (selected.status !== "selected") throw new Error(JSON.stringify(selected));
    const snapshot = structuredClone(selected);
    flow.analyze();
    flow.selectCounterWitness(program.entries[0], [false, false]);
    assert.deepEqual(selected, snapshot);
    const corrupted = structuredClone(selected.path);
    assert.equal(selected.path.writes[2].before.identity, selected.path.writes[1].before.identity,
      "The zero increment preserves the reset value's contents identity");
    assert.notEqual(selected.path.writes[2].before.identity, selected.path.writes[0].before.identity);
    corrupted.writes[2].before.identity = corrupted.writes[0].before.identity;
    assert.notDeepEqual(observation(corrupted), observation(selected.path));
    corrupted.writes[2].before = structuredClone(selected.path.writes[2].before);
    corrupted.writes[2].after.flows[0].trace = [];
    assert.notDeepEqual(observation(corrupted), observation(selected.path));
  });
});


test("later-entry source allocation is scoped while origins and equality relations match full analysis", qualified, () => {
  const text = source(3).replace("export circuit entry", "export circuit preceding(unused: Field): [] {}\nexport circuit entry");
  fixture(text, true, program => {
    const entry = program.entries.find(id => program.functions.get(id)!.symbol.name === "entry")!;
    const flow = new Dataflow(program);
    const full = flow.analyze();
    assert.deepEqual(full.diagnostics, []);
    const path = full.paths.find(path => path.entry === entry && choices(path).every(Boolean))!;
    const selected = flow.selectCounterWitness(entry, [true, true, true]);
    assert.equal(selected.status, "selected");
    if (selected.status !== "selected") throw new Error(JSON.stringify(selected));
    assert.notEqual(selected.path.writes[1].after.flows[0].source.id, path.writes[1].after.flows[0].source.id);
    assert.deepEqual(observation(selected.path), observation(path));
    const changed = structuredClone(selected.path);
    changed.writes[2].after.flows[1].source.id = changed.writes[2].after.flows[0].source.id;
    assert.notDeepEqual(observation(changed), observation(selected.path));
  });
});
