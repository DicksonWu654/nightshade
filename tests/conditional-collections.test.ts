import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { CollectionFacts } from "../src/dataflow/collections.js";
import { ConditionalCollections, type ConditionalCollectionState } from "../src/dataflow/conditional-collections.js";
import type { Region } from "../src/dataflow/regions.js";
import { Program, Dataflow } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const region: Region = { root: "table", path: [], type: "Map<Field,Field>" };
const key = (index: number) => `integer:${index}`;
const required = (state: ConditionalCollectionState | undefined): ConditionalCollectionState => {
  assert.ok(state); return state;
};
function domain(maxSteps = 40000, maxValues = 50000) {
  const work = { steps: 0, values: 0 };
  const graph = new ConditionalCollections((steps, values) => {
    work.steps += steps; work.values += values;
    return work.steps <= maxSteps && work.values <= maxValues;
  });
  return { graph, work };
}

test("conditional collection membership and lookup rejection agree with compiler-valid ordinary paths", () => {
  const source = `import CompactStandardLibrary;
  export ledger table: Map<Field,Field>;
  export circuit entry(flags: Vector<4,Boolean>): Uint<64> {
    table.resetToDefault();
    for (const i of 0..4) {
      if (disclose(flags[i])) { table.insert(i as Field, 9 as Field); }
      else { table.remove(i as Field); }
    }
    const required = table.lookup(2 as Field);
    return table.size();
  }`;
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const { graph } = domain();
    let state = required(graph.initial(new CollectionFacts()));
    state = required(graph.apply(state, { kind: "reset", region }));
    for (let i = 0; i < 4; i++) {
      const yes = required(graph.apply(state, { kind: "insert", region, key: key(i) }));
      const no = required(graph.apply(state, { kind: "remove", region, key: key(i) }));
      state = required(graph.choose(`flag${i}`, yes, no));
    }
    const beforeLookup = state;
    state = required(graph.apply(state, { kind: "lookup", region, key: key(2) }));
    const view = graph.common(state);
    assert.equal(view.status, "available");
    if (view.status !== "available") return assert.fail("Missing must view");
    assert.equal(view.facts.member(region, key(2)), true);
    const program = new Program(file);
    for (const engine of ["instructions", "expressions"] as const) for (const cache of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cache, cache).analyze();
      assert.deepEqual(facts.diagnostics, []); assert.equal(facts.paths.length, 8);
      for (let bits = 0; bits < 16; bits++) {
        const decisions = new Map(Array.from({ length: 4 }, (_, i) => [`flag${i}`, !!(bits & 1 << i)]));
        const before = graph.select(beforeLookup, decisions, 40000);
        assert.equal(before.status, "selected");
        const selected = graph.select(state, decisions, 40000);
        if (!(bits & 4)) { assert.equal(selected.status, "rejected"); continue; }
        assert.equal(selected.status, "selected");
        if (selected.status !== "selected") return assert.fail("Missing selected store");
        const path = facts.paths.find(path => path.path.filter(step => step.kind === "branch")
          .every((step, i) => step.label.endsWith(String(decisions.get(`flag${i}`)))))!;
        assert.ok(path);
        const returned = path.sinks.find(sink => sink.kind === "exported-return")!.value;
        assert.equal(String(selected.facts.size(region)), returned.constant);
        for (let i = 0; i < 4; i++) assert.equal(selected.facts.member(region, key(i)), decisions.get(`flag${i}`));
      }
    }
  });
});

test("24 collection choices retain real alternatives without enumerating them", () => {
  const { graph, work } = domain();
  const facts = new CollectionFacts(); facts.reset(region);
  let state = required(graph.initial(facts));
  for (let i = 0; i < 24; i++) state = required(graph.choose(`flag${i}`,
    required(graph.apply(state, { kind: "insert", region, key: key(i) })),
    required(graph.apply(state, { kind: "remove", region, key: key(i) }))));
  assert.equal(work.values, 73);
  const view = graph.common(state);
  assert.equal(view.status, "available");
  if (view.status !== "available") return assert.fail("Missing must view");
  assert.equal(view.facts.size(region), undefined);
  for (let i = 0; i < 24; i++) assert.equal(view.facts.member(region, key(i)), undefined);
  for (const residue of [0, 1, 2]) {
    const decisions = new Map(Array.from({ length: 24 }, (_, i) => [`flag${i}`, i % 3 === residue]));
    const selected = graph.select(state, decisions, 40000);
    assert.equal(selected.status, "selected");
    if (selected.status !== "selected") return assert.fail("Missing selected store");
    assert.equal(selected.facts.size(region), 8);
    for (let i = 0; i < 24; i++) assert.equal(selected.facts.member(region, key(i)), i % 3 === residue);
  }
  assert.equal(work.values, 73 + 1 + 3 * 25, "the common view and each selected projection charge their detached results");
});

test("same-selector reuse, unknown entry storage and saved snapshots remain distinct", () => {
  const { graph } = domain();
  const input = new CollectionFacts();
  const initial = required(graph.initial(input)); input.reset(region);
  const address: Region = { ...region, path: [] };
  const inserted = required(graph.apply(initial, { kind: "insert", region: address, key: key(1) }));
  address.path.push("key:integer:9");
  const removed = required(graph.apply(initial, { kind: "remove", region, key: key(1) }));
  const chosen = required(graph.choose("flag", inserted, removed));
  const absent = required(graph.apply(chosen, { kind: "member", region, key: key(1), present: false }));
  const current = required(graph.choose("flag", chosen, absent));
  for (const flag of [false, true]) {
    const decisions = new Map([["flag", flag]]), selected = graph.select(current, decisions, 100);
    assert.equal(selected.status, "selected");
    if (selected.status !== "selected") return assert.fail("Missing store");
    assert.equal(selected.facts.member(region, key(1)), flag);
    selected.facts.reset(region);
    const saved = graph.select(initial, decisions, 100);
    assert.equal(saved.status, "selected");
    if (saved.status !== "selected") return assert.fail("Missing saved store");
    assert.equal(saved.facts.member(region, key(1)), undefined);
  }
  assert.equal(graph.select(absent, new Map([["flag", true]]), 100).status, "rejected");
});

test("dynamic and wildcard operations use ordinary may-alias and nested invalidation rules", () => {
  const { graph } = domain();
  const left = new CollectionFacts(), right = new CollectionFacts();
  const nested = { ...region, path: ["key:integer:0"] };
  left.reset(nested); right.reset(nested);
  left.insert(nested, "identity:a"); right.insert(nested, key(2));
  const chosen = required(graph.choose("flag", required(graph.initial(left)), required(graph.initial(right))));
  const wildcard = { ...region, path: ["key:*"] };
  const updated = required(graph.apply(chosen, { kind: "remove", region: wildcard, key: key(2) }));
  for (const flag of [false, true]) {
    const expected = (flag ? left : right).clone(); expected.remove(wildcard, key(2));
    const selected = graph.select(updated, new Map([["flag", flag]]), 100);
    assert.equal(selected.status, "selected");
    if (selected.status !== "selected") return assert.fail("Missing selected store");
    assert.deepEqual(selected.facts.snapshot(), expected.snapshot());
  }
  const reset = required(graph.apply(updated, { kind: "reset", region }));
  const selected = graph.select(reset, new Map([["flag", true]]), 100);
  assert.equal(selected.status, "selected");
  if (selected.status === "selected") assert.equal(selected.facts.member(nested, key(2)), undefined);
});

test("construction, selected facts, missing choices and projection exhaustion are explicit", () => {
  const { graph } = domain(2);
  const initial = required(graph.initial(new CollectionFacts()));
  const updated = required(graph.apply(initial, { kind: "insert", region, key: key(1) }));
  assert.equal(graph.choose("flag", initial, updated), undefined);
  assert.equal(graph.select(updated, new Map(), 100).status, "incomplete");
  assert.equal(graph.common(initial).status, "incomplete");

  const healthy = domain().graph;
  const start = required(healthy.initial(new CollectionFacts()));
  const end = required(healthy.apply(start, { kind: "insert", region, key: key(1) }));
  const branch = required(healthy.choose("flag", start, end));
  assert.equal(healthy.select(branch, new Map(), 100).status, "incomplete");
  assert.equal(healthy.select(branch, new Map([["flag", false]]), 1).status, "incomplete");
  assert.throws(() => healthy.select(initial, new Map(), 100), /Foreign/);

  const shared = domain(4).graph;
  const saved = required(shared.initial(new CollectionFacts()));
  for (let i = 0; i < 3; i++) assert.equal(shared.select(saved, new Map(), 100).status, "selected");
  assert.equal(shared.select(saved, new Map(), 100).status, "incomplete");
  assert.equal(shared.common(saved).status, "incomplete");

  const projectionValues = domain(40000, 2).graph;
  const original = required(projectionValues.initial(new CollectionFacts()));
  assert.equal(projectionValues.select(original, new Map(), 100).status, "selected");
  assert.equal(projectionValues.select(original, new Map(), 100).status, "incomplete");

  // Each branch fits, but its intersection needs all four unknown exceptions.
  const first = new CollectionFacts(2), second = new CollectionFacts(2);
  first.reset(region); second.reset(region);
  first.insert(region, key(0)); first.insert(region, key(1));
  second.insert(region, key(2)); second.insert(region, key(3));
  const constrained = domain().graph;
  const a = required(constrained.initial(first)), b = required(constrained.initial(second));
  assert.equal(constrained.choose("flag", a, b), undefined);
  assert.match(constrained.incompleteReason!, /fact capacity/);
  assert.equal(constrained.select(a, new Map(), 100).status, "incomplete");
});

test("unselected rejection and exhausted depth/value budgets cannot manufacture successful evidence", () => {
  const { graph } = domain();
  const input = new CollectionFacts(); input.reset(region);
  const empty = required(graph.initial(input));
  const rejected = required(graph.apply(empty, { kind: "lookup", region, key: key(1) }));
  assert.deepEqual(graph.common(rejected), { status: "all-rejected" });
  const present = required(graph.apply(empty, { kind: "insert", region, key: key(1) }));
  const selected = required(graph.choose("flag", rejected, present));
  assert.equal(graph.common(selected).status, "available");
  assert.equal(graph.select(selected, new Map([["flag", true]]), 100).status, "rejected");
  assert.equal(graph.select(selected, new Map([["flag", false]]), 100).status, "selected");
  const contradicted = required(graph.apply(selected, { kind: "empty", region, empty: true }));
  assert.equal(graph.common(contradicted).status, "all-rejected");
  for (const flag of [false, true]) assert.equal(graph.select(contradicted, new Map([["flag", flag]]), 100).status, "rejected");

  const limited = domain(40000, 1).graph;
  const seed = required(limited.initial(new CollectionFacts()));
  assert.equal(limited.apply(seed, { kind: "reset", region }), undefined);
  assert.equal(limited.select(seed, new Map(), 100).status, "incomplete");

  const deep = domain().graph;
  let state = required(deep.initial(new CollectionFacts()));
  for (let i = 0; i < 512; i++) state = required(deep.apply(state, { kind: "invalidate", region }));
  assert.equal(deep.select(state, new Map(), 513).status, "selected");
  assert.equal(deep.apply(state, { kind: "invalidate", region }), undefined);
  assert.match(deep.incompleteReason!, /depth/);
  assert.equal(deep.select(state, new Map(), 514).status, "incomplete");
});
