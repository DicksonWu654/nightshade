import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, type AbstractValue } from "../src/index.js";
import type { SuccessfulPath } from "../src/dataflow/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { ConditionalStateGraph, type ConditionalTerm } from "../src/dataflow/conditional-state.js";
import { readStorageRegion, writeStorageRegion, recordStorageWrite, joinStorageValues, selectStorageValue, type RecordedStorageState, type StorageServices } from "../src/dataflow/storage.js";
import { regionFromKey } from "../src/dataflow/regions.js";
import { combine, controlled, step } from "../src/dataflow/transfers.js";
import { withFiles } from "./helpers.js";

interface Current extends RecordedStorageState {
  control: AbstractValue[];
  operand?: AbstractValue;
  sinks: SuccessfulPath["sinks"];
  path: SuccessfulPath["path"];
  predicates: NonNullable<SuccessfulPath["predicates"]>;
}
const required = <T>(value: T | undefined): T => { assert.ok(value); return value; };
const clone = (state: Current): Current => ({ ...state, ledger: new Map(state.ledger), ledgerVersions: new Map(state.ledgerVersions),
  guards: new Set(state.guards), excluded: new Map(state.excluded), writes: state.writes.slice(), control: state.control.slice(),
  sinks: state.sinks.slice(), path: state.path.slice(), predicates: state.predicates.slice() });

for (const count of [4, 8]) test(`conditional storage selects full ordinary payloads, public sinks and histories across ${count} branches`, t => {
  const source = `import CompactStandardLibrary;
struct Pair { first: Field, second: Bytes<32> }
export ledger cells: Map<Field,Pair>;
export ledger output: Pair;
circuit guard(): Pair { return cells.lookup(0 as Field); }
export circuit entry(flags: Vector<${count},Boolean>,x: Field,y: Field): Pair {
  cells.insert(0 as Field,Pair { first: disclose(x), second: disclose(persistentHash<Field>(x)) });
  cells.insert(1 as Field,Pair { first: disclose(y), second: disclose(persistentHash<Field>(y)) });
  const checked = guard();
  ${Array.from({ length: count }, (_, i) => `if (disclose(flags[${i}])) { cells.insert(0 as Field,cells.lookup(1 as Field)); }
  else { cells.insert(1 as Field,cells.lookup(0 as Field)); }`).join("\n  ")}
  output = cells.lookup(0 as Field);
  return output;
}`;
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(file), entry = program.entries[0];
    const guard = [...program.functions.values()].find(fn => fn.symbol.name === "guard")!.symbol.id;
    assert.ok(program.instructionCFG(entry).nodes.filter(node => node.kind === "branch").every(node => node.join === -1));
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, true, "all").analyze();
      assert.deepEqual(facts.diagnostics, []); assert.equal(facts.paths.length, 2 ** count);
      const cfg = engine === "instructions" ? program.instructionCFG(entry) : program.functions.get(entry)!.cfg;
      const branches = cfg.nodes.filter(node => node.kind === "branch");
      const replay = new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, true, "all");
      let sourceSteps = 0, maximumSelectedSteps = 0;
      for (const expected of facts.paths) {
        const decisions = new Map(branches.map(node => {
          const choice = expected.path.find(item => item.kind === "branch" && item.location.start === node.span.start && item.location.end === node.span.end);
          assert.ok(choice);
          return [node.id, choice.label.endsWith("true")];
        }));
        const selected = replay.selectConditionalSource(entry, decisions);
        sourceSteps += selected.metrics.steps;
        maximumSelectedSteps = Math.max(maximumSelectedSteps, selected.metrics.steps);
        assert.equal(selected.status, "selected", selected.status === "incomplete" ? JSON.stringify(selected.diagnostics) : "");
        if (selected.status === "selected") assert.deepEqual(selected.path, expected, "source CFG replay retains the full ordinary history");
      }
      t.diagnostic(JSON.stringify({ representation: "source CFG", count, engine, cached, selectedHistories: facts.paths.length,
        sourceSteps, maximumSelectedSteps, allowanceScope: "per selected invocation, not whole-entry coverage" }));
      let work = 0, values = 0, snapshots = 0, writes = 0;
      const graph = new ConditionalStateGraph((steps, nodes) => { work += steps; values += nodes; return work <= 40000 && values <= 50000; });
      const services: StorageServices<Current> = {
        typedValue: (type, leaf): AbstractValue => {
          if (++values > 50000) graph.refuse("Owned payload expansion exhausted the shared value allowance");
          const fields = program.fieldsOf(type);
          if (!fields) return { ...leaf(), type };
          const children = Object.fromEntries(Object.entries(fields).map(([name, field]) => [name, services.typedValue(field, leaf)]));
          return { ...combine(Object.values(children)), fields: children, type };
        },
        refine: (_state, value) => value, nextSnapshot: () => snapshots++, nextWrite: () => writes++,
        rootType: root => program.symbols.get(root)!.type, representationOf: type => program.representationOf(type),
        fieldsOf: type => program.fieldsOf(type), guardReads: (guard, root) => program.functions.get(guard)?.readsState.has(root) ?? false,
      };
      const common = (left: Current, right: Current): Current => {
        const keys = new Set([...left.ledger.keys(), ...right.ledger.keys()]);
        return { ...left, ledger: new Map([...keys].map(key => {
          const region = regionFromKey(key, (left.ledger.get(key) ?? right.ledger.get(key))!.type!);
          return [key, joinStorageValues([readStorageRegion(left, region, services), readStorageRegion(right, region, services)])];
        })), ledgerVersions: new Map([...new Set([...left.ledgerVersions.keys(), ...right.ledgerVersions.keys()])]
          .map(root => [root, Math.max(left.ledgerVersions.get(root) ?? 0, right.ledgerVersions.get(root) ?? 0)])),
        guards: new Set([...left.guards].filter(guard => right.guards.has(guard))), excluded: new Map(),
        control: left.control.map((value, i) => joinStorageValues([value, right.control[i]])),
        writes: [], sinks: [], predicates: [], path: [], operand: undefined };
      };
      const initial: Current = { ledger: new Map(), ledgerVersions: new Map(), excluded: new Map(), guards: new Set(),
        writes: [], control: [], sinks: [], path: [], predicates: [] };
      let current = required(graph.atom(initial));
      const sample = facts.paths[0];
      assert.ok(sample.writes[0].after.fields!.second.directHash, "the payload oracle includes exact private-preimage metadata");
      const write = (input: ConditionalTerm<Current>, blueprint: SuccessfulPath["writes"][number], value?: AbstractValue): ConditionalTerm<Current> => required(graph.apply([input], previous => {
        const state = clone(previous), region = blueprint.before.region!, location = blueprint.location;
        const assigned = value ?? (region.path.length ? selectStorageValue(state.operand!, step(region.collectionSelectors?.at(-1)?.value
          ?? { flows: [], ledger: new Set(), constantKind: "integer", constant: region.path.at(-1)!.split(":").at(-1), type: "Field" }, "ledger-selection", "insertion key", location, "derived")) : state.operand!);
        const after = controlled(assigned, state.control, location, region.path.length === 0);
        const sink = sample.sinks.find(sink => sink.location.start === location.start)
          ?? facts.paths.flatMap(path => path.sinks).find(sink => sink.location.start === location.start)!;
        assert.ok(sink);
        // Same argument/control kernel as ledgerOperationBody; literal keys have
        // no provenance. Whole-root assignments publish their assigned value.
        state.sinks.push({ ...sink, value: region.path.length ? controlled(combine([assigned]), state.control, location, true) : after });
        recordStorageWrite(state, region, after, location, blueprint.callPath, blueprint.callSites ?? [], services);
        writeStorageRegion(state, region, after, services);
        return state;
      }));
      for (const blueprint of sample.writes.slice(0, 2)) current = write(current, blueprint, blueprint.after);
      current = required(graph.apply([current], previous => { const state = clone(previous); state.guards.add(guard); return state; }));
      const lookup = (input: ConditionalTerm<Current>, blueprint: SuccessfulPath["writes"][number], path: SuccessfulPath): ConditionalTerm<Current> => required(graph.apply([input], previous => {
        const state = clone(previous), region = blueprint.after.region!;
        const sink = path.sinks.find(sink => sink.name === "cells.lookup" && sink.location.start > blueprint.location.start && sink.location.end <= blueprint.location.end)!;
        assert.ok(sink);
        const key = region.collectionSelectors!.at(-1)!.value;
        state.sinks.push({ ...sink, value: controlled(combine([key]), state.control, sink.location, true) });
        state.operand = readStorageRegion(state, region, services);
        return state;
      }));
      for (let index = 0; index < count; index++) {
        const arm = (truth: boolean): ConditionalTerm<Current> => {
          const path = facts.paths.find(path => path.predicates![index].truth === truth)!;
          const blueprint = path.writes[index + 2];
          const entered = required(graph.apply([current], previous => {
            const state = clone(previous), predicate = path.predicates![index];
            state.control.push(predicate.value);
            state.predicates.push({ ...predicate, writesBefore: state.writes.length });
            state.path.push(path.path.filter(item => item.kind === "branch")[index]);
            return state;
          }));
          return write(lookup(entered, blueprint, path), blueprint);
        };
        current = required(graph.choose(`flag${index}`, arm(true), arm(false), common));
      }
      const finalWrite = sample.writes.at(-1)!;
      current = write(lookup(current, finalWrite, sample), finalWrite);
      const exported = sample.sinks.find(sink => sink.kind === "exported-return")!;
      current = required(graph.apply([current], previous => {
        const state = clone(previous), symbol = program.symbols.get(finalWrite.ledger)!;
        const output = readStorageRegion(state, { root: symbol.id, path: [], type: symbol.type }, services);
        const value = { ...controlled(step(output, "return", program.symbols.get(entry)!.name, exported.location), state.control, exported.location), type: program.functions.get(entry)!.declaration.type };
        state.sinks.push({ ...exported, value }); return state;
      }));
      const constructed = graph.size;
      assert.ok(constructed < 8 * count + 10);
      for (const expected of facts.paths) {
        snapshots = writes = 0;
        const decisions = new Map(expected.predicates!.map((predicate, i) => [`flag${i}`, predicate.truth]));
        const selected = graph.select(current, decisions, 40000, state => structuredClone(state));
        assert.equal(selected.status, "selected", selected.status === "incomplete" ? selected.reason : "");
        if (selected.status !== "selected") continue;
        // Full values: traces, identities, regions/revisions, aggregate fields,
        // origin metadata, exclusions, guard order and call sites are retained.
        assert.deepEqual(selected.value.writes, expected.writes);
        assert.deepEqual(selected.value.sinks, expected.sinks);
        assert.deepEqual(selected.value.predicates, expected.predicates);
        assert.deepEqual(selected.value.path, expected.path);
      }
      assert.equal(graph.size, constructed, "selected replay does not expand the retained graph");
      assert.ok(work < 40000 && values < 50000);
      t.diagnostic(JSON.stringify({ representation: "hand-lowered recipe", count, engine, cached, selectedHistories: facts.paths.length, constructed, graphWork: work, values }));
    }
  });
});

test("source construction cannot contaminate assertion reach with an eager joined state", () => {
  const source = `import CompactStandardLibrary;
export circuit entry(flag: Boolean, a: Field, b: Field, c: Field): [] {
  if (disclose(flag)) { assert(a == b, "first"); }
  else { assert(a == c, "second"); assert(c == b, "third"); }
  assert(a != b, "impossible after either arm");
}`;
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) { const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file); assert.equal(compiled.valid, true, compiled.error); }
    const program = new Program(file), entry = program.entries[0];
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(facts.diagnostics, []); assert.equal(facts.paths.length, 0);
      const cfg = engine === "instructions" ? program.instructionCFG(entry) : program.functions.get(entry)!.cfg;
      const branch = cfg.nodes.find(node => node.kind === "branch")!;
      const replay = new Dataflow(program, 40000, 256, 50000, engine, cached, cached);
      for (const selected of [false, true]) {
        const result = replay.selectConditionalSource(entry, new Map([[branch.id, selected]]));
        assert.equal(result.status, "rejected");
        if (result.status !== "rejected") continue;
        const final = result.assertions.at(-1)!;
        assert.equal(final.maySucceed, false); assert.equal(final.mayFail, true);
        assert.equal(result.assertions.length, selected ? 2 : 3, "unselected assertions publish no reach evidence");
      }
    }
  });
});

test("deferred transfers do not run during construction and source choices follow prefix constraints", () => {
  let calls = 0;
  const graph = new ConditionalStateGraph(() => true);
  const input = required(graph.atom(0));
  const transfer = required(graph.defer([input], value => { calls++; return value + 1; }));
  const branch = required(graph.decision("earlier", transfer, () => undefined, (value, selected) => selected ? value : undefined));
  const late = required(graph.decision("later", branch, value => value === undefined ? false : undefined, value => value));
  assert.equal(calls, 0);
  assert.equal(graph.common(transfer, value => value).status, "incomplete");
  assert.equal(calls, 0);
  const selected = graph.select(late, new Map([["earlier", false]]), 100, value => value);
  assert.equal(selected.status, "selected");
  if (selected.status === "selected") assert.equal(selected.value, undefined);
  assert.equal(calls, 1, "rejected prefix makes the later decision unreachable");
});

test("source replay preserves lookup rejection, current revisions, early returns and call sites", () => {
  const source = `import CompactStandardLibrary;
export ledger cells: Map<Field, Field>;
export ledger output: Field;
circuit read(): Field { return cells.lookup(0 as Field); }
export circuit entry(flag: Boolean, later: Boolean): Field {
  if (disclose(flag)) { assert(cells.member(0 as Field), "present"); }
  else { assert(!cells.member(0 as Field), "absent"); }
  output = read();
  if (disclose(later)) { return output; }
  cells.remove(0 as Field);
  return read();
}`;
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) { const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file); assert.equal(compiled.valid, true, compiled.error); }
    const program = new Program(file), entry = program.entries[0];
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const flow = () => new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", true);
      const facts = flow().analyze();
      assert.deepEqual(facts.diagnostics, []); assert.equal(facts.paths.length, 1);
      const cfg = engine === "instructions" ? program.instructionCFG(entry) : program.functions.get(entry)!.cfg;
      const branches = cfg.nodes.filter(node => node.kind === "branch").sort((a, b) => a.span.start - b.span.start);
      const selected = flow().selectConditionalSource(entry, new Map([[branches[0].id, true], [branches[1].id, true]]));
      assert.equal(selected.status, "selected");
      if (selected.status === "selected") {
        assert.deepEqual(selected.path, facts.paths[0]);
        assert.equal(selected.calls.length, 1);
        assert.equal(selected.calls[0].maySucceed, true);
        assert.equal(selected.path.sinks.filter(sink => sink.kind === "exported-return").length, 1);
      }
      const absent = flow().selectConditionalSource(entry, new Map([[branches[0].id, false]]));
      assert.equal(absent.status, "rejected", "missing lookup rejects before an unprovided later branch choice");
      const removed = flow().selectConditionalSource(entry, new Map([[branches[0].id, true], [branches[1].id, false]]));
      assert.equal(removed.status, "rejected", "old presence cannot survive removal");
    }
  });
});

test("source replay retains IR merge predecessors and refuses unsupported expansion and exhausted work", () => {
  const source = `import CompactStandardLibrary;
export ledger output: Field;
circuit choose(flag: Boolean, x: Field, y: Field): Field { if (disclose(flag)) { return x; } else { return y; } }
export circuit entry(flag: Boolean, x: Field, y: Field): Field {
  assert(x != y, "distinct");
  const selected = disclose(flag) ? x : y;
  output = disclose(selected);
  return selected;
}
export circuit nested(flag: Boolean, x: Field, y: Field): Field { return choose(flag, x, y); }
`;
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) { const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file); assert.equal(compiled.valid, true, compiled.error); }
    const program = new Program(file), entry = program.entries.find(id => program.symbols.get(id)!.name === "entry")!;
    const branch = program.instructionCFG(entry).nodes.find(node => node.kind === "branch")!;
    for (const cached of [false, true]) {
      const flow = () => new Dataflow(program, 40000, 256, 50000, "instructions", cached, cached, "equivalent-states", false, true, "all");
      const facts = flow().analyzeSubset([entry]);
      assert.deepEqual(facts.diagnostics, []); assert.equal(facts.paths.length, 2);
      for (const truth of [false, true]) {
        const selected = flow().selectConditionalSource(entry, new Map([[branch.id, truth]]));
        assert.equal(selected.status, "selected");
        if (selected.status === "selected") assert.deepEqual(selected.path, facts.paths.find(path => path.path.some(step => step.kind === "branch" && step.label.endsWith(String(truth)))));
      }
      const nested = program.entries.find(id => program.symbols.get(id)!.name === "nested")!;
      const unsupported = flow().selectConditionalSource(nested, new Map());
      assert.equal(unsupported.status, "incomplete");
      if (unsupported.status === "incomplete") assert.match(unsupported.diagnostics[0].message, /Nested expression\/call alternatives/);
    }
    for (const [steps, values] of [[2, 50000], [40000, 2]]) {
      const exhausted = new Dataflow(program, steps, 256, values).selectConditionalSource(entry, new Map([[branch.id, true]]));
      assert.equal(exhausted.status, "incomplete");
    }
    const missing = new Dataflow(program).selectConditionalSource(entry, new Map());
    assert.equal(missing.status, "incomplete");
    const noPath = new Dataflow(program, 40000, 0).selectConditionalSource(entry, new Map([[branch.id, true]]));
    assert.equal(noPath.status, "incomplete", "selection still consumes one path slot");
    const onePath = new Dataflow(program, 40000, 1).selectConditionalSource(entry, new Map([[branch.id, true]]));
    assert.equal(onePath.status, "selected", "one selected history fits one path slot");
  });
});

test("source blocks retain a selected 24-iteration storage history within unchanged allowances", t => {
  const source = `import CompactStandardLibrary;
export ledger cursor: Uint<64>;
export ledger cells: Map<Uint<64>,Field>;
export circuit entry(end: Uint<64>): [] {
  const start = cursor;
  assert(disclose(end) > start, "nonempty");
  assert(disclose(end) <= 24 as Uint<64>, "bound");
  for (const i of 0..24) {
    const at = i as Uint<64>;
    if (at >= start && at < disclose(end)) { cells.insert(at, 1 as Field); }
  }
  cursor = disclose(end);
}`;
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) { const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file); assert.equal(compiled.valid, true, compiled.error); }
    const program = new Program(file), entry = program.entries[0], cfg = program.instructionCFG(entry);
    assert.ok(cfg.nodes.length > 512, "the selected source has more IR nodes than the graph depth allowance");
    const decisions = new Map(cfg.nodes.filter(node => node.kind === "branch").map(node => [node.id, true]));
    const selected = new Dataflow(program).selectConditionalSource(entry, decisions);
    assert.equal(selected.status, "selected", selected.status === "incomplete" ? JSON.stringify(selected.diagnostics) : "");
    if (selected.status !== "selected") return;
    assert.equal(selected.path.writes.length, 25);
    assert.deepEqual(selected.path.writes.slice(0, 24).map(write => write.region), Array.from({ length: 24 }, (_, i) => [`key:integer:${i}`]));
    assert.ok(selected.metrics.steps <= 40000 && selected.metrics.abstractValues <= 50000);
    t.diagnostic(JSON.stringify({ representation: "source blocks", instructionNodes: cfg.nodes.length,
      selectedSteps: selected.metrics.steps, selectedValues: selected.metrics.abstractValues, scope: "one selected history; entry coverage remains open" }));
  });
});

test("conditional projection checks refusal during detached result construction", () => {
  const graph = new ConditionalStateGraph(() => true), term = required(graph.atom({ value: 1 }));
  const selected = graph.select(term, new Map(), 100, value => {
    graph.refuse("Owned detached-result allowance exhausted"); return value;
  });
  assert.equal(selected.status, "incomplete");
  assert.match(graph.incompleteReason!, /detached-result allowance/);
});

test("conditional common views are detached and share the entry allowance", () => {
  let values = 0;
  const graph = new ConditionalStateGraph((_work, count) => (values += count) <= 2);
  const input = { value: 1 }, term = required(graph.atom(input));
  const view = graph.common(term, value => ({ ...value }));
  assert.equal(view.status, "available");
  if (view.status === "available") view.value.value = 9;
  assert.equal(input.value, 1);
  assert.equal(graph.common(term, value => ({ ...value })).status, "incomplete");
  assert.equal(graph.select(term, new Map(), 100, value => ({ ...value })).status, "incomplete");
});
