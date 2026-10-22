import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { resolve } from "node:path";
import test from "node:test";
import { Dataflow, Program, type AbstractValue } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { ValueFingerprints } from "../src/dataflow/fingerprints.js";
import { withFiles } from "./helpers.js";

// Independent reference: the complete pre-optimization state serialization.
// Compare partitions, not digest bytes; compare returned facts without erasing
// traces, guards, operations or user fields.
function legacyKey(state: Parameters<Dataflow["stateIdentity"]>[0], withoutGuards = false): string {
  const entries = <V>(mapping: Map<string, V>): [string, V][] => [...mapping].sort(([a], [b]) => a.localeCompare(b));
  const writes = withoutGuards ? state.writes.map(({ guards, ...write }) => write) : state.writes;
  const serialized = JSON.stringify({ merkle: state.merkle?.snapshot(), operations: state.operations,
    env: entries(state.env), ledger: entries(state.ledger), ledgerVersions: entries(state.ledgerVersions),
    collections: state.collections.snapshot(), lists: state.lists.snapshot(), known: entries(state.known), truths: entries(state.truths),
    excluded: entries(state.excluded).map(([key, values]) => [key, [...values].sort()]), aggregateExclusions: entries(state.aggregateExclusions),
    aggregateExclusionsExhausted: state.aggregateExclusionsExhausted, guards: withoutGuards ? undefined : [...state.guards].sort(),
    bindings: state.bindings, sinks: state.sinks, writes, control: state.control }, function (key, value) {
    if (key === "trace" && typeof this.source?.id === "string" && (typeof this.form === "string" || typeof this.ledger === "string")) return undefined;
    return value instanceof Set ? [...value].sort() : value;
  });
  return createHash("sha256").update(serialized).digest("hex");
}

const scalar = (constant = "1"): AbstractValue => ({ flows: [], ledger: new Set(), constant, constantKind: "integer" });

test("common-value joins preserve fingerprint equivalence across primitive discriminators", () => {
  withFiles({ "main.compact": "export circuit entry(): Field { return 0 as Field; }" }, directory => {
    const dataflow = new Dataflow(new Program(resolve(directory, "main.compact")));
    const location = { file: resolve(directory, "main.compact"), start: 0, end: 1, line: 1, column: 1, endLine: 1, endColumn: 2 };
    const source = { id: "private", name: "secret", kind: "witness" as const, location };
    const left: AbstractValue = { ...scalar(), identity: "snapshot", type: "Field", ledger: new Set(["store"]),
      flows: [{ source, form: "raw", trace: [{ kind: "read", label: "first", location }] }] };
    const variants: AbstractValue[] = [
      structuredClone(left),
      { ...left, flows: [{ ...left.flows[0], trace: [] }] },
      { ...left, identity: "other" }, { ...left, type: "Uint<64>" },
      { ...left, constant: "2" }, { ...left, constantKind: "boolean" },
      { ...left, ledger: new Set(["other"]) },
      { ...left, flows: [{ ...left.flows[0], form: "hash" }] },
      { ...left, fields: { trace: scalar("9") } },
    ];
    for (const right of variants) {
      const equal = new ValueFingerprints().key(left) === new ValueFingerprints().key(right);
      const before = structuredClone([left, right]);
      const joined = dataflow["commonValue"](left, right, location);
      assert.equal(joined === left, equal);
      assert.deepEqual([left, right], before, "joining must leave both snapshots unchanged");
      if (!equal) {
        assert.equal(joined.constant, left.constant === right.constant && left.constantKind === right.constantKind ? left.constant : undefined);
        assert.deepEqual(joined.ledger, new Set([...left.ledger, ...right.ledger]));
      }
    }
    const absent = { flows: [], ledger: new Set<string>() };
    assert.equal(dataflow["commonValue"](absent, { ...absent, identity: undefined, type: undefined, constant: undefined, constantKind: undefined }, location), absent);
  });
});

test("fingerprints distinguish digest tokens, user fields and ordered mutable histories", () => {
  const fingerprints = new ValueFingerprints();
  const value = scalar();
  // A raw array that duplicates the exact token must not impersonate a value.
  fingerprints.key(value);
  assert.notEqual(fingerprints.key(value), fingerprints.key(["value", fingerprints["values"].get(value)]));
  for (const field of ["trace", "guards", "flows", "source", "identity", "ledger"]) {
    assert.notEqual(fingerprints.key({ ...scalar(), fields: { [field]: scalar("1") } }),
      fingerprints.key({ ...scalar(), fields: { [field]: scalar("2") } }), field);
  }
  const state = { guards: new Set<string>(), writes: [{ after: value }], known: [["x", "1"]] };
  const initial = fingerprints.key(state);
  state.guards.add("guard");
  assert.notEqual(fingerprints.key(state), initial);
  const guarded = fingerprints.key(state);
  state.writes.push({ after: scalar("2") });
  assert.notEqual(fingerprints.key(state), guarded);
  const written = fingerprints.key(state);
  state.writes.reverse();
  assert.notEqual(fingerprints.key(state), written);
  const reversed = fingerprints.key(state);
  state.known[0][1] = "2";
  assert.notEqual(fingerprints.key(state), reversed);
});

test("only diagnostic Flow and HashBinding traces are normalized, with set order preserved semantically", () => {
  const location = { file: "fixture.compact", start: 0, end: 1, line: 1, column: 1, endLine: 1, endColumn: 2 };
  const source = { id: "private", name: "secret", kind: "witness" as const, location };
  const trace = [{ kind: "read", label: "secret", location }];
  const value: AbstractValue = { ...scalar(), ledger: new Set(["b", "a"]),
    flows: [{ source, form: "raw", trace }], equalities: [{ source, ledger: "digest", location, trace }] };
  const fingerprints = new ValueFingerprints();
  const normalized: AbstractValue = { ...value, ledger: new Set(["a", "b"]),
    flows: [{ ...value.flows[0], trace: [] }], equalities: [{ ...value.equalities![0], trace: [] }] };
  assert.equal(fingerprints.key(value), fingerprints.key(normalized));
  assert.notEqual(fingerprints.key(value), fingerprints.key({ ...value, flows: [{ ...value.flows[0], form: "hash" }] }));
  assert.notEqual(fingerprints.key(value), fingerprints.key({ ...value, flows: [{ ...value.flows[0], source: { ...source, id: "other" } }] }));
  for (const change of [{ directPreimage: true }, { directPreimage: false }, { source: { ...source, symbol: "parameter" } },
    { source: { ...source, sequenceStep: 1 as const } }, { source: { ...source, invocation: { site: "call", occurrence: 1, leaf: 0 } } }]) {
    assert.notEqual(fingerprints.key(value), fingerprints.key({ ...value, flows: [{ ...value.flows[0], ...change }] }));
  }
  assert.notEqual(fingerprints.key(value), fingerprints.key({ ...value, identity: "snapshot" }));
  assert.notEqual(fingerprints.key({ ...value, flows: [{ ...value.flows[0], futureMetadata: "a" }] }),
    fingerprints.key({ ...value, flows: [{ ...value.flows[0], futureMetadata: "b" }] }));
  assert.notEqual(fingerprints.key(value), fingerprints.key({ ...value, flows: [{ form: "raw", source, trace }] }),
    "normalized flow reuse preserves the legacy property-order partition");
});

test("immutable event fingerprints retain guards, call sites, order and detached write snapshots", () => {
  const keys = new ValueFingerprints();
  const write = { before: scalar("1"), after: scalar("2"), guards: ["owner"], callPath: ["entry", "put"], callSites: [12] };
  const other = { ...write, guards: ["admin"] };
  assert.equal(keys.record(write), keys.key(write));
  assert.equal(keys.record(structuredClone(write)), keys.record(write));
  assert.notEqual(keys.record(other), keys.record(write));
  assert.equal(keys.record(other, true), keys.record(write, true));
  assert.notEqual(keys.record({ ...write, callSites: [13] }), keys.record(write));
  assert.notEqual(keys.record({ ...write, after: scalar("3") }), keys.record(write));
  const history = [write];
  const identity = () => keys.key(history.map(record => keys.record(record)));
  const first = identity();
  history.push(other);
  assert.notEqual(identity(), first);
  const second = identity();
  history.reverse();
  assert.notEqual(identity(), second);
  // Returned event records may be mutated by clients. A new analysis owns
  // fresh fingerprints, so there is no cross-analysis acceptance reuse.
  const prior = keys.record(write);
  write.callSites.push(14);
  assert.notEqual(new ValueFingerprints().record(write), prior);
});

const cases = {
  "shared ordered write and disclosure prefixes": `
ledger value: Field; ledger enabled: Boolean;
circuit put(input: Field): [] { value = disclose(input); }
circuit guard(): [] { assert(enabled, "enabled"); }
export circuit entry(a: Boolean, b: Boolean, input: Field): Field {
  guard(); put(input); put(input);
  if (disclose(a)) { enabled = false; put(1 as Field); }
  if (disclose(b)) { put(2 as Field); }
  return value;
}`,
  "user fields and retained snapshots": `
struct Payload { trace: Field; guards: Field; flows: Field; source: Field; identity: Field; }
ledger store: Payload;
circuit choose(flag: Boolean): Payload {
  return flag ? Payload { trace: 1 as Field, guards: 2 as Field, flows: 3 as Field, source: 4 as Field, identity: 5 as Field }
              : Payload { trace: 9 as Field, guards: 8 as Field, flows: 7 as Field, source: 6 as Field, identity: 5 as Field };
}
export circuit entry(flag: Boolean, other: Boolean): Payload {
  const retained = choose(flag); store = disclose(retained);
  if (disclose(other)) { store = default<Payload>; }
  return retained;
}`,
  "storage domains, predicates, guards and provenance": `
ledger tree: HistoricMerkleTree<2,Field>; ledger table: Map<Field,Field>; ledger list: List<Field>;
ledger digest: Bytes<32>; ledger enabled: Boolean; ledger output: Field;
circuit guard(): [] { assert(enabled, "authorized"); }
circuit read(): Field { return output; }
circuit put(value: Field): [] { output = disclose(value); }
export circuit entry(flag: Boolean, secret: Field, root: MerkleTreeDigest): Boolean {
  assert(enabled, "enabled"); guard();
  assert(persistentHash<Field>(secret) == digest, "bound");
  const before = tree.isFull();
  table.insert(1 as Field, disclose(secret)); list.pushFront(disclose(secret));
  const saved = list.head().value;
  if (disclose(flag)) { put(secret); } else { put(saved); }
  read(); read(); list.popFront(); tree.insert(disclose(secret));
  if (before) { return false; }
  return tree.checkRoot(disclose(root));
}`,
  "branch summary replay and caller invalidation": `
ledger first: Field; ledger second: Field; ledger enabled: Boolean;
circuit guard(): [] { assert(enabled, "authorized"); }
circuit select(flag: Boolean, value: Field): [] {
  if (disclose(flag)) { enabled = false; first = disclose(value); } else { second = disclose(value); }
}
export circuit entry(a: Uint<8>, b: Uint<8>, value: Field): [] {
  const flag = a < b; select(flag,value); guard(); select(flag,value);
}`,
  "ordered native effects": `
export circuit entry(color: Bytes<32>): Boolean {
  const before = unshieldedBalance(disclose(color)); const self = kernel.self();
  receiveUnshielded(disclose(color), 3);
  sendUnshielded(disclose(color), 2, left<ContractAddress,UserAddress>(self));
  assert(before == unshieldedBalance(disclose(color)), "fixed context");
  if (before == 0) { assert(unshieldedBalanceLt(disclose(color),1), "comparison"); }
  return self == kernel.self();
}`,
};

for (const [name, source] of Object.entries(cases)) test(`memoized state keys preserve legacy partitions and full facts: ${name}`, () => {
  withFiles({ "main.compact": `import CompactStandardLibrary;\n${source}` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(file);
    let observations = 0;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      for (const semantics of ["equivalent-states", "guard-cover"] as const) {
        const current = new Dataflow(program, 40000, 256, 50000, engine, cached, cached, semantics);
        const original = current["stateIdentity"].bind(current);
        const oldToNew = new Map<string, string>(), newToOld = new Map<string, string>();
        current["stateIdentity"] = (state, withoutGuards) => {
          observations++;
          const actual = original(state, withoutGuards);
          const cache = current["valueFingerprints"];
          current["valueFingerprints"] = new ValueFingerprints();
          try { assert.equal(original(state, withoutGuards), actual, "observed values must remain immutable"); }
          finally { current["valueFingerprints"] = cache; }
          const before = legacyKey(state, withoutGuards);
          if (oldToNew.has(before)) assert.equal(oldToNew.get(before), actual, "an old equivalence was lost");
          if (newToOld.has(actual)) assert.equal(newToOld.get(actual), before, "distinct states were merged");
          oldToNew.set(before, actual); newToOld.set(actual, before);
          return actual;
        };
        const reference = new Dataflow(program, 40000, 256, 50000, engine, cached, cached, semantics);
        reference["stateIdentity"] = legacyKey;
        const forget = reference["forgetDeadLocals"].bind(reference);
        reference["forgetDeadLocals"] = (...args) => {
          // A fresh per-visit map reproduces uncached liveness traversal; the
          // ordinary visited set already processes each value once per call.
          reference["liveValueIdentities"] = new WeakMap();
          return forget(...args);
        };
        const facts = current.analyze();
        assert.deepEqual(facts.diagnostics, []);
        assert.deepEqual(facts.completedEntries, program.entries);
        assert.ok(facts.paths.length > 0);
        assert.deepEqual(facts, reference.analyze(), `${engine}/${cached}/${semantics}`);
      }
    }
    assert.ok(observations > 0, "must exercise state fingerprinting");
  });
});

test("repeated analyses discard fingerprints before callers can reuse mutated observations", () => {
  withFiles({ "main.compact": cases["user fields and retained snapshots"] }, directory => {
    const dataflow = new Dataflow(new Program(resolve(directory, "main.compact")));
    const first = dataflow.analyze();
    const expected = structuredClone({ ...first, program: undefined });
    const cache = dataflow["valueFingerprints"];
    const summaryCache = dataflow["summaryFingerprints"];
    const controlCache = dataflow["controlDependencies"];
    const liveCache = dataflow["liveValueIdentities"];
    for (const path of first.paths) for (const sink of path.sinks) {
      sink.value.ledger.add("external mutation");
      sink.value.fields = { trace: scalar("99") };
    }
    const repeated = dataflow.analyze();
    assert.notEqual(dataflow["valueFingerprints"], cache);
    assert.notEqual(dataflow["summaryFingerprints"], summaryCache);
    assert.notEqual(dataflow["controlDependencies"], controlCache);
    assert.notEqual(dataflow["liveValueIdentities"], liveCache);
    assert.deepEqual({ ...repeated, program: undefined }, expected);
  });
});
