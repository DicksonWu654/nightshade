import test from "node:test";
import assert from "node:assert/strict";
import { analyze } from "./helpers.js";

test("unknown Map keys may alias previously written known keys", () => {
  analyze("import CompactStandardLibrary; export ledger table: Map<Field, Field>; export circuit entry(secret: Field, index: Field): Field { table.insert(1 as Field, disclose(secret)); return table.lookup(disclose(index)); }", facts => {
    const returned = facts.paths[0].sinks.find(sink => sink.kind === "exported-return")!.value;
    assert.ok(returned.flows.some(flow => flow.source.name === "secret"));
  });
});

test("weak Map writes do not overwrite earlier possible aliases", () => {
  analyze("import CompactStandardLibrary; export ledger table: Map<Field, Field>; export circuit entry(secret: Field, first: Field, second: Field): Field { table.insert(disclose(first), disclose(secret)); table.insert(disclose(second), 0 as Field); return table.lookup(1 as Field); }", facts => {
    const returned = facts.paths[0].sinks.find(sink => sink.kind === "exported-return")!.value;
    assert.ok(returned.flows.some(flow => flow.source.name === "secret"));
    assert.equal(returned.constant, undefined);
  });
});

test("unknown alias writes invalidate prior constant reads", () => {
  analyze("import CompactStandardLibrary; export ledger table: Map<Field, Field>; export circuit entry(secret: Field, index: Field): Boolean { table.insert(1 as Field, 0 as Field); table.insert(disclose(index), disclose(secret)); return table.lookup(1 as Field) == (0 as Field); }", facts => assert.equal(facts.paths[0].sinks.find(sink => sink.kind === "exported-return")!.value.constant, undefined));
});

test("nested region reset makes removed descendants unavailable", () => {
  analyze("import CompactStandardLibrary; export ledger table: Map<Field, Map<Field, Field>>; export circuit entry(secret: Field): Field { table.lookup(1 as Field).insert(2 as Field, disclose(secret)); table.lookup(1 as Field).resetToDefault(); return table.lookup(1 as Field).lookup(2 as Field); }", facts => assert.deepEqual(facts.paths, []));
});

test("nested region reinsertion cannot recover reset private values", () => {
  analyze("import CompactStandardLibrary; export ledger table: Map<Field, Map<Field, Field>>; export circuit entry(secret: Field): Field { table.lookup(1 as Field).insert(2 as Field, disclose(secret)); table.lookup(1 as Field).resetToDefault(); table.lookup(1 as Field).insert(2 as Field,0 as Field); return table.lookup(1 as Field).lookup(2 as Field); }", facts => {
    const returned = facts.paths[0].sinks.find(sink => sink.kind === "exported-return")!.value;
    assert.equal(returned.flows.length, 0);
    assert.equal(returned.constant, "0");
  });
});

test("distinct byte projections must not compare as identical", () => {
  analyze('export circuit entry(value: Bytes<2>): [] { assert(value[0] != value[1], "distinct bytes"); }', facts => {
    assert.equal(facts.failedAssertions.length, 0);
    assert.equal(facts.paths.length, 1);
  });
});

test("Bytes spread creates one projected element per byte", () => {
  analyze('export circuit entry(): Uint<8> { const bytes = [...pad(2, "a")]; return bytes[1]; }', facts => assert.equal(facts.paths[0].sinks[0].value.constant, "0"));
});

test("witness argument dependencies survive aggregate projection", () => {
  analyze("struct Box { value: Field; } witness transform(value: Field): Box; export circuit entry(secret: Field): Field { return transform(secret).value; }", facts => assert.ok(facts.paths[0].sinks[0].value.flows.some(flow => flow.source.name === "secret")));
});

test("known old ledger values do not constrain subsequent writes", () => {
  analyze('export ledger value: Field; export circuit entry(): Field { assert(value == (1 as Field), "old value"); value = 2 as Field; assert(value == (2 as Field), "new value"); return value; }', facts => {
    assert.equal(facts.failedAssertions.length, 0);
    assert.equal(facts.paths[0].sinks.find(sink => sink.kind === "exported-return")!.value.constant, "2");
  });
});

test("Counter increments do not invent explicit ledger reads", () => {
  for (const body of ["count += 1;", "count.increment(1);"]) analyze(`import CompactStandardLibrary; export ledger count: Counter; export circuit entry(): [] { ${body} }`, facts => {
    const entry = facts.program.functions.get(facts.program.entries[0])!;
    assert.equal(entry.readsState.size, 0);
    assert.equal(entry.writesState.size, 1);
  });
});

test("keyed aggregate projections preserve the stored field dependencies", () => {
  analyze("import CompactStandardLibrary; struct Box { secret: Field; visible: Field; } export ledger table: Map<Field, Box>; export circuit entry(secret: Field): Field { table.insert(1 as Field, Box { secret: disclose(secret), visible: 0 as Field }); return table.lookup(1 as Field).secret; }", facts => {
    const returned = facts.paths[0].sinks.find(sink => sink.kind === "exported-return")!.value;
    assert.ok(returned.flows.some(flow => flow.source.name === "secret"));
  });
});

test("keyed aggregate projections do not contaminate a separate public field", () => {
  analyze("import CompactStandardLibrary; struct Box { secret: Field; visible: Field; } export ledger table: Map<Field, Box>; export circuit entry(secret: Field): Field { table.insert(1 as Field, Box { secret: disclose(secret), visible: 0 as Field }); return table.lookup(1 as Field).visible; }", facts => {
    const returned = facts.paths[0].sinks.find(sink => sink.kind === "exported-return")!.value;
    assert.equal(returned.flows.length, 0);
    assert.equal(returned.constant, "0");
  });
});

test("wildcard aggregate writes reach known-key field reads", () => {
  analyze("import CompactStandardLibrary; struct Box { value: Field; } export ledger table: Map<Field, Box>; export circuit entry(secret: Field, index: Field): Field { table.insert(disclose(index), Box { value: disclose(secret) }); return table.lookup(1 as Field).value; }", facts => {
    const returned = facts.paths[0].sinks.find(sink => sink.kind === "exported-return")!.value;
    assert.ok(returned.flows.some(flow => flow.source.name === "secret"));
  });
});

test("wildcard ancestor mutations invalidate descendant constants and predicates", () => {
  analyze('import CompactStandardLibrary; export ledger table: Map<Field, Map<Field, Field>>; export circuit entry(index: Field): Field { table.lookup(1 as Field).insert(2 as Field, 7 as Field); assert(table.lookup(1 as Field).lookup(2 as Field) == (7 as Field), "stored"); table.lookup(disclose(index)).resetToDefault(); return table.lookup(1 as Field).lookup(2 as Field); }', facts => {
    const returned = facts.paths[0].sinks.find(sink => sink.kind === "exported-return")!.value;
    assert.equal(returned.constant, undefined);
  });
});

test("unknown parent queries retain dependencies of stored descendants", () => {
  analyze("import CompactStandardLibrary; export ledger table: Map<Field, Map<Field, Field>>; export circuit entry(secret: Field, index: Field): Field { table.lookup(1 as Field).insert(2 as Field, disclose(secret)); return table.lookup(disclose(index)).lookup(2 as Field); }", facts => {
    const returned = facts.paths[0].sinks.find(sink => sink.kind === "exported-return")!.value;
    assert.ok(returned.flows.some(flow => flow.source.name === "secret"));
  });
});

test("private lookup selection survives a nested field projection", () => {
  analyze("import CompactStandardLibrary; struct Box { value: Field; } export ledger table: Map<Field, Box>; export circuit entry(index: Field): Field { return table.lookup(disclose(index)).value; }", facts => {
    const returned = facts.paths[0].sinks.find(sink => sink.kind === "exported-return")!.value;
    assert.ok(returned.flows.some(flow => flow.source.name === "index"));
  });
});

test("private insertion keys influence subsequent selected values", () => {
  analyze("import CompactStandardLibrary; struct Box { value: Field; } export ledger table: Map<Field, Box>; export circuit entry(index: Field): Field { table.insert(disclose(index), Box { value: 0 as Field }); return table.lookup(1 as Field).value; }", facts => {
    const returned = facts.paths[0].sinks.find(sink => sink.kind === "exported-return")!.value;
    assert.ok(returned.flows.some(flow => flow.source.name === "index" && flow.form === "derived"));
  });
});

test("writes through private parent selections influence later nested reads", () => {
  analyze("import CompactStandardLibrary; export ledger table: Map<Field, Map<Field, Field>>; export circuit entry(index: Field): Field { table.lookup(disclose(index)).insert(2 as Field, 0 as Field); return table.lookup(1 as Field).lookup(2 as Field); }", facts => {
    const returned = facts.paths[0].sinks.find(sink => sink.kind === "exported-return")!.value;
    assert.ok(returned.flows.some(flow => flow.source.name === "index"));
  });
});

test("region overlap is symmetric and wildcard keys never alias field names", async () => {
  const { mayOverlap, covers } = await import("../src/dataflow/regions.js");
  const paths = [[], ["key:*"], ["key:identity:a"], ["key:identity:b"], ["key:integer:1"], ["key:integer:2"], ["key:integer:1", "field:value"], ["field:value"]];
  for (const first of paths) for (const second of paths) {
    const left = { root: "table", path: first, type: "unknown" };
    const right = { root: "table", path: second, type: "unknown" };
    assert.equal(mayOverlap(left, right), mayOverlap(right, left));
    if (covers(left, right)) assert.ok(mayOverlap(left, right));
    assert.equal(mayOverlap(left, { ...right, root: "other" }), false);
  }
  assert.equal(mayOverlap({ root: "table", path: ["key:*"], type: "unknown" }, { root: "table", path: ["field:value"], type: "unknown" }), false);
  for (const key of ["key:identity:b", "key:integer:1", "key:*"]) {
    assert.equal(mayOverlap({ root: "table", path: ["key:identity:a"], type: "unknown" }, { root: "table", path: [key], type: "unknown" }), true);
    assert.equal(covers({ root: "table", path: ["key:identity:a"], type: "unknown" }, { root: "table", path: [key], type: "unknown" }), false);
  }
});

test("local aggregate copies are snapshots rather than live ledger aliases", () => {
  analyze("struct Box { value: Field; } export ledger box: Box; export circuit entry(secret: Field): Field { box = Box { value: disclose(secret) }; const old = box; box = Box { value: 0 as Field }; return old.value; }", facts => {
    const returned = facts.paths[0].sinks.find(sink => sink.kind === "exported-return")!.value;
    assert.ok(returned.flows.some(flow => flow.source.name === "secret"));
    assert.equal(returned.constant, undefined);
  });
});

test("callee aggregate parameters retain caller snapshot values", () => {
  analyze("struct Box { value: Field; } export ledger box: Box; circuit replace(old: Box): Field { box = Box { value: 0 as Field }; return old.value; } export circuit entry(secret: Field): Field { box = Box { value: disclose(secret) }; return replace(box); }", facts => {
    const returned = facts.paths[0].sinks.find(sink => sink.kind === "exported-return")!.value;
    assert.ok(returned.flows.some(flow => flow.source.name === "secret"));
  });
});

for (const operation of ["count.increment(bump(secret));", "count += bump(secret);"]) test(`read-modify-write observes effects evaluated in its arguments: ${operation}`, () => {
  analyze(`import CompactStandardLibrary; export ledger count: Counter; circuit bump(value: Uint<16>): Uint<16> { count.increment(disclose(value)); return 0; } export circuit entry(secret: Uint<16>): Uint<64> { ${operation} return count; }`, facts => {
    const returned = facts.paths[0].sinks.find(sink => sink.kind === "exported-return")!.value;
    assert.ok(returned.flows.some(flow => flow.source.name === "secret"));
  });
});
