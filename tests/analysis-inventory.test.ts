import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { buildAnalysisInventory, type AnalysisInventory, type InventoryOptions, type InventoryType } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { Program } from "../src/semantic/index.js";
import { withFiles } from "./helpers.js";

const compiler = { skip: !process.env.COMPACTC_TEST ? "Requires COMPACTC_TEST" : false };
function fixture(source: string, check: (program: Program, inventory: AnalysisInventory) => void, qualified = false): void {
  withFiles({ "main.compact": `pragma language_version >= 0.26.0; ${source}` }, directory => {
    const path = resolve(directory, "main.compact");
    if (qualified) {
      const result = validateWithCompiler(process.env.COMPACTC_TEST!, path);
      assert.equal(result.valid, true, result.error);
    }
    const program = new Program(path);
    check(program, buildAnalysisInventory(program));
  });
}

function kind<K extends InventoryType["kind"]>(shape: InventoryType, expected: K): Extract<InventoryType, { kind: K }> {
  assert.equal(shape.kind, expected);
  return shape as Extract<InventoryType, { kind: K }>;
}

test("compiler-qualified inventory preserves imported nominal, aggregate, tuple and enum identities", compiler, () => {
  fixture(`
    module Values {
      export enum Phase { OPEN, CLOSED }
      export new type Quantity = Uint<248>;
      export struct Bundle<T,#N> { amount: T; data: Vector<N,[Boolean,Bytes<2>]>; phase: Phase; }
    }
    import Values prefix V_;
    new type Envelope = V_Bundle<V_Quantity,2>;
    export circuit echo(value: Envelope, bounded: Uint<0..17>): Envelope { return value; }
  `, (program, inventory) => {
    assert.equal(inventory.status, "complete");
    assert.deepEqual(inventory.gaps, []);
    assert.equal(inventory.schemaVersion, "nightshade-analysis-inventory-1");
    assert.equal(inventory.semanticProfile, program.semanticProfile);
    const fn = inventory.functions.find(fn => fn.name === "echo")!;
    const outer = kind(fn.parameters[0].shape, "nominal");
    assert.equal(program.nominalTypes.get(outer.type)!.declaration, outer.declaration);
    const bundle = kind(outer.underlying, "struct");
    assert.equal(program.symbols.get(bundle.declaration)!.name, "Bundle");
    assert.deepEqual(bundle.fields.map(field => field.name), ["amount", "data", "phase"]);
    const quantity = kind(bundle.fields[0].shape, "nominal");
    assert.equal(kind(quantity.underlying, "uint").exclusiveUpperBound, (1n << 248n).toString());
    const vector = kind(bundle.fields[1].shape, "vector");
    assert.equal(vector.length, "2");
    const tuple = kind(vector.element, "tuple");
    kind(tuple.elements[0], "boolean");
    assert.equal(kind(tuple.elements[1], "bytes").length, "2");
    assert.deepEqual(kind(bundle.fields[2].shape, "enum").variants, [{ name: "OPEN", ordinal: "0" }, { name: "CLOSED", ordinal: "1" }]);
    assert.equal(kind(fn.parameters[1].shape, "uint").exclusiveUpperBound, "17");
    assert.deepEqual(fn.result, fn.parameters[0].shape);
    assert.deepEqual(JSON.parse(JSON.stringify(inventory)), inventory);
  }, true);
});

test("compiler-qualified inventory labels direct calls, transitive ledger relations and external witnesses", compiler, () => {
  fixture(`
    export ledger value: Field;
    witness privateInput(): Field;
    circuit put(input: Field): [] { value = disclose(input); }
    circuit relay(input: Field): [] { put(input); }
    export circuit entry(): Field { relay(privateInput()); return value; }
  `, (program, inventory) => {
    assert.equal(inventory.status, "complete");
    const entry = inventory.functions.find(fn => fn.name === "entry")!;
    const relay = inventory.functions.find(fn => fn.name === "relay")!;
    const put = inventory.functions.find(fn => fn.name === "put")!;
    const external = inventory.callTargets.find(target => target.name === "privateInput")!;
    assert.equal(external.implementation, "external-witness");
    assert.deepEqual(entry.calls, [relay.id, external.id].sort());
    assert.ok(!entry.calls.includes(put.id));
    assert.deepEqual(relay.calls, [put.id]);
    const ledger = inventory.ledgers[0];
    assert.equal(ledger.name, "value");
    assert.equal(ledger.type, "Field");
    assert.deepEqual(entry.reads, [ledger.id]);
    assert.deepEqual(entry.writes, [ledger.id]);
    assert.deepEqual(relay.writes, [ledger.id]);
    assert.deepEqual(inventory.entrypoints, program.entries);
    assert.equal(inventory.scope, "resolved-semantic-inventory");
    assert.equal(Object.hasOwn(inventory, "completedEntries"), false);
  }, true);
});

test("compiler-qualified native ordinary structures use the canonical field model", compiler, () => {
  fixture("import { Maybe } from CompactStandardLibrary; export circuit echo(input: Maybe<Bytes<3>>): Maybe<Bytes<3>> { return input; }", (_program, inventory) => {
    assert.equal(inventory.status, "complete");
    const shape = kind(inventory.functions[0].parameters[0].shape, "struct");
    assert.equal(shape.type, "standard-type::Maybe<Bytes<3>>");
    assert.deepEqual(shape.fields.map(field => field.name), ["is_some", "value"]);
    kind(shape.fields[0].shape, "boolean");
    assert.equal(kind(shape.fields[1].shape, "bytes").length, "3");
  }, true);
});

test("compiler-valid Opaque signatures explicitly make inventory incomplete", compiler, () => {
  fixture('export circuit echo(input: Opaque<"string">): Opaque<"string"> { return input; }', (_program, inventory) => {
    assert.equal(inventory.status, "incomplete");
    assert.equal(inventory.gaps.length, 2);
    assert.ok(inventory.gaps.every(gap => gap.code === "inventory-unsupported-type"));
    const fn = inventory.functions[0];
    assert.equal(kind(fn.parameters[0].shape, "unsupported").type, 'Opaque<"string">');
    assert.equal(inventory.gaps[0].location.start, fn.parameters[0].location.start);
    assert.equal(Object.hasOwn(inventory, "errors"), false);
  }, true);
});

test("compiler-valid nested signatures emit explicit depth and node budget gaps", compiler, () => {
  fixture("export circuit echo(input: [Field,Vector<2,[Boolean,Bytes<2>]>]): [Field,Vector<2,[Boolean,Bytes<2>]>] { return input; }", (program, inventory) => {
    assert.equal(inventory.status, "complete");
    const depth = buildAnalysisInventory(program, { maxTypeDepth: 0 });
    assert.equal(depth.status, "incomplete");
    assert.ok(depth.gaps.every(gap => gap.code === "inventory-type-depth"));
    const limited = buildAnalysisInventory(program, { maxTypeNodes: 1 });
    assert.equal(limited.status, "incomplete");
    assert.equal(limited.budget.expandedTypeNodes, 1);
    assert.ok(limited.gaps.every(gap => gap.code === "inventory-type-budget"));
    // The tuple is rejected as a whole, never represented as an empty tuple.
    kind(limited.functions[0].parameters[0].shape, "unsupported");
    kind(limited.functions[0].result, "unsupported");
  }, true);
});

test("compiler-valid repeated enum shapes charge every expanded variant and reject an oversized enum whole", compiler, () => {
  fixture("enum Phase { NEW, ACTIVE, CLOSED } export circuit echo(input: Phase): Phase { return input; }", program => {
    // Each signature occurrence consumes one shape node plus three variants.
    const complete = buildAnalysisInventory(program, { maxTypeNodes: 8 });
    assert.equal(complete.status, "complete");
    assert.equal(complete.budget.expandedTypeNodes, 8);
    assert.deepEqual(complete.gaps, []);
    assert.deepEqual(kind(complete.functions[0].parameters[0].shape, "enum").variants, [
      { name: "NEW", ordinal: "0" }, { name: "ACTIVE", ordinal: "1" }, { name: "CLOSED", ordinal: "2" },
    ]);
    assert.deepEqual(complete.functions[0].result, complete.functions[0].parameters[0].shape);
    const limited = buildAnalysisInventory(program, { maxTypeNodes: 7 });
    assert.equal(limited.status, "incomplete");
    assert.equal(limited.budget.expandedTypeNodes, 5);
    kind(limited.functions[0].parameters[0].shape, "enum");
    const result = kind(limited.functions[0].result, "unsupported");
    assert.equal(result.reason, "inventory-type-budget");
    assert.equal(Object.hasOwn(result, "variants"), false);
    assert.deepEqual(limited.gaps.map(gap => [gap.path, gap.code]), [["result", "inventory-type-budget"]]);
    const minimal = buildAnalysisInventory(program, { maxTypeNodes: 2 });
    assert.equal(minimal.status, "incomplete");
    assert.equal(minimal.budget.expandedTypeNodes, 2);
    kind(minimal.functions[0].parameters[0].shape, "unsupported");
    kind(minimal.functions[0].result, "unsupported");
  }, true);
});

test("inventory is deterministic under public map/set insertion order and does not alias source spans", () => {
  fixture("export ledger value: Field; circuit put(input: Field): [] { value = disclose(input); } export circuit entry(input: Field): Field { put(input); return value; }", (program, expected) => {
    for (const map of [program.functions, program.symbols, program.files] as Map<string, unknown>[]) {
      const entries = [...map].reverse();
      map.clear();
      entries.forEach(([key, value]) => map.set(key, value));
    }
    const actual = buildAnalysisInventory(program);
    assert.deepEqual(actual, expected);
    assert.equal(actual.sources[0].sha256, createHash("sha256").update(program.rootSource.text).digest("hex"));
    actual.sources[0].location.line = 999;
    actual.functions[0].location.line = 999;
    assert.notEqual(program.rootSource.ast.span.line, 999);
    assert.notEqual(program.functions.get(actual.functions[0].id)!.symbol.span.line, 999);
  });
});

test("defensive public-model cycles terminate with incomplete diagnostics", () => {
  fixture("export circuit entry(input: Field): Field { return input; }", (program) => {
    const fn = program.functions.get(program.entries[0])!;
    // Valid source cannot contain these cycles: this exercises defensive handling
    // when an API consumer changes Program's public mutable semantic maps.
    fn.declaration.parameters[0].type = "cycle::First";
    program.nominalTypes.set("cycle::First", { declaration: "first", underlying: "cycle::Second" });
    program.nominalTypes.set("cycle::Second", { declaration: "second", underlying: "cycle::First" });
    const inventory = buildAnalysisInventory(program);
    assert.equal(inventory.status, "incomplete");
    assert.deepEqual(inventory.gaps.map(gap => gap.code), ["inventory-type-cycle"]);
    assert.equal(inventory.gaps[0].path, "parameters/0/underlying/underlying");
  });
});

test("defensive unsupported ADT and invalid numeric signatures remain explicit", () => {
  fixture("export circuit entry(input: Field): Field { return input; }", program => {
    const fn = program.functions.get(program.entries[0])!;
    for (const type of ["standard-type::Map<Field,Field>", "Uint<249>", "missing::Type", "Vector<2>"]) {
      fn.declaration.parameters[0].type = type;
      const inventory = buildAnalysisInventory(program);
      assert.equal(inventory.status, "incomplete");
      assert.equal(inventory.gaps[0].code, "inventory-unsupported-type");
      assert.equal(kind(inventory.functions[0].parameters[0].shape, "unsupported").type, type);
    }
  });
});

test("missing call and ledger targets never turn into clean no-effects relations", () => {
  fixture("circuit helper(): [] {} export circuit entry(): [] { helper(); }", program => {
    const fn = program.functions.get(program.entries[0])!;
    const helper = [...fn.calls][0];
    program.functions.delete(helper);
    fn.calls.add("missing::call");
    fn.readsState.add("missing::ledger");
    const inventory = buildAnalysisInventory(program);
    assert.equal(inventory.status, "incomplete");
    assert.equal(inventory.gaps.length, 3);
    assert.ok(inventory.gaps.every(gap => gap.code === "inventory-unresolved-relation"));
    assert.ok(inventory.functions[0].calls.includes("missing::call"));
    assert.deepEqual(inventory.functions[0].reads, ["missing::ledger"]);
    assert.equal(inventory.callTargets.find(target => target.id === helper)!.implementation, "unresolved");
    program.functions.delete(program.entries[0]);
    assert.ok(buildAnalysisInventory(program).gaps.some(gap => gap.path === "entrypoint"));
  });
});

test("inventory options reject invalid bounds rather than silently changing them", () => {
  fixture("export circuit entry(): [] {}", program => {
    for (const maxTypeDepth of [-1, 33, NaN, 0.5]) assert.throws(() => buildAnalysisInventory(program, { maxTypeDepth }), RangeError);
    for (const maxTypeNodes of [0, 65537, Infinity, 1.5]) assert.throws(() => buildAnalysisInventory(program, { maxTypeNodes }), RangeError);
    for (const options of [null, [], "options", 2, new Date(), { maxTypNodes: 2 }, { [Symbol("budget")]: 3 }, Object.create({ maxTypeNodes: 2 })]) assert.throws(() => buildAnalysisInventory(program, options as InventoryOptions), TypeError);
    for (const options of [{ maxTypeNodes: null }, { maxTypeDepth: null }, { maxTypeNodes: "1" }, { maxTypeDepth: false }]) assert.throws(() => buildAnalysisInventory(program, options as unknown as InventoryOptions), RangeError);
    assert.equal(buildAnalysisInventory(program, { maxTypeNodes: undefined }).status, "complete");
    assert.equal(buildAnalysisInventory(program, { maxTypeDepth: 0, maxTypeNodes: 1 }).status, "complete");
  });
});

test("CLI inventory prints the public schema and exits according to inventory completeness", () => {
  const cli = fileURLToPath(new URL("../src/cli.js", import.meta.url));
  for (const [source, status] of [
    ["export circuit entry(input: Field): Field { return input; }", 0],
    ['export circuit entry(input: Opaque<"string">): Opaque<"string"> { return input; }', 2],
  ] as const) fixture(source, (program, inventory) => {
    // An unusable compiler setting makes accidental qualification/execution fail.
    const result = spawnSync(process.execPath, [cli, "print", "inventory", program.root], { encoding: "utf8", timeout: 10000, env: { ...process.env, COMPACTC_TEST: "/does-not-exist/compactc" } });
    assert.equal(result.status, status, result.error?.message ?? result.stderr);
    assert.equal(result.stderr, "");
    assert.deepEqual(JSON.parse(result.stdout), inventory);
  });
});
