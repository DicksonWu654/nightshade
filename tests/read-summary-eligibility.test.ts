import test from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";
import { Dataflow, Program } from "../src/index.js";
import { ReadCircuitEligibility } from "../src/analysis/summaries.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { semanticPaths, withFiles } from "./helpers.js";

function eligibility(source: string, callback: (program: Program, eligibility: ReadCircuitEligibility, ids: Record<string, string>) => void): void {
  withFiles({ "main.compact": `pragma language_version >= 0.26.0; import CompactStandardLibrary; ${source}` }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const ids: Record<string, string> = {};
    for (const symbol of program.activeSymbols()) {
      if (symbol.kind !== "circuit") continue;
      program.ensureFunction(symbol.id);
      ids[symbol.name] = symbol.id;
    }
    callback(program, new ReadCircuitEligibility(program), ids);
  });
}

test("read eligibility accepts straight-line ledger reads and readonly queries", () => {
  eligibility(`
    struct Box { value: Field; }
    export ledger scalar: Field;
    export ledger box: Box;
    export ledger count: Counter;
    export ledger values: Set<Field>;
    circuit pure(value: Field): Field { return value; }
    circuit direct(): Field { return scalar; }
    circuit field(): Field { return box.value; }
    circuit counter(): Uint<64> { return count.read(); }
    circuit query(): Boolean { return values.member(default<Field>); }
    circuit inner(): Field { return direct(); }
    circuit outer(): Field { return pure(inner()); }
  `, (_program, read, ids) => {
    for (const name of ["pure", "direct", "field", "counter", "query", "inner", "outer"]) assert.equal(read.allows(ids[name]), true, name);
    assert.equal(read.maximumDepth(ids.outer), 3);
    assert.deepEqual(read.completions(ids.outer), [[ids.outer, ids.inner, ids.direct], [ids.outer, ids.inner], [ids.outer, ids.pure], [ids.outer]]);
  });
});

test("read eligibility excludes state refinements and non-linear effects", () => {
  eligibility(`
    new type Small = Uint<8>;
    export ledger scalar: Field;
    export ledger count: Counter;
    export ledger flat: Map<Field, Field>;
    export ledger table: Map<Field, Map<Field, Field>>;
    witness secret(): Field;
    circuit write(): [] { scalar = default<Field>; }
    circuit lookup(): Field { return flat.lookup(default<Field>); }
    circuit nestedLookup(): Uint<64> { return table.lookup(default<Field>).size(); }
    circuit constraint(): [] { assert(scalar == default<Field>, "state"); }
    circuit checked(value: Small): Small { return value + default<Small>; }
    circuit cast(value: Field): Uint<8> { return value as Uint<8>; }
    circuit branch(flag: Boolean): Field { return flag ? scalar : default<Field>; }
    circuit projected(values: Vector<2, Field>, index: Uint<8>): Field { return values[index]; }
    circuit privateValue(): Field { return secret(); }
    circuit derived(value: Bytes<32>): Field { return degradeToTransient(value); }
    circuit recurse(): Field { return recurse(); }
    circuit callsLookup(): Field { return lookup(); }
    export circuit captures(value: Field): [] { map((item: Field): Field => value, [default<Field>]); }
    export circuit folds(values: Vector<1, Field>): Field { return fold((total: Field, item: Field): Field => total + item, default<Field>, values); }
  `, (program, read, ids) => {
    for (const name of ["write", "lookup", "nestedLookup", "constraint", "checked", "cast", "branch", "projected", "privateValue", "derived", "recurse", "callsLookup", "folds"]) {
      assert.equal(read.allows(ids[name]), false, name);
      assert.equal(read.maximumDepth(ids[name]), Infinity, name);
      assert.deepEqual(read.completions(ids[name]), [], name);
    }
    const anonymous = [...program.functions.values()].find(fn => fn.symbol.id.includes("::lambda:"));
    assert.ok(anonymous);
    assert.equal(read.allows(anonymous.symbol.id), false);
  });
});

test("compiler-valid excluded helpers retain lookup, guard, witness and write semantics", () => {
  const source = `pragma language_version >= 0.26.0; import CompactStandardLibrary;
    export ledger stored: Field;
    export ledger table: Map<Field,Field>;
    witness secret(): Field;
    circuit write(): [] { stored = default<Field>; }
    circuit lookup(key: Field): Field { return table.lookup(disclose(key)); }
    circuit callsLookup(key: Field): Field { return lookup(key); }
    circuit constraint(): [] { assert(stored == default<Field>, "state"); }
    circuit checked(value: Field): Uint<8> { return value as Uint<8>; }
    circuit branch(flag: Boolean): Field { if (disclose(flag)) { return stored; } else { return default<Field>; } }
    circuit projected(values: Vector<2,Field>): Field { return values[0]; }
    circuit privateValue(): Field { return secret(); }
    export circuit entry(flag: Boolean, key: Field, values: Vector<2,Field>): [Field,Uint<8>,Field] {
      write(); write(); constraint(); constraint(); lookup(key); lookup(key);
      branch(flag); branch(flag); projected(values); projected(values);
      return [disclose(privateValue()),checked(key),callsLookup(key)];
    }`;
  withFiles({ "main.compact": source }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, path);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(path);
    const read = new ReadCircuitEligibility(program);
    for (const name of ["write", "lookup", "callsLookup", "constraint", "checked", "branch", "projected", "privateValue"]) {
      const symbol = program.activeSymbols().find(symbol => symbol.name === name)!;
      assert.equal(read.allows(symbol.id), false, name);
    }
    const modes = (["instructions", "expressions"] as const).map(engine => {
      const cached = new Dataflow(program, 20000, 256, 50000, engine, true).analyze();
      const expanded = new Dataflow(program, 20000, 256, 50000, engine, false).analyze();
      assert.deepEqual(cached.diagnostics, []);
      assert.deepEqual(expanded.diagnostics, []);
      assert.equal(cached.metrics.readSummaryHits, 0);
      assert.deepEqual(cached.paths, expanded.paths);
      assert.deepEqual(cached.failedAssertions, expanded.failedAssertions);
      assert.deepEqual(cached.completedEntries, program.entries);
      assert.ok(cached.paths.length > 0);
      assert.ok(cached.paths.every(path => path.writes.length === 2));
      assert.ok(cached.paths.every(path => path.sinks.at(-1)!.value.flows.some(flow => flow.source.kind === "witness")));
      return cached;
    });
    assert.deepEqual(semanticPaths(modes[0]), semanticPaths(modes[1]));
  });
});
