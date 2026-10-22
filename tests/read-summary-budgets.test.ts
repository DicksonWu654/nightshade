import test from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";
import { Dataflow, Program } from "../src/index.js";
import { ReadCircuitEligibility } from "../src/analysis/summaries.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { semanticPaths, withFiles } from "./helpers.js";

function programFor(source: string, check: (program: Program) => void): void {
  withFiles({ "main.compact": `pragma language_version >= 0.26.0; import CompactStandardLibrary; ${source}` }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, path);
      assert.equal(compiled.valid, true, compiled.error);
    }
    check(new Program(path));
  });
}

function completeModes(program: Program, maxSteps = 20000): ReturnType<Dataflow["analyze"]> {
  const runs = (["instructions", "expressions"] as const).map(engine => {
    const cached = new Dataflow(program, maxSteps, 256, 50000, engine, true).analyze();
    const expanded = new Dataflow(program, maxSteps, 256, 50000, engine, false).analyze();
    for (const facts of [cached, expanded]) {
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      assert.ok(facts.metrics.summaryEntries <= 256);
      assert.ok(facts.metrics.summaryEffects <= 4096);
    }
    assert.deepEqual(cached.paths, expanded.paths);
    assert.deepEqual(cached.failedAssertions, expanded.failedAssertions);
    return cached;
  });
  assert.deepEqual(semanticPaths(runs[0]), semanticPaths(runs[1]));
  return runs[0];
}

test("cached read summaries cannot bypass nested call-depth limits", () => {
  const chain = Array.from({ length: 30 }, (_, index) => `circuit chain${index}(): Field { return ${index === 29 ? "read" : `chain${index + 1}`}(); }`).join("\n");
  programFor(`export ledger stored: Field; circuit leaf(): Field { return stored; } circuit read(): Field { return leaf(); } ${chain} export circuit entry(): Field { read(); read(); return chain0(); }`, program => {
    for (const engine of ["instructions", "expressions"] as const) {
      const cached = new Dataflow(program, 20000, 256, 50000, engine, true).analyze();
      const expanded = new Dataflow(program, 20000, 256, 50000, engine, false).analyze();
      assert.ok(cached.metrics.readSummaryHits > 0);
      assert.ok(cached.diagnostics.some(diagnostic => diagnostic.code === "call-depth"));
      assert.deepEqual(cached.diagnostics, expanded.diagnostics);
      assert.deepEqual(cached.paths, expanded.paths);
      assert.deepEqual(cached.completedEntries, []);
    }
  });
});

test("read replay charges its ordered effects to the step budget", () => {
  programFor(`export ledger seen: Set<Field>; circuit query(key: Field): Boolean { return seen.member(disclose(key)); } export circuit entry(key: Field): [] { for (const iteration of 0..64) { query(key); } }`, program => {
    for (const engine of ["instructions", "expressions"] as const) for (const summaries of [false, true]) {
      const facts = new Dataflow(program, 100, 256, 50000, engine, summaries).analyze();
      if (summaries) assert.ok(facts.metrics.readSummaryHits > 0);
      assert.ok(facts.diagnostics.some(diagnostic => diagnostic.code === "analysis-budget"));
      assert.deepEqual(facts.completedEntries, []);
      assert.deepEqual(facts.paths, []);
    }
  });
});

test("value-budget failures cannot seed read summaries", () => {
  programFor(`struct Box { values: Vector<8, Field>; } export ledger stored: Box; circuit read(): Box { return stored; } export circuit entry(): Box { read(); return read(); }`, program => {
    for (const engine of ["instructions", "expressions"] as const) for (const summaries of [false, true]) {
      const facts = new Dataflow(program, 20000, 256, 4, engine, summaries).analyze();
      assert.ok(facts.diagnostics.some(diagnostic => diagnostic.code === "value-budget"));
      assert.equal(facts.metrics.readSummaryHits, 0);
      assert.equal(facts.metrics.summaryEntries, 0);
      assert.deepEqual(facts.completedEntries, []);
    }
  });
});

test("oversized read recordings interpret normally and retain every private sink", () => {
  programFor(`export ledger seen: Set<Field>; circuit query(key: Field): Boolean { return seen.member(disclose(key)); } circuit many(key: Field): [] { for (const iteration of 0..128) { query(key); } } export circuit entry(key: Field): [] { many(key); many(key); }`, program => {
    const facts = completeModes(program);
    assert.equal(facts.metrics.readSummaryHits, 255);
    assert.equal(facts.metrics.summaryEntries, 1);
    assert.equal(facts.paths[0].sinks.length, 256);
    assert.ok(facts.paths[0].sinks.every(sink => sink.value.flows.some(flow => flow.source.name === "key")));
  });
});

test("read cache entry exhaustion falls back without making analysis incomplete", () => {
  programFor(`export ledger stored: Field; circuit read(value: Field): Field { return stored + value; } export circuit entry(): Field { for (const iteration of 0..256) { read(iteration as Field); } read(256 as Field); return read(0 as Field); }`, program => {
    const facts = completeModes(program);
    assert.equal(facts.metrics.summaryEntries, 256);
    assert.equal(facts.metrics.readSummaryHits, 1);
    assert.equal(facts.paths.length, 1);
  });
});

for (const count of [64, 65]) test(`${count} transitive read roots respect the cache footprint bound`, () => {
  const declarations = Array.from({ length: count }, (_, index) => `export ledger stored${index}: Field;`).join("\n");
  const value = Array.from({ length: count }, (_, index) => `stored${index}`).join(" + ");
  const initialize = Array.from({ length: count }, (_, index) => `stored${index} = 1 as Field;`).join(" ");
  programFor(`${declarations} circuit read(): Field { return ${value}; } export circuit entry(): Field { ${initialize} read(); return read(); }`, program => {
    const read = program.activeSymbols().find(symbol => symbol.name === "read")!;
    assert.equal(new ReadCircuitEligibility(program).allows(read.id), true);
    const facts = completeModes(program);
    assert.equal(facts.metrics.readSummaryHits, count === 64 ? 1 : 0);
    assert.equal(facts.metrics.summaryEntries, count === 64 ? 1 : 0);
    assert.equal(facts.paths[0].sinks.at(-1)!.value.constant, String(count));
  });
});

for (const count of [255, 256]) test(`read cache handles ${count + 1} stored regions without dropping results`, () => {
  programFor(`export ledger table: Map<Field, Field>; circuit size(): Uint<64> { return table.size(); } export circuit entry(): Uint<64> { table.resetToDefault(); for (const iteration of 0..${count}) { table.insert(iteration as Field, default<Field>); } size(); return size(); }`, program => {
    const facts = completeModes(program);
    assert.equal(facts.metrics.readSummaryHits, count === 255 ? 1 : 0);
    assert.equal(facts.paths[0].sinks.at(-1)!.value.constant, String(count));
  });
});

test("retained read effect exhaustion falls back and preserves sink order", () => {
  programFor(`export ledger stored: Field; export ledger seen: Set<Field>; circuit read(salt: Field, key: Field): Field { for (const iteration of 0..180) { seen.member(disclose(key)); } return stored + salt; } export circuit entry(key: Field): Field { for (const iteration of 0..24) { read(iteration as Field, key); } return read(0 as Field, key); }`, program => {
    const facts = completeModes(program, 200000);
    assert.equal(facts.metrics.readSummaryHits, 1);
    assert.ok(facts.metrics.summaryEntries < 24);
    assert.ok(facts.metrics.summaryEffects > 3900);
    assert.equal(facts.paths[0].sinks.filter(sink => sink.kind === "ledger-operation").length, 25 * 180);
  });
});
