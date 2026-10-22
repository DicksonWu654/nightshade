import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Program, Dataflow, scanFile, type AnalysisFacts } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

function fixture(source: string, check: (program: Program, file: string) => void, zkirVersion: 2 | 3 = 2): void {
  withFiles({ "main.compact": `import CompactStandardLibrary;\n${source}` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const result = validateWithCompiler(process.env.COMPACTC_TEST, file, [], 30000, zkirVersion);
      assert.equal(result.valid, true, result.error);
    }
    check(new Program(file, [], directory, undefined, zkirVersion), file);
  });
}
function modes(program: Program, check: (facts: AnalysisFacts) => void): void {
  for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
    const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze();
    check(facts);
  }
}
function complete(facts: AnalysisFacts): void {
  assert.deepEqual(facts.diagnostics, []);
  assert.deepEqual(facts.completedEntries, facts.program.entries);
}

test("scalar equality rejects direct, transitive, aggregate, constant and exclusion contradictions", () => {
  const bodies = [
    'assert(a == b, "same"); assert(a != b, "different");',
    'assert(a == b, "same"); assert(b == c, "same"); assert(a != c, "different");',
    'assert([a,b] == [b,c], "same fields"); assert(a != c, "different");',
    'assert([a,b] == [b,c], "same fields"); assert([a,b] != [b,c], "different fields");',
    'assert(a == b, "same"); assert(b == 0 as Field, "zero"); assert(a != 0 as Field, "nonzero");',
    'assert(a != c, "different"); assert(a == b, "same"); assert(b == c, "same");',
    'assert(a != 0 as Field, "nonzero"); assert(a == b, "same"); assert(b == 0 as Field, "zero");',
    'assert(a != b, "different"); assert(a == 0 as Field, "zero"); assert(b == 0 as Field, "zero");',
    'assert([a,b] != [b,c], "different fields"); assert(a == b, "same"); assert(b == c, "same");',
    'assert((a == b) == true, "wrapped same"); assert(a != b, "different");',
    'assert((a != b) == false, "wrapped same"); assert(a != b, "different");',
    'assert(!(a == b) == false, "negated same"); assert(a != b, "different");',
  ];
  fixture(bodies.map((body, index) => `export circuit rejected${index}(a: Field,b: Field,c: Field): [] { ${body} }`).join("\n"), (program, file) => {
    modes(program, facts => { complete(facts); assert.equal(facts.paths.length, 0); });
    const report = scanFile(file, { detectors: ["impossible-assertion"] });
    assert.equal(report.status, "complete");
    assert.equal(new Set(report.findings.map(finding => finding.callPath[0])).size, bodies.length);
  });
});

test("ordered aliases and alias exclusions share the same current scalar constraints", () => {
  fixture(`export circuit strict(a: Uint<8>,b: Uint<8>): [] { assert(a == b, "same"); assert(a < b, "ordered"); }
  export circuit bounds(a: Uint<8>,b: Uint<8>): [] {
    assert(a == b, "same"); assert(a > 0, "positive"); assert(b <= 0, "nonpositive");
  }
  export circuit reverse(a: Uint<8>,b: Uint<8>): [] {
    assert(a > 0, "positive"); assert(b <= 0, "nonpositive"); assert(a == b, "same");
  }
  export circuit alias(a: Uint<8>,b: Uint<8>,flag: Boolean): [] {
    assert((a == b) == flag, "alias"); assert(flag, "same"); assert(a < b, "ordered");
  }
  export circuit negatedAlias(a: Uint<8>,b: Uint<8>,flag: Boolean): [] {
    assert(!(a == b) == flag, "alias"); assert(!flag, "same"); assert(a < b, "ordered");
  }
  export circuit redundant(a: Field,b: Field): [] {
    assert(a != 0 as Field, "nonzero"); assert(a == b, "same"); assert(b != 0 as Field, "already known");
  }`, program => modes(program, facts => {
    complete(facts);
    assert.deepEqual(facts.paths.map(path => program.symbols.get(path.entry)!.name), ["redundant"]);
    const last = facts.assertionReaches.filter(reach => program.symbols.get(reach.entry)!.name === "redundant").at(-1)!;
    assert.equal(last.maySucceed, true); assert.equal(last.mayFail, false);
  }));
});

test("ordered operand pairs retain complements, reversed comparisons and strictness", () => {
  const operators = ["<", "<=", ">", ">="] as const;
  const compare = (operator: typeof operators[number], a: number, b: number): boolean =>
    operator === "<" ? a < b : operator === "<=" ? a <= b : operator === ">" ? a > b : a >= b;
  const cases = operators.flatMap(guard => [false, true].flatMap(truth => operators.flatMap(query => [false, true].map(reverse => {
    const possible = new Set<string>();
    for (let a = 0; a < 4; a++) for (let b = 0; b < 4; b++) if (compare(guard, a, b) === truth)
      possible.add(compare(query, reverse ? b : a, reverse ? a : b) ? "1" : "2");
    return { guard, truth, query, reverse, possible };
  }))));
  fixture(cases.map((item, index) => `export circuit ordered${index}(a: Uint<8>, b: Uint<8>): Field {
    assert(${item.truth ? "" : "!"}(a ${item.guard} b), "guard");
    return ${item.reverse ? "b" : "a"} ${item.query} ${item.reverse ? "a" : "b"} ? 1 as Field : 2 as Field;
  }`).join("\n"), program => {
    modes(program, facts => {
      complete(facts);
      for (const [index, item] of cases.entries()) assert.deepEqual(new Set(facts.paths
        .filter(path => program.symbols.get(path.entry)!.name === `ordered${index}`)
        .map(path => path.sinks.at(-1)!.value.constant)), item.possible, JSON.stringify(item));
    });
  });
});

test("ordered pair correlation follows aliases while leaving siblings and stale reads independent", () => {
  fixture(`export ledger cell: Uint<8>;
  export ledger table: Map<Field,Uint<8>>;
  pure circuit greater(a: Uint<8>, b: Uint<8>): Boolean { return a >= b; }
  export circuit rejected(a: Uint<8>, b: Uint<8>, c: Uint<8>, d: Uint<8>): [] {
    assert(a < b, "less"); assert(c >= d, "greater");
    assert(a == c, "left alias"); assert(b == d, "right alias");
  }
  export circuit alias(a: Uint<8>, b: Uint<8>, c: Uint<8>, d: Uint<8>): Boolean {
    const warm = greater(c,d);
    assert(a == c, "left alias"); assert(b == d, "right alias"); assert(a < b, "less");
    return greater(c,d);
  }
  export circuit distinct(a: Uint<8>, b: Uint<8>): Boolean {
    assert(a <= b, "at most"); assert(a != b, "distinct"); return a < b;
  }
  export circuit snapshot(a: Uint<8>, b: Uint<8>): Boolean {
    const old = cell; assert(old < b, "old bound"); cell = disclose(a); return cell >= b;
  }
  export circuit wildcard(a: Field, b: Field, n: Uint<8>): Boolean {
    assert(table.lookup(disclose(a)) < n, "first bound"); return table.lookup(disclose(b)) >= n;
  }
  export circuit siblings(a: Uint<8>, b: Uint<8>, flag: Boolean): Boolean {
    if (flag) { assert(a < b, "less"); } else { assert(a >= b, "at least"); }
    return a >= b;
  }`, (program, file) => {
    modes(program, facts => {
      complete(facts);
      const results = (name: string) => facts.paths.filter(path => program.symbols.get(path.entry)!.name === name)
        .map(path => path.sinks.at(-1)!.value.constant);
      assert.deepEqual(results("rejected"), []);
      assert.deepEqual(results("alias"), ["false"]);
      assert.deepEqual(results("distinct"), ["true"]);
      assert.deepEqual(results("snapshot"), [undefined]);
      assert.deepEqual(results("wildcard"), [undefined]);
      assert.deepEqual(new Set(results("siblings")), new Set(["true", "false"]));
    });
    const report = scanFile(file, { detectors: ["impossible-assertion"] });
    assert.equal(report.status, "complete");
    assert.deepEqual(report.findings.map(finding => finding.callPath[0]), ["rejected"]);
  });
});

test("Boolean aliases select the original hash choice without losing predicate identities", () => {
  fixture(`export circuit rejected(flag: Boolean, other: Boolean, a: Field, b: Field): [] {
    const selected = flag ? persistentHash<[Field,Field]>([a,b]) : persistentHash<[Field,Field]>([b,a]);
    assert(flag == other, "alias"); assert(other, "selected");
    assert(selected != persistentHash<[Field,Field]>([a,b]), "different");
  }`, program => modes(program, facts => { complete(facts); assert.equal(facts.paths.length, 0); }));
});

test("Boolean predicate aliases preserve feasible alternatives and old collection revisions", () => {
  fixture(`export ledger table: Map<Field,Field>;
  export circuit different(a: Uint<8>,b: Uint<8>,flag: Boolean): [] {
    assert((a == b) == flag, "alias"); assert(!flag, "different"); assert(a < b, "ordered");
  }
  export circuit snapshot(flag: Boolean): [] {
    const saved = table.member(1 as Field);
    assert(saved == flag, "alias");
    table.insert(1 as Field, 2 as Field);
    assert(!flag, "previously absent");
    assert(table.member(1 as Field), "now present");
  }`, program => modes(program, facts => {
    complete(facts);
    assert.deepEqual(facts.paths.map(path => program.symbols.get(path.entry)!.name), ["different", "snapshot"]);
    assert.equal(facts.paths[1].writes.length, 1);
  }));
});

test("relations preserve sibling alternatives, old storage, distinct Map keys and noninjective outputs", () => {
  fixture(`export ledger cell: Field; export ledger table: Map<Field,Field>;
  export circuit snapshot(a: Field,b: Field): [] {
    const old = cell; assert(old == a, "snapshot"); cell = disclose(b);
    assert(a != cell, "different current storage");
  }
  export circuit wildcard(first: Field,second: Field,a: Field,b: Field): [] {
    assert(first != second, "different keys");
    const x = table.lookup(disclose(first)); const y = table.lookup(disclose(second));
    assert(x == a, "first"); assert(y == b, "second"); assert(a != b, "different values");
  }
  export circuit siblings(flag: Boolean,a: Field,b: Field): [] {
    if (disclose(flag)) { assert(a == b, "same"); } else { assert(a != b, "different"); }
    cell = disclose(a);
  }
  export circuit noninjective(a: Field,b: Field): [] {
    assert(a != b, "distinct fields"); assert((a as JubjubScalar) == (b as JubjubScalar), "same modular scalar");
  }
  export circuit hashes(a: Field,b: Field): [] {
    assert(a != b, "distinct preimages"); assert(persistentHash<Field>(a) == persistentHash<Field>(b), "same digest");
  }`, program => modes(program, facts => {
    complete(facts);
    const counts = new Map<string, number>();
    for (const path of facts.paths) counts.set(program.symbols.get(path.entry)!.name, (counts.get(program.symbols.get(path.entry)!.name) ?? 0) + 1);
    assert.deepEqual(Object.fromEntries(counts), { snapshot: 1, wildcard: 1, siblings: 2, noninjective: 1, hashes: 1 });
    for (const path of facts.paths.filter(path => program.symbols.get(path.entry)!.name === "siblings")) {
      assert.equal(path.writes.length, 1);
      assert.ok(path.writes[0].after.flows.some(flow => flow.source.name === "a"));
    }
  }), 3);
});

test("pure summary reuse includes caller relation facts even for anonymous aggregate leaves", () => {
  fixture(`pure circuit equal(a: Field,b: Field): Boolean { return a == b; }
  export circuit entry(a: Field,b: Field): Boolean {
    const warmed = equal(a,b);
    assert([a] == [b], "same leaf");
    const again = equal(a,b);
    return equal(a,b);
  }`, program => modes(program, facts => {
    complete(facts); assert.equal(facts.paths.length, 1);
    assert.equal(facts.paths[0].sinks.find(sink => sink.kind === "exported-return")!.value.constant, "true");
    if (facts.metrics.summaryEntries) {
      assert.equal(facts.metrics.summaryEntries, 2, "the changed relation context must have its own summary");
      assert.equal(facts.metrics.summaryHits, 1, "reuse remains available within the same relation context");
    }
  }));
});

test("scalar relation capacity remains explicit at the retained-edge limit", () => {
  for (const extra of [false, true]) fixture(`export circuit entry(a: Vector<256,Field>, b: Field, c: Field): [] {
    assert(a[0] == b, "first");
    ${Array.from({ length: 255 }, (_, index) => `assert(a[${index}] == a[${index + 1}], "chain");`).join("\n")}
    ${extra ? 'assert(a[255] == c, "last");' : ""}
  }`, program => modes(program, facts => {
    if (extra) {
      assert.deepEqual(facts.completedEntries, []);
      assert.ok(facts.diagnostics.some(diagnostic => diagnostic.code === "constraint-budget"));
    } else { complete(facts); assert.equal(facts.paths.length, 1); }
  }));
});

test("oversized aggregate disequalities stay incomplete across a call and branch", () => {
  fixture(`circuit compare(a: Vector<4,Vector<128,Field>>, b: Vector<4,Vector<128,Field>>): [] {
    assert(a != b, "different");
  }
  export circuit entry(a: Vector<4,Vector<128,Field>>, b: Vector<4,Vector<128,Field>>, flag: Boolean): Field {
    compare(a,b);
    if (flag) { return a[0][0]; } else { return b[0][0]; }
  }`, program => modes(program, facts => {
    assert.deepEqual(facts.completedEntries, []);
    assert.ok(facts.diagnostics.some(diagnostic => diagnostic.code === "constraint-budget"), JSON.stringify(facts.diagnostics));
  }));
});
