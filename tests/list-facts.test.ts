import test from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";
import { Dataflow, Program, AnalysisFacts, Policies, detectors, resolvePolicies } from "../src/index.js";
import { AbstractValue } from "../src/dataflow/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { ledgerEffect } from "../src/semantic/intrinsics.js";
import { withFiles, semanticPaths } from "./helpers.js";

const prelude = "pragma language_version >= 0.26.0; import CompactStandardLibrary; export ledger items: List<Field>;";
const outputs = (facts: AnalysisFacts) => facts.paths.flatMap(path => path.sinks.filter(sink => sink.kind === "exported-return").map(sink => sink.value));
const values = (value: AbstractValue): unknown => value.items ? value.items.map(values) : value.fields ? Object.fromEntries(Object.entries(value.fields).map(([key, child]) => [key, values(child)])) : value.constant;
const names = (value: AbstractValue) => [...new Set(value.flows.map(flow => flow.source.name))].sort();

function compare(source: string, check: (facts: AnalysisFacts, program: Program) => void = () => {}, incomplete?: string, policies: Policies = {}, options: { summaries?: boolean; pathSemantics?: AnalysisFacts["pathSemantics"]; maxValues?: number } = {}): void {
  withFiles({ "main.compact": `${prelude}\n${source}` }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, path);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(path);
    const facts = (["instructions", "expressions"] as const).flatMap(engine => [true, false].map(cached => new Dataflow(program, 20000, 256, options.maxValues ?? 50000, engine, cached, cached, options.pathSemantics).analyze()));
    if (options.summaries) for (const index of [0, 2]) {
      assert.ok(facts[index].metrics.readSummaryHits > 0);
      assert.ok(facts[index].metrics.statefulSummaryHits > 0);
    }
    for (const result of facts) {
      assert.deepEqual(result.completedEntries, incomplete ? [] : program.entries);
      if (incomplete) assert.ok(result.diagnostics.some(diagnostic => diagnostic.code === incomplete), JSON.stringify(result.diagnostics));
      else assert.deepEqual(result.diagnostics, []);
      check(result, program);
    }
    assert.deepEqual(facts[0].paths, facts[1].paths);
    assert.deepEqual(facts[2].paths, facts[3].paths);
    const configured = resolvePolicies(program, policies);
    const findings = facts.map(result => detectors.flatMap(detector => detector.run(result, configured)));
    for (let index = 1; index < facts.length; index++) {
      assert.deepEqual(semanticPaths(facts[index]), semanticPaths(facts[0]));
      assert.deepEqual(facts[index].failedAssertions, facts[0].failedAssertions);
      assert.deepEqual(facts[index].diagnostics, facts[0].diagnostics);
      assert.deepEqual(findings[index], findings[0]);
    }
  });
}

test("List length follows compiler catalogue and size is not a List method", () => {
  assert.equal(ledgerEffect("List<Field>", "length")?.result, "Uint<64>");
  assert.equal(ledgerEffect("List<Field>", "size"), undefined);
  compare("export circuit entry(): Uint<64> { items.resetToDefault(); return items.length(); }", facts => assert.deepEqual(outputs(facts).map(values), ["0"]));
  withFiles({ "main.compact": `${prelude} export circuit entry(): Uint<64> { return items.size(); }` }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, path).valid, false);
    assert.throws(() => new Program(path), /No effect model/);
  });
});

test("List constructor defaults and reset have an empty shape and default Maybe value", () => {
  compare('export ledger observed: Uint<64>; constructor() { assert(items.isEmpty(), "default empty"); observed = items.length(); }', facts => {
    assert.deepEqual(facts.failedAssertions, []);
    assert.equal(facts.paths[0].sinks.find(sink => sink.kind === "ledger-write")!.value.constant, "0");
  });
  compare("export circuit entry(): [Boolean,Uint<64>,Maybe<Field>] { items.resetToDefault(); return [items.isEmpty(),items.length(),items.head()]; }", facts => {
    assert.deepEqual(outputs(facts).map(values), [["true", "0", { is_some: "false", value: "0" }]]);
  });
});

test("List writes invalidate nested literal and dynamic aliases without losing provenance", () => {
  for (const [first, second] of [["1 as Field", "disclose(key)"], ["disclose(key)", "1 as Field"]]) {
    compare(`export ledger table: Map<Field,List<Field>>; export circuit entry(key: Field, secret: Field): [Boolean,Uint<64>,Field] {
      table.insertDefault(${first});
      table.lookup(${second}).pushFront(disclose(secret));
      return [table.lookup(${first}).isEmpty(),table.lookup(${first}).length(),table.lookup(${first}).head().value];
    }`, facts => {
      assert.deepEqual(outputs(facts).map(values), [[undefined, undefined, undefined]]);
      assert.ok(names(outputs(facts)[0]).includes("secret"));
      assert.ok(names(outputs(facts)[0]).includes("key"));
    });
  }
});

test("popping a dynamic List invalidates a concrete alias prefix", () => compare(`
export ledger table: Map<Field,List<Field>>;
export circuit entry(key: Field): Uint<64> {
  table.insertDefault(1 as Field);
  table.lookup(1 as Field).pushFront(7 as Field);
  assert(!table.lookup(disclose(key)).isEmpty(), "selected list exists");
  table.lookup(disclose(key)).popFront();
  return table.lookup(1 as Field).length();
}`, facts => assert.deepEqual(outputs(facts).map(values), [undefined])));

test("List ordering, nonempty pops and retained heads follow a concrete stack", () => {
  compare(`export circuit entry(): [Field,Field,Uint<64>,Boolean,Maybe<Field>] {
    items.resetToDefault(); items.pushFront(3 as Field); items.pushFront(9 as Field);
    const saved = items.head(); items.popFront(); const current = items.head();
    const length = items.length(); items.popFront();
    return [saved.value,current.value,length,items.isEmpty(),items.head()];
  }`, facts => assert.deepEqual(outputs(facts).map(values), [["9", "3", "1", "true", { is_some: "false", value: "0" }]]));
});

test("known pushed prefixes do not invent an empty incoming tail", () => {
  compare("export circuit entry(secret: Field): [Field,Boolean,Uint<64>] { items.pushFront(disclose(secret)); const saved = items.head(); items.popFront(); return [saved.value,items.isEmpty(),items.length()]; }", facts => {
    const result = outputs(facts)[0].items!;
    assert.deepEqual(names(result[0]), ["secret"]);
    assert.equal(result[0].flows[0].form, "raw");
    assert.equal(result[1].constant, undefined);
    assert.equal(result[2].constant, undefined);
    assert.deepEqual(names(result[1]), []);
    assert.deepEqual(names(result[2]), []);
  });
});

test("List payload provenance does not taint unconditional structural queries", () => {
  compare("export circuit entry(secret: Field): [Field,Uint<64>,Boolean,Boolean] { items.resetToDefault(); items.pushFront(disclose(secret)); return [items.head().value,items.length(),items.isEmpty(),items.head().is_some]; }", facts => {
    const result = outputs(facts)[0].items!;
    assert.deepEqual(names(result[0]), ["secret"]);
    assert.ok(result[0].flows.some(flow => flow.source.name === "secret" && flow.form === "raw"));
    for (const query of result.slice(1)) assert.deepEqual(names(query), []);
    assert.deepEqual(result.slice(1).map(values), ["1", "false", "true"]);
  });
});

test("popping a pushed ledger value restores unknown-tail binding provenance", () => {
  compare(`export ledger other: Field;
    circuit read(): Field { return items.head().value; }
    export circuit entry(): [Field,Field,Field] {
      const before = read(); items.pushFront(other); const pushed = read();
      items.popFront(); return [before,pushed,read()];
    }`, (facts, program) => {
    const result = outputs(facts)[0].items!;
    const root = (name: string) => program.activeSymbols().find(symbol => symbol.name === name)!.id;
    assert.deepEqual([...result[0].ledger], [root("items")]);
    assert.ok(result[1].ledger.has(root("other")));
    assert.deepEqual([...result[2].ledger], [root("items")]);
    assert.equal(result[2].constant, undefined);
  });
});

test("conditional List changes and successive pops retain structural control provenance", () => {
  compare(`export circuit entry(flag: Boolean): Field {
    items.resetToDefault(); items.pushFront(1 as Field); items.pushFront(2 as Field); items.pushFront(3 as Field);
    if (disclose(flag)) items.popFront(); items.popFront(); return items.head().value;
  }`, facts => {
    assert.deepEqual(outputs(facts).map(output => output.constant).sort(), ["1", "2"]);
    assert.ok(outputs(facts).some(output => names(output).includes("flag")));
    assert.deepEqual(names(outputs(facts).find(output => output.constant === "1")!), ["flag"]);
  });
  compare("export circuit entry(flag: Boolean): Field { if (disclose(flag)) items.resetToDefault(); return items.head().value; }", facts => {
    assert.deepEqual(names(outputs(facts).find(output => output.constant === "0")!), ["flag"]);
  });
});

test("List snapshots preserve original values through reset and saved predicates cannot mutate newer facts", () => {
  compare('export circuit entry(): [Field,Field] { items.resetToDefault(); const before = items.isEmpty(); items.pushFront(7 as Field); const saved = items.head(); items.resetToDefault(); items.pushFront(9 as Field); assert(before,"old snapshot"); return [saved.value,items.head().value]; }', facts => {
    assert.deepEqual(outputs(facts).map(values), [["7", "9"]]);
  });
  compare('export circuit entry(): Field { const saved = items.head().is_some; items.pushFront(7 as Field); assert(!saved,"old absent head"); return items.head().value; }', facts => assert.deepEqual(outputs(facts).map(values), ["7"]));
});

test("nominal List aliases retain ordered element identities", () => {
  compare("new type Token = Field; new type Queue = List<Token>; export ledger queue: Queue; export circuit entry(secret: Token): [Token,Uint<64>] { queue.resetToDefault(); queue.pushFront(disclose(secret)); return [queue.head().value,queue.length()]; }", facts => {
    assert.deepEqual(names(outputs(facts)[0].items![0]), ["secret"]);
    assert.equal(outputs(facts)[0].items![1].constant, "1");
  });
});

test("List aggregate elements are stored snapshots rather than live projections", () => {
  compare(`struct Box { value: Field; } export ledger box: Box; export ledger boxes: List<Box>;
    export circuit entry(): Field {
      box = Box { value: 7 as Field }; boxes.pushFront(box); box = Box { value: 9 as Field };
      return boxes.head().value.value;
    }`, facts => assert.deepEqual(outputs(facts).map(values), ["7"]));
});

test("List payload constraints survive the end of their producing helper's locals", () => {
  compare(`witness secret(): Field;
    circuit fill(): [] {
      const value = secret(); items.pushFront(disclose(value));
      assert(value == (5 as Field), "fixed owned value");
    }
    export circuit entry(): Field { items.resetToDefault(); fill(); return items.head().value; }
  `, facts => {
    assert.deepEqual(outputs(facts).map(values), ["5"]);
    assert.deepEqual(names(outputs(facts)[0]), ["secret"]);
  });
});

test("nested Map defaults and ancestor replacement reset matching List facts", () => {
  compare(`export ledger table: Map<Field,List<Field>>;
    export circuit entry(): [Field,Maybe<Field>,Uint<64>] {
      table.resetToDefault(); table.insertDefault(1 as Field); table.insertDefault(2 as Field);
      table.lookup(1 as Field).pushFront(7 as Field); table.lookup(2 as Field).pushFront(8 as Field);
      const saved = table.lookup(1 as Field).head(); table.insertDefault(1 as Field);
      return [saved.value,table.lookup(1 as Field).head(),table.lookup(2 as Field).length()];
    }`, facts => assert.deepEqual(outputs(facts).map(values), [["7", { is_some: "false", value: "0" }, "1"]]));
});

test("wildcard Map replacement forgets may-alias List order and length", () => {
  compare(`export ledger table: Map<Field,List<Field>>; export circuit entry(key: Field): [Maybe<Field>,Uint<64>] {
    table.resetToDefault(); table.insertDefault(1 as Field); table.lookup(1 as Field).pushFront(7 as Field);
    table.insertDefault(disclose(key)); return [table.lookup(1 as Field).head(),table.lookup(1 as Field).length()];
  }`, facts => {
    const result = outputs(facts)[0].items!;
    assert.equal(result[0].fields!.value.constant, undefined);
    assert.equal(result[1].constant, undefined);
    assert.ok(names(result[0]).includes("key"));
  });
});

test("List read and mutation summaries replay current ordered prefixes and unrelated roots", () => {
  compare(`export ledger other: Field;
    circuit read(): [Maybe<Field>,Uint<64>] { return [items.head(),items.length()]; }
    circuit outer(): [Maybe<Field>,Uint<64>] { return read(); }
    circuit push(value: Field): [] { items.pushFront(disclose(value)); }
    circuit pop(): [] { items.popFront(); }
    export circuit entry(): [Field,Field,Field,Uint<64>] {
      items.resetToDefault(); push(3 as Field); outer(); outer();
      other = 8 as Field; const first = outer(); push(9 as Field); outer(); const second = outer();
      pop(); push(9 as Field); pop(); const third = outer();
      return [first[0].value,second[0].value,third[0].value,third[1]];
    }`, facts => {
    assert.deepEqual(outputs(facts).map(values), [["3", "9", "3", "1"]]);
  }, undefined, {}, { summaries: true });
});

test("List mutations invalidate guards after recording the guarded write", () => {
  const policies: Policies = { authorization: [{ state: "items", guard: "guard" }] };
  compare('circuit guard(): [] { assert(!items.isEmpty(),"nonempty"); } export circuit entry(): [] { items.resetToDefault(); items.pushFront(1 as Field); guard(); items.pushFront(2 as Field); items.popFront(); }', (facts, program) => {
    const writes = facts.paths[0].writes;
    const guard = program.activeSymbols().find(symbol => symbol.name === "guard")!.id;
    assert.ok(writes[2].guards.includes(guard));
    assert.ok(!writes[3].guards.includes(guard));
  }, undefined, policies);
});

for (const [name, body] of [
  ["known empty", "items.resetToDefault(); items.popFront();"],
  ["unknown incoming", "items.popFront();"],
  ["after exhausting a known prefix", "items.pushFront(1 as Field); items.popFront(); items.popFront();"],
  ["cached nonempty pop replayed against empty", "items.resetToDefault(); items.pushFront(1 as Field); pop(); pop();"],
  ["later reset does not erase unsupported outcome", "items.resetToDefault(); items.popFront(); items.resetToDefault();"],
] as const) test(`List ${name} pop is explicitly incomplete without invented assertion failure`, () => {
  compare(`circuit pop(): [] { items.popFront(); } export circuit entry(): [] { ${body} }`, facts => {
    assert.deepEqual(facts.failedAssertions, []);
    assert.deepEqual(facts.paths, []);
  }, "list-pop-outcome-unqualified");
});

test("a possibly empty List pop keeps the entry incomplete alongside modeled branch results", () => {
  compare("export circuit entry(flag: Boolean): Uint<64> { items.resetToDefault(); if (disclose(flag)) items.pushFront(7 as Field); items.popFront(); return items.length(); }", facts => {
    assert.deepEqual(facts.failedAssertions, []);
    assert.deepEqual(outputs(facts).map(values), ["0"]);
  }, "list-pop-outcome-unqualified");
});

test("List retained-prefix budget exhaustion is explicit in every mode", () => {
  compare("export circuit entry(): Uint<64> { items.resetToDefault(); for (const index of 0..256) items.pushFront(index as Field); items.pushFront(256 as Field); return items.length(); }", facts => {
    assert.ok(facts.diagnostics.some(diagnostic => diagnostic.code === "list-budget"));
  }, "list-budget");
});

test("cached List pushes cannot bypass or change prefix-budget exhaustion", () => {
  compare("circuit push(): [] { items.pushFront(0 as Field); } export circuit entry(): Uint<64> { items.resetToDefault(); for (const index of 0..256) push(); push(); return items.length(); }", facts => {
    assert.deepEqual(facts.paths, []);
    assert.ok(facts.diagnostics.some(diagnostic => diagnostic.code === "list-budget"));
  }, "list-budget");
});

test("cached List pushes charge stored snapshots to the value budget", () => {
  compare("circuit push(): [] { items.pushFront(0 as Field); } export circuit entry(): [] { items.resetToDefault(); push(); push(); push(); }", facts => {
    assert.deepEqual(facts.paths, []);
  }, "value-budget", {}, { maxValues: 3 });
});

for (const pathSemantics of ["equivalent-states", "guard-cover"] as const) test(`List branch order stays correlated under ${pathSemantics}`, () => {
  compare(`export circuit entry(flag: Boolean): [Field,Field] {
    items.resetToDefault();
    if (disclose(flag)) { items.pushFront(1 as Field); items.pushFront(2 as Field); }
    else { items.pushFront(2 as Field); items.pushFront(1 as Field); }
    const head = items.head(); items.popFront(); return [head.value,items.head().value];
  }`, facts => assert.deepEqual(outputs(facts).map(values).sort(), [["1", "2"], ["2", "1"]]), undefined, {}, { pathSemantics });
});
