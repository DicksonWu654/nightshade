import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { AnalysisFacts, Dataflow, Policies, Program, detectors, resolvePolicies, scanFile } from "../src/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { estimateWork } from "../src/analysis/work.js";
import { semanticPaths, withFiles } from "./helpers.js";

function compare(source: string, check: (facts: AnalysisFacts) => void, policies: Policies = {}): void {
  withFiles({ "main.compact": `pragma language_version >= 0.26.0; ${source}` }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const accepted = validateWithCompiler(process.env.COMPACTC_TEST, path);
      assert.equal(accepted.valid, true, accepted.error);
    }
    const program = new Program(path);
    const facts = new Dataflow(program).analyze();
    const expanded = new Dataflow(program, 20000, 256, 50000, "instructions", false).analyze();
    const reference = new Dataflow(program, 20000, 256, 50000, "expressions").analyze();
    for (const result of [facts, expanded, reference]) {
      assert.deepEqual(result.diagnostics, []);
      assert.deepEqual(result.completedEntries, program.entries);
    }
    assert.deepEqual(facts.paths, expanded.paths);
    assert.deepEqual(facts.failedAssertions, expanded.failedAssertions);
    assert.deepEqual(semanticPaths(facts), semanticPaths(reference));
    const configuration = resolvePolicies(program, policies);
    const observations = (result: AnalysisFacts) => detectors.flatMap(detector => detector.run(result, configuration)).map(finding => `${finding.detectorId}:${finding.fingerprint}`).sort();
    assert.deepEqual(observations(facts), observations(reference));
    check(facts);
  });
}

function returned(facts: AnalysisFacts) {
  return facts.paths.flatMap(path => path.sinks.filter(sink => sink.kind === "exported-return").map(sink => sink.value));
}

test("mapped witnesses have distinct invocation identities and exact reference spans", () => {
  compare('witness reveal(value: Field): Field; export circuit entry(secret: Field): Vector<2, Field> { return disclose(map(/* Ω🚀 */ reveal, [secret, 0 as Field])); }', facts => {
    const items = returned(facts)[0].items!;
    const witnesses = items.map(item => item.flows.find(flow => flow.source.kind === "witness")!);
    assert.notEqual(witnesses[0].source.id, witnesses[1].source.id);
    assert.ok(witnesses.every(flow => flow.form === "raw"));
    assert.ok(items[0].flows.some(flow => flow.source.name === "secret" && flow.form === "derived"));
    assert.equal(items[1].flows.some(flow => flow.source.name === "secret"), false);
    const location = witnesses[0].source.location;
    const source = readFileSync(location.file);
    assert.equal(source.subarray(location.start, location.end).toString(), "reveal");
    assert.equal(location.column, source.toString().lastIndexOf("reveal,") + 1);
    assert.equal(facts.program.findCallers(witnesses[0].source.symbol!).length, 1);
    const graph = facts.program.instructionCFG(facts.program.entries[0]);
    assert.ok(graph.nodes.some(node => node.instruction?.kind === "evaluate" && node.instruction.expression.kind === "map" && node.instruction.effects.includes("witness")));
  });
});

test("generic witness targets specialize before mapped source classification", () => {
  compare("witness reveal<T>(value: T): T; export circuit entry(secret: Field): Field { return disclose(map(reveal<Field>, [secret])[0]); }", facts => {
    assert.equal(returned(facts)[0].type, "Field");
    assert.equal(returned(facts)[0].flows.filter(flow => flow.source.kind === "witness").length, 1);
  });
});

test("folded witnesses retain prior accumulator dependencies and fresh sources", () => {
  compare("witness next(total: Field, value: Field): Field; export circuit entry(secret: Field): Field { return disclose(fold(next, secret, [1 as Field, 2 as Field])); }", facts => {
    const flows = returned(facts)[0].flows;
    assert.equal(new Set(flows.filter(flow => flow.source.kind === "witness").map(flow => flow.source.id)).size, 2);
    assert.equal(flows.filter(flow => flow.source.kind === "witness" && flow.form === "raw").length, 1);
    assert.ok(flows.some(flow => flow.source.name === "secret" && flow.form === "derived"));
  });
});

test("mapped hash bindings participate in the existing preimage detector", () => {
  compare('import CompactStandardLibrary; witness secret(): Field; export ledger digest: Bytes<32>; export circuit entry(): Field { const value = secret(); const hashes = map(persistentHash<Field>, [value]); assert(hashes[0] == digest, "bound"); return disclose(value); }', facts => {
    assert.equal(detectors[0].run(facts).length, 1);
  });
});

test("publishing only mapped hashes does not become raw preimage publication", () => {
  compare('import CompactStandardLibrary; witness secret(): Field; export ledger digest: Bytes<32>; export circuit entry(): Bytes<32> { const value = secret(); const hashes = map(persistentHash<Field>, [value]); assert(hashes[0] == digest, "bound"); return disclose(hashes[0]); }', facts => {
    assert.equal(detectors[0].run(facts).length, 0);
    assert.ok(returned(facts)[0].flows.every(flow => flow.form === "hash"));
  });
});

for (const predictable of [true, false]) test(`mapped commitment randomness remains ${predictable ? "known" : "unknown"}`, () => {
  compare(`import CompactStandardLibrary; witness random(): Bytes<32>; export circuit entry(secret: Field): Vector<1, Bytes<32>> { return disclose(map(persistentCommit<Field>, [secret], [${predictable ? "default<Bytes<32>>" : "random()"}])); }`, facts => {
    const findings = detectors.find(detector => detector.id === "predictable-commitment-randomness")!.run(facts);
    assert.equal(findings.length, predictable ? 1 : 0);
    assert.equal(returned(facts)[0].items![0].commitments![0].primitive, "persistentCommit");
  });
});

test("intrinsic folds retain private-derived commitment provenance", () => {
  compare("import CompactStandardLibrary; export circuit entry(secret: Field): Field { return fold(transientCommit<Field>, secret, [0 as Field, 1 as Field]); }", facts => {
    assert.equal(returned(facts)[0].flows[0].form, "commitment");
    assert.equal(detectors.find(detector => detector.id === "predictable-commitment-randomness")!.run(facts).length, 1);
  });
});

test("pure Merkle folds join private direction alternatives without path explosion", () => {
  withFiles({ "main.compact": "pragma language_version >= 0.26.0; import CompactStandardLibrary; export circuit entry(path: MerkleTreePath<16, Bytes<32>>): MerkleTreeDigest { return merkleTreePathRootNoLeafHash<16>(path); }" }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const accepted = validateWithCompiler(process.env.COMPACTC_TEST, path);
      assert.equal(accepted.valid, true, accepted.error);
    }
    const program = new Program(path);
    const facts = new Dataflow(program).analyze();
    assert.deepEqual(facts.diagnostics, []);
    assert.deepEqual(facts.completedEntries, program.entries);
    assert.equal(facts.paths.length, 1);
    assert.ok(facts.metrics.paths < 16);
    for (const flow of returned(facts)[0].fields!.field.flows) {
      const summaries = flow.trace.filter(step => step.kind === "fold-choice");
      assert.ok(summaries.length <= 1, "preceding iterations share one provenance summary");
    }
  });
});

test("pure fold joins retain known numeric accumulators", () => compare(`
circuit add(total: Field, item: Field): Field { return total + item; }
export circuit entry(): Field { return fold(add, 0 as Field, [1 as Field, 2 as Field, 3 as Field]); }
`, facts => assert.equal(returned(facts)[0].constant, "6")));

test("pure folds retain distinct aggregate choices and common constants", () => compare(`
struct Box { stable: Field; value: Field; }
pure circuit choose(previous: Box, next: Box, flag: Boolean): Box {
  return flag ? Box { stable: previous.stable, value: previous.value }
              : Box { stable: previous.stable, value: next.value };
}
export circuit entry(first: Field, second: Field, flags: Vector<2,Boolean>): Box {
  const seed = Box { stable: 7 as Field, value: first };
  return fold(choose, seed, [Box { stable: 7 as Field, value: second }, seed], flags);
}
`, facts => {
  const values = returned(facts);
  assert.ok(values.length > 1);
  for (const value of values) {
    assert.equal(value.fields!.stable.constant, "7");
    assert.equal(value.fields!.value.constant, undefined);
    const origins = value.fields!.value.flows.filter(flow => ["first", "second"].includes(flow.source.name));
    assert.equal(origins.length, 1, "one real value origin per successful history");
  }
  const sources = new Set(values.flatMap(value => value.fields!.value.flows.map(flow => flow.source.name)));
  assert.ok(sources.has("first") && sources.has("second") && sources.has("flags"));
}));

for (const shape of ["scalar", "hash", "aggregate"] as const) test(`pure fold preserves ${shape} choice after caller refinement`, () => {
  const declaration = shape === "scalar"
    ? `pure circuit choose(previous: Uint<8>, flag: Boolean): Uint<8> { return flag ? 1 : 2; }`
    : shape === "hash"
      ? `pure circuit choose(previous: Bytes<32>, flag: Boolean, next: Bytes<32>): Bytes<32> {
          return flag ? persistentHash<Vector<2, Bytes<32>>>([previous,next]) : persistentHash<Vector<2, Bytes<32>>>([next,previous]); }`
      : `struct Box { value: Uint<8>; }
         pure circuit choose(previous: Box, flag: Boolean): Box { return flag ? Box { value: 1 } : Box { value: 2 }; }`;
  const call = shape === "scalar" ? "fold(choose, 0 as Uint<8>, [flag])"
    : shape === "hash" ? "fold(choose, first, [flag], [second])" : "fold(choose, Box { value: 0 }, [flag])";
  const equality = shape === "scalar" ? "selected == 1" : shape === "hash"
    ? "selected == persistentHash<Vector<2, Bytes<32>>>([first,second])" : "selected.value == 1";
  withFiles({ "main.compact": `import CompactStandardLibrary; ${declaration}
    export circuit rejected(flag: Boolean, first: Bytes<32>, second: Bytes<32>): [] {
      const selected = ${call}; assert(flag, "select first"); assert(!(${equality}), "contradiction");
    }
    export circuit accepted(flag: Boolean, first: Bytes<32>, second: Bytes<32>): [] {
      const selected = ${call}; assert(flag, "select first"); assert(${equality}, "consistent");
    }` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(file);
    let oracle: AnalysisFacts | undefined;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) for (const partitions of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, partitions, "all").analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      assert.deepEqual(facts.paths.map(path => program.symbols.get(path.entry)!.name), ["accepted"]);
      if (oracle) {
        assert.deepEqual(semanticPaths(facts), semanticPaths(oracle));
        assert.deepEqual(facts.assertionReaches, oracle.assertionReaches);
      } else oracle = facts;
    }
  });
});

test("mapped constructors preserve active and inactive field provenance", () => {
  compare("import CompactStandardLibrary; export circuit entry(secret: Field): [Field, Field, Field] { const options = map(some<Field>, [secret, 0 as Field]); const choices = map(left<Field, Field>, [secret]); return [options[0].value, options[1].value, choices[0].right]; }", facts => {
    const items = returned(facts)[0].items!;
    assert.equal(items[0].flows[0].source.name, "secret");
    assert.equal(items[0].flows[0].form, "raw");
    assert.ok(items.slice(1).every(item => item.flows.length === 0 && item.constant === "0"));
  });
});

test("mapped conversion intrinsics retain derived dependencies", () => {
  compare("import CompactStandardLibrary; export circuit entry(secret: Bytes<32>): Field { return map(degradeToTransient, [secret])[0]; }", facts => {
    assert.equal(returned(facts)[0].type, "Field");
    assert.equal(returned(facts)[0].flows[0].source.name, "secret");
    assert.equal(returned(facts)[0].flows[0].form, "derived");
  });
});

test("keccak generic parameters denote input types rather than byte lengths", () => {
  compare("import CompactStandardLibrary; new type Input = Bytes<2>; export circuit entry(value: Input): [Bytes<32>, Bytes<32>] { return [keccak256<Input>(value), map(keccak256<Input>, [value])[0]]; }", facts => {
    assert.ok(returned(facts)[0].items!.every(item => item.flows[0].form === "hash"));
  });
});

test("mapped overloads use the entire sequence common type", () => {
  compare("circuit choose(value: Uint<8>): Uint<16> { return 1 as Uint<16>; } circuit choose(value: Uint<16>): Uint<16> { return value; } export circuit entry(): Vector<2, Uint<16>> { return map(choose, [1 as Uint<8>, 300 as Uint<16>]); }", facts => {
    assert.deepEqual(returned(facts)[0].items!.map(item => item.constant), ["1", "300"]);
    const calls = [...facts.program.functions.get(facts.program.entries[0])!.calls];
    assert.equal(facts.program.symbols.get(calls[0])!.declaration!.parameters[0].type, "Uint<16>");
  });
});

test("fold overload selection excludes incompatible accumulator return types", () => {
  compare("circuit accumulate(total: Uint<8>, item: Uint<8>): Boolean { return true; } circuit accumulate(total: Uint<16>, item: Uint<8>): Uint<16> { return (total + item) as Uint<16>; } export circuit entry(): Uint<16> { return fold(accumulate, 0 as Uint<8>, [1 as Uint<8>, 2 as Uint<8>]); }", facts => assert.equal(returned(facts)[0].constant, "3"));
});

test("generic kind filtering applies to overloaded higher-order references", () => {
  compare("circuit choose<T>(value: T): T { return value; } circuit choose<#N>(value: Vector<N, Field>): Field { return value[0]; } export circuit entry(secret: Field): Field { return map(choose<Field>, [secret])[0]; }", facts => assert.equal(returned(facts)[0].flows[0].source.name, "secret"));
});

test("selected prefixed imports preserve higher-order overload groups", () => {
  compare("module Library { export circuit choose(value: Field): Field { return value; } export circuit choose(value: Boolean): Field { return 0 as Field; } } import { choose as select } from Library prefix L_; export circuit entry(secret: Field): Field { return map(L_select, [secret])[0]; }", facts => assert.equal(returned(facts)[0].flows[0].source.name, "secret"));
});

test("anonymous map parameters use common aggregate sequence types", () => {
  compare("export circuit entry(): Vector<2, Uint<16>> { return map((item) => item[0], [[1 as Uint<8>, 2 as Field], [300 as Uint<16>, 4 as Field]]); }", facts => {
    assert.deepEqual(returned(facts)[0].items!.map(item => item.constant), ["1", "300"]);
    assert.equal([...facts.program.functions.values()].find(fn => fn.symbol.name.startsWith("$lambda"))!.symbol.type, "Uint<16>");
  });
});

test("an annotated fold result contextualizes its undeclared accumulator parameter", () => {
  compare("export circuit entry(): Uint<16> { return fold((total, item): Uint<16> => (total + item) as Uint<16>, 0, [1 as Uint<8>, 2 as Uint<8>]); }", facts => {
    assert.equal(returned(facts)[0].constant, "3");
    const fn = [...facts.program.functions.values()].find(fn => fn.symbol.name.startsWith("$lambda"))!;
    assert.equal(fn.declaration.parameters[0].type, "Uint<16>");
  });
});

test("Uint and Field overloads do not introduce an implicit numeric conversion", () => {
  compare("circuit choose(value: Uint<16>): Field { return value as Field; } circuit choose(value: Field): Field { return 99 as Field; } export circuit entry(): Field { return choose(1 as Uint<8>); }", facts => {
    assert.equal(returned(facts)[0].constant, "1");
    assert.equal(facts.program.assignable("Uint<8>", "Field"), false);
  });
});

test("repeated mapped mutations reuse transfers without reusing storage snapshots", () => {
  compare("export ledger stored: Field; circuit put(value: Field): [] { stored = disclose(value); } export circuit entry(secret: Field): [] { map(put, [secret, secret]); }", facts => {
    assert.equal(facts.paths[0].writes.length, 2);
    assert.equal(facts.metrics.statefulSummaryHits, 1);
    assert.ok(facts.paths[0].writes.every(write => write.after.flows[0].source.name === "secret"));
  });
});

test("nested anonymous maps preserve captured outer iteration values", () => {
  compare("export circuit entry(secret: Field): Field { return map((item: Field): Field => map((inner: Field): Field => item + inner, [0 as Field])[0], [secret])[0]; }", facts => {
    assert.equal(returned(facts)[0].flows[0].source.name, "secret");
    assert.equal(returned(facts)[0].flows[0].form, "derived");
  });
});

test("zero-byte sequences retain their Uint element type without invoking a hash", () => {
  compare("import CompactStandardLibrary; export circuit entry(): Vector<0, Bytes<32>> { return map(persistentHash<Uint<8>>, default<Bytes<0>>); }", facts => assert.deepEqual(returned(facts)[0].items, []));
});

test("zero-length vectors retain their declared element type during overload resolution", () => {
  compare("circuit choose(value: Vector<0, Field>): Field { return 1 as Field; } circuit choose(value: Vector<0, Boolean>): Field { return 2 as Field; } export circuit entry(): Field { return map(choose, [default<Vector<0, Field>>])[0]; }", facts => {
    assert.equal(returned(facts)[0].constant, "1");
    assert.equal(facts.program.sameType("Vector<0, Field>", "Vector<0, Boolean>"), false);
    assert.equal(facts.program.assignable("Vector<0, Field>", "Vector<0, Boolean>"), false);
  });
});

test("oversized compiler-valid higher-order inputs remain explicitly incomplete", () => {
  withFiles({ "main.compact": "circuit identity(value: Field): Field { return value; } export circuit entry(): Vector<257, Field> { return map(identity, default<Vector<257, Field>>); }" }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const accepted = validateWithCompiler(process.env.COMPACTC_TEST, path);
      assert.equal(accepted.valid, true, accepted.error);
    }
    const result = scanFile(path);
    assert.equal(result.status, "incomplete");
    assert.ok(result.diagnostics.some(diagnostic => diagnostic.code === "sequence-budget"));
    assert.deepEqual(result.coverage.completedEntries, []);
  });
});

test("for-of iteration uses the same whole-sequence common type as map", () => {
  compare("export ledger stored: Field; circuit choose(value: Uint<8>): Field { return 1 as Field; } circuit choose(value: Uint<16>): Field { return 2 as Field; } export circuit entry(): [] { for (const value of [1 as Uint<8>, 300 as Uint<16>]) { stored = choose(value); } }", facts => {
    assert.deepEqual(facts.paths[0].writes.map(write => write.after.constant), ["2", "2"]);
  });
});

test("slices use the sequence common element type for subsequent overloads", () => {
  compare("circuit choose(value: Vector<2, Uint<8>>): Field { return 1 as Field; } circuit choose(value: Vector<2, Uint<16>>): Field { return 2 as Field; } export circuit entry(): Field { return choose(slice<2>([1 as Uint<8>, 300 as Uint<16>], 0)); }", facts => {
    assert.equal(returned(facts)[0].constant, "2");
  });
});

test("nominal aggregate comparisons and conditionals accept either subtype direction", () => {
  compare("new type Token = Field; export circuit entry(flag: Boolean, value: Token): [Uint<16>, Boolean] { const pair = flag ? [value, 300 as Uint<16>] : [value, 1 as Uint<8>]; return [pair[1], pair == [value, 1 as Uint<8>]]; }", facts => {
    const local = [...facts.program.symbols.values()].find(symbol => symbol.kind === "local" && symbol.name === "pair")!;
    assert.ok(local.type.endsWith(",Uint<16>]"));
    assert.equal(facts.paths.length, 2);
  });
});

test("empty mapped witnesses produce no private sources or invocations", () => {
  compare("witness reveal(value: Field): Field; export circuit entry(): Vector<0, Field> { return map(reveal, []); }", facts => {
    assert.equal(facts.metrics.sources, 0);
    assert.deepEqual(returned(facts)[0].items, []);
  });
});

test("an empty fold evaluates its initializer but never its callback", () => {
  compare('export ledger stored: Field; circuit start(): Field { stored = 7 as Field; return 1 as Field; } circuit stop(total: Field, value: Field): Field { assert(false, "not called"); return total; } export circuit entry(): Field { return fold(stop, start(), []); }', facts => {
    assert.equal(returned(facts)[0].constant, "1");
    assert.deepEqual(facts.paths[0].writes.map(write => write.after.constant), ["7"]);
    assert.deepEqual(facts.failedAssertions, []);
  });
});

test("zero-iteration maps do not fabricate authorization guard completion", () => {
  const policies = { authorization: [{ state: "stored", guard: "guard" }] };
  compare('export ledger allowed: Boolean; export ledger stored: Field; circuit guard(value: Field): [] { assert(allowed, "allowed"); } export circuit entry(): [] { map(guard, default<Vector<0, Field>>); stored = 1 as Field; }', facts => {
    const rule = detectors.find(detector => detector.id === "unguarded-sensitive-state-write")!;
    assert.equal(rule.run(facts, resolvePolicies(facts.program, policies)).length, 1);
  }, policies);
});

for (const kind of ["map", "fold"] as const) for (const helper of [false, true]) {
  test(`empty ${kind}${helper ? " helper" : ""} does not retain private control on an unconditional write`, () => {
    const operation = kind === "map"
      ? "map(reject, default<Vector<0, Field>>)"
      : "fold(reject, true, default<Vector<0, Field>>)";
    const parameters = kind === "map" ? "value: Field" : "total: Boolean, value: Field";
    withFiles({ "main.compact": `pragma language_version >= 0.26.0;
      export ledger stored: Field;
      witness flag(): Boolean;
      circuit reject(${parameters}): Boolean { assert(false, "unreached"); return true; }
      ${helper ? `circuit empty(): [] { ${operation}; }` : ""}
      export circuit entry(): [] {
        if (flag()) { ${helper ? "empty()" : operation}; }
        stored = 7 as Field;
      }` }, directory => {
      const file = resolve(directory, "main.compact");
      if (process.env.COMPACTC_TEST) {
        const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
        assert.equal(compiled.valid, true, compiled.error);
      }
      const program = new Program(file);
      let previous: unknown;
      for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
        const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze();
        assert.deepEqual(facts.diagnostics, []);
        assert.deepEqual(facts.completedEntries, program.entries);
        assert.deepEqual(facts.failedAssertions, []);
        assert.ok(facts.paths.length > 0);
        for (const path of facts.paths) {
          assert.equal(path.writes.length, 1);
          assert.equal(path.writes[0].after.constant, "7");
          assert.deepEqual(path.writes[0].after.flows, []);
          assert.equal(path.writes[0].guards.some(id => id.endsWith("::reject")), false);
        }
        const paths = semanticPaths(facts);
        previous ??= paths; assert.deepEqual(paths, previous);
      }
    });
  });
}

for (const kind of ["map", "fold"] as const) test(`empty ${kind} still evaluates rejecting arguments`, () => {
  const operation = kind === "map" ? "map(reject, values(false))" : "fold(reject, initial(false), default<Vector<0, Field>>)";
  compare(`export ledger stored: Field;
    circuit values(allowed: Boolean): Vector<0, Field> { assert(allowed, "argument"); return []; }
    circuit initial(allowed: Boolean): Boolean { assert(allowed, "argument"); return true; }
    circuit reject(${kind === "map" ? "value: Field" : "total: Boolean, value: Field"}): Boolean { assert(false, "unreached"); return true; }
    export circuit entry(): [] { ${operation}; stored = 7 as Field; }`, facts => {
    assert.equal(facts.failedAssertions.length, 1);
    assert.deepEqual(facts.paths, []);
  });
});

for (const kind of ["map", "fold"] as const) test(`nonempty ${kind} retains callback rejection and abort edges`, () => {
  const operation = kind === "map" ? "map(reject, [true, false])" : "fold(reject, true, [true, false])";
  compare(`export ledger stored: Field;
    circuit reject(${kind === "map" ? "value: Boolean" : "total: Boolean, value: Boolean"}): ${kind === "map" ? "[]" : "Boolean"} { assert(value, "reached"); stored = 8 as Field; return ${kind === "map" ? "[]" : "true"}; }
    export circuit entry(): [] { ${operation}; stored = 7 as Field; }`, facts => {
    assert.deepEqual(facts.paths, []);
    assert.equal(facts.failedAssertions.length, 1);
    const graph = facts.program.instructionCFG(facts.program.entries[0]);
    const node = graph.nodes.find(node => node.instruction?.kind === "evaluate" && node.instruction.expression.kind === kind)!;
    assert.ok(node.instruction!.effects.includes("may-abort"));
    assert.ok(node.edges.some(edge => edge.target === graph.abort));
  });
});

test("map evaluates all sequences once before left-to-right callback effects", () => {
  compare("export ledger stored: Field; circuit first(): Vector<2, Field> { stored = 1 as Field; return [3 as Field, 4 as Field]; } circuit second(): Vector<2, Field> { stored = 2 as Field; return [0 as Field, 0 as Field]; } circuit put(value: Field, ignored: Field): [] { stored = disclose(value); } export circuit entry(): [] { map(put, first(), second()); }", facts => {
    assert.deepEqual(facts.paths[0].writes.map(write => write.after.constant), ["1", "2", "3", "4"]);
  });
});

test("aborting later map callbacks discard successful writes from earlier iterations", () => {
  compare('export ledger stored: Field; circuit put(flag: Boolean): [] { assert(flag, "allowed"); stored = 1 as Field; } export circuit entry(): [] { map(put, [true, false]); }', facts => {
    assert.deepEqual(facts.paths, []);
    assert.equal(facts.failedAssertions.length, 1);
  });
});

test("nominal sequence work estimates include every callback", () => {
  compare("new type Values = Vector<3, Field>; circuit identity(value: Field): Field { return value; } export circuit entry(values: Values): Vector<3, Field> { return map(identity, values); }", facts => {
    const estimate = estimateWork(facts.program, facts.program.entries[0]);
    assert.ok(estimate && estimate.units >= 3);
    assert.equal(returned(facts)[0].items!.length, 3);
  });
});

test("higher-order witness interpretation remains budgeted and repeatable", () => {
  compare("witness reveal(value: Field): Field; export circuit entry(): Vector<8, Field> { return disclose(map(reveal, default<Vector<8, Field>>)); }", facts => {
    const limited = new Dataflow(facts.program, 5).analyze();
    assert.ok(limited.diagnostics.some(diagnostic => diagnostic.code === "analysis-budget"));
    assert.deepEqual(limited.completedEntries, []);
    const analysis = new Dataflow(facts.program);
    assert.deepEqual(analysis.analyze().paths, analysis.analyze().paths);
  });
});

const rejected: [string, string][] = [
  ["export circuit entry(): Vector<2, Field> { return map((value: Field): Field => value, [true, false]); }", "call-type-mismatch"],
  ["export circuit entry(): Field { return ((value: Field): Field => value)(true); }", "call-type-mismatch"],
  ["export circuit entry(): Vector<1, Boolean> { return map((value: Field): Boolean => value, [0 as Field]); }", "return-type-mismatch"],
  ["export circuit entry(): Vector<2, Field> { return map((value) => 0 as Field, [true, 1 as Field]); }", "incompatible-sequence-elements"],
  ["new type Token = Field; export circuit entry(value: Token): Vector<2, Token> { return map((item: Token): Token => item, [value, 0 as Field]); }", "incompatible-sequence-elements"],
  ["export circuit entry(): Vector<1, Field> { return map((first: Field, second: Field): Field => first, [1 as Field], [2 as Field, 3 as Field]); }", "unknown-higher-order-size"],
  ["export circuit entry(): Vector<1, Field> { return map((value: Field): Field => value, 0 as Field); }", "unknown-higher-order-size"],
  ["export circuit entry(): Field { return fold((total: Uint<8>, item: Field): Field => item, 0, [1 as Field]); }", "fold-type-mismatch"],
  ["export circuit entry(): Uint<16> { return fold((total, item) => total + item, 0, [1]); }", "fold-type-mismatch"],
  ["circuit identity<T>(value: T): T { return value; } export circuit entry(): Vector<1, Field> { return map(identity, [0 as Field]); }", "generic-arity"],
  ["import CompactStandardLibrary; export circuit entry(): Vector<1, Bytes<32>> { return map(persistentHash, [0 as Field]); }", "generic-arity"],
  ["import CompactStandardLibrary; export circuit entry(): Vector<1, Bytes<32>> { return map(persistentHash<4>, [0 as Field]); }", "generic-kind"],
  ["import CompactStandardLibrary; export circuit entry(): Vector<1, Bytes<32>> { return map(persistentHash<Field>, [true]); }", "call-type-mismatch"],
  ["import CompactStandardLibrary; export circuit entry(value: Field): Field { return fold(persistentCommit<Field>, value, [default<Bytes<32>>]); }", "fold-type-mismatch"],
  ["circuit choose(value: Uint<8>): Field { return 0 as Field; } circuit choose(value: Uint<16>): Field { return 1 as Field; } export circuit entry(): Vector<1, Field> { return map(choose, [1]); }", "overload-resolution"],
  ["circuit choose(value: Boolean): Field { return 0 as Field; } circuit choose(value: Field): Field { return 1 as Field; } export circuit entry(): Vector<0, Field> { return map(choose, []); }", "overload-resolution"],
  ["export circuit entry(): Vector<1, Field> { return map((value: Field): Field => value, [0]); }", "call-type-mismatch"],
  ["export circuit entry(): Field { return fold((total, item): Field => total + item, 0, [1 as Field]); }", "call-type-mismatch"],
  ["circuit accumulate(total: Uint<16>, item: Field): Boolean { return true; } circuit accumulate(total: Field, item: Field): Field { return total + item; } export circuit entry(): Field { return fold(accumulate, 0 as Uint<8>, [1 as Field]); }", "overload-resolution"],
  ["export circuit entry(): Vector<1, Field> { return map((first: Field, second: Field): Field => first, [0 as Field]); }", "call-arity"],
];

for (const [index, [source, code]] of rejected.entries()) test(`compiler-rejected higher-order application ${index + 1} is diagnosed`, () => {
  withFiles({ "main.compact": source }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, path).valid, false);
    const result = scanFile(path);
    assert.equal(result.status, "incomplete");
    assert.ok(result.diagnostics.some(diagnostic => diagnostic.code === code), JSON.stringify(result.diagnostics));
    assert.deepEqual(result.coverage.completedEntries, []);
  });
});
