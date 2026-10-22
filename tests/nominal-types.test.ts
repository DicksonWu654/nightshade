import test from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { AnalysisFacts, Dataflow, Program, Policies, detectors, resolvePolicies, scanFile } from "../src/index.js";
import { FIELD_MODULUS, castConstant } from "../src/dataflow/constants.js";
import { PureCircuitEligibility } from "../src/analysis/summaries.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { semanticPaths, withFiles } from "./helpers.js";

function compare(source: string, check: (facts: AnalysisFacts) => void, policies: Policies = {}): void {
  withFiles({ "main.compact": `pragma language_version >= 0.26.0; ${source}` }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, path);
      assert.equal(compiled.valid, true, compiled.error);
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
    const configured = resolvePolicies(program, policies);
    const observations = (result: AnalysisFacts) => detectors.flatMap(detector => detector.run(result, configured)).map(finding => `${finding.detectorId}:${finding.fingerprint}`).sort();
    assert.deepEqual(observations(facts), observations(reference));
    check(facts);
  });
}

function returned(facts: AnalysisFacts) {
  return facts.paths.flatMap(path => path.sinks.filter(sink => sink.kind === "exported-return").map(sink => sink.value));
}

test("nominal overloads keep distinct names despite identical representations", () => {
  compare("new type Left = Field; new type Right = Field; circuit select(value: Left): Field { return 1 as Field; } circuit select(value: Right): Field { return 2 as Field; } export circuit entry(): [Field, Field] { return [select(default<Left>), select(default<Right>)]; }", facts => {
    assert.deepEqual(returned(facts)[0].items!.map(item => item.constant), ["1", "2"]);
    assert.equal(facts.program.nominalTypes.size, 2);
    const [first, second] = [...facts.program.nominalTypes.keys()];
    assert.equal(facts.program.sameType(first, second), false);
    assert.equal(facts.program.assignable(first, "Field"), false);
  });
});

test("nominal defaults and chained aliases retain their shapes and scalar constants", () => {
  compare('new type Flag = Boolean; new type Amount = Uint<8>; new type Digest = Bytes<2>; new type Pair = [Flag, Amount]; new type Chained = Pair; export circuit entry(): [Flag, Amount, Digest, Chained] { return [default<Flag>, default<Amount>, default<Digest>, default<Chained>]; }', facts => {
    const items = returned(facts)[0].items!;
    assert.deepEqual(items.slice(0, 3).map(item => item.constant), ["false", "0", "0000"]);
    assert.deepEqual(items[3].items!.map(item => item.constant), ["false", "0"]);
  });
});

for (const [operation, first, second, expected] of [["+", 200, 55, "255"], ["+", 200, 56, undefined], ["*", 16, 16, undefined], ["-", 0, 1, undefined]] as const) test(`nominal Uint arithmetic ${first} ${operation} ${second} preserves checked bounds`, () => {
  compare(`new type Small = Uint<8>; circuit calculate(first: Small, second: Small): Small { return first ${operation} second; } export circuit entry(): Small { return calculate(${first} as Small, ${second} as Small); }`, facts => {
    assert.deepEqual(returned(facts).map(value => value.constant), expected === undefined ? [] : [expected]);
    const fn = [...facts.program.functions.values()].find(fn => fn.symbol.name === "calculate")!;
    assert.equal(new PureCircuitEligibility(facts.program).allows(fn.symbol.id), false);
    assert.ok(facts.program.instructionCFG(fn.symbol.id).nodes.some(node => node.instruction?.kind === "evaluate" && node.instruction.expression.kind === "binary" && node.instruction.effects.includes("may-abort")));
  });
});

test("nominal Field subtraction wraps instead of underflowing", () => {
  compare("new type Amount = Field; export circuit entry(): Amount { return (0 as Amount) - (1 as Amount); }", facts => {
    assert.equal(returned(facts)[0].constant, String(FIELD_MODULUS - 1n));
    const graph = facts.program.instructionCFG(facts.program.entries[0]);
    const subtraction = graph.nodes.find(node => node.instruction?.kind === "evaluate" && node.instruction.expression.kind === "binary")!;
    assert.equal(subtraction.instruction!.effects.includes("may-abort"), false);
  });
});

test("failed nominal arithmetic cannot leave successful ledger writes", () => {
  compare("new type Small = Uint<8>; export ledger published: Field; circuit overflow(): Small { return (255 as Small) + (1 as Small); } export circuit entry(): [] { published = 1 as Field; overflow(); }", facts => assert.deepEqual(facts.paths, []));
});

test("representation-only casts preserve raw witnesses, hash bindings and caller constraints", () => {
  compare('import CompactStandardLibrary; new type Secret = Field; witness secret(): Secret; export ledger digest: Bytes<32>; export circuit entry(): Field { const value = secret(); assert(persistentHash<Secret>(value) == digest, "bound"); return disclose(value as Field); }', facts => {
    assert.equal(returned(facts)[0].flows[0].form, "raw");
    assert.equal(detectors[0].run(facts).length, 1);
  });
  compare('new type Flag = Boolean; export circuit entry(flag: Boolean): Boolean { assert(flag as Flag, "true"); return flag; }', facts => assert.equal(returned(facts)[0].constant, "true"));
});

test("nominal hash-only returns do not turn into raw publication findings", () => {
  compare('import CompactStandardLibrary; new type Secret = Field; witness secret(): Secret; export ledger digest: Bytes<32>; export circuit entry(): Bytes<32> { const value = secret(); assert(persistentHash<Secret>(value) == digest, "bound"); return disclose(persistentHash<Secret>(value)); }', facts => assert.equal(detectors[0].run(facts).length, 0));
});

test("nominal structs and vectors preserve field-sensitive provenance", () => {
  compare('new type Secret = Field; new type Pair = [Secret, Field]; struct Record { privateValue: Secret; publicValue: Field; } new type Wrapped = Record; export circuit entry(secret: Field): [Field, Field] { const pair = [secret as Secret, 0 as Field] as Pair; const value = Wrapped { privateValue: pair[0], publicValue: pair[1] }; return [value.publicValue, value.privateValue as Field]; }', facts => {
    const items = returned(facts)[0].items!;
    assert.equal(items[0].flows.length, 0);
    assert.equal(items[1].flows[0].source.name, "secret");
    assert.equal(items[1].flows[0].form, "raw");
  });
});

test("unused nominal generic parameters do not invent distinct compiler type identities", () => {
  compare("new type Marker<#N> = Field; export circuit entry(value: Marker<1>): Marker<2> { return value; }", facts => {
    const fn = facts.program.functions.get(facts.program.entries[0])!;
    assert.equal(fn.declaration.parameters[0].type, fn.symbol.type);
    assert.equal(facts.program.nominalTypes.size, 1);
  });
});

test("nominal generic dimensions and alias chains retain distinct identities", () => {
  compare("new type Sized<#N> = Bytes<N>; new type Wrapped = Sized<2>; type Alias = Wrapped; export circuit entry(first: Sized<1>, second: Alias): [Sized<1>, Wrapped] { return [first, second]; }", facts => {
    const parameters = facts.program.functions.get(facts.program.entries[0])!.declaration.parameters;
    assert.equal(facts.program.representationOf(parameters[0].type), "Bytes<1>");
    assert.equal(facts.program.representationOf(parameters[1].type), "Bytes<2>");
    assert.notEqual(parameters[0].type, parameters[1].type);
  });
});

test("nominally identical module arguments share one state specialization", () => {
  compare("new type Marker<#N> = Field; module Store<T> { export ledger value: T; export circuit put(value: T): [] { StoreValue(value); } circuit StoreValue(input: T): [] { value = disclose(input); } } import Store<Marker<1>> prefix First_; import Store<Marker<2>> prefix Second_; export { First_value, Second_value }; export circuit entry(secret: Marker<1>): Marker<2> { First_put(secret); return Second_value; }", facts => {
    assert.equal(facts.program.activeSymbols().filter(symbol => symbol.kind === "ledger").length, 1);
    assert.equal(returned(facts)[0].flows[0].source.name, "secret");
    if (process.env.COMPACTC_TEST) {
      withFiles({ "main.compact": readFileSync(facts.program.root, "utf8") }, directory => {
        const compiled = spawnSync(process.env.COMPACTC_TEST!, ["--skip-zk", resolve(directory, "main.compact"), resolve(directory, "output")], { encoding: "utf8", timeout: 30000 });
        assert.equal(compiled.status, 0, compiled.stderr);
        const generated = readFileSync(resolve(directory, "output/contract/index.js"), "utf8");
        const first = /get First_value\(\)[\s\S]*?\.toValue\((\d+)n\)/.exec(generated)?.[1];
        const second = /get Second_value\(\)[\s\S]*?\.toValue\((\d+)n\)/.exec(generated)?.[1];
        assert.notEqual(first, undefined);
        assert.equal(first, second);
      });
    }
  });
});

test("nominal ledger ADTs reuse modeled methods without erasing stored value types", () => {
  compare("import CompactStandardLibrary; new type Token = Field; new type Count = Counter; new type Table = Map<Field, Token>; new type Queue = List<Token>; new type Seen = Set<Token>; export ledger count: Count; export ledger table: Table; export ledger queue: Queue; export ledger seen: Seen; circuit put(value: Token): [] { table.insert(default<Field>, disclose(value)); queue.pushFront(disclose(value)); seen.insert(disclose(value)); count.increment(1); } export circuit entry(secret: Token): Token { put(secret); put(secret); return table.lookup(default<Field>); }", facts => {
    assert.ok(facts.metrics.statefulSummaryHits > 0);
    assert.equal(facts.paths[0].writes.length, 8);
    assert.equal(returned(facts)[0].flows[0].source.name, "secret");
    assert.equal(facts.program.representationOf(returned(facts)[0].type!), "Field");
  });
});

test("nested nominal Map aliases preserve precise leaf regions", () => {
  compare("import CompactStandardLibrary; new type Token = Field; new type Inner = Map<Field, Token>; new type Outer = Map<Field, Inner>; export ledger table: Outer; export circuit entry(secret: Token): Token { table.lookup(0 as Field).insert(1 as Field, disclose(secret)); return table.lookup(0 as Field).lookup(1 as Field); }", facts => {
    assert.deepEqual(facts.paths[0].writes[0].region, ["key:integer:0", "key:integer:1"]);
    assert.equal(returned(facts)[0].flows[0].source.name, "secret");
  });
});

test("nominal enum members, scalar methods and transition policies retain enum values", () => {
  const policies = { transitions: [{ state: "phase", from: "END", to: "START" }] };
  compare('enum Stage { START, END } new type Phase = Stage; export ledger phase: Phase; export circuit entry(): Phase { assert(phase == Phase.END, "end"); phase.write(Phase.START); return phase.read(); }', facts => {
    assert.ok(returned(facts)[0].constant!.endsWith(".START"));
    assert.equal(detectors.flatMap(detector => detector.run(facts, resolvePolicies(facts.program, policies))).filter(finding => finding.detectorId === "forbidden-state-transition").length, 1);
  }, policies);
});

test("nominal bytes support bounded spreads, slices, map and representation conversions", () => {
  compare("new type BytesTwo = Bytes<2>; new type Byte = Uint<8>; new type Pair = Vector<2, Byte>; export circuit entry(): [Uint<8>, BytesTwo, Uint<8>] { const bytes = default<BytesTwo>; const selected = slice<1>(bytes, 0); const mapped = map((value: Uint<8>): Uint<8> => value, bytes); const values = bytes as Pair; return [selected[0], values as BytesTwo, mapped[1]]; }", facts => {
    assert.deepEqual(returned(facts)[0].items!.map(item => item.constant), ["0", "0000", "0"]);
  });
});

test("nominal sequences pass their element identity through higher-order arguments", () => {
  compare("new type Amount = Field; new type Values = Vector<2, Amount>; export circuit entry(values: Values): Amount { return fold((total: Amount, value: Amount): Amount => total + value, default<Amount>, values); }", facts => {
    assert.equal(returned(facts)[0].flows.length, 2);
    assert.ok(returned(facts)[0].flows.every(flow => flow.source.name === "values"));
  });
});

test("annotated anonymous circuit results retain their declared type rather than punctuation", () => {
  compare("export circuit entry(): [Field, Boolean] { return [((value: Field): Field => value)(1 as Field), ((value: Boolean): Boolean => { return value; })(true)]; }", facts => {
    const lambdas = [...facts.program.functions.values()].filter(fn => fn.symbol.name.startsWith("$lambda"));
    assert.deepEqual(lambdas.map(fn => fn.symbol.type), ["Field", "Boolean"]);
    assert.deepEqual(returned(facts)[0].items!.map(item => item.constant), ["1", "true"]);
  });
});

test("direct anonymous calls preserve explicitly matched and inferred nominal parameters", () => {
  compare("new type Token = Field; export circuit entry(value: Token): [Token, Token] { return [((item: Token): Token => item)(value), ((item) => item)(value)]; }", facts => {
    const items = returned(facts)[0].items!;
    assert.ok(items.every(item => item.flows[0].source.name === "value" && item.flows[0].form === "raw"));
    assert.ok(items.every(item => facts.program.nominalTypes.has(item.type!)));
  });
});

test("policy guards can return a nominal alias of the empty tuple", () => {
  const policies = { authorization: [{ state: "stored", guard: "guard" }] };
  compare('new type Done = []; export ledger allowed: Boolean; export ledger stored: Field; circuit guard(): Done { assert(allowed, "allowed"); return default<Done>; } export circuit entry(): [] { guard(); stored = 1 as Field; }', facts => {
    assert.equal(detectors.flatMap(detector => detector.run(facts, resolvePolicies(facts.program, policies))).filter(finding => finding.detectorId === "unguarded-sensitive-state-write").length, 0);
  }, policies);
});

test("scalar cast semantics include nonzero Boolean conversion and checked Boolean narrowing", () => {
  compare("new type Truth = Boolean; new type Zero = Uint<0..1>; export circuit entry(): [Truth, Truth, Zero] { return [2 as Truth, 0 as Truth, false as Zero]; }", facts => assert.deepEqual(returned(facts)[0].items!.map(item => item.constant), ["true", "false", "0"]));
  compare("new type Zero = Uint<0..1>; export circuit entry(): Zero { return true as Zero; }", facts => assert.deepEqual(facts.paths, []));
  assert.deepEqual(castConstant({ kind: "integer", value: "2" }, "Boolean"), { kind: "boolean", value: "true" });
  assert.equal(castConstant({ kind: "boolean", value: "true" }, "Uint<0..1>"), null);
});

test("compiler-generated JavaScript agrees with nominal cast and arithmetic semantics", { skip: !process.env.COMPACTC_TEST ? "Requires COMPACTC_TEST" : false }, () => {
  const source = `pragma language_version >= 0.26.0;
new type Truth = Boolean;
new type Zero = Uint<0..1>;
new type Small = Uint<8>;
new type OtherSmall = Uint<8>;
export circuit nonzero(): Truth { return 2 as Truth; }
export circuit narrow(): Zero { return true as Zero; }
export circuit add(first: Small, second: Small): Small { return first + second; }
export circuit identity(value: Small): OtherSmall { return value as OtherSmall; }`;
  withFiles({ "main.compact": source }, directory => {
    const path = resolve(directory, "main.compact");
    assert.equal(validateWithCompiler(process.env.COMPACTC_TEST!, path).valid, true);
    const compiled = spawnSync(process.env.COMPACTC_TEST!, ["--skip-zk", path, resolve(directory, "output")], { encoding: "utf8", timeout: 30000 });
    assert.equal(compiled.status, 0, compiled.stderr);
    const generated = readFileSync(resolve(directory, "output/contract/index.js"), "utf8");
    assert.match(generated, /_nonzero_0\(\)\s*\{\s*return !\(2n === 0n\);\s*\}/);
    const narrowing = generated.slice(generated.indexOf("  _narrow_0()"), generated.indexOf("  _add_0("));
    assert.match(narrowing, /return true\s*\?/);
    assert.match(narrowing, /if \(t1 > 0n\)\s*\{\s*throw new __compactRuntime\.CompactError/);
    assert.match(narrowing, /\}\)\(1n\)/);
    const addition = generated.slice(generated.indexOf("  _add_0("), generated.indexOf("  _identity_0("));
    assert.match(addition, /if \(t1 > 255n\)\s*\{\s*throw new __compactRuntime\.CompactError/);
    assert.match(addition, /\}\)\(first_0 \+ second_0\)/);
    assert.match(generated, /_identity_0\(value_0\)\s*\{\s*return value_0;\s*\}/);
    const facts = new Dataflow(new Program(path)).analyze();
    assert.deepEqual(facts.diagnostics, []);
    const returns = (name: string) => facts.paths.filter(path => facts.program.symbols.get(path.entry)!.name === name).flatMap(path => path.sinks.filter(sink => sink.kind === "exported-return"));
    assert.equal(returns("nonzero")[0].value.constant, "true");
    assert.deepEqual(returns("narrow"), []);
    assert.equal(returns("identity")[0].value.flows[0].form, "raw");
  });
});

test("nominal integer and byte casts retain little-endian values and checked bounds", () => {
  compare("new type Word = Uint<16>; new type Encoded = Bytes<2>; export circuit entry(): [Encoded, Word] { return [513 as Encoded, (513 as Encoded) as Word]; }", facts => assert.deepEqual(returned(facts)[0].items!.map(item => item.constant), ["0102", "513"]));
  compare("new type Byte = Bytes<1>; export circuit entry(): Byte { return 256 as Byte; }", facts => assert.deepEqual(facts.paths, []));
});

test("nominal enum casts preserve ordinals and reject out-of-range values", () => {
  compare("enum Stage { START, END } new type Phase = Stage; export circuit entry(): [Uint<8>, Phase] { return [Phase.END as Uint<8>, 1 as Phase]; }", facts => {
    assert.equal(returned(facts)[0].items![0].constant, "1");
    assert.ok(returned(facts)[0].items![1].constant!.endsWith(".END"));
  });
  compare("enum Stage { START, END } new type Phase = Stage; export circuit entry(): Phase { return 2 as Phase; }", facts => assert.deepEqual(facts.paths, []));
});

const rejected = [
  "new type Token = Field; export circuit entry(value: Token): Field { return value; }",
  "new type Token = Field; export circuit entry(value: Field): Token { return value; }",
  "new type First = Field; new type Second = Field; export circuit entry(value: First): Second { return value; }",
  "new type Token = Field; circuit take(value: Field): [] {} export circuit entry(value: Token): [] { take(value); }",
  "new type Token = Field; witness take(value: Field): Boolean; export circuit entry(value: Token): Boolean { return take(value); }",
  "new type Token = Field; export circuit entry(value: Token): Boolean { return value == (0 as Field); }",
  "new type Token = Field; export circuit entry(value: Token): Token { return value + (0 as Field); }",
  "new type Token = Field; export ledger stored: Token; export circuit entry(): [] { stored = 0 as Field; }",
  "new type Token = Field; export circuit entry(): [] { const value: Token = 0 as Field; }",
  "new type Token = Field; struct Box { value: Token; } export circuit entry(): Box { return Box { value: 0 as Field }; }",
  "import CompactStandardLibrary; new type Token = Field; export circuit entry(value: Token): Bytes<32> { return persistentHash<Field>(value); }",
  "import CompactStandardLibrary; new type Token = Field; export ledger table: Map<Token, Token>; export circuit entry(value: Token): [] { table.insert(0 as Field, disclose(value)); }",
  "import CompactStandardLibrary; new type Quantity = Uint<16>; export ledger count: Counter; export circuit entry(value: Quantity): [] { count.increment(disclose(value)); }",
  "new type Sized<#N> = Bytes<N>; export circuit entry(value: Sized<1>): Sized<2> { return value; }",
  "struct Box { value: Field; } new type Wrapped = Box; export circuit entry(value: Boolean): Wrapped { return value as Wrapped; }",
  "new type Token = Field; export circuit entry(value: Token): Field { return ((item: Field): Field => item)(value); }",
  "new type Token = Field; export circuit entry(value: Field): Token { return ((item: Token): Token => item)(value); }",
  "new type Token = Field; export circuit entry(value: Token): Token { return fold((total: Field, item: Field): Token => value, 0 as Field, [1 as Field]); }",
  "new type Token = Field; export circuit entry(value: Token): Field { return fold((total: Token, item: Field): Field => 0 as Field, value, [1 as Field]); }",
  "new type Token = Field; circuit accumulate(total: Token, item: Field): Field { return 0 as Field; } export circuit entry(value: Token): Field { return fold(accumulate, value, [1 as Field]); }",
  "import CompactStandardLibrary; new type Token = Field; export circuit entry(value: Token): Vector<1, Bytes<32>> { return map(persistentHash<Field>, [value]); }",
  "new type Empty<T> = Vector<0, T>; export circuit entry(value: Empty<Field>): Empty<Boolean> { return value; }",
];

for (const [index, source] of rejected.entries()) test(`compiler-rejected implicit nominal conversion ${index + 1} is diagnosed`, () => {
  withFiles({ "main.compact": source }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, path).valid, false);
    const result = scanFile(path);
    assert.equal(result.status, "incomplete");
    assert.ok(result.diagnostics.some(diagnostic => diagnostic.code === "nominal-type-mismatch"), JSON.stringify(result.diagnostics));
    assert.deepEqual(result.coverage.completedEntries, []);
  });
});

test("anonymous invocation arity errors are diagnosed before data-flow evaluation", () => {
  for (const argumentsText of ["", "1 as Field, 2 as Field"]) withFiles({ "main.compact": `export circuit entry(): Field { return ((item: Field): Field => item)(${argumentsText}); }` }, directory => {
    const path = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, path).valid, false);
    const result = scanFile(path);
    assert.equal(result.status, "incomplete");
    assert.ok(result.diagnostics.some(diagnostic => diagnostic.code === "call-arity"), JSON.stringify(result.diagnostics));
  });
});

test("recursive nominal aliases remain bounded diagnostics", () => {
  withFiles({ "main.compact": "new type First = Second; new type Second = First; export circuit entry(value: First): First { return value; }" }, directory => {
    const result = scanFile(resolve(directory, "main.compact"));
    assert.equal(result.status, "incomplete");
    assert.ok(result.diagnostics.some(diagnostic => diagnostic.code === "type-depth"));
  });
});
