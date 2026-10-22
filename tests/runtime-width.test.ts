import assert from "node:assert/strict";
import { resolve } from "node:path";
import test from "node:test";
import { Dataflow, type AnalysisFacts, type RuntimeOperation } from "../src/dataflow/index.js";
import { runtimeWidthFindings, shieldedCoinRuntimeWidth as rule } from "../src/detectors/runtime-width.js";
import { Program } from "../src/semantic/index.js";
import { runtimeWidthScope, SHIELDED_WIDTH_RULE } from "../src/semantic/runtime-width-targets.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const oversized = "18446744073709551616", maximum = "18446744073709551615";
const recipient = 'left<ZswapCoinPublicKey,ContractAddress>(ZswapCoinPublicKey { bytes: pad(32,"recipient") })';
const coin = (value: string) => `ShieldedCoinInfo { nonce: pad(32,"nonce"), color: pad(32,"color"), value: ${value} as Uint<128> }`;
const output = (value: string) => `createZswapOutput(${coin(value)},${recipient});`;

function flowFor(program: Program, engine: "instructions" | "expressions" = "instructions", cached = true): Dataflow {
  return new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, true, "all",
    false, false, false, true, false, false, false, false, false, true);
}

function factsFor(program: Program, engine: "instructions" | "expressions" = "instructions", cached = true): AnalysisFacts {
  return flowFor(program, engine, cached).analyze();
}

function qualified(file: string): void {
  if (process.env.COMPACTC_TEST) {
    const result = validateWithCompiler(process.env.COMPACTC_TEST, file, [], 30000, 2, "0.34.0");
    assert.equal(result.valid, true, result.error);
  }
}

function compare(source: string, expected: string[], verify?: (facts: AnalysisFacts) => void): void {
  withFiles({ "main.compact": "import CompactStandardLibrary;\n" + source }, directory => {
    const file = resolve(directory, "main.compact");
    qualified(file);
    const program = new Program(file);
    let baseline: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = factsFor(program, engine, cached);
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      const findings = rule.run(facts).sort((a, b) => a.fingerprint.localeCompare(b.fingerprint));
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(findings.map(item => item.metadata.entry).sort(), expected.slice().sort());
      baseline ??= findings;
      assert.deepEqual(findings, baseline);
      verify?.(facts);
    }
  });
}

test("owned Counter width fixtures preserve exact native operands across both engines and caches", () => {
  assert.equal(rule.id, SHIELDED_WIDTH_RULE);
  assert.equal(rule.defaultEnabled, false);
  for (const variant of ["positive", "corrected", "lookalike"]) {
    const file = resolve(`tests/corpus/known-bugs/counter-runtime-width-${variant}.compact`);
    qualified(file);
    const program = new Program(file);
    let baseline: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = factsFor(program, engine, cached);
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      const findings = rule.run(facts);
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(findings.map(item => item.location.line), variant === "positive" ? [34] : []);
      for (const item of findings) {
        assert.equal(item.severity, "low"); assert.equal(item.confidence, "high");
        assert.deepEqual(item.metadata.values, [oversized]);
        assert.equal(item.metadata.referenceRuntimeVersion, "0.19.0");
        assert.equal(item.metadata.runtimeApplicability, "expressly-assumed-reference-runtime");
        assert.equal(item.metadata.actualRuntime, "unverified");
        assert.equal(item.metadata.runtimeRejection, "not-proven");
        assert.equal(item.metadata.funding, "not-proven");
      }
      baseline ??= findings; assert.deepEqual(findings, baseline);
    }
  }
});

test("the width boundary is distinct from unknown source amounts and ordinary coin returns", () => compare(`
export circuit boundary(): [] { ${output(oversized)} }
export circuit inside(): [] { ${output(maximum)} }
export circuit unknown(value: Uint<128>): [] { createZswapOutput(disclose(${coin("value")}),${recipient}); }
export circuit onlyReturns(): ShieldedCoinInfo { return ${coin(oversized)}; }
`, ["boundary"]));

test("legal aggregate widening keeps inferred narrower Uint operands admissible", () => compare(`
export circuit inferredWide(): [] {
  createZswapOutput(ShieldedCoinInfo { nonce: pad(32,"n"), color: pad(32,"c"),
    value: ${oversized} }, ${recipient});
}
export circuit inferredSmall(): [] {
  createZswapOutput(ShieldedCoinInfo { nonce: pad(32,"n"), color: pad(32,"c"),
    value: 1 }, ${recipient});
}
`, ["inferredWide"]));

test("canonical aliases and helpers match while user namesakes stay outside applicability", () => compare(`
import {createZswapOutput as emitCoin} from CompactStandardLibrary;
circuit helper(value: Uint<128>): [] { createZswapOutput(disclose(${coin("value")}),${recipient}); }
export circuit throughHelper(): [] { helper(${oversized}); }
export circuit renamed(): [] { emitCoin(${coin(oversized)},${recipient}); }
module Fake { export circuit createZswapOutput(value: Uint<128>): [] {} }
import Fake prefix F_;
export circuit namesake(): [] { F_createZswapOutput(${oversized}); }
`, ["throughHelper", "renamed"], facts => {
  const entry = facts.program.entries.find(id => facts.program.symbols.get(id)?.name === "namesake")!;
  assert.equal(runtimeWidthScope(facts.program, entry).applicable, false);
}));

test("subset observations diagnose only the explicitly selected entry", () => {
  withFiles({ "main.compact": `import CompactStandardLibrary;
export circuit selected(): [] { ${output(oversized)} }
export circuit unobserved(): [] { ${output(oversized)} }
export circuit onlyReturns(): ShieldedCoinInfo { return ${coin(oversized)}; }
` }, directory => {
    const file = resolve(directory, "main.compact"); qualified(file);
    const program = new Program(file);
    const entry = program.entries.find(id => program.symbols.get(id)?.name === "selected")!;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = flowFor(program, engine, cached).analyzeSubset([entry]);
      assert.deepEqual(facts.diagnostics, []);
      assert.equal(facts.program.entries.length, 3);
      assert.deepEqual(facts.completedEntries, [entry]);
      const findings = runtimeWidthFindings(facts, undefined, undefined, [entry]);
      assert.deepEqual(findings.map(item => item.metadata.entry), ["selected"]);
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(runtimeWidthFindings(facts, undefined, undefined, []), []);
      assert.deepEqual(facts.diagnostics, []);
    }
  });
});

test("callback applicability stays conservative while empty maps emit no native output", () => compare(`
circuit callback(value: Uint<128>): [] { createZswapOutput(disclose(${coin("value")}),${recipient}); }
export circuit activeMapped(): [] { map(callback, [${oversized} as Uint<128>]); }
export circuit emptyMapped(): [] { map(callback, default<Vector<0, Uint<128>>>); }
export circuit activeInline(): [] {
  map((value: Uint<128>): [] => { createZswapOutput(disclose(${coin("value")}),${recipient}); }, [${oversized} as Uint<128>]);
}
export circuit emptyInline(): [] {
  map((value: Uint<128>): [] => { createZswapOutput(disclose(${coin("value")}),${recipient}); }, default<Vector<0, Uint<128>>>);
}
`, ["activeMapped", "activeInline"], facts => {
  for (const entry of facts.program.entries) {
    const scope = runtimeWidthScope(facts.program, entry);
    assert.equal(scope.complete, true);
    assert.equal(scope.applicable, true);
    const name = facts.program.symbols.get(entry)!.name;
    const outputs = facts.paths.filter(path => path.entry === entry).flatMap(path => path.operations ?? [])
      .filter(operation => operation.kind === "native-witness" && operation.name === "createZswapOutput");
    assert.equal(outputs.length, name.startsWith("empty") ? 0 : 1);
  }
}));

test("direct native callback references retain canonical output applicability and sites", () => compare(`
import {createZswapOutput as emitCoin} from CompactStandardLibrary;
export circuit nativeCallback(): [] { map(createZswapOutput, [${coin(oversized)}], [${recipient}]); }
export circuit aliasCallback(): [] { map(emitCoin, [${coin(oversized)}], [${recipient}]); }
export circuit boundaryCallback(): [] { map(createZswapOutput, [${coin(maximum)}], [${recipient}]); }
export circuit emptyNative(): [] {
  map(createZswapOutput, default<Vector<0, ShieldedCoinInfo>>, default<Vector<0, Either<ZswapCoinPublicKey, ContractAddress>>>);
}
module Fake {
  export circuit createZswapOutput(coin: ShieldedCoinInfo, recipient: Either<ZswapCoinPublicKey, ContractAddress>): [] {}
}
import Fake prefix F_;
export circuit namesakeCallback(): [] { map(F_createZswapOutput, [${coin(oversized)}], [${recipient}]); }
`, ["nativeCallback", "aliasCallback"], facts => {
  for (const entry of facts.program.entries) {
    const name = facts.program.symbols.get(entry)!.name;
    const scope = runtimeWidthScope(facts.program, entry);
    assert.equal(scope.complete, true);
    assert.equal(scope.applicable, name !== "namesakeCallback");
    if (name === "emptyNative") {
      assert.deepEqual(facts.paths.filter(path => path.entry === entry).flatMap(path => path.operations ?? []), []);
    }
  }
}));

test("branch history, later abort and inactive output keep their own source semantics", () => compare(`
export circuit active(flag: Boolean): [] { if(disclose(flag)) { ${output(oversized)} } else { ${output(maximum)} } }
export circuit aborts(): [] { ${output(oversized)} assert(false,"owned abort"); }
export circuit inactive(): [] { if(false) { ${output(oversized)} } }
`, ["active"]));

test("the emitted constant is an immutable snapshot rather than the final ledger value", () => compare(`
export ledger amount: Uint<128>;
export circuit retained(): [] {
  amount=${oversized}; const saved=amount; amount=1;
  createZswapOutput(${coin("saved")},${recipient});
}
export circuit overwritten(): [] { amount=${oversized}; amount=1; createZswapOutput(${coin("amount")},${recipient}); }
`, ["retained"]));

test("repeated helper outputs group exact amounts and retain every invocation site", () => compare(`
circuit outputCoin(value: Uint<128>): [] { createZswapOutput(disclose(${coin("value")}),${recipient}); }
export circuit repeated(): [] { outputCoin(${oversized}); outputCoin(18446744073709551617); outputCoin(${oversized}); }
`, ["repeated"], facts => {
  const findings = rule.run({ ...facts, diagnostics: [] });
  assert.equal(findings.length, 1);
  assert.deepEqual(findings[0].metadata.values, [oversized, "18446744073709551617"]);
  assert.equal((findings[0].metadata.invocationSites as unknown[]).length, 3);
}));

test("applicable unsupported profiles are rule-scoped unavailable; irrelevant entries stay quiet", () => {
  withFiles({ "main.compact": `import CompactStandardLibrary;
export circuit real(): [] { ${output(oversized)} }
export circuit onlyReturns(): ShieldedCoinInfo { return ${coin(oversized)}; }
module Fake { export circuit createZswapOutput(value: Uint<128>): [] {} }
import Fake prefix F_;
export circuit namesake(): [] { F_createZswapOutput(${oversized}); }
` }, directory => {
    const file = resolve(directory, "main.compact"); qualified(file);
    for (const [version, zkir] of [["0.31.1", 2], ["0.35.0", 2], ["0.34.0", 3]] as const) {
      const program = new Program(file, [], directory, undefined, zkir, version);
      const facts = factsFor(program);
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(rule.run(facts), []);
      assert.equal(facts.diagnostics.length, 1);
      const diagnostic = (facts as AnalysisFacts).diagnostics[0];
      assert.equal(diagnostic.code, "shielded-width-evidence-unavailable");
      assert.equal(diagnostic.scope?.kind, "rule");
      assert.equal(diagnostic.scope?.detectorId, rule.id);
      assert.equal(program.symbols.get(diagnostic.scope!.entry!)?.name, "real");
    }
  });
});

test("quantity mode, predicate scope and equivalent histories are mandatory", () => {
  withFiles({ "main.compact": `import CompactStandardLibrary; export circuit real(): [] { ${output(oversized)} }` }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const original = factsFor(program); assert.deepEqual(original.diagnostics, []);
    for (const changed of [
      { mintQuantityEvidence: undefined }, { predicateScope: "witness" as const },
      { predicateScope: "all-private" as const }, { pathSemantics: "guard-cover" as const },
    ]) {
      const facts: AnalysisFacts = { ...original, ...changed, diagnostics: [] };
      assert.deepEqual(rule.run(facts), []); assert.equal(facts.diagnostics.length, 1);
      assert.equal(facts.diagnostics[0].scope?.detectorId, rule.id);
    }
    const ordinary = new Dataflow(program).analyze();
    assert.deepEqual(rule.run(ordinary), []);
    assert.equal(ordinary.diagnostics.at(-1)?.code, "shielded-width-evidence-unavailable");
  });
});

test("bounded source applicability cannot certify absence after exhaustion", () => {
  withFiles({ "main.compact": `import CompactStandardLibrary;
export circuit real(): [] { ${output(oversized)} }
export circuit quiet(): [] {}
` }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    for (const entry of program.entries) {
      const scope = runtimeWidthScope(program, entry, 0);
      assert.equal(scope.complete, false); assert.equal(scope.applicable, true);
    }
    const facts = factsFor(program);
    assert.deepEqual(runtimeWidthFindings(facts, 200000, 0), []);
    assert.deepEqual(facts.diagnostics.map(item => item.scope?.entry).sort(), program.entries.slice().sort());
  });
});

test("one incomplete or exhausted entry preserves independent complete findings", () => {
  withFiles({ "main.compact": `import CompactStandardLibrary;
export circuit unavailable(): [] { ${output(oversized)} }
export circuit complete(): [] { ${output(oversized)} }
` }, directory => {
    const program = new Program(resolve(directory, "main.compact")); qualified(program.root);
    const original = factsFor(program), bad = program.entries.find(id => program.symbols.get(id)?.name === "unavailable")!;
    const incomplete: AnalysisFacts = { ...original, diagnostics: [], completedEntries: original.completedEntries.filter(entry => entry !== bad) };
    assert.deepEqual(rule.run(incomplete).map(item => item.metadata.entry), ["complete"]);
    assert.equal(incomplete.diagnostics.length, 1); assert.equal(incomplete.diagnostics[0].scope?.entry, bad);
    const exhausted: AnalysisFacts = { ...original, diagnostics: [], paths: original.paths.map(path => path.entry === bad
      ? { ...path, operations: Array.from({ length: 30 }, () => path.operations![0]) } : path) };
    assert.deepEqual(runtimeWidthFindings(exhausted, 10).map(item => item.metadata.entry), ["complete"]);
    assert.equal(exhausted.diagnostics.length, 1); assert.equal(exhausted.diagnostics[0].scope?.entry, bad);
  });
});

test("unsupported typed operand evidence and noncanonical observed sites fail per entry", () => {
  withFiles({ "main.compact": `import CompactStandardLibrary;
export circuit unavailable(): [] { ${output(oversized)} }
export circuit complete(): [] { ${output(oversized)} }
` }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const original = factsFor(program), bad = program.entries.find(id => program.symbols.get(id)?.name === "unavailable")!;
    const changes: Array<(operation: RuntimeOperation) => RuntimeOperation> = [
      operation => ({ ...operation, location: { ...operation.location, start: operation.location.start + 1 } }),
      operation => ({ ...operation, args: [] }),
      ...[{ type: "Field" }, { type: "Uint<64>" }, { constantKind: "boolean" as const }, { constant: "1e20" }, { constant: "-1" }, { constant: String(1n << 128n) }].map(changed =>
        (operation: RuntimeOperation): RuntimeOperation => ({ ...operation, args: [{ ...operation.args[0],
          fields: { ...operation.args[0].fields, value: { ...operation.args[0].fields!.value, ...changed } } }, ...operation.args.slice(1)] })),
    ];
    for (const change of changes) {
      const facts: AnalysisFacts = { ...original, diagnostics: [], paths: original.paths.map(path => path.entry === bad
        ? { ...path, operations: path.operations!.map(operation => operation.kind === "native-witness" && operation.name === "createZswapOutput" ? change(operation) : operation) } : path) };
      assert.deepEqual(rule.run(facts).map(item => item.metadata.entry), ["complete"]);
      assert.equal(facts.diagnostics.length, 1); assert.equal(facts.diagnostics[0].scope?.entry, bad);
    }
  });
});
