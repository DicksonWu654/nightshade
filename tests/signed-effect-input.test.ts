import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile } from "../src/index.js";
import { signedEffectInput as rule } from "../src/detectors/signed-effect-input.js";
import { enforcedSignatureResults } from "../src/dataflow/signed-effect-input.js";
import type { AbstractValue, SuccessfulPath } from "../src/dataflow/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";
const header = `import CompactStandardLibrary; export ledger selected: Field;
circuit verify(msg: Vector<1, Field>, sig: JubjubSchnorrSignature, pk: JubjubPoint): Boolean { return jubjubSchnorrVerify<1>(msg, sig, pk); }
`;
function fixture(body: string, expected: string[]) {
  withFiles({ "main.compact": header + body }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) { const validation = validateWithCompiler(process.env.COMPACTC_TEST, file); assert.equal(validation.valid, true, validation.error); }
    const program = new Program(file);
    let baseline: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached,
        "equivalent-states", false, false, "all", false, false, false, false, true).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      const findings = rule.run(facts);
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual([...new Set(findings.map(item => item.metadata.entry))].sort(), expected.sort());
      assert.ok(findings.every(item => item.metadata.reviewRequired && item.severity === "low"));
      baseline ??= findings; assert.deepEqual(findings, baseline);
    }
    for (const experimentalCounterQueries of [false, true]) {
      const scan = scanFile(file, { detectors: [rule.id], experimentalCounterQueries });
      assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics));
      assert.deepEqual([...new Set(scan.findings.map(item => item.metadata.entry))].sort(), expected.slice().sort());
    }
  });
}
test("signed effect input positive, fixed and independent-effect lookalike", () => fixture(`
export circuit positive(msg: Field, input: Field, sig: JubjubSchnorrSignature, pk: JubjubPoint): [] {
  assert(verify([msg], sig, pk), "signature"); selected = disclose(input);
}
export circuit fixed(input: Field, sig: JubjubSchnorrSignature, pk: JubjubPoint): [] {
  assert(verify([input], sig, pk), "signature"); selected = disclose(input);
}
export circuit lookalike(msg: Field, sig: JubjubSchnorrSignature, pk: JubjubPoint): [] {
  assert(verify([msg], sig, pk), "signature"); selected = 7 as Field;
}
export circuit equalInput(msg: Field, input: Field, sig: JubjubSchnorrSignature, pk: JubjubPoint): [] {
  assert(verify([msg], sig, pk), "signature"); assert(input == msg, "bound input"); selected = disclose(input);
}
`, ["positive"]));
test("only exact enforced outcome on original successful later-effect history", () => fixture(`
export circuit alias(msg: Field, input: Field, sig: JubjubSchnorrSignature, pk: JubjubPoint): [] {
  const outcome = verify([msg], sig, pk); const alias = outcome;
  assert(alias == true, "signature"); selected = disclose(input);
}
export circuit optional(msg: Field, input: Field, sig: JubjubSchnorrSignature, pk: JubjubPoint): [] {
  const outcome = verify([msg], sig, pk); selected = disclose(input);
}
export circuit falseResult(msg: Field, input: Field, sig: JubjubSchnorrSignature, pk: JubjubPoint): Boolean {
  assert(verify([msg], sig, pk), "signature"); selected = disclose(input); return false;
}
export circuit aborted(msg: Field, input: Field, sig: JubjubSchnorrSignature, pk: JubjubPoint): [] {
  assert(verify([msg], sig, pk), "signature"); selected = disclose(input); assert(false, "disabled");
}
export circuit before(msg: Field, input: Field, sig: JubjubSchnorrSignature, pk: JubjubPoint): [] {
  selected = disclose(input); assert(verify([msg], sig, pk), "signature");
}
export circuit repeated(input: Field, msg: Field, sig: JubjubSchnorrSignature, pk: JubjubPoint): [] {
  const unused = verify([msg], sig, pk); assert(verify([input], sig, pk), "signature"); selected = disclose(input);
}
export circuit transitive(msg: Field, input: Field, sig: JubjubSchnorrSignature, pk: JubjubPoint, first: Boolean, second: Boolean): [] {
  const outcome = verify([msg], sig, pk);
  assert(outcome == first, "first alias"); assert(first == second, "second alias"); assert(second, "enforcement");
  selected = disclose(input);
}
`, ["alias", "falseResult", "transitive"]));
test("Boolean equality closure is transitive, bounded and does not equate provenance", () => {
  const bool = (identity: string): AbstractValue => ({ identity, type: "Boolean", flows: [], ledger: new Set() });
  const a = bool("a"), b = bool("b"), c = bool("c");
  const equality = (left: AbstractValue, right: AbstractValue): AbstractValue => ({ type: "Boolean", flows: [], ledger: new Set(), comparison: { operator: "==", left, right } });
  const truth: AbstractValue = { type: "Boolean", flows: [], ledger: new Set(), constantKind: "boolean", constant: "true" };
  const path: SuccessfulPath = { entry: "test", bindings: [], sinks: [], path: [], writes: [], predicates: [equality(a,b), equality(b,c), equality(c,truth)].map(value => ({value, truth:true, location: {file:"test",start:0,end:1,line:1,column:1,endLine:1,endColumn:2},callPath:[],callSites:[],writesBefore:0,operationsBefore:1})) };
  const result = enforcedSignatureResults(path, 0, 1000);
  assert.equal(result.complete, true); assert.deepEqual([...result.identities].sort(), ["a", "b", "c"]);
  assert.equal(enforcedSignatureResults(path, 0, 1).complete, false);
  const unrelated = bool("other"); unrelated.flows = a.flows;
  assert.ok(!result.identities.has(unrelated.identity!));
});
test("missing exact observers diagnoses rule-scoped incompleteness", () => {
  withFiles({ "main.compact": header + `export circuit entry(msg: Field, input: Field, sig: JubjubSchnorrSignature, pk: JubjubPoint): [] { assert(verify([msg],sig,pk),"signature"); selected=disclose(input); }` }, directory => {
    const facts = new Dataflow(new Program(resolve(directory,"main.compact"))).analyze();
    assert.deepEqual(rule.run(facts), []);
    assert.ok(facts.diagnostics.some(issue => issue.scope?.detectorId === rule.id));
  });
});

test("witness and aggregate leaf identities, constructor exclusion and custom verifier names", () => fixture(`
struct Pair { message: Field; input: Field; }
witness supplied(): Field;
module Checks { export circuit jubjubSchnorrVerify<#N>(msg: Vector<N, Field>, sig: JubjubSchnorrSignature, pk: JubjubPoint): Boolean { return true; } }
import Checks prefix App_;
constructor(msg: Field, input: Field, sig: JubjubSchnorrSignature, pk: JubjubPoint) {
  assert(verify([msg], sig, pk), "signature"); selected = disclose(input);
}
export circuit aggregate(pair: Pair, sig: JubjubSchnorrSignature, pk: JubjubPoint): [] {
  assert(verify([pair.message], sig, pk), "signature"); selected = disclose(pair.input);
}
export circuit aggregateFixed(pair: Pair, sig: JubjubSchnorrSignature, pk: JubjubPoint): [] {
  assert(verify([pair.input], sig, pk), "signature"); selected = disclose(pair.input);
}
export circuit witnessInput(msg: Field, sig: JubjubSchnorrSignature, pk: JubjubPoint): [] {
  assert(verify([msg], sig, pk), "signature"); selected = disclose(supplied());
}
export circuit namesake(msg: Field, input: Field, sig: JubjubSchnorrSignature, pk: JubjubPoint): [] {
  assert(App_jubjubSchnorrVerify<1>([msg], sig, pk), "application"); selected = disclose(input);
}
`, ["aggregate", "witnessInput"]));
