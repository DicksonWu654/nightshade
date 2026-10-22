import test from "node:test";
import assert from "node:assert/strict";
import { analyze } from "./helpers.js";
import { detectors } from "../src/detectors/index.js";
import { ledgerEffect } from "../src/semantic/intrinsics.js";
import { FIELD_MODULUS, binaryConstant, castConstant } from "../src/dataflow/constants.js";

const prelude = `import CompactStandardLibrary;
struct Pair { first: Field; second: Field; }
export ledger digest: Bytes<32>;
export ledger published: Field;
witness pair(): Pair;
`;

for (const condition of ["!flag", "!!flag", "!!!flag"]) {
  test(`unknown ${condition} preserves both statement branches`, () => {
    analyze(`export circuit entry(flag: Boolean): Field { if (${condition}) { return 1 as Field; } else { return 2 as Field; } }`, facts => {
      assert.equal(facts.paths.length, 2);
      assert.deepEqual(facts.paths.flatMap(path => path.sinks.map(sink => sink.value.constant)).sort(), ["1", "2"]);
      assert.ok(facts.paths.every(path => path.sinks[0].value.flows.some(flow => flow.trace.some(step => step.kind === "implicit-flow"))));
    });
  });
  test(`unknown ${condition} preserves conditional branches`, () => {
    analyze(`export circuit entry(flag: Boolean): Field { return ${condition} ? 1 as Field : 2 as Field; }`, facts => assert.equal(facts.paths.length, 2));
  });
}

test("constant negation still prunes impossible branches", () => {
  analyze("export circuit entry(): Field { if (!!false) { return 1 as Field; } return 2 as Field; }", facts => assert.deepEqual(facts.paths.map(path => path.sinks[0].value.constant), ["2"]));
});

test("struct fields retain distinct witness identities", () => {
  analyze(`${prelude}export circuit entry(): [] { const value = pair(); assert(persistentHash<Field>(value.first) == digest, "binding"); published = disclose(value.second); }`, facts => assert.equal(detectors.flatMap(detector => detector.run(facts)).filter(finding => finding.detectorId === "ledger-bound-preimage-publication").length, 0));
});

test("publishing one field of a jointly hashed private struct is not a full-preimage claim", () => {
  analyze(`${prelude}export circuit entry(): [] { const value = pair(); assert(persistentHash<Pair>(value) == digest, "binding"); published = disclose(value.first); }`, facts => assert.equal(detectors.flatMap(detector => detector.run(facts)).filter(finding => finding.detectorId === "ledger-bound-preimage-publication").length, 0));
});

test("struct destructuring preserves the selected identity", () => {
  analyze(`${prelude}circuit pass(value: Pair): Field { const { first: result } = value; return result; }
export circuit entry(): [] { const value = pair(); assert(persistentHash<Field>(value.first) == digest, "binding"); published = disclose(pass(value)); }`, facts => assert.equal(detectors.flatMap(detector => detector.run(facts)).filter(finding => finding.detectorId === "ledger-bound-preimage-publication").length, 1));
});

test("struct updates replace rather than merge the overwritten field", () => {
  analyze(`${prelude}export circuit entry(): [] { const value = pair(); assert(persistentHash<Field>(value.first) == digest, "binding"); const clean = Pair { ...value, first: 0 as Field }; published = disclose(clean.first); }`, facts => assert.equal(facts.paths[0].sinks.find(sink => sink.kind === "ledger-write")!.value.flows.length, 0));
});

test("Maybe inactive default does not inherit input provenance", () => {
  analyze("import CompactStandardLibrary; export circuit entry(secret: Field): Field { const value = right<Field, Field>(secret); return value.left; }", facts => assert.equal(facts.paths[0].sinks[0].value.flows.length, 0));
});

test("Maybe active field retains raw identity", () => {
  analyze("import CompactStandardLibrary; export circuit entry(secret: Field): Field { return some<Field>(secret).value; }", facts => assert.equal(facts.paths[0].sinks[0].value.flows[0].form, "raw"));
});

test("multiple bindings and tuple spreads keep field isolation", () => {
  analyze("export circuit entry(secret: Field): Field { const first = [secret, 0 as Field], second = [...first, 1]; const [ignored, clean] = second; return clean; }", facts => assert.equal(facts.paths[0].sinks[0].value.flows.length, 0));
});

test("sequence witness is evaluated once for a loop", () => {
  analyze("witness values(): Vector<2, Field>; export ledger published: Field; export circuit entry(): [] { for (const value of values()) { published = disclose(value); } }", facts => {
    const writes = facts.paths[0].sinks.filter(sink => sink.kind === "ledger-write");
    assert.equal(writes.length, 2);
    assert.equal(writes[0].value.flows[0].source.id.split(":").at(-1), "0");
    assert.equal(writes[1].value.flows[0].source.id.split(":").at(-1), "1");
  });
});

test("map calls preserve provenance and anonymous captures", () => {
  analyze("export circuit entry(secret: Field): Field { const result = map((value: Field): Field => secret, [1 as Field, 2 as Field]); return result[0]; }", facts => assert.equal(facts.paths[0].sinks[0].value.flows[0].source.name, "secret"));
});

test("fold threads the accumulator through the circuit", () => {
  analyze("circuit add(total: Field, item: Field): Field { return total + item; } export circuit entry(): Field { return fold(add, 0 as Field, [1 as Field, 2 as Field, 3 as Field]); }", facts => assert.equal(facts.paths[0].sinks[0].value.constant, "6"));
});

test("short-circuit RHS effects carry implicit provenance", () => {
  analyze("export ledger published: Field; circuit mutate(): Boolean { published = 1 as Field; return true; } export circuit entry(flag: Boolean): Boolean { return flag && mutate(); }", facts => {
    const write = facts.paths.flatMap(path => path.sinks).find(sink => sink.kind === "ledger-write")!;
    assert.equal(write.value.flows[0].source.name, "flag");
    assert.ok(write.value.flows[0].trace.some(step => step.kind === "implicit-flow"));
    assert.ok(facts.paths.every(path => path.sinks.filter(sink => sink.kind === "exported-return").every(sink => sink.value.flows.every(flow => flow.form === "derived"))));
  });
});

test("constant normalization compares values rather than source spellings", () => {
  analyze('export circuit entry(): Boolean { return 0x01 == 1 && pad(2, "a") == pad(2, "a"); }', facts => assert.equal(facts.paths[0].sinks[0].value.constant, "true"));
});

test("Field operations use the official modulus; narrowing casts can abort", () => {
  assert.deepEqual(binaryConstant("+", { kind: "integer", value: String(FIELD_MODULUS - 1n) }, { kind: "integer", value: "1" }, "Field"), { kind: "integer", value: "0" });
  assert.equal(castConstant({ kind: "integer", value: "256" }, "Uint<8>"), null);
});

test("ledger query keys are public sinks even without writes", () => {
  analyze("import CompactStandardLibrary; export ledger table: Map<Field, Field>; export circuit entry(key: Field): [] { table.member(disclose(key)); }", facts => {
    const sink = facts.paths[0].sinks.find(sink => sink.kind === "ledger-operation")!;
    assert.equal(sink.value.flows[0].source.name, "key");
  });
});

test("constant Map writes remain isolated by key", () => {
  analyze("import CompactStandardLibrary; export ledger table: Map<Field, Field>; export circuit entry(secret: Field): Field { table.insert(1 as Field, disclose(secret)); table.insert(2 as Field, 0 as Field); return table.lookup(2 as Field); }", facts => assert.equal(facts.paths[0].sinks.find(sink => sink.kind === "exported-return")!.value.flows.length, 0));
});

test("List catalogue follows the official ADT return signatures", () => {
  assert.equal(ledgerEffect("List<Field>", "head")?.result, "Maybe<Field>");
  assert.equal(ledgerEffect("List<Field>", "popFront")?.result, "[]");
});
