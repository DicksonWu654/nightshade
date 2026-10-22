import test from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";
import { analyze, withFiles } from "./helpers.js";
import { scanFile } from "../src/index.js";
import { compatible, substituteType } from "../src/semantic/types.js";

test("overload selection respects argument kinds", () => {
  analyze("circuit select(value: Boolean): Field { return 0 as Field; } circuit select(value: Field): Field { return value; } export circuit entry(secret: Field): Field { return select(secret); }", facts => {
    assert.equal(facts.paths[0].sinks[0].value.flows[0].source.name, "secret");
    assert.equal([...facts.program.functions.values()].filter(fn => fn.symbol.name === "select").length, 2);
  });
});

test("overloads do not choose a narrower signature when both are compatible", () => {
  withFiles({ "main.compact": "circuit select(value: Uint<8>): Uint<8> { return value; } circuit select(value: Uint<16>): Uint<16> { return value; } export circuit entry(): Uint<16> { return select(1); }" }, directory => assert.equal(scanFile(resolve(directory, "main.compact")).diagnostics[0].code, "overload-resolution"));
});

test("generic argument kinds distinguish overloads", () => {
  analyze("circuit select<T>(value: T): T { return value; } circuit select<#N>(value: Vector<N, Field>): Field { return value[0]; } export circuit entry(secret: Field): Field { return select<Field>(secret); }", facts => assert.equal(facts.paths[0].sinks[0].value.flows[0].source.name, "secret"));
});

test("selected prefixed imports preserve the entire overload group", () => {
  analyze("module M { export circuit select(value: Field): Field { return value; } export circuit select(value: Boolean): Field { return 0 as Field; } } import { select as pass } from M prefix M_; export circuit entry(secret: Field): Field { return M_pass(secret); }", facts => assert.equal(facts.paths[0].sinks[0].value.flows[0].source.name, "secret"));
});

test("generic higher-order targets are specialized before invocation", () => {
  analyze("circuit identity<T>(value: T): T { return value; } export circuit entry(secret: Field): Field { const result = map(identity<Field>, [secret]); return result[0]; }", facts => assert.equal(facts.paths[0].sinks[0].value.flows[0].form, "raw"));
});

test("anonymous map parameters and return types are inferred from the sequence", () => {
  analyze("export circuit entry(secret: Field): Field { const result = map((value) => value, [secret]); return result[0]; }", facts => {
    assert.equal(facts.paths[0].sinks[0].value.flows[0].source.name, "secret");
    assert.equal([...facts.program.functions.values()].find(fn => fn.symbol.name.startsWith("$lambda"))!.symbol.type, "Field");
  });
});

test("type substitution does not rewrite quoted opaque kinds or symbol paths", () => {
  const bindings = new Map([["T", "Field"], ["N", "4"]]);
  assert.equal(substituteType('Opaque<"T">', bindings), 'Opaque<"T">');
  assert.equal(substituteType("Vector<N,T>", bindings), "Vector<4,Field>");
  assert.equal(substituteType("/project/T/source.compact::Box", bindings), "/project/T/source.compact::Box");
  assert.equal(substituteType("Uint<0..N>", bindings), "Uint<0..4>");
  assert.equal(compatible("Uint<8>", "Field"), false);
});

test("filesystem import strings do not resolve to a same-named local module", () => {
  withFiles({ "main.compact": 'module Helper { export circuit answer(): Field { return 0 as Field; } } import "Helper"; export circuit entry(): Field { return answer(); }', "Helper.compact": "module Helper { export circuit answer(): Field { return 1 as Field; } }" }, directory => {
    const result = scanFile(resolve(directory, "main.compact"));
    assert.deepEqual(result.diagnostics, []);
    assert.equal(result.scanned.length, 2);
  });
});
