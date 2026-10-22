import assert from "node:assert/strict";
import { resolve } from "node:path";
import test from "node:test";
import { genericWitnessAbi } from "../src/semantic/generic-witness-abi.js";
import { Program } from "../src/semantic/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

function qualified(file: string): void {
  if (process.env.COMPACTC_TEST) {
    const result = validateWithCompiler(process.env.COMPACTC_TEST, file, [], 30000, 2, "0.34.0");
    assert.equal(result.valid, true, result.error);
  }
}

function withProgram(source: string, check: (program: Program) => void): void {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact"); qualified(file);
    check(new Program(file));
  });
}

const declaration = "import CompactStandardLibrary; witness lookup<T>(key: Bytes<4>): Maybe<T>;";
const number = "export circuit number(key: Bytes<4>): Maybe<Uint<64>> { return disclose(lookup<Uint<64>>(key)); }";
const bytes = "export circuit bytes(key: Bytes<4>): Maybe<Bytes<32>> { return disclose(lookup<Bytes<32>>(key)); }";

test("owned compiler-valid fixtures expose only the incompatible shared witness ABI", () => {
  for (const variant of ["positive", "corrected", "lookalike"]) {
    const file = resolve(`tests/corpus/known-bugs/counter-generic-witness-${variant}.compact`);
    qualified(file);
    const program = new Program(file), result = genericWitnessAbi(program);
    assert.equal(result.complete, true);
    assert.equal(result.applicable, variant !== "corrected");
    assert.equal(result.conflicts.length, variant === "positive" ? 1 : 0);
    if (!result.conflicts.length) continue;
    const conflict = result.conflicts[0], origin = program.symbols.get(conflict.template)!;
    assert.equal(origin.kind, "witness"); assert.equal(origin.declaration?.generics, "<T>");
    assert.deepEqual(conflict.specializations.map(item => item.representation).sort(), ["bigint", "bytes"]);
    assert.deepEqual(conflict.entries.map(entry => program.symbols.get(entry)!.name).sort(), ["getBytes", "getNumber"]);
    for (const specialization of conflict.specializations) {
      assert.equal(program.symbols.get(specialization.symbol)!.specializationOrigin, conflict.template);
      assert.equal(specialization.sites.length, 1);
      assert.equal(specialization.sites[0].target, specialization.symbol);
      assert.equal(specialization.sites[0].caller, specialization.sites[0].entry);
      assert.equal(specialization.sites[0].kind, "call");
    }
    const selected = program.entries.find(entry => program.symbols.get(entry)?.name === "getNumber")!;
    assert.equal(genericWitnessAbi(program, 20000, [selected]).conflicts.length, 0);
  }
});

test("import and native type aliases preserve canonical witness identity and semantic parameters", () => withProgram(`
import { Maybe as Optional } from CompactStandardLibrary;
type Key = Bytes<4>;
module Library { export witness lookup<T>(key: Key): Optional<T>; }
import {lookup as choose} from Library;
import {lookup as other} from Library;
export circuit number(key: Key): Optional<Uint<64>> { return disclose(choose<Uint<64>>(key)); }
export circuit bytes(key: Bytes<4>): Optional<Bytes<32>> { return disclose(other<Bytes<32>>(key)); }
`, program => {
  const result = genericWitnessAbi(program);
  assert.equal(result.complete, true); assert.equal(result.conflicts.length, 1);
  const conflict = result.conflicts[0];
  assert.equal(program.symbols.get(conflict.template)!.name, "lookup");
  assert.equal(program.sameType(conflict.specializations[0].parameters[0], conflict.specializations[1].parameters[0]), true);
}));

test("equivalent module aliases share origins while distinct module instances stay separate", () => {
  for (const size of [1, 2]) withProgram(`
import CompactStandardLibrary;
module Library<#N> { export witness lookup<T>(key: Bytes<4>): Maybe<T>; }
import Library<1> prefix A_;
import Library<${size}> prefix B_;
export circuit number(key: Bytes<4>): Maybe<Uint<64>> { return disclose(A_lookup<Uint<64>>(key)); }
export circuit bytes(key: Bytes<4>): Maybe<Bytes<32>> { return disclose(B_lookup<Bytes<32>>(key)); }
`, program => {
  const witnesses = program.activeSymbols().filter(symbol => symbol.kind === "witness");
  assert.equal(witnesses.length, 2);
  assert.equal(witnesses[0].specializationOrigin === witnesses[1].specializationOrigin, size === 1);
  assert.deepEqual(witnesses[0].span, witnesses[1].span);
  const result = genericWitnessAbi(program);
  assert.equal(result.complete, true); assert.equal(result.applicable, true);
  assert.equal(result.conflicts.length, size === 1 ? 1 : 0);
  });
});

test("different semantic witness parameter signatures and user Maybe namesakes stay quiet", () => {
  withProgram(`import CompactStandardLibrary;
witness lookup<T>(key: T): Maybe<T>;
export circuit number(): Maybe<Uint<64>> { return disclose(lookup<Uint<64>>(0)); }
export circuit bytes(): Maybe<Bytes<32>> { return disclose(lookup<Bytes<32>>(default<Bytes<32>>)); }
`, program => {
    const result = genericWitnessAbi(program);
    assert.equal(result.complete, true); assert.equal(result.applicable, true); assert.deepEqual(result.conflicts, []);
  });
  withProgram(`struct Maybe<T> { is_some: Boolean, value: T }
witness lookup<T>(key: Bytes<4>): Maybe<T>;
${number}
${bytes}
`, program => {
    const result = genericWitnessAbi(program);
    assert.equal(result.complete, true); assert.equal(result.applicable, false); assert.deepEqual(result.conflicts, []);
  });
});

test("entry reachability follows resolved helpers and records their actual witness sites", () => withProgram(`
${declaration}
circuit helper<T>(key: Bytes<4>): Maybe<T> { return lookup<T>(key); }
export circuit entry(key: Bytes<4>): [] { disclose(helper<Uint<64>>(key)); disclose(helper<Bytes<32>>(key)); }
`, program => {
  const result = genericWitnessAbi(program);
  assert.equal(result.complete, true); assert.equal(result.conflicts.length, 1);
  const conflict = result.conflicts[0]; assert.deepEqual(conflict.entries, program.entries);
  for (const specialization of conflict.specializations) {
    assert.equal(specialization.sites[0].entry, program.entries[0]);
    assert.equal(program.symbols.get(specialization.sites[0].caller)!.name, "helper");
  }
}));

test("qualified dead branches and empty callbacks remain schema references without invocation claims", () => {
  for (const body of [
    "export circuit bytes(key: Bytes<4>): Maybe<Bytes<32>> { if (false) { lookup<Bytes<32>>(key); } return none<Bytes<32>>(); }",
    "export circuit bytes(): [] { map(lookup<Bytes<32>>, default<Vector<0, Bytes<4>>>); }",
    "export circuit bytes(): [] { map(lookup<Bytes<32>>, [default<Bytes<4>>]); }",
    "export circuit bytes(): [] { map((key: Bytes<4>): Maybe<Bytes<32>> => lookup<Bytes<32>>(key), default<Vector<0, Bytes<4>>>); }",
    "export circuit bytes(key: Bytes<4>): [] { for (const i of 0..0) { lookup<Bytes<32>>(key); } }",
  ]) withProgram(`${declaration}\n${number}\n${body}`, program => {
    const result = genericWitnessAbi(program);
    assert.equal(result.complete, true); assert.equal(result.conflicts.length, 1);
    const specialization = result.conflicts[0].specializations.find(item => item.representation === "bytes")!;
    assert.equal(specialization.sites[0].kind, body.includes("map(lookup") ? "callback" : "call");
  });
});

test("unqualified relevant representations and profiles are unavailable, never quiet absence", () => withProgram(`
${declaration}
${number}
${bytes}
export circuit flag(key: Bytes<4>): Maybe<Boolean> { return disclose(lookup<Boolean>(key)); }
`, program => {
  const result = genericWitnessAbi(program);
  assert.equal(result.complete, false); assert.equal(result.applicable, true);
  assert.ok(result.candidateEntries.includes(program.entries[0]));
  assert.deepEqual(result.conflicts, []);
  if (!result.complete) assert.match(result.reason, /unqualified host representation/);
}));

test("unsupported profiles and incomplete identity fail closed only for relevant generic Maybe witnesses", () => withProgram(`
${declaration}\n${number}\n${bytes}
`, program => {
  for (const [version, zkir] of [["0.31.1", 2], ["0.35.0", 2], ["0.34.0", 3]] as const) {
    const changed = new Program(program.root, [], program.sourceRoot, undefined, zkir, version);
    const result = genericWitnessAbi(changed);
    assert.equal(result.complete, false); assert.equal(result.applicable, true); assert.deepEqual(result.conflicts, []);
    assert.ok(result.candidateEntries.length > 0);
  }
  const witness = program.activeSymbols().find(symbol => symbol.kind === "witness")!;
  witness.specializationOrigin = "unresolved";
  assert.equal(genericWitnessAbi(program).complete, false);
}));

test("entry, call-site and type enumeration exhaustions withhold partial conflicts", () => withProgram(`
${declaration}\n${number}\n${bytes}
`, program => {
  const complete = genericWitnessAbi(program);
  assert.equal(complete.complete, true); assert.equal(complete.conflicts.length, 1);
  for (const allowance of [0, 1, 10, 100, complete.work - 1, -1, NaN, Infinity]) {
    const result = genericWitnessAbi(program, allowance);
    assert.equal(result.complete, false); assert.equal(result.applicable, true); assert.deepEqual(result.conflicts, []);
  }
  assert.equal(genericWitnessAbi(program, complete.work).complete, true);
  assert.equal(genericWitnessAbi(program, 20000, ["unresolved"]).complete, false);
}));
