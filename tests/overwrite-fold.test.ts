import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { symlinkSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { Dataflow, Program, type AnalysisFacts } from "../src/index.js";
import { overwriteFoldPlan } from "../src/analysis/overwrite-fold.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { semanticPaths, withFiles } from "./helpers.js";

const callback = `pure circuit compareByte(acc: Boolean, left: Uint<8>, right: Uint<8>): Boolean {
  return left == right ? acc : left < right;
}`;
const returns = (facts: AnalysisFacts) => facts.paths.flatMap(path => path.sinks.filter(sink => sink.kind === "exported-return").map(sink => sink.value));
function withProgram(source: string, check: (program: Program) => void, zkirVersion: 2 | 3 = 2): void {
  withFiles({ "main.compact": `import CompactStandardLibrary;\n${source}` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const result = validateWithCompiler(process.env.COMPACTC_TEST, file, [], 30000, zkirVersion);
      assert.equal(result.valid, true, result.error);
    }
    check(new Program(file, [], directory, undefined, zkirVersion));
  });
}
function compare(program: Program, check: (facts: AnalysisFacts) => void): void {
  let expected: AnalysisFacts | undefined;
  for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
    const analysis = new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", true);
    const facts = analysis.analyze();
    assert.deepEqual(facts.diagnostics, []);
    assert.deepEqual(facts.completedEntries, program.entries);
    check(facts);
    if (expected) {
      assert.deepEqual(semanticPaths(facts), semanticPaths(expected));
      assert.deepEqual(facts.assertionReaches, expected.assertionReaches);
      assert.deepEqual(facts.callReaches, expected.callReaches);
    } else expected = facts;
    assert.deepEqual(analysis.analyze(), facts);
  }
}

for (const length of [0, 1, 2, 8, 9, 32]) test(`pure overwrite fold length ${length} completes at default budgets in all four modes`, () => {
  withProgram(`${callback}
export circuit entry(value: Vector<${length}, Uint<8>>, seed: Boolean): Boolean {
  return fold(compareByte, seed, value, default<Vector<${length}, Uint<8>>>);
}`, program => compare(program, facts => {
    assert.equal(facts.paths.length, length + 1);
    assert.equal(facts.callReaches!.some(reach => program.symbols.get(reach.callee)!.name === "compareByte"), length > 0);
    assert.ok(facts.callReaches!.every(reach => reach.maySucceed && !reach.failedWithoutAssertion));
    assert.ok(returns(facts).some(value => value.flows.some(flow => flow.source.name === "seed")));
  }));
});

test("suffix partition agrees with ordinary interpretation after caller restrictions at every small boundary", () => {
  const entries: string[] = [];
  const expected = new Map<string, string>();
  for (const seed of [false, true]) for (const left of [0, 127, 255]) for (const right of [0, 127, 255]) {
    const name = `case_${seed}_${left}_${right}`;
    entries.push(`export circuit ${name}(value: Vector<2, Uint<8>>): Boolean {
      const result = fold(compareByte, ${seed}, value, [127 as Uint<8>, 127 as Uint<8>]);
      assert(value[0] == ${left}, "lower"); assert(value[1] == ${right}, "higher");
      return result;
    }`);
    expected.set(name, String(right === 127 ? left === 127 ? seed : left < 127 : right < 127));
  }
  withProgram(`${callback}\n${entries.join("\n")}`, program => {
    const observed = (facts: AnalysisFacts) => facts.paths.map(path => [program.symbols.get(path.entry)!.name,
      path.sinks.find(sink => sink.kind === "exported-return")!.value.constant]).sort();
    const ordinary = new Dataflow(program, 40000, 256, 50000, "expressions", false, false, "equivalent-states", false, false).analyze();
    assert.deepEqual(ordinary.diagnostics, []);
    assert.deepEqual(observed(ordinary), [...expected].sort());
    compare(program, facts => assert.deepEqual(observed(facts), observed(ordinary)));
  });
});

test("aliased fold elements retain caller exclusions and reject impossible suffix cases", () => {
  withProgram(`${callback}
export circuit entry(value: Uint<8>): Boolean {
  assert(value != 127, "not equal");
  const result = fold(compareByte, false, [value, value], [127 as Uint<8>, 127 as Uint<8>]);
  assert(value == 0, "lower"); return result;
}`, program => compare(program, facts => {
    assert.equal(facts.paths.length, 1);
    assert.equal(returns(facts)[0].constant, "true");
  }));
});

for (const repeated of [false, true]) test(`saved and repeated fold predicates cannot contradict (${repeated})`, () => {
  withProgram(`${callback}
pure circuit predicate(value: Vector<2, Uint<8>>): Boolean { return fold(compareByte, true, value, [127 as Uint<8>, 127 as Uint<8>]); }
export circuit entry(value: Vector<2, Uint<8>>): Boolean {
  const first = predicate(value); assert(first == true, "accepted");
  assert(!${repeated ? "predicate(value)" : "first"}, "contradiction"); return true;
}`, program => compare(program, facts => {
    assert.equal(facts.paths.length, 0);
    assert.ok(facts.failedAssertions.some(failure => failure.message === '"contradiction"'));
  }));
});

test("partitioned fold preserves seed/suffix provenance and real histories around argument evaluation", () => {
  withProgram(`${callback}
export ledger stored: Vector<2, Uint<8>>;
export ledger output: Boolean;
circuit authorize(): [] { assert(true, "guard"); }
circuit argument(value: Vector<2, Uint<8>>): Vector<2, Uint<8>> { emit(Unpaused {}); return value; }
export circuit entry(seed: Boolean, low: Uint<8>, high: Uint<8>, control: Boolean): Boolean {
  authorize(); stored = disclose([low, high]);
  if (disclose(control)) {
    const snapshot = stored;
    const result = fold(compareByte, seed, argument(snapshot), [127 as Uint<8>, 127 as Uint<8>]);
    stored = [0 as Uint<8>, 0 as Uint<8>];
    output = disclose(result); emit(Paused {}); return result;
  }
  return false;
}`, program => compare(program, facts => {
    const paths = facts.paths.filter(path => path.operations?.length);
    assert.equal(paths.length, 3);
    const guard = [...program.functions.values()].find(fn => fn.symbol.name === "authorize")!.symbol.id;
    for (const path of paths) {
      assert.deepEqual(path.operations!.map(operation => operation.name), ["Unpaused", "Paused"]);
      assert.ok(path.writes.every(write => write.guards.includes(guard)));
      assert.deepEqual(path.writes.map(write => program.symbols.get(write.ledger)!.name), ["stored", "stored", "output"]);
      const result = path.sinks.find(sink => sink.kind === "exported-return")!.value;
      assert.ok(result.flows.some(flow => flow.source.name === "control"));
      assert.ok(result.flows.some(flow => flow.source.name === "high"));
      assert.ok(path.sinks.find(sink => sink.kind === "ledger-write" && sink.name === "output")!.value.flows.some(flow => flow.source.name === "high"));
    }
    assert.ok(paths.some(path => path.sinks.at(-1)!.value.flows.some(flow => flow.source.name === "seed")));
  }));
});

test("ordered predicates retain operand order and detect later conflicting constants", () => {
  withProgram(`export circuit reversed(left: Uint<8>, right: Uint<8>): Boolean {
    assert(left < right, "ascending"); assert(right < left, "descending");
    assert(left == 0, "left"); assert(right == 255, "right"); return true;
  }
  export circuit valid(left: Uint<8>, right: Uint<8>): Boolean {
    assert(left < right, "ascending"); assert(!(right < left), "descending");
    assert(left == 0, "left"); assert(right == 255, "right"); return true;
  }`, program => compare(program, facts => {
    assert.deepEqual(facts.paths.map(path => program.symbols.get(path.entry)!.name), ["valid"]);
  }));
});

for (const body of ["return left == right ? acc : (acc && left < right);", "assert(left != 0, \"checked\"); return left == right ? acc : left < right;", "return left == right ? left < right : acc;"]) test(`ineligible callback retains ordinary interpretation: ${body}`, () => {
  withProgram(`pure circuit compareByte(acc: Boolean, left: Uint<8>, right: Uint<8>): Boolean { ${body} }
export circuit entry(value: Vector<2, Uint<8>>): Boolean { return fold(compareByte, true, value, [127 as Uint<8>, 127 as Uint<8>]); }`, program => {
    const fn = [...program.functions.values()].find(fn => fn.symbol.name === "compareByte")!;
    assert.equal(overwriteFoldPlan(fn), undefined);
    const ordinary = new Dataflow(program, 40000, 256, 50000, "instructions", false, false, "equivalent-states", false, false).analyze();
    assert.deepEqual(semanticPaths(new Dataflow(program).analyze()), semanticPaths(ordinary));
  });
});

test("partition work, alternatives and values remain explicitly budgeted", () => {
  withProgram(`${callback}
export circuit entry(value: Vector<32, Uint<8>>): Boolean { return fold(compareByte, true, value, default<Vector<32, Uint<8>>>); }`, program => {
    for (const [steps, paths, values] of [[100, 256, 50000], [40000, 1, 50000], [40000, 256, 40]]) {
      const facts = new Dataflow(program, steps, paths, values).analyze();
      assert.equal(facts.completedEntries.length, 0);
      assert.ok(facts.diagnostics.some(diagnostic => /budget/.test(diagnostic.code)));
    }
  });
});

test("anonymous derived fold operands use ordinary interpretation without overlapping partitions", () => {
  withProgram(`${callback}
export circuit entry(value: Uint<7>): Boolean { return fold(compareByte, true, [(value + 1) as Uint<8>], [127 as Uint<8>]); }`, program => {
    const ordinary = new Dataflow(program, 40000, 2, 50000, "instructions", false, false, "equivalent-states", false, false).analyze();
    const actual = new Dataflow(program, 40000, 2).analyze();
    assert.deepEqual(actual.diagnostics, []);
    assert.equal(actual.paths.length, 2);
    assert.deepEqual(semanticPaths(actual), semanticPaths(ordinary));
  });
});

test("old fold snapshots remain constrained while a later ledger value is independent", () => {
  withProgram(`${callback}
export ledger bytes: Vector<2, Uint<8>>;
export circuit entry(replacement: Vector<2, Uint<8>>): Boolean {
  const old = bytes;
  assert(fold(compareByte, true, old, [127 as Uint<8>, 127 as Uint<8>]), "old accepted");
  bytes = disclose(replacement);
  assert(!fold(compareByte, true, bytes, [127 as Uint<8>, 127 as Uint<8>]), "new rejected");
  return fold(compareByte, true, old, [127 as Uint<8>, 127 as Uint<8>]);
}`, program => compare(program, facts => {
    assert.ok(facts.paths.length > 0);
    assert.ok(returns(facts).every(value => value.constant === "true"));
  }));
});

test("all admitted ordered comparison shapes agree with the ordinary oracle", () => {
  const shapes = ["left < right", "left <= right", "left > right", "left >= right", "right < left", "left < left"];
  const declarations = shapes.map((shape, index) => `pure circuit cmp${index}(acc: Boolean, left: Uint<8>, right: Uint<8>): Boolean {
    return right == left ? acc : ${shape};
  }
  export circuit entry${index}(left: Vector<2, Uint<8>>, right: Vector<2, Uint<8>>): Boolean {
    const result = fold(cmp${index}, false, left, right);
    assert(left == [0 as Uint<8>, 255 as Uint<8>], "left");
    assert(right == [255 as Uint<8>, 127 as Uint<8>], "right"); return result;
  }`).join("\n");
  withProgram(declarations, program => {
    const ordinary = new Dataflow(program, 40000, 256, 50000, "expressions", false, false, "equivalent-states", false, false).analyze();
    assert.deepEqual(ordinary.diagnostics, []);
    assert.deepEqual(returns(ordinary).map(value => value.constant), ["false", "false", "true", "true", "true", "false"]);
    const observed = (facts: AnalysisFacts) => facts.paths.map(path => [path.entry, path.sinks.at(-1)!.value.constant]).sort();
    compare(program, facts => assert.deepEqual(observed(facts), observed(ordinary)));
  });
});

test("prefix elision preserves ordinary private dependencies and observable effect histories", () => {
  withProgram(`${callback}
export ledger output: Boolean;
circuit authorize(): [] { assert(true, "guard"); }
export circuit entry(seed: Boolean, low: Uint<8>, high: Uint<8>): Boolean {
  authorize(); emit(Unpaused {});
  const result = fold(compareByte, seed, [low, high], [127 as Uint<8>, 127 as Uint<8>]);
  assert(high == 0, "higher byte overrides lower");
  output = disclose(result); if (disclose(result)) { emit(Paused {}); } return result;
}`, program => {
    const ordinary = new Dataflow(program, 40000, 256, 50000, "expressions", false, false, "equivalent-states", false, false).analyze();
    const value = (item: { flows: { source: { name: string }; form: string }[]; constant?: string }) => ({
      constant: item.constant, flows: item.flows.map(flow => [flow.source.name, flow.form]).sort() });
    const observed = (facts: AnalysisFacts) => [...new Set(facts.paths.map(path => JSON.stringify({
      sinks: path.sinks.map(sink => [sink.kind, value(sink.value)]),
      writes: path.writes.map(write => [write.ledger, value(write.before), value(write.after), [...write.guards].sort()]),
      operations: path.operations!.map(operation => [operation.name, [...operation.guards].sort(), operation.control.map(value)]),
    })))].sort();
    assert.deepEqual(ordinary.diagnostics, []);
    compare(program, facts => assert.deepEqual(observed(facts), observed(ordinary)));
  });
});

test("ordered predicate retention exhaustion is explicitly incomplete", () => {
  withProgram(`export circuit entry(value: Uint<16>): [] {
    ${Array.from({ length: 257 }, (_, index) => `assert(value < ${index + 1}, "bound");`).join("\n")}
  }`, program => {
    for (const engine of ["instructions", "expressions"] as const) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine).analyze();
      assert.equal(facts.completedEntries.length, 0);
      assert.ok(facts.diagnostics.some(diagnostic => diagnostic.code === "constraint-budget" && /Ordered/.test(diagnostic.message)));
    }
  });
});

test("pure-fold retained snapshot capacity is explicitly bounded", () => {
  withProgram(`${callback}
export circuit entry(${Array.from({ length: 5 }, (_, index) => `v${index}: Vector<256, Uint<8>>`).join(", ")}): [] {
  ${Array.from({ length: 5 }, (_, index) => `assert(v${index} == default<Vector<256, Uint<8>>>, "zero"); fold(compareByte, true, v${index}, default<Vector<256, Uint<8>>>);`).join("\n")}
}`, program => {
    const facts = new Dataflow(program, 200000).analyze();
    assert.equal(facts.completedEntries.length, 0);
    assert.ok(facts.diagnostics.some(diagnostic => diagnostic.code === "constraint-budget" && /snapshot/.test(diagnostic.message)), JSON.stringify(facts.diagnostics));
  });
});

test("partitioned calls obey callback depth and surrounding path allowances", () => {
  const chain = Array.from({ length: 32 }, (_, index) => `pure circuit f${index}(value: Uint<8>): Boolean {
    return ${index === 31 ? "fold(compareByte, true, [value], [127 as Uint<8>])" : `f${index + 1}(value)`};
  }`).join("\n");
  withProgram(`${callback}\n${chain}\nexport circuit entry(value: Uint<8>): Boolean { return f0(value); }`, program => {
    const facts = new Dataflow(program).analyze();
    assert.equal(facts.completedEntries.length, 0);
    assert.ok(facts.diagnostics.some(diagnostic => diagnostic.code === "call-depth"));
  });
  withProgram(`${callback}\nexport ledger marker: Boolean;
export circuit entry(flag: Boolean, value: Vector<2, Uint<8>>): Boolean {
  if (disclose(flag)) { marker = true; } else { marker = false; }
  return fold(compareByte, true, value, [127 as Uint<8>, 127 as Uint<8>]);
}`, program => {
    const facts = new Dataflow(program, 40000, 5).analyze();
    assert.equal(facts.completedEntries.length, 0);
    assert.ok(facts.diagnostics.some(diagnostic => diagnostic.code === "analysis-budget"));
    assert.deepEqual(new Dataflow(program, 40000, 6).analyze().diagnostics, []);
  });
});

test("pinned OZ Ecdsa compiler/runtime agrees at scalar half-order boundaries", {
  skip: !process.env.COMPACT_RUNTIME_TEST || !process.env.OZ_COMPACT_TEST ? "Requires pinned runtime and OZ sources" : false,
}, () => {
  assert.ok(process.env.COMPACTC_TEST);
  const source = resolve(process.env.OZ_COMPACT_TEST!, "contracts/src/crypto/test/mocks/MockEcdsa.compact");
  withFiles({}, directory => {
    const compiled = spawnSync(process.env.COMPACTC_TEST!, ["--skip-zk", "--feature-zkir-v3", source, resolve(directory, "compiled")], { encoding: "utf8", timeout: 30000 });
    assert.equal(compiled.status, 0, compiled.stderr);
    symlinkSync(resolve(process.env.COMPACT_RUNTIME_TEST!, "node_modules"), resolve(directory, "node_modules"), "dir");
    writeFileSync(resolve(directory, "run.mjs"), `import assert from 'node:assert/strict';
import * as runtime from '@midnight-ntwrk/compact-runtime';
import {Contract} from './compiled/contract/index.js';
const contract = new Contract({});
const initial = await contract.initialState(runtime.createConstructorContext({},'0'.repeat(64)));
const context = name => runtime.createCircuitContext(name,runtime.dummyContractAddress(),'0'.repeat(64),initial.currentContractState,{});
const order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
for (const s of [0n, order/2n-1n, order/2n, order/2n+1n, order-1n]) {
  const expected = s <= order/2n;
  assert.equal((await contract.circuits.isLowS(context('isLowS'),s)).result, expected);
  if (expected) await contract.circuits.assertLowS(context('assertLowS'),{r:1n,s});
  else await assert.rejects(contract.circuits.assertLowS(context('assertLowS'),{r:1n,s}), /high-s signature/);
}
`);
    const run = spawnSync(process.execPath, [resolve(directory, "run.mjs")], { encoding: "utf8", timeout: 30000 });
    assert.equal(run.status, 0, run.stderr);
  });
});

const order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const bytesOf = (value: bigint) => `[${Array.from({ length: 32 }, (_, index) => `${value >> BigInt(8 * index) & 255n} as Uint<8>`).join(",")} ]`;
const scalarFold = `${callback}
pure circuit low(value: Secp256k1Scalar): Boolean {
  const bytes = (value as Bytes<32>) as Vector<32, Uint<8>>;
  return fold(compareByte, true, bytes, ${bytesOf(order / 2n)});
}`;

test("native scalar byte comparisons compose without enumerating byte alternatives", () => {
  withProgram(`${scalarFold}
export circuit entry(first: Secp256k1Scalar, second: Secp256k1Scalar): Boolean {
  assert(low(first), "first accepted"); assert(low(second), "second accepted");
  return low(first) && low(second);
}`, program => compare(program, facts => {
    assert.equal(facts.paths.length, 1);
    assert.equal(returns(facts)[0].constant, "true");
    assert.ok(facts.paths[0].path.some(step => step.kind === "summary"));
    const callbacks = facts.callReaches!.filter(reach => program.symbols.get(reach.callee)!.name === "compareByte");
    assert.equal(callbacks.length, 1);
    assert.ok(callbacks.every(reach => reach.maySucceed && !reach.failedWithoutAssertion));
  }), 3);
});

test("scalar comparison folding agrees with ordinary interpretation at exact native boundaries", () => {
  const inputs = [0n, order / 2n - 1n, order / 2n, order / 2n + 1n, order - 1n];
  withProgram(`${scalarFold}\n${inputs.map((value, index) => `export circuit case${index}(): Boolean { return low((${bytesOf(value)} as Bytes<32>) as Secp256k1Scalar); }`).join("\n")}`, program => {
    const ordinary = new Dataflow(program, 40000, 256, 50000, "expressions", false, false, "equivalent-states", false, false).analyze();
    assert.deepEqual(ordinary.diagnostics, []);
    const expected = ["true", "true", "true", "false", "false"];
    assert.deepEqual(returns(ordinary).map(value => value.constant), expected);
    compare(program, facts => assert.deepEqual(returns(facts).map(value => value.constant), expected));
  }, 3);
});

test("scalar-fold assertions retain the underlying scalar relationship after caller constants", () => {
  withProgram(`${scalarFold}
export circuit entry(value: Secp256k1Scalar): Boolean {
  const saved = low(value); assert(saved, "low");
  assert(value == ((${bytesOf(order - 1n)} as Bytes<32>) as Secp256k1Scalar), "high scalar");
  return saved;
}`, program => compare(program, facts => {
    assert.equal(facts.paths.length, 0);
    assert.ok(facts.failedAssertions.some(failure => failure.message === '"high scalar"'));
  }), 3);
});

test("native byte views retain old snapshot constraints and discard changed sequence encodings", () => {
  withProgram(`${scalarFold}
export ledger stored: Vector<32, Uint<8>>;
export circuit entry(value: Secp256k1Scalar): Boolean {
  stored = disclose((value as Bytes<32>) as Vector<32, Uint<8>>);
  const old = stored;
  assert(fold(compareByte, true, old, ${bytesOf(order / 2n)}), "old low");
  stored = map((item) => 255 as Uint<8>, old);
  assert(!fold(compareByte, true, stored, ${bytesOf(order / 2n)}), "new high");
  return fold(compareByte, true, old, ${bytesOf(order / 2n)});
}`, program => compare(program, facts => {
    assert.equal(facts.paths.length, 1);
    assert.equal(returns(facts)[0].constant, "true");
    assert.equal(facts.paths[0].writes.length, 2);
  }), 3);
});

test("native scalar folding preserves caller guards, private disclosure and argument effects", () => {
  withProgram(`${scalarFold}
circuit authorize(): [] { assert(true, "allowed"); }
circuit input(value: Secp256k1Scalar): Secp256k1Scalar { emit(Unpaused {}); return value; }
export ledger published: Boolean;
export circuit entry(value: Secp256k1Scalar, flag: Boolean): Boolean {
  authorize(); const result = low(input(value));
  if (disclose(flag)) { published = disclose(result); }
  if (disclose(result)) { emit(Paused {}); } return result;
}`, program => compare(program, facts => {
    const guard = [...program.functions.values()].find(fn => fn.symbol.name === "authorize")!.symbol.id;
    assert.equal(facts.paths.length, 4);
    for (const path of facts.paths) {
      assert.equal(path.operations![0].name, "Unpaused");
      assert.ok(path.operations!.every(operation => operation.guards.includes(guard)));
      assert.ok(path.sinks.at(-1)!.value.flows.some(flow => flow.source.name === "value"));
      for (const sink of path.sinks.filter(sink => sink.kind === "ledger-write" || sink.kind === "event" && sink.name === "Paused"))
        assert.ok(sink.value.flows.some(flow => flow.source.name === "value"));
    }
  }), 3);
});

test("noncanonical scalar fold comparison and private seed retain suffix interpretation", () => {
  for (const [replacement, seed, parameter] of [["right < left", "true", ""], ["left < right", "seed", ", seed: Boolean"]]) {
    withProgram(`${callback.replace("left < right", replacement)}
export circuit entry(value: Secp256k1Scalar${parameter}): Boolean {
  return fold(compareByte, ${seed}, (value as Bytes<32>) as Vector<32, Uint<8>>, ${bytesOf(order / 2n)});
}`, program => compare(program, facts => {
      assert.equal(facts.paths.length, 33);
      assert.ok(facts.paths.every(path => path.path.every(step => step.kind !== "summary")));
    }), 3);
  }
});

test("native scalar-fold transfer obeys callback depth, step and value limits", () => {
  const wrappers = Array.from({ length: 30 }, (_, index) => `pure circuit f${index}(value: Secp256k1Scalar): Boolean { return ${index === 29 ? "low" : `f${index + 1}`}(value); }`).join("\n");
  withProgram(`${scalarFold}\n${wrappers}\nexport circuit entry(value: Secp256k1Scalar): Boolean { return f0(value); }`, program => {
    const facts = new Dataflow(program).analyze();
    assert.equal(facts.completedEntries.length, 0);
    assert.ok(facts.diagnostics.some(diagnostic => diagnostic.code === "call-depth"));
  }, 3);
  withProgram(`${scalarFold}\nexport circuit entry(value: Secp256k1Scalar): Boolean { return low(value); }`, program => {
    for (const [steps, values] of [[100, 50000], [40000, 2]]) {
      const facts = new Dataflow(program, steps, 256, values, "instructions", true, true, "equivalent-states", true).analyze();
      assert.equal(facts.completedEntries.length, 0);
      assert.ok(facts.diagnostics.some(diagnostic => /budget/.test(diagnostic.code)));
    }
  }, 3);
});

for (const after of [false, true]) test(`scalar-fold predicates preserve byte constraints ${after ? "after" : "before"} the fold`, () => {
  withProgram(`${callback}
export circuit entry(value: Secp256k1Scalar): Boolean {
  const bytes = (value as Bytes<32>) as Vector<32, Uint<8>>;
  ${Array.from({ length: after ? 31 : 32 }, (_, index) => `assert(bytes[${index}] == 0, "zero byte");`).join("\n")}
  const result = fold(compareByte, true, bytes, [127 as Uint<8>, ...default<Vector<31, Uint<8>>>]);
  ${after ? 'assert(bytes[31] == 0, "last zero byte");' : ""}
  assert(!result, "contradiction"); return result;
}`, program => {
    const ordinary = new Dataflow(program, 40000, 256, 50000, "expressions", false, false, "equivalent-states", false, false).analyze();
    assert.deepEqual(ordinary.diagnostics, []);
    assert.equal(ordinary.paths.length, 0);
    compare(program, facts => {
      assert.equal(facts.paths.length, 0);
      assert.ok(facts.failedAssertions.some(failure => failure.message === '"contradiction"'));
    });
  }, 3);
});

test("scalar-fold guards reject later contradictory byte restrictions", () => {
  withProgram(`${scalarFold}
export circuit entry(value: Secp256k1Scalar): Boolean {
  const bytes = (value as Bytes<32>) as Vector<32, Uint<8>>;
  ${Array.from({ length: 31 }, (_, index) => `assert(bytes[${index}] == 0, "zero prefix");`).join("\n")}
  const result = low(value); assert(result, "low");
  assert(bytes[31] == 255, "high byte"); return result;
}`, program => {
    const ordinary = new Dataflow(program, 40000, 256, 50000, "expressions", false, false, "equivalent-states", false, false).analyze();
    assert.deepEqual(ordinary.diagnostics, []);
    assert.equal(ordinary.paths.length, 0);
    compare(program, facts => assert.equal(facts.paths.length, 0));
  }, 3);
});

test("scalar-fold thresholds remain unsigned integers for either constant seed", () => {
  const inputs = [0n, order / 2n, order - 1n], thresholds = [0n, order, (1n << 256n) - 1n];
  const cases = [false, true].flatMap(seed => thresholds.flatMap(bound => inputs.map(input => ({ seed, bound, input }))));
  withProgram(`${callback}\n${cases.map(({ seed, bound, input }, index) => `export circuit case${index}(): Boolean {
    const value = (${bytesOf(input)} as Bytes<32>) as Secp256k1Scalar;
    return fold(compareByte, ${seed}, (value as Bytes<32>) as Vector<32, Uint<8>>, ${bytesOf(bound)});
  }`).join("\n")}`, program => {
    const expected = cases.map(({ seed, bound, input }) => String(seed ? input <= bound : input < bound));
    const ordinary = new Dataflow(program, 40000, 256, 50000, "expressions", false, false, "equivalent-states", false, false).analyze();
    assert.deepEqual(ordinary.diagnostics, []);
    assert.deepEqual(returns(ordinary).map(value => value.constant), expected);
    compare(program, facts => assert.deepEqual(returns(facts).map(value => value.constant), expected));
  }, 3);
});

test("scalar-fold native range proves extreme thresholds for unknown scalars", () => {
  withProgram(`${callback}
export circuit belowZero(value: Secp256k1Scalar): Boolean {
  return fold(compareByte, false, (value as Bytes<32>) as Vector<32, Uint<8>>, ${bytesOf(0n)});
}
export circuit belowOrder(value: Secp256k1Scalar): Boolean {
  return fold(compareByte, false, (value as Bytes<32>) as Vector<32, Uint<8>>, ${bytesOf(order)});
}`, program => compare(program, facts => {
    assert.deepEqual(returns(facts).map(value => value.constant), ["false", "true"]);
  }), 3);
});

for (const [name, sequence, partitioned] of [
  ["full byte/vector round trip", "((bytes as Bytes<32>) as Vector<32, Uint<8>>)", false],
  ["reconstructed byte vector", "[...bytes]", true],
  ["reordered byte vector", `[${Array.from({ length: 32 }, (_, index) => `bytes[${31 - index}]`).join(",")}]`, true],
  ["different native scalar domain", "(((bytes as Bytes<32>) as Secp256k1Base) as Bytes<32>) as Vector<32, Uint<8>>", true],
] as const) test(`scalar byte metadata follows the actual representation: ${name}`, () => {
  withProgram(`${callback}
export circuit entry(value: Secp256k1Scalar): Boolean {
  const bytes = (value as Bytes<32>) as Vector<32, Uint<8>>;
  return fold(compareByte, true, ${sequence}, ${bytesOf(order / 2n)});
}`, program => compare(program, facts => {
    assert.equal(facts.paths.length, partitioned ? 33 : 1);
    assert.equal(facts.paths.some(path => path.path.some(step => step.kind === "summary")), !partitioned);
  }), 3);
});

test("scalar-byte correspondence rejects exclusions even inside a byte range", () => {
  withProgram(`${scalarFold}
export circuit entry(value: Secp256k1Scalar): Boolean {
  const bytes = (value as Bytes<32>) as Vector<32, Uint<8>>;
  assert(low(value), "low"); assert(bytes[0] != 127, "excluded byte");
  assert(value == (${bytesOf(127n)} as Bytes<32>) as Secp256k1Scalar, "contradiction"); return true;
}`, program => compare(program, facts => assert.equal(facts.paths.length, 0)), 3);
});

test("accepted scalar-fold predicates constrain subsequent byte exclusions", () => {
  withProgram(`${callback}
export circuit entry(value: Secp256k1Scalar): Boolean {
  const bytes = (value as Bytes<32>) as Vector<32, Uint<8>>;
  assert(fold(compareByte, true, bytes, default<Vector<32, Uint<8>>>), "at most zero");
  assert(bytes != default<Vector<32, Uint<8>>>, "contradiction"); return true;
}`, program => compare(program, facts => assert.equal(facts.paths.length, 0)), 3);
});

test("scalar-fold predicates with different thresholds preserve their shared operand", () => {
  withProgram(`${callback}
export circuit entry(value: Secp256k1Scalar): Boolean {
  const bytes = (value as Bytes<32>) as Vector<32, Uint<8>>;
  assert(fold(compareByte, true, bytes, ${bytesOf(127n)}), "at most 127");
  assert(!fold(compareByte, false, bytes, ${bytesOf(256n)}), "contradiction"); return true;
}`, program => compare(program, facts => assert.equal(facts.paths.length, 0)), 3);
});


test("native scalar fold byte restrictions agree with the ordinary callback at carry boundaries", () => {
  const cases = [false, true].flatMap(seed => [[0n, [0n, 1n]], [255n, [127n, 255n, 256n]], [256n, [255n, 256n, 257n]]]
    .flatMap(([bound, inputs]) => (inputs as bigint[]).map(input => ({ seed, bound: bound as bigint, input }))));
  withProgram(`${callback}\n${cases.map(({ seed, bound, input }, index) => `export circuit case${index}(value: Secp256k1Scalar): Boolean {
    const bytes = (value as Bytes<32>) as Vector<32, Uint<8>>;
    ${Array.from({ length: 30 }, (_, index) => `assert(bytes[${index + 2}] == 0, "zero prefix");`).join("\n")}
    const result = fold(compareByte, ${seed}, bytes, ${bytesOf(bound)}); assert(result, "accepted");
    assert(bytes[0] == ${input & 255n}, "low byte"); assert(bytes[1] == ${input >> 8n}, "high byte"); return result;
  }`).join("\n")}`, program => {
    const observed = (facts: AnalysisFacts) => facts.paths.map(path => program.symbols.get(path.entry)!.name).sort();
    const expected = cases.flatMap(({ seed, bound, input }, index) => (seed ? input <= bound : input < bound) ? [`case${index}`] : []).sort();
    const ordinary = new Dataflow(program, 40000, 256, 50000, "expressions", false, false, "equivalent-states", false, false).analyze();
    assert.deepEqual(ordinary.diagnostics, []);
    assert.deepEqual(observed(ordinary), expected);
    compare(program, facts => assert.deepEqual(observed(facts), expected));
  }, 3);
});

test("scalar-fold predicates retain ordered byte guards before and after the fold", () => {
  const cases = (["<", "<=", ">", ">="] as const).flatMap(operator => [true, false].flatMap(truth =>
    [false, true].flatMap(reversed => [false, true].map(after => ({ operator, truth, reversed, after })))));
  const reverse = { "<": ">", "<=": ">=", ">": "<", ">=": "<=" };
  withProgram(`${callback}\n${cases.map(({ operator, truth, reversed, after }, index) => {
    const ordered = reversed ? `127 ${reverse[operator]} bytes[0]` : `bytes[0] ${operator} 127`;
    const guard = `assert(${truth ? ordered : `!(${ordered})`}, "byte guard");`;
    const seed = operator === "<=" || operator === ">";
    const accepted = operator.startsWith("<") === truth;
    const fold = `const result = fold(compareByte, ${seed}, bytes, ${bytesOf(127n)});`;
    return `export circuit case${index}(value: Secp256k1Scalar): Boolean {
      const bytes = (value as Bytes<32>) as Vector<32, Uint<8>>;
      for (const i of 1..32) { assert(bytes[i] == 0, "zero high bytes"); }
      ${after ? `${fold} ${guard}` : `${guard} ${fold}`}
      assert(${accepted ? "!result" : "result"}, "contradiction"); return result;
    }`;
  }).join("\n")}`, program => {
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) for (const optimized of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, optimized).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      // Ordinary callbacks retain repeated byte predicates but do not normalize
      // reversed/complementary comparisons. Use them as an oracle only for the
      // exact predicate they express; all variants must reject in the byte domain.
      const applicable = optimized ? facts.paths : facts.paths.filter(path => {
        const index = Number(program.symbols.get(path.entry)!.name.slice(4)), item = cases[index];
        return item.operator === "<" && !item.reversed;
      });
      assert.equal(applicable.length, 0, JSON.stringify({ engine, cached, optimized }));
    }
  }, 3);
});

test("ordered scalar-byte domains preserve feasible values at strict and inclusive boundaries", () => {
  const cases = (["<", "<=", ">", ">="] as const).flatMap(operator => [true, false].flatMap(truth =>
    [126n, 127n, 128n].map(input => ({ operator, truth, input }))));
  const accepted = ({ operator, truth, input }: typeof cases[number]) =>
    (operator === "<" ? input < 127n : operator === "<=" ? input <= 127n : operator === ">" ? input > 127n : input >= 127n) === truth;
  withProgram(`${callback}\n${cases.map(({ operator, truth, input }, index) => `export circuit case${index}(value: Secp256k1Scalar): Boolean {
    const bytes = (value as Bytes<32>) as Vector<32, Uint<8>>;
    assert(${truth ? `bytes[0] ${operator} 127` : `!(bytes[0] ${operator} 127)`}, "byte guard");
    const result = fold(compareByte, true, bytes, ${bytesOf(127n)});
    assert(value == (${bytesOf(input)} as Bytes<32>) as Secp256k1Scalar, "input");
    return result;
  }`).join("\n")}`, program => compare(program, facts => {
    const actual = facts.paths.map(path => [program.symbols.get(path.entry)!.name,
      path.sinks.find(sink => sink.kind === "exported-return")!.value.constant]).sort();
    const expected = cases.flatMap((item, index) => accepted(item) ? [[`case${index}`, String(item.input <= 127n)]] : []).sort();
    assert.deepEqual(actual, expected);
  }), 3);
});

test("retaining an unasserted scalar byte view obeys the constraint capacity", () => {
  withProgram(`${scalarFold}
export circuit entry(value: Uint<16>, scalar: Secp256k1Scalar): Boolean {
  ${Array.from({ length: 256 }, (_, index) => `assert(value < ${index + 1}, "bound");`).join("\n")}
  return low(scalar);
}`, program => {
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(facts.completedEntries, []);
      assert.ok(facts.diagnostics.some(diagnostic => diagnostic.code === "constraint-budget" && /Ordered/.test(diagnostic.message)));
    }
  }, 3);
});
