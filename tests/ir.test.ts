import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Dataflow, Program, Policies, detectors, resolvePolicies } from "../src/index.js";
import { lowerInstructions, verifyInstructions } from "../src/ir/index.js";
import { withFiles } from "./helpers.js";

const cases = (JSON.parse(readFileSync("tests/corpus/manifest.json", "utf8")) as { cases: { file: string }[] }).cases.map(fixture => ({ file: fixture.file, policies: {} as Policies }));
const policies = JSON.parse(readFileSync("tests/corpus/policies-manifest.json", "utf8")) as { cases: { name: string; policies: Policies }[] };
for (const fixture of policies.cases) for (const label of ["vulnerable", "safe"]) cases.push({ file: `${label}/${fixture.name}.compact`, policies: fixture.policies });

for (const fixture of cases) test(`instruction/reference differential: ${fixture.file}`, () => {
  const program = new Program(resolve("tests/corpus", fixture.file));
  const configured = resolvePolicies(program, fixture.policies);
  const outputs = (["instructions", "expressions"] as const).map(engine => {
    const facts = new Dataflow(program, 20000, 256, 50000, engine).analyze();
    assert.deepEqual(facts.diagnostics, []);
    return {
      findings: detectors.flatMap(detector => detector.run(facts, configured)).map(finding => `${finding.detectorId}:${finding.fingerprint}`).sort(),
      paths: facts.paths.map(path => JSON.stringify({
        sinks: path.sinks.map(sink => ({ kind: sink.kind, line: sink.location.line, flows: sink.value.flows.map(flow => `${flow.source.kind}:${flow.source.location.start}:${flow.form}`).sort(), constant: sink.value.constant })),
        writes: path.writes.map(write => ({ ledger: write.ledger, before: write.before.constant, after: write.after.constant, guards: write.guards.slice().sort() })),
      })).sort(),
    };
  });
  assert.deepEqual(outputs[0], outputs[1]);
});

test("expression instructions preserve short-circuit order and side-effect paths", () => {
  withFiles({ "main.compact": 'export ledger value: Boolean; circuit touch(): Boolean { value = true; return true; } export circuit entry(flag: Boolean): Boolean { return flag && touch(); }' }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const graph = program.instructionCFG(program.entries[0]);
    const branch = graph.nodes.find(node => node.kind === "branch")!;
    const call = graph.nodes.find(node => node.instruction?.kind === "evaluate" && node.instruction.expression.kind === "call")!;
    const skipped = branch.edges.find(edge => edge.condition === false)!;
    const evaluated = branch.edges.find(edge => edge.condition === true)!;
    assert.equal(graph.isReachable(skipped.target, call.id), false);
    assert.equal(graph.isReachable(evaluated.target, call.id), true);
    assert.ok(call.instruction!.effects.includes("may-abort"));
    const facts = new Dataflow(program).analyze();
    assert.deepEqual(facts.diagnostics, []);
    assert.deepEqual(facts.paths.map(path => path.writes.length).sort(), [0, 1]);
    assert.ok(facts.paths.find(path => path.writes.length)!.writes[0].after.flows.some(flow => flow.source.name === "flag"));
  });
});

test("conditional values have single-definition temporaries and predecessor-selected merges", () => {
  withFiles({ "main.compact": "export circuit entry(flag: Boolean): Field { return flag ? 3 as Field : 8 as Field; }" }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const graph = program.instructionCFG(program.entries[0]);
    verifyInstructions(graph);
    const definitions = graph.nodes.flatMap(node => node.instruction?.result ? [node.instruction.result] : []);
    assert.equal(new Set(definitions).size, definitions.length);
    assert.equal(graph.nodes.filter(node => node.instruction?.kind === "merge").length, 1);
    const facts = new Dataflow(program).analyze();
    assert.deepEqual(facts.diagnostics, []);
    assert.deepEqual(facts.paths.flatMap(path => path.sinks.map(sink => sink.value.constant)).sort(), ["3", "8"]);
    assert.ok(facts.paths.every(path => path.sinks[0].value.flows.some(flow => flow.source.name === "flag")));
  });
});

test("instruction verifier rejects undefined operands and invalid merge edges", () => {
  withFiles({ "main.compact": "export circuit entry(flag: Boolean): Boolean { return flag ? true : false; }" }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const source = program.functions.get(program.entries[0])!.cfg;
    const missing = lowerInstructions(source, "missing", program.symbols);
    missing.nodes.find(node => node.instruction?.kind === "copy")!.instruction!.inputs[0] = "missing";
    assert.throws(() => verifyInstructions(missing), /not defined on every incoming path/);
    const invalid = lowerInstructions(source, "invalid", program.symbols);
    const merge = invalid.nodes.find(node => node.instruction?.kind === "merge")!.instruction!;
    if (merge.kind === "merge") merge.predecessors[0] = invalid.entry;
    assert.throws(() => verifyInstructions(invalid), /Merge inputs/);
    assert.throws(() => lowerInstructions(source, "budget", program.symbols, 4), /instruction budget/);
  });
});

test("nested assertions and checked casts expose source-mapped abort edges", () => {
  withFiles({ "main.compact": 'export circuit entry(value: Field): Uint<8> { return (assert(value != (0 as Field), "nonzero"), 0, value as Uint<8>); }' }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const graph = program.instructionCFG(program.entries[0]);
    for (const kind of ["assert", "cast"]) {
      const node = graph.nodes.find(node => node.instruction?.kind === "evaluate" && node.instruction.expression.kind === kind)!;
      assert.ok(node.edges.some(edge => edge.target === graph.abort));
      assert.equal(node.span.line, 1);
      assert.ok(node.span.start > 0);
    }
  });
});

test("Counter address formation does not invent a ledger read instruction", () => {
  withFiles({ "main.compact": "import CompactStandardLibrary; export ledger count: Counter; export circuit entry(): [] { count.increment(1); }" }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const effects = program.instructionCFG(program.entries[0]).nodes.flatMap(node => node.instruction?.effects ?? []);
    assert.ok(effects.includes("state-address"));
    assert.ok(effects.includes("state-write"));
    assert.equal(effects.includes("state-read"), false);
  });
});

test("total hashing does not extend private control past a completed branch", () => {
  withFiles({ "main.compact": "import CompactStandardLibrary; export circuit entry(secret: Boolean): Field { if (secret) { persistentHash<Boolean>(secret); } return 0 as Field; }" }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const facts = new Dataflow(program).analyze();
    assert.deepEqual(facts.diagnostics, []);
    assert.ok(facts.paths.every(path => path.sinks[0].value.flows.length === 0));
  });
});

test("total helper calls do not manufacture a possible circuit abort", () => {
  withFiles({ "main.compact": "import CompactStandardLibrary; circuit digest(value: Boolean): Bytes<32> { return persistentHash<Boolean>(value); } export circuit entry(secret: Boolean): Field { if (secret) { digest(secret); } return 0 as Field; }" }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const facts = new Dataflow(program).analyze();
    assert.deepEqual(facts.diagnostics, []);
    assert.ok(facts.paths.every(path => path.sinks[0].value.flows.length === 0));
  });
});


test("identity and widening numeric casts are total while narrowing retains abort edges", () => {
  withFiles({ "main.compact": `export circuit entry(value: Uint<8>, wide: Field): [] {
    const widened = value as Field;
    const same = wide as Field;
    const narrowed = wide as Uint<8>;
  }` }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const graph = program.instructionCFG(program.entries[0]);
    const casts = graph.nodes.filter(node => node.instruction?.kind === "evaluate" && node.instruction.expression.kind === "cast");
    assert.equal(casts.length, 3);
    for (const node of casts) {
      const narrowing = node.instruction!.kind === "evaluate" && node.instruction!.expression.type === "Uint<8>";
      assert.equal(node.instruction!.effects.includes("may-abort"), narrowing);
      assert.equal(node.edges.some(edge => edge.target === graph.abort), narrowing);
    }
  });
});


test("in-bounds literal and bounded-domain indexing is total; unknown bounds retain rejection", () => {
  withFiles({ "main.compact": `export circuit entry(single: Vector<1,Boolean>, many: Vector<4,Boolean>, index: Uint<8>): [] {
    const literal = single[0];
    const widened = single[0 as Uint<8>];
    const unknown = many[index];
  }` }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const graph = program.instructionCFG(program.entries[0]);
    const indices = graph.nodes.filter(node => node.instruction?.kind === "evaluate" && node.instruction.expression.kind === "index");
    assert.equal(indices.length, 3);
    for (const node of indices) {
      const unknown = node.instruction!.kind === "evaluate" && node.instruction!.expression.args[1].kind === "ref";
      assert.equal(node.instruction!.effects.includes("may-abort"), unknown);
      assert.equal(node.edges.some(edge => edge.target === graph.abort), unknown);
    }
  });
});
