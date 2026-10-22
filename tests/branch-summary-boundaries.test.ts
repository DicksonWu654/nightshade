import assert from "node:assert/strict";
import { resolve } from "node:path";
import test from "node:test";
import { BranchMutationEligibility } from "../src/analysis/summaries.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { Dataflow, Program, detectors, resolvePolicies } from "../src/index.js";
import { semanticPaths, withFiles } from "./helpers.js";

type Facts = ReturnType<Dataflow["analyze"]>;
const globals = "export ledger first: Field; export ledger second: Field; export ledger enabled: Boolean;";
const arms = "if (disclose(flag)) { first = disclose(value); } else { second = disclose(value); }";
function source(body: string, entry: string, result = "[]", parameters = "a: Uint<8>, b: Uint<8>, value: Field", extra = ""): string {
  return `${globals} ${extra} circuit select(flag: Boolean,value: Field): [] { ${body} } export circuit entry(${parameters}): ${result} { ${entry} }`;
}
function qualified(text: string, check: (program: Program) => void): void {
  withFiles({ "main.compact": text }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) { const result = validateWithCompiler(process.env.COMPACTC_TEST, file); assert.equal(result.valid, true, result.error); }
    const program = new Program(file), helper = [...program.functions.values()].find(fn => fn.symbol.name === "select")!;
    assert.equal(new BranchMutationEligibility(program).allows(helper.symbol.id), true);
    check(program);
  });
}
function modes(program: Program, check: (cached: Facts, expanded: Facts) => void, paths = 256, values = 50000): void {
  let reference: string[] | undefined;
  for (const engine of ["instructions", "expressions"] as const) {
    const cached = new Dataflow(program, 20000, paths, values, engine, true, true).analyze();
    const expanded = new Dataflow(program, 20000, paths, values, engine, false, false).analyze();
    assert.deepEqual(cached.paths, expanded.paths); assert.deepEqual(cached.failedAssertions, expanded.failedAssertions);
    assert.deepEqual(cached.diagnostics, expanded.diagnostics); assert.deepEqual(cached.completedEntries, expanded.completedEntries);
    assert.ok(cached.metrics.statefulSummaryHits > 0, `${engine} must exercise actual branch replay`);
    const semantic = semanticPaths(cached); if (reference) assert.deepEqual(semantic, reference); reference = semantic;
    check(cached, expanded);
  }
}
const names = (value: { flows: { source: { name: string } }[] }) => [...new Set(value.flows.map(flow => flow.source.name))].sort();

test("branch replay keeps prefix data separate from abort-sensitive suffix control and public consumers", () => qualified(source(
  `first = default<Field>; ${arms} enabled = false; return [];`,
  "const flag = (a + 1) < (b + 1); select(flag,value); select(flag,value); return [first,enabled];", "[Field,Boolean]",
), program => {
  const helper = [...program.functions.values()].find(fn => fn.symbol.name === "select")!;
  const plan = new BranchMutationEligibility(program).plan(helper.symbol.id)!;
  for (const route of [plan.instructions, plan.expressions]) { assert.equal(route.controlUntil, -1); assert.notEqual(route.convergence, route.controlUntil); }
  const policy = resolvePolicies(program, { secrets: [{ circuit: "entry", parameter: "a" }] });
  const publication = detectors.find(detector => detector.id === "declared-secret-publication")!;
  modes(program, (cached, expanded) => {
    assert.deepEqual(cached.diagnostics, []); assert.equal(cached.paths.length, 4);
    for (const path of cached.paths) {
      assert.equal(path.writes.length, 6);
      for (const offset of [0, 3]) {
        assert.equal(program.symbols.get(path.writes[offset].ledger)!.name, "first");
        assert.equal(path.writes[offset].after.constant, "0"); assert.deepEqual(names(path.writes[offset].after), []);
        assert.deepEqual(names(path.writes[offset + 1].after), ["a", "b", "value"]);
        assert.equal(program.symbols.get(path.writes[offset + 2].ledger)!.name, "enabled");
        assert.equal(path.writes[offset + 2].after.constant, "false"); assert.deepEqual(names(path.writes[offset + 2].after), ["a", "b"]);
      }
      const returned = path.sinks.at(-1)!;
      assert.equal(returned.kind, "exported-return"); assert.equal(returned.value.items!.length, 2);
      assert.deepEqual(names(returned.value.items![1]), ["a", "b"]);
      if (program.symbols.get(path.writes[4].ledger)!.name === "second") {
        assert.equal(returned.value.items![0].constant, "0"); assert.deepEqual(names(returned.value.items![0]), []);
      } else assert.deepEqual(names(returned.value.items![0]), ["a", "b", "value"]);
    }
    const findings = publication.run(cached, policy);
    assert.deepEqual(findings, publication.run(expanded, policy));
    const suffixSite = cached.paths[0].writes[2].location.start;
    assert.ok(findings.some(finding => finding.location.start === suffixSite && finding.metadata?.sinkKind === "ledger-write"));
    assert.ok(findings.some(finding => finding.metadata?.sinkKind === "exported-return"));
    const prefixSite = cached.paths[0].writes[0].location.start;
    assert.ok(findings.every(finding => finding.location.start !== prefixSite), "Uncontrolled constant prefix is not a secret publication");
  });
}));

test("unknown empty arms survive actual replay without acquiring the opposite arm's effects", () => {
  for (const body of ["if (disclose(flag)) { first = disclose(value); }", "if (disclose(flag)) {} else { first = disclose(value); }"]) {
    qualified(source(body, "const flag = (a + 1) < (b + 1); select(flag,value); select(flag,value); return [];"), program => modes(program, cached => {
      assert.deepEqual(cached.diagnostics, []); assert.equal(cached.paths.length, 4);
      assert.deepEqual(cached.paths.map(path => path.writes.length).sort(), [0, 1, 1, 2]);
      for (const path of cached.paths) {
        assert.equal(path.sinks.filter(sink => sink.kind === "ledger-write").length, path.writes.length);
        assert.deepEqual(path.sinks.at(-1)!.value.flows, []); assert.deepEqual(path.sinks.at(-1)!.value.items, []);
        assert.ok(path.writes.every(write => program.symbols.get(write.ledger)!.name === "first"));
        assert.ok(path.writes.every(write => names(write.after).join(",") === "a,b,value"));
      }
    }));
  }
});

test("repeated analyses clear branch evidence and retain direct Boolean correlation and caller hash bindings", () => qualified(source(
  arms,
  'assert(persistentHash<Field>(value) == digest,"owned binding"); select(flag,value); select(flag,value); select(flag,value); return disclose(value);',
  "Field", "flag: Boolean,value: Field", "import CompactStandardLibrary; export ledger digest: Bytes<32>;",
), program => {
  const snapshot = ({ paths, diagnostics, failedAssertions, metrics, completedEntries }: Facts) => structuredClone({ paths, diagnostics, failedAssertions, metrics, completedEntries });
  const preimage = detectors.find(detector => detector.id === "ledger-bound-preimage-publication")!;
  let reference: string[] | undefined;
  for (const engine of ["instructions", "expressions"] as const) {
    const analysis = new Dataflow(program, 20000, 256, 50000, engine, true, true);
    const first = analysis.analyze(), expected = snapshot(first), findings = preimage.run(first);
    assert.deepEqual(first.diagnostics, []); assert.equal(first.paths.length, 2); assert.ok(first.metrics.statefulSummaryHits > 0);
    for (const path of first.paths) {
      assert.equal(path.writes.length, 3); assert.equal(new Set(path.writes.map(write => write.ledger)).size, 1);
      assert.equal(path.bindings.length, 1); assert.equal(path.bindings[0].source.name, "value");
      assert.ok(path.writes.every(write => names(write.after).join(",") === "flag,value"));
    }
    assert.equal(findings.length, 3); assert.deepEqual([...new Set(findings.map(finding => finding.metadata?.sinkKind))].sort(), ["exported-return", "ledger-write"]);
    const semantic = semanticPaths(first); if (reference) assert.deepEqual(semantic, reference); reference = semantic;
    // Facts expose shared diagnostic arrays; snapshot before rerunning so reset
    // cannot make an assertion pass by mutating the expected result in place.
    assert.deepEqual(snapshot(analysis.analyze()), expected);
    const empty = analysis.analyzeSubset([]);
    assert.deepEqual(empty.paths, []); assert.deepEqual(empty.completedEntries, []); assert.deepEqual(empty.diagnostics, []);
    assert.equal(empty.metrics.summaryEntries, 0); assert.equal(empty.metrics.summaryEffects, 0); assert.equal(empty.metrics.summaryHits, 0);
    assert.equal(empty.metrics.statefulSummaryHits, 0); assert.equal(empty.metrics.sources, 0); assert.equal(empty.metrics.abstractValues, 0);
    const again = analysis.analyze(), expanded = new Dataflow(program, 20000, 256, 50000, engine, false, false).analyze();
    assert.deepEqual(snapshot(again), expected); assert.deepEqual(again.paths, expanded.paths); assert.deepEqual(again.diagnostics, expanded.diagnostics);
    assert.deepEqual(again.failedAssertions, expanded.failedAssertions); assert.deepEqual(again.completedEntries, expanded.completedEntries);
    assert.deepEqual(preimage.run(again), findings); assert.deepEqual(preimage.run(expanded), findings);
  }
}));

test("a warmed two-arm summary in the final return cannot exceed the caller's path allowance", () => qualified(source(
  arms + " return [];", "const flag = (a + 1) < (b + 1); select(flag,value); return select(flag,value);",
), program => {
  modes(program, cached => { assert.deepEqual(cached.diagnostics, []); assert.equal(cached.paths.length, 4); assert.deepEqual(cached.completedEntries, program.entries); }, 4);
  modes(program, cached => {
    assert.ok(cached.diagnostics.some(diagnostic => diagnostic.code === "analysis-budget"));
    assert.deepEqual(cached.completedEntries, []); assert.equal(cached.paths.length, 2); assert.ok(cached.paths.length <= 3);
    assert.ok(cached.paths.every(path => path.sinks.at(-1)!.kind === "exported-return"));
  }, 3);
}));

test("a completed branch cache hit cannot clear subsequent final-result value exhaustion", () => qualified(source(
  arms, "select(true,default<Field>); select(true,default<Field>); return default<Vector<8,Field>>;", "Vector<8,Field>", "",
), program => {
  modes(program, cached => {
    assert.deepEqual(cached.diagnostics, []); assert.deepEqual(cached.completedEntries, program.entries);
    assert.equal(cached.paths[0].sinks.at(-1)!.value.items!.length, 8);
  });
  modes(program, cached => {
    assert.ok(cached.diagnostics.some(diagnostic => diagnostic.code === "value-budget"));
    assert.deepEqual(cached.completedEntries, []); assert.ok(cached.metrics.abstractValues > 4);
    assert.equal(cached.paths.length, 1); assert.equal(cached.paths[0].writes.length, 2);
  }, 256, 4);
}));
