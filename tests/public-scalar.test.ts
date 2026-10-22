import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Dataflow, Program, resolvePolicies, scanFile } from "../src/index.js";
import { observeRules } from "../src/analysis/rule-observations.js";
import { scanFileIsolated } from "../src/runtime/index.js";
import { PUBLIC_SCALAR_TARGETS, publicScalarScope } from "../src/semantic/public-scalar-targets.js";
import { publicScalarFindings, publishedDigestGeneratorScalarReview as rule } from "../src/detectors/public-scalar.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const root = "tests/corpus/synthetic-regressions/privacy16/account-key-domain";
const positive = readFileSync(`${root}/positive.compact`, "utf8");
function observe(file: string, engine: "instructions" | "expressions", cached: boolean, targets = PUBLIC_SCALAR_TARGETS) {
  const program = new Program(file, [], undefined, undefined, 2, "0.34.0");
  return new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, true,
    "witness", false, false, false, true, false, false, true, false, false, false, targets).analyze();
}
function check(file: string, expected: number) {
  if (process.env.COMPACTC_TEST) { const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file); assert.equal(compiled.valid, true, compiled.error); }
  let baseline: unknown;
  for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
    const facts = observe(file, engine, cached);
    assert.deepEqual(facts.diagnostics, []); assert.deepEqual(facts.completedEntries, facts.program.entries);
    const findings = rule.run(facts); assert.deepEqual(facts.diagnostics, []); assert.equal(findings.length, expected);
    assert.ok(findings.every(f => f.severity === "info" && f.metadata.encryptionUseProven === false));
    baseline ??= findings; assert.deepEqual(findings, baseline, `${engine}/${cached}`);
  }
  for (const experimentalCounterQueries of [false, true]) {
    const scan = scanFile(file, { compilerVersion: "0.34.0", detectors: [rule.id], experimentalCounterQueries });
    assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics)); assert.equal(scan.findings.length, expected);
  }
}
test("owned Encryption-secret modern triplet uses exact native operands in both engines and summary modes", () => {
  for (const [name, expected] of [["positive", 1], ["corrected", 0], ["lookalike", 0]] as const) check(resolve(root, `${name}.compact`), expected);
  const selected = scanFile(resolve(root, "positive.compact"), { compilerVersion: "0.34.0", detectors: [rule.id] });
  assert.equal(selected.findings[0].location.line, 17);
  const defaults = scanFile(resolve(root, "positive.compact"), { compilerVersion: "0.34.0" });
  assert.ok(!defaults.coverage.detectors.includes(rule.id)); assert.ok(!defaults.findings.some(f => f.detectorId === rule.id));
  const unobserved = observe(resolve(root, "positive.compact"), "instructions", true, new Set());
  assert.ok(!unobserved.paths.some(p => p.operations?.some(o => o.kind === "circuit-invocation")));
  assert.deepEqual(rule.run(unobserved), []); assert.ok(unobserved.diagnostics.some(d => d.code === "public-scalar-evidence"));
});

test("owned boundary cases reject overwritten results, missing persistence, arithmetic and separate witness calls", () => {
  const variants = [
    positive.replace("encryptionPublicKey = disclose(derivePk(secret));", "encryptionPublicKey = disclose(derivePk(secret)); encryptionPublicKey = default<JubjubPoint>;"),
    positive.replace("encryptionPublicKey = disclose(derivePk(secret));", "const unused = derivePk(secret);"),
    positive.replace("ecMulGenerator(secretToScalar(secret))", "ecMulGenerator((degradeToTransient(persistentHash<Vector<1, Bytes<32>>>([secret])) + 1) as JubjubScalar)"),
    positive.replace("disclose(derivePk(secret))", "disclose(derivePk(keyMaterial()))"),
    positive.replace("ecMulGenerator(secretToScalar(secret))", "default<JubjubPoint>"),
  ];
  for (const text of variants) withFiles({ "main.compact": text }, directory => check(resolve(directory, "main.compact"), 0));
});

test("selected candidate fails closed on observation budget exhaustion", () => {
  const facts = observe(resolve(root, "positive.compact"), "instructions", true);
  assert.deepEqual(publicScalarFindings(facts, 1), []); assert.ok(facts.diagnostics.some(d => d.code === "public-scalar-budget"));
  const scan = scanFile(resolve(root, "positive.compact"), { compilerVersion: "0.34.0", detectors: [rule.id], maxSteps: 1 });
  assert.equal(scan.status, "incomplete"); assert.equal(scan.findings.length, 0);
});

test("supervised workers preserve selected modern scalar review", async () => {
  for (const experimentalCounterQueries of [false, true]) {
    const scan = await scanFileIsolated(resolve(root, "positive.compact"), { compilerVersion: "0.34.0", detectors: [rule.id], experimentalCounterQueries });
    assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics)); assert.equal(scan.findings.length, 1); assert.equal(scan.findings[0].location.line, 17);
  }
});

test("selected unsupported modern profile remains incomplete in both scan modes", () => {
  for (const experimentalCounterQueries of [false, true]) {
    const scan = scanFile(resolve(root, "positive.compact"), { compilerVersion: "0.35.0", detectors: [rule.id], experimentalCounterQueries });
    assert.equal(scan.status, "incomplete"); assert.equal(scan.findings.length, 0);
    assert.ok(scan.diagnostics.some(d => d.code === "public-scalar-profile"));
  }
});

test("ordinary facts certify generator absence before profile and exact evidence requirements", () => {
  const sources = [
    "import CompactStandardLibrary; export ledger items: List<Field>; export circuit entry(): Boolean { return items.isEmpty(); }",
    "import CompactStandardLibrary; circuit unused(): JubjubPoint { return ecMulGenerator(default<JubjubScalar>); } export circuit entry(): Field { return 1 as Field; }",
    "import { JubjubPoint, JubjubScalar } from CompactStandardLibrary; circuit ecMulGenerator(scalar: JubjubScalar): JubjubPoint { return default<JubjubPoint>; } export circuit entry(): JubjubPoint { return ecMulGenerator(default<JubjubScalar>); }",
  ];
  for (const source of sources) withFiles({ "main.compact": `pragma language_version >= 0.26.0; ${source}` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    for (const compilerVersion of ["0.34.0", "0.35.0"] as const) {
      const program = new Program(file, [], undefined, undefined, 2, compilerVersion);
      for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
        const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze();
        assert.ok(!facts.digestEvidence);
        assert.equal(publicScalarScope(program, program.entries[0]).applicable, false);
        assert.deepEqual(rule.run(facts), []); assert.deepEqual(facts.diagnostics, []);
      }
      for (const experimentalCounterQueries of [false, true]) {
        const scan = scanFile(file, { compilerVersion, detectors: [rule.id], experimentalCounterQueries });
        assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics)); assert.deepEqual(scan.findings, []);
        if (!experimentalCounterQueries) {
          assert.ok(scan.coverage.rules?.every(row => row.status === "not-applicable" && row.evidence === "structural-absence"));
          assert.ok((scan.ruleObservationWork?.[0].metrics.steps ?? 0) > 0, "Scalar absence preparation is charged");
        }
      }
    }
  });
});

test("canonical generator scope retains renamed helpers and zero-iteration callbacks", () => {
  const renamed = positive.replace("import CompactStandardLibrary;", "import CompactStandardLibrary; import { ecMulGenerator as generator } from CompactStandardLibrary;")
    .replace("ecMulGenerator(secretToScalar(secret))", "generator(secretToScalar(secret))");
  withFiles({ "main.compact": renamed }, directory => check(resolve(directory, "main.compact"), 1));
  for (const callback of ["ecMulGenerator", "(scalar: JubjubScalar): JubjubPoint => { return ecMulGenerator(scalar); }"]) {
    withFiles({ "main.compact": `pragma language_version >= 0.26.0; import CompactStandardLibrary;
      export circuit entry(): Vector<0,JubjubPoint> { return map(${callback}, [] as Vector<0,JubjubScalar>); }` }, directory => {
      const file = resolve(directory, "main.compact");
      if (process.env.COMPACTC_TEST) {
        const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file);
        assert.equal(compiled.valid, true, compiled.error);
      }
      for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
        const facts = observe(file, engine, cached, new Set());
        assert.equal(facts.diagnostics.length, 0);
        assert.equal(publicScalarScope(facts.program, facts.program.entries[0]).applicable, true);
        assert.deepEqual(rule.run(facts), []);
        assert.ok(facts.diagnostics.some(d => d.code === "public-scalar-evidence"));
      }
      for (const experimentalCounterQueries of [false, true]) {
        const scan = scanFile(file, { compilerVersion: "0.35.0", detectors: [rule.id], experimentalCounterQueries });
        assert.equal(scan.status, "incomplete"); assert.ok(scan.diagnostics.some(d => d.code === "public-scalar-profile"));
      }
    });
  }
});

test("missing evidence applies only to entries reaching the native generator", () => {
  withFiles({ "main.compact": `${positive}\nexport circuit idle(): Field { return 0 as Field; }` }, directory => {
    const file = resolve(directory, "main.compact");
    const facts = observe(file, "instructions", true, new Set());
    assert.deepEqual(rule.run(facts), []);
    const relevant = facts.program.entries.find(id => facts.program.symbols.get(id)?.name === "register")!;
    assert.deepEqual(facts.diagnostics.map(d => [d.code, d.scope?.entry]), [["public-scalar-evidence", relevant]]);
    const idle = facts.program.entries.find(id => facts.program.symbols.get(id)?.name === "idle")!;
    const subset = new Dataflow(facts.program).analyzeSubset([idle]);
    assert.deepEqual(rule.run(subset), []); assert.deepEqual(subset.diagnostics, []);
    for (const experimentalCounterQueries of [false, true]) {
      const scan = scanFile(file, { compilerVersion: "0.34.0", detectors: [rule.id], experimentalCounterQueries });
      assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics)); assert.equal(scan.findings.length, 1);
      if (!experimentalCounterQueries) assert.equal(scan.coverage.rules?.find(row => row.entry === idle)?.status, "not-applicable");
    }
  });
});

test("unknown callable models and applicability budgets never certify generator absence", () => {
  const facts = observe(resolve(root, "positive.compact"), "instructions", true);
  const program = facts.program, entry = program.entries[0];
  const helper = [...program.functions.values()].find(fn => fn.symbol.name === "derivePk")!;
  program.functions.delete(helper.symbol.id);
  assert.equal(publicScalarScope(program, entry).unavailable, "unresolved");
  assert.deepEqual(rule.run(facts), []); assert.ok(facts.diagnostics.some(d => d.code === "public-scalar-target-unavailable"));
  const unavailable = observeRules(program, [rule], resolvePolicies(program, {}), {});
  assert.equal(unavailable.coverage[0].status, "incomplete");
  assert.ok(unavailable.diagnostics.some(d => d.code === "public-scalar-target-unavailable"));

  withFiles({ "main.compact": "pragma language_version >= 0.26.0; export circuit entry(): Field { return 0 as Field; }" }, directory => {
    const ordinary = new Dataflow(new Program(resolve(directory, "main.compact"))).analyze();
    for (const allowance of [0, -1, NaN, 0.5]) {
      const scope = publicScalarScope(ordinary.program, ordinary.program.entries[0], allowance);
      assert.equal(scope.complete, false); assert.equal(scope.applicable, true); assert.equal(scope.unavailable, "budget");
      ordinary.diagnostics.length = 0;
      assert.deepEqual(publicScalarFindings(ordinary, allowance), []);
      assert.ok(ordinary.diagnostics.some(d => d.code === "public-scalar-budget"));
    }
    // Owned call-graph stress: applicability charges edges before scheduling
    // their traversal. A broad graph cannot bypass the fixed semantic allowance.
    const fn = ordinary.program.functions.get(ordinary.program.entries[0])!;
    for (let index = 0; index < 20001; index++) {
      const id = `witness::budget-${index}`;
      ordinary.program.symbols.set(id, { ...fn.symbol, id, kind: "witness" });
      fn.calls.add(id);
    }
    const exhausted = observeRules(ordinary.program, [rule], resolvePolicies(ordinary.program, {}), {});
    assert.equal(exhausted.coverage[0].status, "incomplete");
    assert.ok(exhausted.diagnostics.some(d => d.code === "public-scalar-target-budget"));
    ordinary.diagnostics.length = 0;
    assert.deepEqual(rule.run(ordinary), []);
    assert.ok(ordinary.diagnostics.some(d => d.code === "public-scalar-budget"));
  });
});
