import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile } from "../src/index.js";
import { publicScalarFindings, publishedDigestGeneratorScalarReview as rule } from "../src/detectors/public-scalar.js";
import { PUBLIC_SCALAR_TARGETS, publicScalarRecipe } from "../src/semantic/public-scalar-targets.js";
import type { CompilerVersion, ZkirVersion } from "../src/semantic/profile.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const original = readFileSync("tests/corpus/synthetic-regressions/privacy16/account-key-domain/positive.compact", "utf8");
const profiles = [["0.31.1", 2], ["0.34.0", 3]] as const;
function source(version: CompilerVersion, text = original) {
  return version === "0.31.1" ? text.replace("0.26.0", "0.23.0").replaceAll(": JubjubScalar", ": Field").replaceAll(" as JubjubScalar", "") : text;
}
function check(text: string, version: CompilerVersion, zkir: ZkirVersion, expected: number) {
  withFiles({ "main.compact": source(version, text) }, directory => {
    const file = resolve(directory, "main.compact");
    const compiler = version === "0.31.1" ? process.env.COMPACTC_031_TEST : process.env.COMPACTC_TEST;
    if (compiler) {
      const compiled = validateWithCompiler(compiler, file, [], 30000, zkir, version);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(file, [], undefined, undefined, zkir, version);
    assert.equal(publicScalarRecipe(program), version === "0.31.1" ? "field" : "scalar-cast");
    let oracle: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, true,
        "witness", false, false, false, true, false, false, true, false, false, false, PUBLIC_SCALAR_TARGETS).analyze();
      assert.equal(facts.diagnostics.length, 0); assert.deepEqual(facts.completedEntries, program.entries);
      const findings = rule.run(facts);
      assert.equal(facts.diagnostics.length, 0); assert.equal(findings.length, expected);
      for (const finding of findings) {
        assert.equal(finding.severity, "info"); assert.equal(finding.metadata.encryptionUseProven, false);
        assert.equal(finding.trace.some(item => item.label === "resolved Field-to-JubjubScalar cast"), version !== "0.31.1");
      }
      oracle ??= findings; assert.deepEqual(findings, oracle, `${version}/${zkir}/${engine}/${cached}`);
      assert.deepEqual(publicScalarFindings(facts, 1), []);
      assert.ok(facts.diagnostics.some(issue => issue.code === "public-scalar-budget"));
    }
    for (const experimentalCounterQueries of [false, true]) {
      const scan = scanFile(file, { compilerVersion: version, zkirVersion: zkir, detectors: [rule.id], experimentalCounterQueries });
      assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics)); assert.equal(scan.findings.length, expected);
    }
    const bounded = scanFile(file, { compilerVersion: version, zkirVersion: zkir, detectors: [rule.id], maxSteps: 1 });
    assert.equal(bounded.status, "incomplete"); assert.deepEqual(bounded.findings, []);
    const values = scanFile(file, { compilerVersion: version, zkirVersion: zkir, detectors: [rule.id], maxValues: 1 });
    assert.equal(values.status, "incomplete"); assert.deepEqual(values.findings, []);
  });
}

for (const [version, zkir] of profiles) {
  test(`exact native scalar profile ${version}/ZKIR${zkir} preserves recipes, aliases and canonical renaming`, () => {
    check(original, version, zkir, 1);
    check(original.replace("import CompactStandardLibrary;", "import CompactStandardLibrary; import { ecMulGenerator as generator } from CompactStandardLibrary;")
      .replace("ecMulGenerator(secretToScalar(secret))", "generator(secretToScalar(secret))"), version, zkir, 1);
    check(original.replace("return ecMulGenerator(secretToScalar(secret));", "const scalar = secretToScalar(secret); const alias = scalar; return ecMulGenerator(alias);"), version, zkir, 1);
  });
  test(`exact native scalar profile ${version}/ZKIR${zkir} refuses distinct, changed, nonpersistent and unknown operands`, () => {
    for (const variant of [
      original.replace("disclose(derivePk(secret))", "disclose(derivePk(keyMaterial()))"),
      original.replace("persistentHash<Vector<1, Bytes<32>>>([secret])) as JubjubScalar", "persistentHash<Vector<2, Bytes<32>>>([secret, pad(32, \"domain\")])) as JubjubScalar"),
      original.replace("degradeToTransient(persistentHash<Vector<1, Bytes<32>>>([secret])) as JubjubScalar", "(degradeToTransient(persistentHash<Vector<1, Bytes<32>>>([secret])) + 1) as JubjubScalar"),
      original.replace("encryptionPublicKey = disclose(derivePk(secret));", "encryptionPublicKey = disclose(derivePk(secret)); encryptionPublicKey = default<JubjubPoint>;"),
      original.replace("encryptionPublicKey = disclose(derivePk(secret));", "const unused = derivePk(secret);"),
      original.replace("const secret = keyMaterial();", "const secret = accountId;"),
      original.replace("export ledger accountId: Bytes<32>;", "export ledger accountId: Bytes<32>; export ledger values: Map<Bytes<32>, Bytes<32>>;")
        .replace("export circuit register(): []", "export circuit register(key: Bytes<32>): []").replace("const secret = keyMaterial();", "const secret = values.lookup(disclose(key));"),
      original.replace("export circuit register(): []", "export circuit register(flag: Boolean): []")
        .replace("accountId = disclose(computeAccountId(secret));", "if (disclose(flag)) { accountId = disclose(computeAccountId(secret)); } else {")
        .replace("encryptionPublicKey = disclose(derivePk(secret));", "encryptionPublicKey = disclose(derivePk(secret)); }"),
    ]) check(variant, version, zkir, 0);
  });
  test(`zero-iteration native callback ${version}/ZKIR${zkir} is applicable and quiet with complete selected evidence`, () => {
    const scalar = version === "0.31.1" ? "Field" : "JubjubScalar";
    check(`pragma language_version >= 0.23.0; import CompactStandardLibrary;
      export circuit entry(): Vector<0,JubjubPoint> { return map(ecMulGenerator, [] as Vector<0,${scalar}>); }`, version, zkir, 0);
  });
}

test("profile expansion retains unsupported compiler refusals and absent-evidence refusal", () => {
  for (const version of ["0.30.0", "0.33.0-rc.2", "0.35.0"] as const) withFiles({ "main.compact": source(version === "0.30.0" ? "0.31.1" : version).replace(/0\.(23|26)\.0/, "0.22.0") }, directory => {
    const scan = scanFile(resolve(directory, "main.compact"), { compilerVersion: version, detectors: [rule.id] });
    assert.equal(scan.status, "incomplete"); assert.deepEqual(scan.findings, []);
    assert.ok(scan.diagnostics.some(issue => issue.code === "public-scalar-profile"), JSON.stringify(scan.diagnostics));
  });
  for (const [version, zkir] of profiles) withFiles({ "main.compact": source(version) }, directory => {
    const facts = new Dataflow(new Program(resolve(directory, "main.compact"), [], undefined, undefined, zkir, version)).analyze();
    assert.deepEqual(rule.run(facts), []); assert.ok(facts.diagnostics.some(issue => issue.code === "public-scalar-evidence"));
  });
});

for (const [version, zkir] of profiles) test(`application generator namesake ${version}/ZKIR${zkir} is quiet`, () => {
  const text = source(version, original).replace("import CompactStandardLibrary;",
    `import { JubjubPoint, persistentHash, degradeToTransient${version === "0.31.1" ? "" : ", JubjubScalar"} } from CompactStandardLibrary;`)
    .replace("pure circuit derivePk", `pure circuit ecMulGenerator(value: ${version === "0.31.1" ? "Field" : "JubjubScalar"}): JubjubPoint { return default<JubjubPoint>; }\npure circuit derivePk`);
  withFiles({ "main.compact": text }, directory => {
    const file = resolve(directory, "main.compact");
    const compiler = version === "0.31.1" ? process.env.COMPACTC_031_TEST : process.env.COMPACTC_TEST;
    if (compiler) { const compiled = validateWithCompiler(compiler, file, [], 30000, zkir, version); assert.equal(compiled.valid, true, compiled.error); }
    const program = new Program(file, [], undefined, undefined, zkir, version);
    for (const engine of ["instructions", "expressions"] as const) for (const cache of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cache, cache).analyze();
      assert.deepEqual(rule.run(facts), []); assert.equal(facts.diagnostics.length, 0);
    }
    const scan = scanFile(file, { compilerVersion: version, zkirVersion: zkir, detectors: [rule.id] });
    assert.equal(scan.status, "complete"); assert.deepEqual(scan.findings, []);
    assert.ok(scan.coverage.rules?.every(row => row.status === "not-applicable"));
  });
});
