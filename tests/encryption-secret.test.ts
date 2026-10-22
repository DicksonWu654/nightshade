import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile } from "../src/index.js";
import type { AnalysisFacts } from "../src/dataflow/index.js";
import { immutableOperandKey } from "../src/dataflow/immutable-key.js";
import { encryptionScope, encryptionTargets } from "../src/semantic/encryption-targets.js";
import { encryptionSecretFindings, publiclyDerivableEncryptionSecret as rule } from "../src/detectors/encryption-secret.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const root = "tests/corpus/known-bugs/digest-key";
const derivation = readFileSync(`${root}/KeyDerivation.compact`, "utf8");
const separated = readFileSync(`${root}/DomainKey.compact`, "utf8").replace("module DomainKey", "module KeyDerivation");
const digestModule = readFileSync(`${root}/PublicDigest.compact`, "utf8");
const header = `pragma language_version >= 0.23.0;
import CompactStandardLibrary;
import "KeyDerivation" prefix K_;
import "PublicDigest" prefix D_;
export ledger accountId: Bytes<32>;
export ledger encryptionPublicKey: JubjubPoint;
witness keyMaterial(): Bytes<32>;
`;
function observe(program: Program, engine: "instructions" | "expressions", cached: boolean, values = 50000): AnalysisFacts {
  return new Dataflow(program, 40000, 256, values, engine, cached, cached, "equivalent-states", false, true,
    "witness", false, false, false, true, false, false, true, false, false, false, encryptionTargets(program).targets).analyze();
}
function fixture(body: string, expected: string[], module = derivation, inspect?: (facts: AnalysisFacts) => void) {
  withFiles({ "main.compact": header + body, "KeyDerivation.compact": module, "PublicDigest.compact": digestModule }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_031_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_031_TEST, file);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(file, [], undefined, undefined, 2, "0.31.1");
    let oracle: unknown, operations: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = observe(program, engine, cached);
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      const actual = rule.run(facts);
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(actual.map(f => f.metadata.entry).sort(), expected);
      oracle ??= actual; assert.deepEqual(actual, oracle, `${engine}/${cached}`);
      const observed = facts.paths.map(path => (path.operations ?? []).filter(op => op.kind === "circuit-invocation")
        .map(op => ({ name: op.name, args: op.args.map(arg => immutableOperandKey(arg).key), result: immutableOperandKey(op.result).key, callSites: op.callSites })));
      operations ??= observed; assert.deepEqual(observed, operations, `${engine}/${cached} invocation snapshots`);
      inspect?.(facts);
    }
    for (const experimentalCounterQueries of [false, true]) {
      const scan = scanFile(file, { compilerVersion: "0.31.1", detectors: [rule.id], experimentalCounterQueries });
      assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics));
      assert.deepEqual(scan.findings.map(f => f.metadata.entry).sort(), expected);
    }
  });
}
const registration = `export circuit register(): [] {
  const secret = keyMaterial();
  accountId = disclose(D_computeAccountId(secret));
  encryptionPublicKey = disclose(K_derivePk(secret));
}`;

test("Owned native-chain registration is detected; separate hash domains are quiet", () => {
  fixture(registration, ["register"], derivation, facts => {
    const finding = rule.run(facts)[0];
    assert.equal(finding.severity, "high"); assert.equal(finding.confidence, "high");
    assert.equal(finding.metadata.derivedScalarPublic, true);
    assert.equal(finding.metadata.originalSeedRecovered, false);
    assert.equal(finding.metadata.encryptionUseProven, false);
    assert.equal(finding.metadata.ciphertextUseProven, false);
  });
  fixture(registration, [], separated);
});

test("exact witness invocation, type, domain and unchanged point are required", () => {
  fixture(`
export circuit distinct(): [] { accountId = disclose(D_computeAccountId(keyMaterial())); encryptionPublicKey = disclose(K_derivePk(keyMaterial())); }
export circuit transformed(): [] { const secret = keyMaterial(); accountId = disclose(D_computeAccountId(secret)); encryptionPublicKey = disclose(K_derivePk(persistentHash<Bytes<32>>(secret))); }
export circuit changedPoint(): [] { const secret = keyMaterial(); accountId = disclose(D_computeAccountId(secret)); encryptionPublicKey = disclose(ecMul(K_derivePk(secret), 2 as Field)); }
export circuit changedDomain(): [] { const secret = keyMaterial(); accountId = disclose(persistentHash<Vector<2, Bytes<32>>>([pad(32, "domain"), secret])); encryptionPublicKey = disclose(K_derivePk(secret)); }
export circuit changedType(): [] { const secret = keyMaterial(); accountId = disclose(persistentHash<[Bytes<32>]>([secret])); encryptionPublicKey = disclose(K_derivePk(secret)); }
export circuit discarded(): [] { const secret = keyMaterial(); accountId = disclose(D_computeAccountId(secret)); const pk = K_derivePk(secret); }
export circuit unpublished(): [] { encryptionPublicKey = disclose(K_derivePk(keyMaterial())); }
export circuit returned(): Bytes<32> { const secret = keyMaterial(); encryptionPublicKey = disclose(K_derivePk(secret)); return disclose(D_computeAccountId(secret)); }
`, []);
});

test("typed hash choices retain the surviving recipe rather than the first branch recipe", () => {
  fixture(`
export circuit tupleOnly(flag: Boolean): [] {
  const secret = keyMaterial();
  const digest = flag ? persistentHash<Vector<1, Bytes<32>>>([secret]) : persistentHash<[Bytes<32>]>([secret]);
  assert(!flag, "only tuple route");
  accountId = disclose(digest); encryptionPublicKey = disclose(K_derivePk(secret));
}
export circuit vectorOnly(flag: Boolean): [] {
  const secret = keyMaterial();
  const digest = flag ? persistentHash<[Bytes<32>]>([secret]) : persistentHash<Vector<1, Bytes<32>>>([secret]);
  assert(!flag, "only vector route");
  accountId = disclose(digest); encryptionPublicKey = disclose(K_derivePk(secret));
}
`, ["vectorOnly"]);
});

test("nested calls, repeated operands, caller guards and ledger invalidation keep history-local evidence", () => {
  fixture(`
circuit forward(secret: Bytes<32>): JubjubPoint { return K_derivePk(secret); }
circuit nested(secret: Bytes<32>): JubjubPoint { return forward(secret); }
export circuit aliases(allowed: Boolean): [] { assert(allowed, "caller guard"); const secret = keyMaterial(); const alias = secret; const first = nested(alias); const second = nested(alias); accountId = disclose(D_computeAccountId(secret)); encryptionPublicKey = disclose(second); }
export circuit different(): [] { const secret = keyMaterial(); const other = keyMaterial(); const first = nested(secret); accountId = disclose(D_computeAccountId(secret)); encryptionPublicKey = disclose(nested(other)); }
export circuit overwritten(): [] { const secret = keyMaterial(); accountId = disclose(D_computeAccountId(secret)); encryptionPublicKey = disclose(nested(secret)); encryptionPublicKey = disclose(nested(keyMaterial())); }
export circuit changedStorage(): [] { const secret = keyMaterial(); accountId = disclose(D_computeAccountId(secret)); encryptionPublicKey = disclose(nested(secret)); encryptionPublicKey = default<JubjubPoint>; }
export circuit exclusive(flag: Boolean): [] { const secret = keyMaterial(); if (disclose(flag)) { accountId = disclose(D_computeAccountId(secret)); } else { encryptionPublicKey = disclose(nested(secret)); } }
export circuit rejected(): [] { const secret = keyMaterial(); accountId = disclose(D_computeAccountId(secret)); encryptionPublicKey = disclose(nested(secret)); assert(false, "disabled"); }
`, ["aliases"]);
});

test("committed checkpoint prefixes retain only their own surviving registrations", () => {
  fixture(`
export circuit committedPrefix(): [] { const secret = keyMaterial(); accountId = disclose(D_computeAccountId(secret)); encryptionPublicKey = disclose(K_derivePk(secret)); kernel.checkpoint(); encryptionPublicKey = disclose(K_derivePk(keyMaterial())); }
export circuit late(): [] { const secret = keyMaterial(); accountId = disclose(D_computeAccountId(secret)); kernel.checkpoint(); encryptionPublicKey = disclose(K_derivePk(keyMaterial())); }
export circuit impossible(): [] { const secret = keyMaterial(); accountId = disclose(D_computeAccountId(secret)); encryptionPublicKey = disclose(K_derivePk(secret)); kernel.checkpoint(); assert(false, "disabled"); }
`, ["committedPrefix"]);
});

test("resolved recipe recognition ignores provider, circuit names and comments", () => {
  const renamed = derivation.replaceAll("derivePk", "makePoint").replace("// Owned synthetic", "// Alternate owned");
  fixture(registration.replaceAll("K_derivePk", "K_makePoint"), ["register"], renamed);
  fixture(registration, [], `module KeyDerivation { import CompactStandardLibrary; export pure circuit derivePk(seed: Bytes<32>): JubjubPoint { return ecMulGenerator(7); } }`);
});

test("canonical native identity and bounded applicability cannot be replaced by names", () => {
  fixture(registration, [], `module KeyDerivation {
    import { JubjubPoint, persistentHash, degradeToTransient } from CompactStandardLibrary;
    pure circuit ecMulGenerator(value: Field): JubjubPoint { return default<JubjubPoint>; }
    export pure circuit derivePk(seed: Bytes<32>): JubjubPoint {
      return ecMulGenerator(degradeToTransient(persistentHash<Vector<1, Bytes<32>>>([seed])));
    }
  }`);
  fixture(registration.replaceAll("K_derivePk", "K_makePoint"), ["register"], `module KeyDerivation {
    import CompactStandardLibrary;
    pure circuit reduceSeed(value: Bytes<32>): Field {
      const digest = persistentHash<Vector<1, Bytes<32>>>([value]);
      return degradeToTransient(digest);
    }
    export pure circuit makePoint(seed: Bytes<32>): JubjubPoint { return ecMulGenerator(reduceSeed(seed)); }
  }`);
  withFiles({ "main.compact": header + registration, "KeyDerivation.compact": derivation, "PublicDigest.compact": digestModule }, directory => {
    const program = new Program(resolve(directory, "main.compact"), [], undefined, undefined, 2, "0.31.1");
    assert.equal(encryptionTargets(program, 1).complete, false);
    assert.equal(encryptionTargets(program).complete, true, "A bounded probe cannot poison the default proof cache");
    assert.equal(encryptionScope(program, program.entries[0], 1).complete, false);
    assert.equal(encryptionScope(program, program.entries[0]).applicable, true);
  });
});

test("observation, consumer and unsupported-provider failures are explicit and scoped", () => {
  withFiles({ "main.compact": header + registration, "KeyDerivation.compact": derivation, "PublicDigest.compact": digestModule }, directory => {
    const file = resolve(directory, "main.compact"), program = new Program(file, [], undefined, undefined, 2, "0.31.1");
    const ordinary = new Dataflow(program).analyze(); assert.deepEqual(rule.run(ordinary), []);
    assert.ok(ordinary.diagnostics.some(d => d.code === "encryption-evidence-unavailable" && d.scope?.detectorId === rule.id));
    const facts = observe(program, "instructions", true);
    assert.deepEqual(encryptionSecretFindings(facts, 1), []);
    assert.ok(facts.diagnostics.some(d => d.code === "encryption-evidence-budget"));
    const exhausted = observe(program, "instructions", true, 4);
    assert.ok(exhausted.diagnostics.some(d => d.code === "effect-budget"));
    assert.deepEqual(exhausted.completedEntries, []);
    assert.deepEqual(rule.run(exhausted), []);
    const bounded = scanFile(file, { compilerVersion: "0.31.1", detectors: [rule.id], maxValues: 5 });
    assert.equal(bounded.status, "incomplete"); assert.equal(bounded.coverage.baselineStatus, "complete");
    assert.ok(bounded.diagnostics.every(d => d.scope?.detectorId === rule.id));
    assert.ok(bounded.coverage.rules?.some(row => row.detectorId === rule.id && row.status === "incomplete"));
  });
  const conditional = `module KeyDerivation {
    import CompactStandardLibrary;
    export pure circuit derivePk(seed: Bytes<32>): JubjubPoint {
      if (persistentHash<Vector<1, Bytes<32>>>([seed]) == default<Bytes<32>>) {
        return ecMulGenerator(1);
      } else { return ecMulGenerator(degradeToTransient(persistentHash<Vector<1, Bytes<32>>>([seed]))); }
    }
  }`;
  withFiles({ "main.compact": header + registration, "KeyDerivation.compact": conditional, "PublicDigest.compact": digestModule }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_031_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_031_TEST, file).valid, true);
    const scan = scanFile(file, { compilerVersion: "0.31.1", detectors: [rule.id] });
    assert.equal(scan.status, "incomplete"); assert.equal(scan.coverage.baselineStatus, "complete");
    assert.equal(scan.findings.length, 0);
    assert.ok(scan.diagnostics.some(d => d.code === "encryption-target-unavailable" && d.scope?.detectorId === rule.id));
  });
});

test("unproven singleton construction stays incomplete even when empty spreads are compiler-valid", () => {
  const spread = `module KeyDerivation {
    import CompactStandardLibrary;
    export pure circuit derivePk(seed: Bytes<32>): JubjubPoint {
      const input = [...([] as Vector<0, Bytes<32>>), seed];
      return ecMulGenerator(degradeToTransient(persistentHash<Vector<1, Bytes<32>>>(input)));
    }
  }`;
  withFiles({ "main.compact": header + registration, "KeyDerivation.compact": spread, "PublicDigest.compact": digestModule }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_031_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_031_TEST, file).valid, true);
    const scan = scanFile(file, { compilerVersion: "0.31.1", detectors: [rule.id] });
    assert.equal(scan.status, "incomplete"); assert.equal(scan.coverage.baselineStatus, "complete");
    assert.ok(scan.diagnostics.some(item => item.code === "encryption-target-unavailable" && item.scope?.detectorId === rule.id));
    assert.deepEqual(scan.findings, []);
  });
});

test("owned generator registration and both controls compile under the historical profile", () => {
  const registry = JSON.parse(readFileSync("tests/corpus/known-bugs.json", "utf8"));
  const seed = registry.cases.find((item: { id: string }) => item.id === "library-public-encryption-secret");
  assert.equal(seed.test, "tests/encryption-secret.test.ts"); assert.equal(seed.compiler, "0.31.1");
  for (const [path, expected] of [[seed.file, seed.expectedLines], [seed.corrected, []], [seed.lookalike, []]]) {
    const file = resolve("tests/corpus", path);
    if (process.env.COMPACTC_031_TEST) { const compiled = validateWithCompiler(process.env.COMPACTC_031_TEST, file); assert.equal(compiled.valid, true, `${path}: ${compiled.error}`); }
    const scan = scanFile(file, { compilerVersion: "0.31.1", detectors: [rule.id] });
    assert.equal(scan.status, "complete", JSON.stringify(scan.diagnostics));
    assert.deepEqual(scan.findings.map(f => f.location.line), expected);
  }
});

test("selected leaf summary hits record every actual invocation with immutable arguments and results", () => {
  withFiles({ "main.compact": `import CompactStandardLibrary;
witness material(): Bytes<32>;
circuit identity(value: Bytes<32>): Bytes<32> { return value; }
export circuit entry(): Bytes<32> { const value = material(); const first = identity(value); return disclose(identity(value)); }
` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) { const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file); assert.equal(compiled.valid, true, compiled.error); }
    const program = new Program(file), target = new Set([...program.functions.values()].filter(fn => fn.symbol.name === "identity").map(fn => fn.symbol.id));
    let oracle: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, true,
        "witness", false, false, false, true, false, false, false, false, false, false, target).analyze();
      assert.deepEqual(facts.diagnostics, []); assert.deepEqual(facts.completedEntries, program.entries);
      const ops = facts.paths[0].operations!.filter(op => op.kind === "circuit-invocation");
      assert.equal(ops.length, 2);
      assert.notDeepEqual(ops[0].location, ops[1].location);
      assert.equal(immutableOperandKey(ops[0].args[0]).key, immutableOperandKey(ops[1].args[0]).key);
      assert.equal(immutableOperandKey(ops[0].result).key, immutableOperandKey(ops[1].result).key);
      oracle ??= ops; assert.deepEqual(ops, oracle, `${engine}/${cached}`);
      assert.equal(facts.metrics.summaryHits > 0, cached);
    }
  });
});
