import assert from "node:assert/strict";
import test from "node:test";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile, type AnalysisFacts } from "../src/index.js";
import { lowEntropyHashDisclosure as rule, detectSmallDomainHash } from "../src/detectors/small-domain-hash.js";
import { digestTargets } from "../src/semantic/digest-targets.js";
import { finiteDomain } from "../src/semantic/domains.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";
const header = `import CompactStandardLibrary; export ledger digest: Bytes<32>; export ledger context: Field;\n`;
function fixture(source: string, expected: string[], prefix = header): void {
  withFiles({ "main.compact": prefix + source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const result = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(result.valid, true, result.error);
    }
    const program = new Program(file);
    let baseline: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached, "equivalent-states", false, true, "witness", false, false, false, true, false, false, true).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      const findings = rule.run(facts).sort((a, b) => a.fingerprint.localeCompare(b.fingerprint));
      assert.deepEqual(findings.map(finding => finding.metadata.entry).sort(), [...expected].sort());
      baseline ??= findings;
      assert.deepEqual(findings, baseline);
    }
    // Differential oracle: a conservative absence certificate never covers an
    // entry with an exact finding (see rule-certificates.ts).
    for (const entry of program.entries) {
      const certificate = new Dataflow(program, 40000, 256, 50000, "instructions", true, true, "equivalent-states", false, true, "witness", false, false, false, true, false, false, true)
        .conservativeRuleCertificate(entry, "digest");
      const name = program.symbols.get(entry)!.name;
      if (certificate.status === "absent") assert.equal(expected.includes(name), false, `${name} has an exact finding but a digest absence certificate`);
    }
    const result = scanFile(file, { detectors: [rule.id] });
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.deepEqual(result.findings.sort((a, b) => a.fingerprint.localeCompare(b.fingerprint)), baseline);
  });
}

test("published direct Boolean hashes report; public context adds no private uncertainty", () => {
  fixture(`witness choice(): Boolean;
export circuit entry(value: Boolean): [] { digest = disclose(persistentHash<Boolean>(value)); }
export circuit witnessEntry(): [] { digest = disclose(persistentHash<Boolean>(choice())); }
export circuit withContext(value: Boolean): [] { digest = disclose(persistentHash<[Boolean,Field]>([value,context])); }
export circuit transient(value: Boolean): Field { return disclose(transientHash<Boolean>(value)); }
export circuit keccak(value: Boolean): Bytes<32> { return disclose(keccak256<Boolean>(value)); }`, ["entry", "witnessEntry", "withContext", "transient", "keccak"]);
});

test("private salt, commitments, large sources and comparisons stay outside direct-digest scope", () => {
  fixture(`export circuit salt(value: Boolean, opening: Bytes<32>): [] { digest = disclose(persistentHash<[Boolean,Bytes<32>]>([value,opening])); }
export circuit commit(value: Boolean, opening: Bytes<32>): [] { digest = persistentCommit<Boolean>(value,opening); }
export circuit large(value: Field): [] { digest = disclose(persistentHash<Field>(value)); }
export circuit publicValue(): [] { digest = persistentHash<Field>(context); }
export circuit constantValue(): [] { digest = persistentHash<Boolean>(true); }
export circuit controlOnly(value: Boolean): [] { if (disclose(persistentHash<Boolean>(value) == default<Bytes<32>>)) { context = 1 as Field; } }
export circuit transformed(value: Boolean): Boolean { return disclose(persistentHash<Boolean>(value) == default<Bytes<32>>); }
export circuit unused(value: Boolean): [] { persistentHash<Boolean>(value); }`, []);
});

test("declared Uint, Bytes, enum and nominal domains are bounded without entropy estimates", () => {
  fixture(`enum Choice { yes, no, abstain }
new type Flag = Boolean;
export circuit byte(value: Uint<8>): Bytes<32> { return disclose(persistentHash<Uint<8>>(value)); }
export circuit bytes(value: Bytes<1>): Bytes<32> { return disclose(persistentHash<Bytes<1>>(value)); }
export circuit enumeration(value: Choice): Bytes<32> { return disclose(persistentHash<Choice>(value)); }
export circuit alias(value: Flag): Bytes<32> { return disclose(persistentHash<Flag>(value)); }
export circuit boundary(value: Uint<16>): Bytes<32> { return disclose(persistentHash<Uint<16>>(value)); }
export circuit beyond(value: Uint<17>): Bytes<32> { return disclose(persistentHash<Uint<17>>(value)); }`, ["byte", "bytes", "enumeration", "alias", "boundary"]);
});

test("aggregate digest copies retain direct evidence but computations do not publish it", () => {
  fixture(`circuit hashed(value: Boolean): Bytes<32> { return persistentHash<Boolean>(value); }
export circuit helper(value: Boolean): Bytes<32> { return disclose(hashed(value)); }
export circuit repeated(value: Boolean): [Bytes<32>,Bytes<32>] { const saved = hashed(value); return disclose([saved,saved]); }
export circuit projection(value: Boolean): Bytes<32> { const pair = [hashed(value),default<Bytes<32>>]; return disclose(pair[0]); }
export circuit rebuilt(value: Boolean): Bytes<32> { const hashed = persistentHash<Boolean>(value); return disclose(hashed); }`, ["helper", "repeated", "projection", "rebuilt"]);
});

test("same-named user helpers are not native hash evidence", () => {
  fixture(`circuit persistentHash(value: Boolean): Bytes<32> { return default<Bytes<32>>; }
export circuit entry(value: Boolean): Bytes<32> { return persistentHash(value); }`, [], "");
});

test("typed domain traversal and detector work exhaustion are explicitly incomplete", () => {
  withFiles({ "main.compact": header + `export circuit entry(value: Boolean): [] { digest = disclose(persistentHash<Boolean>(value)); }` }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    assert.equal(finiteDomain(program, "Vector<16,Boolean>").upperBound, 65536);
    assert.equal(finiteDomain(program, "Vector<17,Boolean>").upperBound, undefined);
    assert.equal(finiteDomain(program, "[Boolean,Boolean]", 65536, 1).complete, false);
    assert.equal(finiteDomain(program, "Boolean", 65536, 0).complete, false);
    const facts = new Dataflow(program, 40000, 256, 50000, "instructions", true, true, "equivalent-states", false, true, "witness", false, false, false, true, false, false, true).analyze();
    assert.equal(rule.run(facts).length, 1);
    assert.deepEqual(detectSmallDomainHash(facts, 1), []);
    assert.ok(facts.diagnostics.some(diagnostic => diagnostic.code === "hash-domain-budget"));
    const scan = scanFile(program.root, { detectors: [rule.id], maxSteps: 1 });
    assert.equal(scan.status, "incomplete");
    assert.ok(scan.diagnostics.length);
  });
});


test("projected Boolean leaves retain their own domain rather than the enclosing declaration", () => {
  fixture(`struct Inputs { flag: Boolean, unusedLarge: Field }
witness inputs(): Inputs;
export circuit fieldProjection(value: Inputs): Bytes<32> { return disclose(persistentHash<Boolean>(value.flag)); }
export circuit tupleProjection(value: [Boolean,Field]): Bytes<32> { return disclose(persistentHash<Boolean>(value[0])); }
export circuit witnessProjection(): Bytes<32> { return disclose(persistentHash<Boolean>(inputs().flag)); }`, ["fieldProjection", "tupleProjection", "witnessProjection"]);
});

test("salt published on the same successful history is public context without erasing provenance", () => {
  fixture(`export ledger salt: Bytes<32>; export ledger revealed: Boolean;
export circuit publishedSalt(value: Boolean, opening: Bytes<32>): [] { salt = disclose(opening); digest = disclose(persistentHash<[Boolean,Bytes<32>]>([value,salt])); }
export circuit lateSalt(value: Boolean, opening: Bytes<32>): [] { digest = disclose(persistentHash<[Boolean,Bytes<32>]>([value,opening])); salt = disclose(opening); }
export circuit privateSalt(value: Boolean, opening: Bytes<32>): [] { digest = disclose(persistentHash<[Boolean,Bytes<32>]>([value,opening])); }
export circuit intentionalReveal(value: Boolean): [] { revealed = disclose(value); digest = disclose(persistentHash<Boolean>(value)); }
export circuit oneBranch(value: Boolean, opening: Bytes<32>, branch: Boolean): [] { if (disclose(branch)) { salt = disclose(opening); } digest = disclose(persistentHash<[Boolean,Bytes<32>]>([value,opening])); }
export circuit transformedSalt(value: Boolean, opening: Bytes<32>): [] { salt = disclose(persistentHash<Bytes<32>>(opening)); digest = disclose(persistentHash<[Boolean,Bytes<32>]>([value,opening])); }`, ["publishedSalt", "lateSalt", "oneBranch"]);
});


test("digest observation is explicit and correlated APIs fall back to exact histories", () => {
  withFiles({ "main.compact": header + `export circuit entry(value: Boolean): [] {
    digest = disclose(persistentHash<Boolean>(value));
  }` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const result = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(result.valid, true, result.error);
    }
    const program = new Program(file);
    const unobserved = new Dataflow(program).analyze();
    assert.equal(unobserved.digestEvidence, undefined);
    assert.deepEqual(rule.run(unobserved), []);
    assert.ok(unobserved.diagnostics.some(diagnostic => diagnostic.code === "hash-domain-evidence-unavailable"));
    const observed = new Dataflow(program, 40000, 256, 50000, "instructions", true, true,
      "equivalent-states", false, true, "witness", false, false, false, true, false, false, true);
    const result = observed.analyzeWithCorrelatedQueries([]);
    assert.deepEqual(result.correlated, []);
    assert.deepEqual(result.sources, []);
    assert.deepEqual(result.exact.diagnostics, []);
    assert.equal(result.exact.digestEvidence, true);
    assert.equal(rule.run(result.exact).length, 1);
    const selection = observed.selectSourceWitness(program.entries[0], false);
    assert.equal(selection.status, "selected");
    if (selection.status === "selected") assert.ok(selection.path.sinks.some(sink => sink.value.directDigest));
    const joined: AnalysisFacts = { ...result.exact, diagnostics: [], pathSemantics: "guard-cover" };
    assert.deepEqual(rule.run(joined), []);
    assert.ok(joined.diagnostics.some(diagnostic => diagnostic.code === "hash-domain-evidence-unavailable"));
  });
});

test("default hash choices retain compression; exact digest observation reports its budget", () => {
  withFiles({ "main.compact": header + `export circuit entry(bits: Vector<5,Boolean>, choice: Boolean): [] {
    digest = disclose(persistentHash<Boolean>(choice));
    for (const i of 0..5) {
      digest = disclose(disclose(bits[i]) ? persistentHash<[Bytes<32>,Boolean]>([digest,true])
        : persistentHash<[Bytes<32>,Boolean]>([digest,false]));
    }
  }` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const result = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(result.valid, true, result.error);
    }
    const ordinary = scanFile(file, { detectors: [], maxPaths: 1 });
    assert.equal(ordinary.status, "complete", JSON.stringify(ordinary.diagnostics));
    const observed = scanFile(file, { detectors: [rule.id], maxPaths: 1 });
    assert.equal(observed.status, "incomplete");
    // Baseline coverage is retained; this exact rule still has no complete result.
    assert.equal(observed.coverage.baselineStatus, "complete");
    assert.equal(observed.coverage.completedEntries.length, 1);
    assert.equal(observed.coverage.rules!.find(row => row.detectorId === rule.id)!.status, "incomplete");
    assert.ok(observed.diagnostics.some(diagnostic => diagnostic.code.endsWith("budget")));
  });
});


test("large-domain hashes do not require the optional digest observer", () => {
  withFiles({ "main.compact": header + `export circuit entry(value: Field): [] { digest = disclose(persistentHash<Field>(value)); }` }, directory => {
    const program = new Program(resolve(directory,"main.compact"));
    assert.equal(digestTargets(program).applicable,false);
    assert.equal(digestTargets(program,1).complete,false);
    const facts = new Dataflow(program).analyze();
    assert.deepEqual(rule.run(facts),[]);
    assert.deepEqual(facts.diagnostics,[]);
    assert.equal(scanFile(program.root).status,"complete");
  });
});

test("joined large typed leaves certify digest absence without hiding small alternatives", () => {
  withFiles({ "main.compact": header + `
export circuit largeChoice(flag: Boolean, first: Bytes<32>, second: Bytes<32>): Bytes<32> {
  const selected = flag ? first : second;
  return disclose(persistentHash<Bytes<32>>(selected));
}
export circuit smallChoice(flag: Boolean, first: Boolean, second: Boolean): Bytes<32> {
  const selected = flag ? first : second;
  return disclose(persistentHash<Boolean>(selected));
}
export circuit constructedChoice(flag: Boolean, first: Uint<8>, second: Uint<8>): Bytes<32> {
  const selected = flag ? Bytes[first, 0, 0] : Bytes[second, 0, 0];
  return disclose(persistentHash<Bytes<3>>(selected));
}
export circuit mixedShape(flag: Boolean, value: Uint<8>): Bytes<32> {
  const selected = flag ? Bytes[value, 0, 0] : pad(3, "");
  return disclose(persistentHash<Bytes<3>>(selected));
}` }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const validated = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(validated.valid, true, validated.error);
    }
    const program = new Program(file);
    const certificates = new Map(program.entries.map(entry => [program.symbols.get(entry)!.name,
      new Dataflow(program, 40000, 256, 50000, "instructions", true, true, "equivalent-states", false, true, "witness", false, false, false, true, false, false, true)
        .conservativeRuleCertificate(entry, "digest").status]));
    assert.equal(certificates.get("largeChoice"), "absent");
    assert.equal(certificates.get("smallChoice"), "candidate");
    assert.equal(certificates.get("constructedChoice"), "candidate");
    assert.equal(certificates.get("mixedShape"), "candidate");
    const result = scanFile(file, { detectors: [rule.id] });
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.deepEqual([...new Set(result.findings.map(finding => finding.metadata.entry))].sort(), ["constructedChoice", "mixedShape", "smallChoice"]);
  });
});

test("small-domain, inactive-payload and discarded-verifier rules ship enabled by default", () => {
  for (const [file,id] of [
    ["counter-small-domain-hash-positive.compact",rule.id],
    ["counter-either-payload-positive.compact","either-payload-mismatch"],
    ["counter-ignored-validation-positive.compact","ignored-validation-result"],
  ]) {
    const scan = scanFile(resolve("tests/corpus/known-bugs",file));
    assert.equal(scan.status,"complete",JSON.stringify(scan.diagnostics));
    assert.ok(scan.findings.some(finding => finding.detectorId === id));
  }
});


test("large Bytes constructions retain a small private byte through copies and helpers", () => {
  fixture(`circuit bytes(value: Uint<8>): Bytes<3> { return Bytes[value, 0, 0]; }
export circuit constructed(value: Uint<8>): Bytes<32> { return disclose(persistentHash<Bytes<3>>(Bytes[value, 0, 0])); }
export circuit copied(value: Uint<8>): Bytes<32> { const original = Bytes[value, 0, 0]; const copy = original; return disclose(persistentHash<Bytes<3>>(copy)); }
export circuit helper(value: Uint<8>): Bytes<32> { return disclose(persistentHash<Bytes<3>>(bytes(value))); }`, ["constructed", "copied", "helper"]);
  withFiles({"main.compact": header + `export circuit entry(value: Uint<8>): Bytes<32> { return disclose(persistentHash<Bytes<3>>(Bytes[value, 0, 0])); }`}, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    assert.equal(digestTargets(program).applicable, true);
    const result = scanFile(program.root);
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    const findings = result.findings.filter(finding => finding.detectorId === rule.id);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].metadata.inputDomainUpperBound, 256);
  });
});


test("native hashes used as higher-order callbacks cannot be certified absent", () => {
  fixture(`export circuit mapped(value: Boolean): Bytes<32> { return disclose(map(persistentHash<Boolean>, [value])[0]); }
export circuit mappedTransient(value: Boolean): Field { return disclose(map(transientHash<Boolean>, [value])[0]); }`, ["mapped", "mappedTransient"]);
  withFiles({"main.compact": header + `export circuit entry(value: Boolean): Bytes<32> { return disclose(map(persistentHash<Boolean>, [value])[0]); }`}, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    assert.equal(digestTargets(program).applicable, true);
    const result = scanFile(program.root);
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.equal(result.findings.filter(finding => finding.detectorId === rule.id).length, 1);
  });
});
