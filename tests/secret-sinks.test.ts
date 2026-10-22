import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { Dataflow, Program, scanFile, type Policies } from "../src/index.js";
import type { PublicSink } from "../src/dataflow/index.js";
import { AnalysisError } from "../src/model.js";
import { resolvePolicies, validatePolicies } from "../src/policies.js";
import { secretPublication } from "../src/detectors/rules.js";
import { counterPolicyFindings } from "../src/detectors/counter-consumers.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const detector = "declared-secret-publication";
const allKinds: PublicSink["kind"][] = ["ledger-write", "exported-return", "ledger-operation", "event"];
const subject = { circuit: "entry", parameter: "secret" };
const source = `import CompactStandardLibrary;
export ledger stored: Bytes<32>;
circuit publish(value: Bytes<32>): Bytes<32> {
  stored = value;
  emit(ShieldedSpend {nullifier: value});
  return value;
}
export circuit entry(secret: Bytes<32>): Bytes<32> {
  publish(disclose(secret));
  return publish(disclose(secret));
}`;
const compile = (file: string) => {
  if (!process.env.COMPACTC_TEST) return;
  const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file, [], 30000, 2, "0.34.0");
  assert.equal(compiled.valid, true, compiled.error);
};
const expectDiagnostic = (code: string) => (error: unknown) => error instanceof AnalysisError && error.diagnostic.code === code;

test("sink selections resolve for parameters and witnesses without changing absent policies", () => {
  withFiles({ "main.compact": "witness privateValue(): Field; export circuit entry(secret: Field): Field { return disclose(secret); }" }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const absent = resolvePolicies(program, { secrets: [subject] }).secrets[0];
    assert.equal(Object.hasOwn(absent, "sinkKinds"), false);
    for (const selected of [allKinds, ...allKinds.map(kind => [kind])]) {
      const policies: Policies = { secrets: [{ ...subject, sinkKinds: selected }, { witness: "privateValue", sinkKinds: selected }] };
      assert.equal(validatePolicies(policies, program.rootSource.ast.span), policies);
      const resolved = resolvePolicies(program, policies);
      assert.deepEqual(resolved.secrets.map(policy => policy.sinkKinds), [selected, selected]);
      assert.notEqual(resolved.secrets[0].sinkKinds, selected, "Resolved selections own their arrays");
      assert.notEqual(resolved.secrets[0].sinkKinds, resolved.secrets[1].sinkKinds);
    }
  });
});

test("config validation and direct resolution reject invalid or sparse sink selections", () => {
  withFiles({ "main.compact": "export circuit entry(secret: Field): Field { return disclose(secret); }" }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const inherited = new Array(1);
    Object.setPrototypeOf(inherited, Object.assign(Object.create(Array.prototype), { 0: "event" }));
    const getter = new Array(1);
    Object.defineProperty(getter, 0, { enumerable: true, get() { throw new Error("Do not execute array accessors"); } });
    const extra = Object.assign(["event"], { extra: "exported-return" });
    const invalid = [null, "event", {}, [], ["unknown"], ["event", "event"], [...allKinds, "event"], [undefined], new Array(1), inherited, getter, extra];
    for (const sinkKinds of invalid) {
      const policies = { secrets: [{ ...subject, sinkKinds }] } as unknown as Policies;
      assert.throws(() => validatePolicies(policies, program.rootSource.ast.span), expectDiagnostic("invalid-config"));
      assert.throws(() => resolvePolicies(program, policies), expectDiagnostic("invalid-policy"));
    }
  });
});

test("each public sink kind filters findings while preserving facts and approved forms in all four modes", () => {
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    compile(file);
    const program = new Program(file);
    let baseline: ReturnType<typeof secretPublication.run> | undefined;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      const broad = secretPublication.run(facts, resolvePolicies(program, { secrets: [subject] }));
      assert.deepEqual(new Set(broad.map(finding => finding.metadata?.sinkKind)), new Set(["ledger-write", "event", "exported-return"]));
      assert.deepEqual(secretPublication.run(facts, resolvePolicies(program, { secrets: [{ ...subject, sinkKinds: allKinds }] })), broad);
      if (baseline) assert.deepEqual(broad, baseline);
      baseline = broad;
      const retainedSinks = facts.paths.map(path => [...path.sinks]);
      for (const kind of allKinds) {
        const selected = { ...subject, sinkKinds: [kind] };
        const expected = broad.filter(finding => finding.metadata?.sinkKind === kind);
        assert.deepEqual(secretPublication.run(facts, resolvePolicies(program, { secrets: [selected] })), expected);
        assert.deepEqual(secretPublication.run(facts, resolvePolicies(program, { secrets: [{ ...selected, allowedForms: ["raw"] }] })), []);
        for (const secrets of [[selected, subject], [subject, selected]]) {
          assert.deepEqual(secretPublication.run(facts, resolvePolicies(program, { secrets })), secrets[0] === selected ? expected : broad);
        }
      }
      assert.deepEqual(facts.paths.map(path => path.sinks), retainedSinks);
    }
  });
});

for (const [label, returns] of [["positive", 1], ["corrected", 0], ["lookalike", 0]] as const) {
  test(`unchanged shielded-result-return/${label} selects application output in both engines/cache modes`, () => {
    const file = resolve("tests/corpus/synthetic-regressions/privacy16/shielded-result-return", `${label}.compact`);
    compile(file);
    const program = new Program(file);
    const secret = { circuit: "drain", parameter: "coin" };
    const broadPolicy = resolvePolicies(program, { secrets: [secret] });
    const returnPolicy = resolvePolicies(program, { secrets: [{ ...secret, sinkKinds: ["exported-return"] }] });
    let baseline: ReturnType<typeof secretPublication.run> | undefined;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      const broad = secretPublication.run(facts, broadPolicy);
      assert.equal(broad.filter(finding => finding.metadata?.sinkKind === "ledger-operation").length, 5);
      assert.equal(broad.length, 5 + returns);
      assert.deepEqual(secretPublication.run(facts, resolvePolicies(program, { secrets: [{ ...secret, sinkKinds: allKinds }] })), broad);
      assert.deepEqual(secretPublication.run(facts, resolvePolicies(program, { secrets: [{ ...secret, sinkKinds: ["ledger-operation"] }] })), broad.filter(finding => finding.metadata?.sinkKind === "ledger-operation"));
      const selected = secretPublication.run(facts, returnPolicy);
      assert.equal(selected.length, returns);
      assert.deepEqual(selected.map(finding => finding.location.line), returns ? [3] : []);
      assert.ok(selected.every(finding => finding.metadata?.sinkKind === "exported-return" && finding.metadata?.visibility === "application-output"));
      // The engines may retain different valid internal standard-library trace
      // representatives. The public finding semantics and fingerprint must agree.
      // Trace positions and their serialized evidence chain may retain valid
      // engine-specific standard-library representatives; compare semantic
      // finding fields while leaving the contract's chain covered separately.
      const semanticFindings = (findings: typeof selected) => findings.map(({ trace, evidenceChain, ...finding }) => finding);
      if (baseline) assert.deepEqual(semanticFindings(selected), semanticFindings(baseline));
      baseline = selected;
    }
    const report = scanFile(file, { detectors: [detector], policies: { secrets: [{ ...secret, sinkKinds: ["exported-return"] }] } });
    assert.equal(report.status, "complete");
    assert.deepEqual(report.diagnostics, []);
    assert.equal(report.findings.length, returns);
  });
}

const counterSource = (count: number) => `import CompactStandardLibrary; export ledger count: Counter;
export circuit entry(${Array.from({ length: count }, (_, i) => `flag${i}: Boolean`).join(",")}): [] {
${Array.from({ length: count }, (_, i) => `if (disclose(flag${i})) { count.increment(1); }`).join("\n")}
}`;

test("correlated and Counter scans retain sink selection, approved forms and first-match precedence", () => {
  withFiles({ "main.compact": counterSource(10) }, directory => {
    const file = resolve(directory, "main.compact");
    compile(file);
    const secret = { circuit: "entry", parameter: "flag0" };
    const onlyReturns = { ...secret, sinkKinds: ["exported-return"] as PublicSink["kind"][] };
    const operations = { ...secret, sinkKinds: ["ledger-operation"] as PublicSink["kind"][] };
    const approved = { ...operations, allowedForms: ["derived"] as const };
    for (const experimentalCounterQueries of [false, true]) {
      const broad = scanFile(file, { detectors: [detector], policies: { secrets: [secret] }, experimentalCounterQueries });
      assert.equal(broad.status, "complete", JSON.stringify(broad.diagnostics));
      assert.deepEqual(broad.diagnostics, []);
      assert.equal(broad.findings.length, 10);
      for (const secrets of [[onlyReturns], [operations], [onlyReturns, secret], [secret, onlyReturns], [{ ...approved, allowedForms: [...approved.allowedForms] }]]) {
        const report = scanFile(file, { detectors: [detector], policies: { secrets }, experimentalCounterQueries });
        assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
        assert.deepEqual(report.diagnostics, []);
        assert.deepEqual(report.findings, secrets[0] === secret || secrets[0] === operations ? broad.findings : []);
      }
    }
  });
});

test("query-backed Counter consumer matches the ordinary selected-sink findings in all four modes", () => {
  withFiles({ "main.compact": counterSource(3) }, directory => {
    const file = resolve(directory, "main.compact");
    compile(file);
    const program = new Program(file);
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const flow = new Dataflow(program, 20000, 256, 50000, engine, cached, cached);
      const facts = flow.analyze();
      assert.deepEqual(facts.diagnostics, []);
      for (const sinkKinds of [["exported-return"], ["ledger-operation"], allKinds] as PublicSink["kind"][][]) {
        const policies = resolvePolicies(program, { secrets: [{ circuit: "entry", parameter: "flag0", sinkKinds }] });
        const queried = counterPolicyFindings(flow, program.entries[0], policies, [detector]);
        assert.equal(queried.status, "complete");
        if (queried.status !== "complete") throw new Error("Expected complete Counter query");
        const sort = (findings: ReturnType<typeof secretPublication.run>) => [...findings].sort((a, b) => a.fingerprint.localeCompare(b.fingerprint));
        assert.deepEqual(sort(queried.findings), sort(secretPublication.run(facts, policies)));
        assert.equal(queried.findings.length, sinkKinds.includes("ledger-operation") ? 3 : 0);
      }
    }
  });
});

test("CLI accepts optional sink selection and reports invalid JSON selections as incomplete", () => {
  withFiles({ "main.compact": "export circuit entry(secret: Field): Field { return disclose(secret); }" }, directory => {
    const config = resolve(directory, "config.json");
    for (const [sinkKinds, findings] of [[undefined, 1], [["exported-return"], 1], [["ledger-write"], 0], [allKinds, 1]] as const) {
      writeFileSync(config, JSON.stringify({ version: 1, roots: ["main.compact"], detectors: [detector], failOn: "none", policies: { secrets: [{ ...subject, sinkKinds }] } }));
      const run = spawnSync(process.execPath, [resolve("dist/src/cli.js"), "--config", config, "--json"], { encoding: "utf8", timeout: 30000 });
      assert.equal(run.status, 0, run.stderr);
      const report = JSON.parse(run.stdout);
      assert.equal(report.status, "complete");
      assert.deepEqual(report.diagnostics, []);
      assert.equal(report.findings.length, findings);
    }
    for (const sinkKinds of [[], ["unknown"], ["event", "event"], [...allKinds, "event"], [null], null, "event"]) {
      writeFileSync(config, JSON.stringify({ version: 1, roots: ["main.compact"], policies: { secrets: [{ ...subject, sinkKinds }] } }));
      const run = spawnSync(process.execPath, [resolve("dist/src/cli.js"), "--config", config, "--json"], { encoding: "utf8", timeout: 30000 });
      assert.equal(run.status, 2, run.stderr);
      const report = JSON.parse(run.stdout);
      assert.equal(report.status, "incomplete");
      assert.equal(report.diagnostics[0].code, "invalid-config");
      assert.deepEqual(report.findings, []);
    }
  });
});
