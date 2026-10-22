import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { scanFile, Policies } from "../src/index.js";
import { analyze, withFiles } from "./helpers.js";
import { estimateWork } from "../src/analysis/work.js";

const manifest = JSON.parse(readFileSync("tests/corpus/policies-manifest.json", "utf8")) as { cases: { name: string; detector: string; line: number; policies: Policies }[] };
for (const fixture of manifest.cases) for (const label of ["vulnerable", "safe"]) {
  test(`policy corpus ${label}/${fixture.name}`, () => {
    const result = scanFile(resolve("tests/corpus", label, `${fixture.name}.compact`), { policies: fixture.policies, compiler: process.env.COMPACTC_TEST });
    assert.deepEqual(result.diagnostics, []);
    assert.deepEqual(result.findings.filter(finding => finding.detectorId === fixture.detector).map(finding => finding.location.line), label === "vulnerable" ? [fixture.line] : []);
  });
}

function expectRule(source: string, policies: Policies, rule: string, count: number): void {
  withFiles({ "main.compact": source }, directory => {
    const result = scanFile(resolve(directory, "main.compact"), { policies });
    assert.deepEqual(result.diagnostics, []);
    assert.equal(result.findings.filter(finding => finding.detectorId === rule).length, count);
  });
}

const secretRule = "declared-secret-publication";
const secretPolicy = { secrets: [{ circuit: "entry", parameter: "secret" }] };
for (const [body, count] of [
  ["return disclose(secret) as Field;", 1],
  ["return secret ? 1 as Field : 2 as Field;", 1],
  ["if (secret) { return 1 as Field; } else { return 2 as Field; }", 2],
  ["if (secret) { return 1 as Field; } return 2 as Field;", 2],
  ["if (secret) { disclose(secret); } return 0 as Field;", 0],
  ["disclose(secret); return 0 as Field;", 0],
  ["if (false) { return secret ? 1 as Field : 2 as Field; } return 0 as Field;", 0],
  ["const value = [secret, false]; return value[1] ? 1 as Field : 2 as Field;", 0],
] as const) test(`secret policy: ${body}`, () => expectRule(`export circuit entry(secret: Boolean): Field { ${body} }`, secretPolicy, secretRule, count));

test("privacy transformations must be explicitly approved", () => {
  const source = "import CompactStandardLibrary; export circuit entry(secret: Field): Bytes<32> { return disclose(persistentHash<Field>(secret)); }";
  expectRule(source, { secrets: [{ circuit: "entry", parameter: "secret", allowedForms: ["hash"] }] }, secretRule, 0);
  expectRule(source, secretPolicy, secretRule, 1);
  expectRule(source, {}, secretRule, 0);
});

const authPrefix = "export ledger allowed: Boolean; export ledger value: Field; circuit guard(): [] { assert(allowed, \"required\"); } circuit store(): [] { value = 1 as Field; }";
const authPolicy = { authorization: [{ state: "value", guard: "guard" }] };
for (const [body, count] of [
  ["guard(); store();", 0],
  ["if (flag) { guard(); } store();", 1],
  ["store(); guard();", 1],
  ["guard(); allowed = false; store();", 1],
  ["store(); assert(false, \"abort\");", 0],
  ["if (flag) { guard(); store(); }", 0],
  ["guard(); if (true) return []; store();", 0],
] as const) test(`guard policy: ${body}`, () => expectRule(`${authPrefix}export circuit entry(flag: Boolean): [] { ${body} }`, authPolicy, "unguarded-sensitive-state-write", count));

test("guard calls do not carry over between separate entrypoint analyses", () => {
  expectRule(`${authPrefix}export circuit first(): [] { guard(); store(); } export circuit second(): [] { store(); }`, authPolicy, "unguarded-sensitive-state-write", 1);
});

const statePrefix = "export enum Phase { OPEN, CLOSED } export ledger phase: Phase;";
const statePolicy = { transitions: [{ state: "phase", from: "CLOSED", to: "OPEN" }] };
for (const [body, count] of [
  ["phase = Phase.OPEN;", 1],
  ["assert(phase == Phase.OPEN, \"open\"); phase = Phase.OPEN;", 0],
  ["assert(phase != Phase.CLOSED, \"not closed\"); phase = Phase.OPEN;", 0],
  ["assert(phase == Phase.CLOSED, \"closed\"); phase = Phase.OPEN;", 1],
  ["phase = Phase.CLOSED;", 0],
  ["phase = Phase.CLOSED; phase = Phase.OPEN;", 1],
  ["phase = Phase.OPEN; assert(false, \"abort\");", 0],
] as const) test(`transition policy: ${body}`, () => expectRule(`${statePrefix}export circuit entry(): [] { ${body} }`, statePolicy, "forbidden-state-transition", count));

const commitPrefix = "import CompactStandardLibrary; witness secret(): Field; witness random(): Bytes<32>;";
for (const [body, count] of [
  ['return persistentCommit<Field>(secret(), pad(32, ""));', 1],
  ["return persistentCommit<Field>(secret(), random());", 0],
  ['return persistentCommit<Field>(1 as Field, pad(32, ""));', 0],
  ['persistentCommit<Field>(secret(), pad(32, "")); return pad(32, "");', 0],
  ['return disclose(persistentHash<Field>(secret()));', 0],
  ['if (false) { return persistentCommit<Field>(secret(), pad(32, "")); } return pad(32, "");', 0],
] as const) test(`commitment review: ${body}`, () => expectRule(`${commitPrefix}export circuit entry(): Bytes<32> { ${body} }`, {}, "predictable-commitment-randomness", count));

for (const [body, count] of [
  ['assert(flag, "first"); assert(!flag, "second");', 1],
  ['assert(!flag, "first"); assert(flag, "second");', 1],
  ['assert(flag, "first"); assert(flag, "second");', 0],
  ['assert(1 == 0x01, "same");', 0],
  ['if (false) { assert(false, "unreachable"); }', 0],
  ['if (true) return []; assert(false, "unreachable");', 0],
] as const) test(`assertion constraints: ${body}`, () => expectRule(`export circuit entry(flag: Boolean): [] { ${body} }`, {}, "impossible-assertion", count));

test("constraints do not leak between witness invocations", () => {
  expectRule('witness flag(): Boolean; export circuit entry(): [] { assert(flag(), "first"); assert(!flag(), "independent"); }', {}, "impossible-assertion", 0);
});

test("work estimates expand loops and callees without inventing proof rows", () => {
  analyze("circuit helper(): Field { return 1 as Field; } export circuit entry(): [] { for (const index of 0..3) { helper(); } }", facts => {
    const estimate = estimateWork(facts.program, facts.program.entries[0])!;
    assert.equal(estimate.model, "expanded-syntax-upper-bound-v1");
    assert.ok(estimate.units > 5);
    assert.ok(facts.program.functions.get(facts.program.entries[0])!.cfg.dominators().get(1)!.has(0));
  });
});

test("invalid policy subjects and Boolean guard results fail visibly", () => {
  withFiles({ "main.compact": "export ledger value: Field; circuit guard(): Boolean { return true; } export circuit entry(): [] { value = 0 as Field; }" }, directory => {
    for (const policies of [{ authorization: [{ state: "typo", guard: "guard" }] }, { authorization: [{ state: "value", guard: "guard" }] }]) assert.equal(scanFile(resolve(directory, "main.compact"), { policies }).diagnostics[0].code, "invalid-policy");
  });
});

test("constructor transition reasoning starts from default ledger values", () => {
  expectRule(`${statePrefix}constructor() { phase = Phase.OPEN; }`, statePolicy, "forbidden-state-transition", 0);
});
test("unavailable work estimates cannot silently pass a configured budget", () => {
  withFiles({ "main.compact": "circuit hidden(): [] { hidden(); } export circuit entry(): [] {}" }, directory => {
    const result = scanFile(resolve(directory, "main.compact"), { policies: { workBudgets: [{ circuit: "hidden", maxUnits: 100 }] } });
    assert.equal(result.status, "incomplete");
    assert.ok(result.diagnostics.some(diagnostic => diagnostic.code === "work-estimate-unavailable"));
  });
});
