import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile } from "../src/index.js";
import type { AnalysisFacts } from "../src/dataflow/index.js";
import { roleBootstrapObservations } from "../src/analysis/role-bootstrap.js";
import { missingRoleBootstrap as rule, roleBootstrapFindings } from "../src/detectors/role-bootstrap.js";
import { human, sarif } from "../src/reporting/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const external = process.env.OZ_COMPACT_TEST;
const searchPaths = external ? [resolve(external, "contracts/src")] : [];
const header = `pragma language_version >= 0.26.0;
import CompactStandardLibrary;
import "access/ShieldedAccessControl" prefix SAC_;
`;
const grant = `export circuit grant(role: SAC_RoleIdentifier, account: SAC_AccountIdentifier): [] { SAC_grantRole(role,account); }`;
const ctor = (seed = "") => `constructor(salt: Bytes<32>, admin: SAC_AccountIdentifier) { SAC_initialize(salt); ${seed} }`;

function check(source: string, expected: number, extras: Record<string, string> = {}): void {
  withFiles({ "main.compact": source, ...extras }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file, searchPaths);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(file, searchPaths);
    let previous: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.completedEntries, program.entries);
      const findings = rule.run(facts);
      assert.equal(findings.length, expected);
      previous ??= findings; assert.deepEqual(findings, previous);
    }
    for (const experimentalCounterQueries of [false, true]) {
      const result = scanFile(file, { searchPaths, detectors: [rule.id], experimentalCounterQueries });
      assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
      assert.deepEqual(result.findings, previous);
    }
  });
}

test("initialized authenticated role tree without any seeding route reports", { skip: !external }, () => check(header + ctor() + grant, 1));

test("constructor seeds and delayed dynamic-role grants are valid alternative setup routes", { skip: !external }, () => {
  check(header + ctor("SAC__grantRole(SAC_DEFAULT_ADMIN_ROLE(),admin);") + grant, 0);
  check(header + ctor() + grant + `
circuit seed(role: SAC_RoleIdentifier, account: SAC_AccountIdentifier): [] { SAC__grantRole(role,account); }
export circuit bootstrap(role: SAC_RoleIdentifier, account: SAC_AccountIdentifier): [] { seed(role,account); }`, 0);
});

test("direct imported raw-grant export is a bootstrap route", { skip: !external }, () => check(header + ctor() + grant + `export { SAC__grantRole };`, 0));

test("application storage reads and direct insertion conservatively withhold absence", { skip: !external }, () => {
  check(header + ctor() + grant + `export circuit full(): Boolean { return SAC__operatorRoles.isFull(); }`, 0);
  check(header + ctor() + grant + `export circuit bootstrap(value: SAC_RoleCommitment): [] { SAC__operatorRoles.insert(disclose(value)); }`, 0);
});

test("zero-iteration loop and captured callback storage references conservatively withhold absence", { skip: !external }, () => {
  check(header + ctor() + `export circuit grant(role: SAC_RoleIdentifier, account: SAC_AccountIdentifier): [] {
    for (const item of 0..0) { const observed = SAC__adminRoles.isEmpty(); }
    SAC_grantRole(role, account);
  }`, 0);
  check(header + ctor() + grant + `export circuit flags(): Vector<0, Boolean> {
    return map((item: Field): Boolean => SAC__adminRoles.isEmpty(), default<Vector<0, Field>>);
  }`, 0);
});

test("same-named custom module and modified authenticated bytes do not acquire library requirements", () => {
  const source = `module ShieldedAccessControl {
    export new type RoleIdentifier = Bytes<32>; export new type AccountIdentifier = Bytes<32>;
    export circuit initialize(salt: Bytes<32>): [] {}
    export circuit grantRole(role: RoleIdentifier, account: AccountIdentifier): [] {}
  }
  import ShieldedAccessControl prefix SAC_;
  constructor(salt: Bytes<32>, admin: SAC_AccountIdentifier) { SAC_initialize(salt); }
  ${grant}`;
  check(source, 0);
  if (external) check(header + ctor() + grant, 0, {
    "access/ShieldedAccessControl.compact": readFileSync(resolve(external, "contracts/src/access/ShieldedAccessControl.compact"), "utf8") + "\n// Unauthenticated modified copy.\n",
    "utils/Utils.compact": readFileSync(resolve(external, "contracts/src/utils/Utils.compact"), "utf8"),
  });
});

test("upstream test mock exposes deliberate delayed bootstrap and remains quiet", { skip: !external }, () => {
  const file = resolve(external!, "contracts/src/access/test/mocks/MockShieldedAccessControl.compact");
  const report = scanFile(file, { searchPaths, detectors: [rule.id] });
  assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
  assert.deepEqual(report.findings, []);
});

test("source budget and missing constructor histories cannot certify role-bootstrap absence", { skip: !external }, () => {
  withFiles({ "main.compact": header + ctor() + grant }, directory => {
    const facts = new Dataflow(new Program(resolve(directory, "main.compact"), searchPaths)).analyze();
    const full = roleBootstrapObservations(facts);
    assert.equal(full.complete, true); assert.equal(full.observations.length, 1);
    assert.deepEqual(roleBootstrapObservations(facts, full.work), full);
    const exhausted = roleBootstrapObservations(facts, full.work - 1);
    assert.equal(exhausted.complete, false); assert.equal(exhausted.work, full.work);
    assert.deepEqual(exhausted.observations, []);
    assert.deepEqual(roleBootstrapFindings(facts, 1), []);
    assert.ok(facts.diagnostics.every(issue => issue.scope?.detectorId === rule.id));
    const partial: AnalysisFacts = { ...facts, diagnostics: [], paths: [], completedEntries: [] };
    assert.deepEqual(rule.run(partial), []);
    assert.ok(partial.diagnostics.every(issue => issue.code === "role-bootstrap-constructor-incomplete" && issue.scope?.kind === "rule"));
  });
});

test("rule-scoped source exhaustion preserves baseline and other selected-rule coverage in reports", { skip: !external }, () => {
  withFiles({ "main.compact": header + ctor() + grant }, directory => {
    const file = resolve(directory, "main.compact"), original = rule.run;
    try {
      // Exercise the real production consumer under a smaller source allowance.
      rule.run = facts => roleBootstrapFindings(facts, 1);
      const report = scanFile(file, { searchPaths, detectors: [rule.id, "ignored-validation-result"] });
      assert.equal(report.status, "incomplete"); assert.equal(report.coverage.baselineStatus, "complete");
      assert.ok(report.coverage.rules!.filter(row => row.detectorId === rule.id).every(row => row.status === "incomplete"));
      assert.ok(report.coverage.rules!.filter(row => row.detectorId !== rule.id).every(row => row.status === "complete"));
      assert.ok(report.diagnostics.every(issue => issue.scope?.detectorId === rule.id));
      assert.match(human(report), /Baseline analysis: complete; selected rules: incomplete/);
      assert.match(JSON.stringify(sarif(report)), /role-bootstrap-observation-budget/);
    } finally { rule.run = original; }
  });
});

test("separate authenticated compilation units keep their bootstrap routes independent", { skip: !external }, () => {
  const library = readFileSync(resolve(external!, "contracts/src/access/ShieldedAccessControl.compact"), "utf8");
  const utils = readFileSync(resolve(external!, "contracts/src/utils/Utils.compact"), "utf8");
  check(`import CompactStandardLibrary;
import "A/access/ShieldedAccessControl" prefix A_;
import "B/access/ShieldedAccessControl" prefix B_;
constructor(salt: Bytes<32>, admin: B_AccountIdentifier) {
  A_initialize(salt); B_initialize(salt); B__grantRole(B_DEFAULT_ADMIN_ROLE(),admin);
}
export circuit grant(role: A_RoleIdentifier, account: A_AccountIdentifier): [] { A_grantRole(role,account); }`, 1,
    { "A/access/ShieldedAccessControl.compact": library, "A/utils/Utils.compact": utils,
      "B/access/ShieldedAccessControl.compact": library, "B/utils/Utils.compact": utils });
});

test("generic wrappers sharing one external dependency retain one bootstrap requirement", { skip: !external }, () => {
  const source = `import CompactStandardLibrary;
module Wrapper<#N> {
  import "access/ShieldedAccessControl" prefix SAC_;
  export circuit initialize(salt: Bytes<32>): [] { SAC_initialize(salt); }
  export circuit grant(role: Bytes<32>, account: Bytes<32>): [] {
    SAC_grantRole(role as SAC_RoleIdentifier, account as SAC_AccountIdentifier);
  }
}
import Wrapper<1> prefix A_; import Wrapper<2> prefix B_;
constructor(salt: Bytes<32>) { A_initialize(salt); }
export { A_grant, B_grant };`;
  check(source, 1);
  withFiles({ "main.compact": source }, directory => {
    const report = scanFile(resolve(directory, "main.compact"), { searchPaths, detectors: [rule.id] });
    assert.equal(report.findings.length, 1);
    assert.equal(typeof report.findings[0].metadata.instance, "string");
  });
});

test("authenticated library on an unqualified profile stays explicitly rule-incomplete", { skip: !external || !process.env.COMPACTC_035_RC1_TEST }, () => {
  withFiles({ "main.compact": header + ctor() + grant }, directory => {
    const file = resolve(directory, "main.compact");
    const compiled = validateWithCompiler(process.env.COMPACTC_035_RC1_TEST!, file, searchPaths, 30000, 2, "0.35.0-rc.1");
    assert.equal(compiled.valid, true, compiled.error);
    const report = scanFile(file, { searchPaths, detectors: [rule.id], compilerVersion: "0.35.0-rc.1" });
    assert.equal(report.status, "incomplete"); assert.equal(report.coverage.baselineStatus, "complete");
    assert.deepEqual(report.findings, []);
    assert.ok(report.diagnostics.length > 0);
    assert.ok(report.diagnostics.every(issue => issue.code === "role-bootstrap-profile-unavailable" && issue.scope?.detectorId === rule.id));
  });
});
