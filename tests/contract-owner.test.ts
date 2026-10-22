import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile } from "../src/index.js";
import type { AnalysisFacts } from "../src/dataflow/index.js";
import { contractOwnerObservations } from "../src/analysis/contract-owner.js";
import { unsupportedContractOwner as rule } from "../src/detectors/contract-owner.js";
import { defaultRecipientOrOwner } from "../src/detectors/default-address.js";
import { resolvePolicies, validatePolicies, type Policies } from "../src/policies.js";
import { human, sarif } from "../src/reporting/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const external = process.env.OZ_COMPACT_TEST;
const searchPaths = external ? [resolve(external, "contracts/src")] : [];
const policies: Policies = { callableOwnable: [{ owner: "_owner" }] };
const fixture = (kind: string) => readFileSync(`tests/corpus/known-bugs/library-contract-owner-${kind}.compact`, "utf8");
const positive = fixture("positive");
const transfer = "  Ownable__unsafeTransferOwnership(right<Bytes<32>, ContractAddress>(next));";
const replace = (body: string) => positive.replace(transfer, body);
const fake = `module Ownable {
  import CompactStandardLibrary;
  export ledger _owner: Either<Bytes<32>, ContractAddress>;
  export circuit initialize(value: Either<Bytes<32>, ContractAddress>): [] { _owner = disclose(value); }
  export circuit owner(): Either<Bytes<32>, ContractAddress> { return _owner; }
  export circuit transferOwnership(value: Either<Bytes<32>, ContractAddress>): [] { _owner = disclose(value); }
  export circuit _unsafeTransferOwnership(value: Either<Bytes<32>, ContractAddress>): [] { _owner = disclose(value); }
  export circuit renounceOwnership(): [] { _owner = left<Bytes<32>, ContractAddress>(default<Bytes<32>>); }
  export circuit assertOnlyOwner(): [] {}
}
import Ownable prefix Ownable_;`;
const namesake = positive.replace('import "access/Ownable" prefix Ownable_;', fake);

function analyze(program: Program, selected: Policies = policies, engine: "instructions" | "expressions" = "instructions", cached = true) {
  const resolved = resolvePolicies(program, selected);
  const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached,
    "equivalent-states", false, true, "all").analyze();
  assert.deepEqual(facts.diagnostics, []);
  assert.deepEqual(facts.completedEntries, program.entries);
  return { facts, resolved };
}

function check(source: string, expected: number, code?: string, extras: Record<string, string> = {}) {
  withFiles({ "main.compact": source, ...extras }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file, searchPaths);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const program = new Program(file, searchPaths);
    let previous: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const { facts, resolved } = analyze(program, policies, engine, cached);
      const observation = contractOwnerObservations(facts, resolved);
      assert.equal(observation.complete, !code);
      const findings = rule.run(facts, resolved);
      assert.equal(findings.length, expected);
      assert.ok(facts.diagnostics.every(item => item.code === code && item.scope?.detectorId === rule.id), JSON.stringify(facts.diagnostics));
      assert.equal(facts.diagnostics.length > 0, !!code);
      previous ??= findings; assert.deepEqual(findings, previous);
      for (const item of findings) {
        assert.equal(item.severity, "medium"); assert.equal(item.confidence, "high");
        assert.equal(item.metadata.activeArm, "right"); assert.equal(item.metadata.crossEntryCoverage, false);
        assert.equal(item.metadata.pathFeasibility, "not-proven"); assert.equal(item.metadata.entry, "handover");
      }
    }
    const scan = scanFile(file, { searchPaths, policies, detectors: [rule.id] });
    assert.equal(scan.status, code ? "incomplete" : "complete", JSON.stringify(scan.diagnostics));
    assert.deepEqual(scan.findings, previous);
    assert.equal(scan.coverage.baselineStatus, "complete");
    assert.ok(scan.diagnostics.every(item => item.code === code && item.scope?.detectorId === rule.id));
  });
}

test("declared callable owner: compiler-valid authenticated positive/corrected/unrelated-ledger triple", { skip: !external }, () => {
  check(positive, 1); check(fixture("corrected"), 0); check(fixture("lookalike"), 0);
  const manifest = JSON.parse(readFileSync("tests/corpus/manifest.json", "utf8")).contractOwner;
  assert.deepEqual(manifest.policies, policies);
  const report = scanFile(resolve("tests/corpus/known-bugs/library-contract-owner-positive.compact"), { searchPaths, policies, detectors: [rule.id] });
  assert.deepEqual(report.findings.map(item => item.location.line), manifest.cases[0].lines);
  assert.equal(report.findings[0].trace[0].location.file, resolve(external!, "contracts/src/access/Ownable.compact"));
});

test("explicit intent and rule selection are required; nonzero right owner has no default-address overlap", { skip: !external }, () => {
  assert.equal(rule.defaultEnabled, false); assert.equal(rule.policyRequired, true);
  withFiles({ "main.compact": positive }, directory => {
    const file = resolve(directory, "main.compact"), { facts, resolved } = analyze(new Program(file, searchPaths));
    assert.deepEqual(rule.run(facts), []);
    assert.deepEqual(defaultRecipientOrOwner.run(facts, resolved), []);
    const report = scanFile(file, { searchPaths, detectors: [rule.id] });
    assert.equal(report.status, "complete"); assert.deepEqual(report.findings, []);
    assert.ok(report.coverage.rules!.every(row => row.status === "not-applicable"));
    assert.ok(!scanFile(file, { searchPaths, policies }).findings.some(item => item.detectorId === rule.id));
  });
});

test("restored owner, later abort, explicit left/zero renunciation and separate branch histories remain quiet", { skip: !external }, () => {
  check(replace(transfer + '\n  Ownable__unsafeUncheckedTransferOwnership(left<Bytes<32>, ContractAddress>(pad(32,"restored")));'), 0);
  check(replace(transfer + '\n  assert(false, "later abort");'), 0);
  check(replace('  Ownable_renounceOwnership();'), 0);
  const branch = replace(`  if (disclose(next.bytes == default<Bytes<32>>)) {
    Ownable__unsafeUncheckedTransferOwnership(right<Bytes<32>, ContractAddress>(next));
    assert(false, "rejected right");
  } else {
    Ownable__unsafeUncheckedTransferOwnership(left<Bytes<32>, ContractAddress>(pad(32,"account")));
  }`).replace('  assert(next.bytes != default<Bytes<32>>, "nonzero destination");\n', '');
  check(branch, 0);
});

test("compiler-valid aggregate reconstruction honors final tags and payload changes", { skip: !external }, () => {
  check(replace(transfer + '\n  Ownable__owner = Either<Bytes<32>, ContractAddress> { is_left: true, left: Ownable__owner.left, right: Ownable__owner.right };'), 0);
  check(replace('  Ownable__owner = left<Bytes<32>, ContractAddress>(pad(32,"account"));\n  Ownable__owner = Either<Bytes<32>, ContractAddress> { is_left: false, left: Ownable__owner.left, right: Ownable__owner.right };'), 1);
  check(replace(transfer + '\n  Ownable__owner = Either<Bytes<32>, ContractAddress> { is_left: Ownable__owner.is_left, left: Ownable__owner.left, right: ContractAddress { bytes: pad(32,"replacement") } };'), 1);
  check(replace(transfer + '\n  Ownable__owner = Either<Bytes<32>, ContractAddress> { is_left: Ownable__owner.is_left, left: pad(32,"inactive"), right: Ownable__owner.right };'), 1);
  check(replace(transfer + '\n  Ownable__owner = disclose(Either<Bytes<32>, ContractAddress> { is_left: flag, left: Ownable__owner.left, right: Ownable__owner.right });').replace('handover(next: ContractAddress)', 'handover(next: ContractAddress, flag: Boolean)'), 0, "contract-owner-tag-unavailable");
});

test("constructors, direct owner assignments and immutable later tag constraints are supported", { skip: !external }, () => {
  check(replace('  Ownable__owner = disclose(right<Bytes<32>, ContractAddress>(next));'), 1);
  check(replace('  const value = right<Bytes<32>, ContractAddress>(next);\n  setOwner(value);') + '\ncircuit setOwner(value: Either<Bytes<32>, ContractAddress>): [] { Ownable__unsafeUncheckedTransferOwnership(value); }', 1);
  const constrained = replace('  Ownable__owner = disclose(Either<Bytes<32>, ContractAddress> { is_left: flag, left: default<Bytes<32>>, right: next });\n  assert(flag == false, "right tag");')
    .replace('handover(next: ContractAddress)', 'handover(next: ContractAddress, flag: Boolean)');
  check(constrained, 1);
  const changed = constrained.replace('  assert(flag == false, "right tag");', '  Ownable__owner = left<Bytes<32>, ContractAddress>(pad(32,"account"));\n  assert(Ownable__owner.is_left, "current revision");');
  check(changed, 0);
  const source = fixture("corrected").replace('  Ownable_initialize(left<Bytes<32>, ContractAddress>(initialOwner));',
    '  Ownable_initialize(left<Bytes<32>, ContractAddress>(initialOwner));\n  Ownable__owner = right<Bytes<32>, ContractAddress>(ContractAddress { bytes: pad(32,"contract") });');
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, file, searchPaths).valid, true);
    const program = new Program(file, searchPaths);
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const { facts, resolved } = analyze(program, policies, engine, cached);
      const findings = rule.run(facts, resolved);
      assert.equal(findings.length, 1); assert.equal(findings[0].metadata.entry, "constructor");
      assert.deepEqual(facts.diagnostics, []);
    }
    assert.equal(scanFile(file, { searchPaths, policies, detectors: [rule.id] }).findings.length, 1);
  });
});

test("partial tag/payload facts never report a stale root value", { skip: !external }, () => {
  // Compact 0.34.0 source rejects direct native Either field assignment. These
  // synthetic owned fact controls exercise the consumer boundary, not source
  // applicability or compiler qualification of that assignment syntax.
  withFiles({ "main.compact": positive }, directory => {
    const program = new Program(resolve(directory, "main.compact"), searchPaths);
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const { facts, resolved } = analyze(program, policies, engine, cached);
      const handover = program.entries.find(entry => program.symbols.get(entry)!.name === "handover")!;
      const base = { flows: [], ledger: new Set<string>() };
      for (const [region, after, count, code] of [
        [["field:is_left"], { ...base, constantKind: "boolean" as const, constant: "true" }, 0, undefined],
        [["field:is_left"], { ...base, constantKind: "boolean" as const, constant: "false" }, 1, undefined],
        [["field:is_left"], { ...base, type: "Boolean" }, 0, "contract-owner-tag-unavailable"],
        [["field:left"], { ...base, type: "Bytes<32>" }, 1, undefined],
        [["field:right", "field:bytes"], { ...base, type: "Bytes<32>" }, 1, undefined],
      ] as const) {
        const changed: AnalysisFacts = { ...facts, diagnostics: [], paths: facts.paths.map(path => path.entry !== handover ? path : {
          ...path, writes: [...path.writes.slice(0, -1),
            // The false descendant write must also override a preceding left
            // root, rather than merely repeating the positive's right tag.
            "constant" in after && after.constant === "false" ? { ...path.writes.at(-1)!, after: { ...path.writes.at(-1)!.after,
              fields: { ...path.writes.at(-1)!.after.fields, is_left: { ...base, constantKind: "boolean", constant: "true" } } } }
              : path.writes.at(-1)!,
            { ...path.writes.at(-1)!, region: [...region], after }],
        }) };
        assert.equal(rule.run(changed, resolved).length, count);
        assert.deepEqual(changed.diagnostics.map(item => item.code), code ? [code] : []);
      }
    }
  });
});

test("namesake and changed Ownable/Utils providers stay rule-scoped incomplete", { skip: !external }, () => {
  const library = readFileSync(resolve(external!, "contracts/src/access/Ownable.compact"), "utf8");
  const utils = readFileSync(resolve(external!, "contracts/src/utils/Utils.compact"), "utf8");
  check(namesake, 0, "contract-owner-provider-unavailable");
  check(positive, 0, "contract-owner-provider-unavailable", { "access/Ownable.compact": library + '\n// Owned modified provider.\n', "utils/Utils.compact": utils });
  check(positive, 0, "contract-owner-provider-unavailable", { "access/Ownable.compact": library, "utils/Utils.compact": utils + '\n// Owned modified dependency.\n' });
});

test("separate authenticated instances use exact selectors and cannot exchange owner writes", { skip: !external }, () => {
  const library = readFileSync(resolve(external!, "contracts/src/access/Ownable.compact"), "utf8");
  const utils = readFileSync(resolve(external!, "contracts/src/utils/Utils.compact"), "utf8");
  const source = positive.replace('import "access/Ownable" prefix Ownable_;', 'import "A/access/Ownable" prefix Ownable_;\nimport "B/access/Ownable" prefix Other_;')
    .replace('  Ownable_initialize(left<Bytes<32>, ContractAddress>(initialOwner));', '  Ownable_initialize(left<Bytes<32>, ContractAddress>(initialOwner));\n  Other_initialize(left<Bytes<32>, ContractAddress>(initialOwner));')
    .replace(transfer, '  Other__unsafeTransferOwnership(right<Bytes<32>, ContractAddress>(next));');
  withFiles({ "main.compact": source, "A/access/Ownable.compact": library, "A/utils/Utils.compact": utils,
    "B/access/Ownable.compact": library, "B/utils/Utils.compact": utils }, directory => {
    const file = resolve(directory, "main.compact"), program = new Program(file);
    if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, file).valid, true);
    assert.throws(() => resolvePolicies(program, policies), /resolves to 2/);
    const owners = program.activeSymbols().filter(symbol => symbol.name === "_owner");
    const selected = owners.find(symbol => symbol.span.file === resolve(directory, "A/access/Ownable.compact"))!;
    const other = owners.find(symbol => symbol.id !== selected.id)!;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const { facts, resolved } = analyze(program, { callableOwnable: [{ owner: selected.id }] }, engine, cached);
      assert.deepEqual(rule.run(facts, resolved), []); assert.deepEqual(facts.diagnostics, []);
      const both = resolvePolicies(program, { callableOwnable: [{ owner: selected.id }, { owner: other.id }] });
      assert.equal(rule.run(facts, both).length, 1); assert.deepEqual(facts.diagnostics, []);
    }
    assert.equal(scanFile(file, { policies: { callableOwnable: [{ owner: other.id }] }, detectors: [rule.id] }).findings.length, 1);
  });
});

test("unsupported independent relations preserve valid findings and unrelated baseline coverage", { skip: !external }, () => {
  const source = replace(transfer + '\n  backupOwner = disclose(right<Bytes<32>, ContractAddress>(next));')
    + '\nexport ledger backupOwner: Either<Bytes<32>, ContractAddress>;\nexport ledger unrelatedUnused: Boolean;\n';
  const selected: Policies = { callableOwnable: [{ owner: "backupOwner" }, { owner: "_owner" }, { owner: "backupOwner" }] };
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact"), program = new Program(file, searchPaths);
    if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, file, searchPaths).valid, true);
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const { facts, resolved } = analyze(program, selected, engine, cached);
      assert.equal(resolved.callableOwnable!.length, 2);
      assert.equal(rule.run(facts, resolved).length, 1);
      assert.deepEqual(facts.diagnostics.map(item => item.code), ["contract-owner-provider-unavailable"]);
      assert.ok(facts.diagnostics[0].message.includes("backupOwner"));
    }
    const baseline = scanFile(file, { searchPaths, detectors: ["unused-declaration"] });
    const report = scanFile(file, { searchPaths, policies: selected, detectors: [rule.id, "unused-declaration"] });
    assert.equal(report.status, "incomplete"); assert.equal(report.coverage.baselineStatus, "complete");
    assert.deepEqual(report.findings.filter(item => item.detectorId !== rule.id), baseline.findings);
    assert.equal(report.findings.filter(item => item.detectorId === rule.id).length, 1);
    assert.ok(report.coverage.rules!.filter(row => row.detectorId !== rule.id).every(row => row.status === "complete"));
    assert.match(human(report), /Baseline analysis: complete; selected rules: incomplete/);
    assert.match(JSON.stringify(sarif(report)), /contract-owner-provider-unavailable/);
  });
});

test("missing predicates, overlapping unknown writes, incomplete no-path entries and budgets fail closed", { skip: !external }, () => {
  withFiles({ "main.compact": positive }, directory => {
    const program = new Program(resolve(directory, "main.compact"), searchPaths);
    const { facts, resolved } = analyze(program);
    const handover = program.entries.find(entry => program.symbols.get(entry)!.name === "handover")!;
    const damagedFacts: AnalysisFacts[] = [
      { ...facts, diagnostics: [], predicateScope: "witness" as const },
      { ...facts, diagnostics: [], paths: facts.paths.map(path => ({ ...path, predicates: undefined })) },
      { ...facts, diagnostics: [], paths: facts.paths.filter(path => path.entry !== handover), completedEntries: facts.completedEntries.filter(entry => entry !== handover) },
    ];
    for (const damaged of damagedFacts) {
      assert.deepEqual(rule.run(damaged, resolved), []);
      assert.ok(damaged.diagnostics.some(item => item.code === "contract-owner-observation-unavailable" && item.scope?.entry === handover));
      assert.ok(damaged.diagnostics.every(item => item.scope?.detectorId === rule.id));
    }
    const partial: AnalysisFacts = { ...facts, diagnostics: [], paths: facts.paths.map(path => path.entry !== handover ? path : {
      ...path, writes: [...path.writes, { ...path.writes.at(-1)!, region: ["*"], after: { flows: [], ledger: new Set() } }],
    }) };
    assert.deepEqual(rule.run(partial, resolved), []);
    assert.equal(partial.diagnostics[0].code, "contract-owner-final-write-unavailable");
    const missingSite: AnalysisFacts = { ...facts, diagnostics: [], paths: facts.paths.map(path => path.entry !== handover ? path : {
      ...path, writes: path.writes.map(write => ({ ...write, callSites: undefined })),
    }) };
    assert.deepEqual(rule.run(missingSite, resolved), []);
    assert.equal(missingSite.diagnostics[0].code, "contract-owner-observation-unavailable");
    const missingTag: AnalysisFacts = { ...facts, diagnostics: [], paths: facts.paths.map(path => path.entry !== handover ? path : {
      ...path, writes: path.writes.map(write => ({ ...write, after: { flows: [], ledger: new Set(), constantKind: "boolean", constant: "false" } })),
    }) };
    assert.deepEqual(rule.run(missingTag, resolved), []);
    assert.equal(missingTag.diagnostics[0].code, "contract-owner-tag-unavailable");
    const exhausted = contractOwnerObservations(facts, resolved, 1);
    assert.equal(exhausted.complete, false); assert.deepEqual(exhausted.observations, []);
    assert.ok(exhausted.diagnostics.every(item => item.code === "contract-owner-observation-budget"));
    const scan = scanFile(program.root, { searchPaths, policies, detectors: [rule.id], maxValues: 1 });
    assert.equal(scan.status, "incomplete"); assert.deepEqual(scan.findings, []);
    assert.ok(scan.diagnostics.some(item => item.scope?.detectorId === rule.id));
  });
});

test("unqualified ZKIR3 and compiler prerelease profiles stay rule-scoped incomplete", { skip: !external }, () => {
  const file = resolve("tests/corpus/known-bugs/library-contract-owner-positive.compact");
  for (const options of [{ zkirVersion: 3 as const }, { compilerVersion: "0.35.0-rc.1" as const }]) {
    const report = scanFile(file, { searchPaths, policies, detectors: [rule.id], ...options });
    assert.equal(report.status, "incomplete"); assert.equal(report.coverage.baselineStatus, "complete");
    assert.deepEqual(report.findings, []);
    assert.ok(report.diagnostics.every(item => item.code === "contract-owner-profile-unavailable" && item.scope?.detectorId === rule.id));
  }
  if (process.env.COMPACTC_035_RC1_TEST) for (const kind of ["positive", "corrected", "lookalike"]) {
    const compiled = validateWithCompiler(process.env.COMPACTC_035_RC1_TEST, resolve(`tests/corpus/known-bugs/library-contract-owner-${kind}.compact`), searchPaths, 30000, 2, "0.35.0-rc.1");
    assert.equal(compiled.valid, true, `${kind}: ${compiled.error}`);
  }
});

test("callable Ownable arrays, selectors and native owner types are strictly validated", () => {
  withFiles({ "main.compact": namesake + '\nexport ledger wrong: Field;\n' }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const location = program.rootSource.ast.span;
    assert.deepEqual(validatePolicies(policies, location), policies);
    assert.equal(resolvePolicies(program, policies).callableOwnable!.length, 1);
    assert.equal("callableOwnable" in resolvePolicies(program), false);
    for (const value of [
      { callableOwnable: [{}] }, { callableOwnable: [{ owner: "", extra: true }] }, { callableOwnable: [{ owner: "_owner", extra: true }] },
      { callableOwnable: [{ owner: 1 }] }, { callableOwnable: Array(1) }, { callableOwnable: Array(65).fill({ owner: "_owner" }) },
    ]) assert.throws(() => validatePolicies(value, location), /policy|policies|Missing|Invalid/);
    assert.throws(() => resolvePolicies(program, { callableOwnable: [{ owner: "wrong" }] }), /native Either/);
    assert.throws(() => resolvePolicies(program, { callableOwnable: [{ owner: "missing" }] }), /resolves to 0/);
    assert.throws(() => resolvePolicies(program, { callableOwnable: [{ owner: "increment" }] }), /resolves to 0/);
  });
});
