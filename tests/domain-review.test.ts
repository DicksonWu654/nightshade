import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { Dataflow, Program, scanFile } from "../src/index.js";
import { publicTwoComponentDomainReview as rule } from "../src/detectors/domain-review.js";
import { observeDomainReview } from "../src/analysis/domain-review-observation.js";
import { detectors } from "../src/detectors/index.js";
import { domainReviewScope } from "../src/semantic/domain-review.js";
import { withFiles } from "./helpers.js";

const draft = (name: string) => resolve("tests/corpus/drafts/owner-domain43", `${name}.compact`);
const frozen = (name: string) => resolve("tests/corpus/synthetic-regressions/privacy16/domain-separated-owner", `${name}.compact`);
const source = readFileSync(frozen("positive"), "utf8");

test("compiler-qualified owned manifest labels preserve the restricted structural scope", () => {
  const manifest = JSON.parse(readFileSync("tests/corpus/manifest.json", "utf8")).publicTwoComponentDomainReview43;
  assert.equal(manifest.detector, rule.id);
  assert.equal(manifest.fullRecordRecallCredit, false);
  for (const row of manifest.cases) {
    const result = scanFile(resolve("tests/corpus", row.file), { detectors: [rule.id] });
    assert.equal(result.status, row.status ?? "complete", `${row.file}: ${JSON.stringify(result.diagnostics)}`);
    assert.deepEqual(result.findings.map(finding => finding.location.line), row.lines, row.file);
  }
});

test("two scalar component review retains frozen and compiler-qualified source boundaries", () => {
  for (const path of [frozen("positive"), draft("positive"), draft("lookalike"), draft("no-authorization-consumer"),
    draft("unrelated-nonzero-guard"), draft("public-global-id"), resolve("tests/corpus/drafts/state37/publication/intentional-shared-credential.compact")]) {
    const result = scanFile(path, { detectors: [rule.id] });
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.equal(result.findings.length, 1, path);
    assert.equal(result.findings[0].severity, "info");
    assert.equal(result.findings[0].metadata.componentRoles, "not-inferred");
    assert.equal(result.findings[0].metadata.globallyFeasibleDefaults, "not-proven");
  }
  for (const path of [frozen("corrected"), frozen("lookalike"), draft("corrected"), draft("salt-only-correction"),
    draft("self-only-correction"), draft("helper-self-binding"), draft("late-salt-guard"), draft("global-id-lookalike"),
    draft("single-parameter-struct"), draft("constant-identifier"), resolve("tests/corpus/drafts/state37/publication/instance-constant-lookalike.compact")]) {
    const result = scanFile(path, { detectors: [rule.id] });
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.equal(result.findings.length, 0, path);
  }
  assert.equal(detectors[0].id, "ledger-bound-preimage-publication");
  assert.equal(detectors.at(-1)!.id, "configured-membership-capacity-review");
  assert.equal(rule.defaultEnabled, false);
  assert.equal(scanFile(frozen("positive")).findings.some(finding => finding.detectorId === rule.id), false);
  withFiles({ "main.compact": source.replaceAll("OwnerCommitment", "Pair").replaceAll("salt", "alpha").replaceAll("ownerSecret", "beta").replaceAll("owner", "second") }, directory => {
    const renamed = scanFile(resolve(directory, "main.compact"), { detectors: [rule.id] });
    assert.equal(renamed.status, "complete", JSON.stringify(renamed.diagnostics));
    assert.equal(renamed.findings.length, 1);
  });
});

test("exact identities and findings agree across instruction/reference and cached/uncached execution", () => {
  for (const path of [frozen("positive"), draft("helper-self-binding"), draft("salt-only-correction")]) {
    const program = new Program(path);
    const entry = program.entries.find(id => program.symbols.get(id)?.name === "initialize")!;
    let expected: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached).analyzeDomainReviewEntry(entry);
      const findings = rule.run(facts);
      assert.deepEqual(facts.diagnostics, [], `${engine}/${cached}`);
      expected ??= findings;
      assert.deepEqual(findings, expected, `${engine}/${cached}`);
    }
  }
});

test("metadata selects the published native hash and its exact supplied parameters", () => {
  const result = scanFile(frozen("positive"), { detectors: [rule.id] });
  const finding = result.findings[0];
  assert.equal(finding.location.line, 7);
  assert.equal(finding.source!.line, 7);
  assert.equal(source.slice(finding.source!.start, finding.source!.end), "persistentHash<OwnerCommitment>(OwnerCommitment { salt: salt, owner: ownerSecret })");
  const components = finding.metadata.components as { identity: string; location: { start: number; end: number } }[];
  assert.deepEqual(components.map(component => source.slice(component.location.start, component.location.end)), ["salt: Bytes<32>", "ownerSecret: Bytes<32>"]);
  assert.equal(new Set(components.map(component => component.identity)).size, 2);
  const unrelated = source.replace("export ledger commitment", "export ledger noise: Bytes<32>;\nexport ledger commitment")
    .replace("  // Default salt", '  noise = disclose(persistentHash<Bytes<32>>(pad(32, "irrelevant")));\n  // Default salt');
  withFiles({ "main.compact": unrelated }, directory => {
    const result = scanFile(resolve(directory, "main.compact"), { detectors: [rule.id] });
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].source!.line, 9);
  });
});

test("either component exclusion narrows scope without claiming a general domain repair", () => {
  for (const guard of ['salt != pad(32, "")', 'ownerSecret != pad(32, "")', 'salt == pad(32, "nonzero")', 'ownerSecret == pad(32, "nonzero")', 'salt != ownerSecret']) {
    const guarded = source.replace("  // Default salt", `  assert(${guard}, "restriction");\n  // Default salt`);
    withFiles({ "main.compact": guarded }, directory => {
      const result = scanFile(resolve(directory, "main.compact"), { detectors: [rule.id] });
      assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
      assert.equal(result.findings.length, 0, guard);
    });
  }
  for (const guard of ['salt == pad(32, "")', 'salt == ownerSecret', 'salt != pad(32, "nonzero")']) {
    withFiles({ "main.compact": source.replace("  // Default salt", `  assert(${guard}, "restriction");\n  // Default salt`) }, directory => {
      const result = scanFile(resolve(directory, "main.compact"), { detectors: [rule.id] });
      assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
      assert.equal(result.findings.length, 1, guard);
    });
  }
});

test("path guards remain separate and late checks constrain full successful histories", () => {
  const branched = source.replace("ownerSecret: Bytes<32>)", "ownerSecret: Bytes<32>, flag: Boolean)")
    .replace("  // Default salt", '  if (disclose(flag)) { assert(salt != pad(32, ""), "restriction"); }\n  // Default salt');
  withFiles({ "main.compact": branched }, directory => {
    const result = scanFile(resolve(directory, "main.compact"), { detectors: [rule.id] });
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.equal(result.findings.length, 1);
    const tight = scanFile(resolve(directory, "main.compact"), { detectors: [rule.id], maxPaths: 1 });
    assert.equal(tight.status, "incomplete");
    assert.equal(tight.findings.length, 0);
  });
  const both = branched.replace('  if (disclose(flag)) { assert(salt != pad(32, ""), "restriction"); }',
    '  if (disclose(flag)) { assert(salt != pad(32, ""), "restriction"); } else { assert(ownerSecret != pad(32, ""), "restriction"); }');
  withFiles({ "main.compact": both }, directory => {
    const result = scanFile(resolve(directory, "main.compact"), { detectors: [rule.id] });
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.equal(result.findings.length, 0);
  });
});

test("self bytes bind the preimage while a transformed self computation stays unavailable", () => {
  const bound = readFileSync(draft("self-only-correction"), "utf8")
    .replace("selfAddress: ContractAddress", "selfBytes: Bytes<32>")
    .replaceAll("selfAddress: kernel.self()", "selfBytes: kernel.self().bytes");
  for (const [value, expected] of [[bound, "complete"], [bound.replaceAll("selfBytes: kernel.self().bytes", "selfBytes: persistentHash<Bytes<32>>(kernel.self().bytes)"), "incomplete"]] as const) {
    withFiles({ "main.compact": value }, directory => {
      const result = scanFile(resolve(directory, "main.compact"), { detectors: [rule.id] });
      assert.equal(result.status, expected, JSON.stringify(result.diagnostics));
      assert.equal(result.findings.length, 0);
    });
  }
});

test("opaque guards, mixed preimages and unavailable histories never certify clean coverage", () => {
  const opaque = scanFile(draft("opaque-salt-guard"), { detectors: [rule.id] });
  assert.equal(opaque.status, "incomplete"); assert.equal(opaque.findings.length, 0);
  assert.ok(opaque.diagnostics.some(issue => issue.code === "domain-review-evidence-unavailable"));
  for (const edit of [(value: string) => value.replace("salt: salt,", "salt: persistentHash<Bytes<32>>(salt),"),
    (value: string) => value.replace("OwnerCommitment { salt: salt, owner: ownerSecret }", "OwnerCommitment { salt: salt, owner: commitment }")]) {
    withFiles({ "main.compact": edit(source) }, directory => {
      const result = scanFile(resolve(directory, "main.compact"), { detectors: [rule.id] });
      assert.equal(result.status, "incomplete"); assert.equal(result.findings.length, 0);
    });
  }
  const program = new Program(frozen("positive"));
  const entry = program.entries[0];
  for (const lose of [(facts: ReturnType<Dataflow["analyze"]>) => { facts.paths[0].predicates = undefined; },
    (facts: ReturnType<Dataflow["analyze"]>) => { facts.paths[0].writes[0].after.directDigest = undefined; }]) {
    const facts = new Dataflow(program).analyzeDomainReviewEntry(entry);
    lose(facts);
    assert.deepEqual(rule.run(facts), []);
    assert.ok(facts.diagnostics.some(issue => issue.code === "domain-review-evidence-unavailable"));
  }
});

test("preparation, proof and retained findings share the original work/value limits", () => {
  const program = new Program(frozen("positive"));
  const entry = program.entries[0];
  for (const options of [{ maxSteps: 1 }, { maxSteps: 80 }, { maxValues: 1 }, { maxValues: 80 }]) {
    const result = scanFile(frozen("positive"), { detectors: [rule.id], ...options });
    assert.equal(result.status, "incomplete", JSON.stringify(options));
    assert.equal(result.findings.length, 0);
    assert.ok(result.coverage.rules!.some(row => row.detectorId === rule.id && row.status === "incomplete"));
  }
  const prep = observeDomainReview(program, rule, { maxValues: 1 });
  assert.equal(prep.work.metrics.sources, 0);
  assert.ok(prep.work.metrics.abstractValues > 1);
  const facts = new Dataflow(program).analyzeDomainReviewEntry(entry);
  const before = { ...facts.metrics };
  assert.equal(rule.run(facts).length, 1);
  assert.ok(facts.metrics.steps > before.steps);
  assert.ok(facts.metrics.abstractValues > before.abstractValues);
  const tight = new Dataflow(program).analyzeDomainReviewEntry(entry);
  tight.domainReviewEvidence!.maxValues = tight.metrics.abstractValues + 5;
  assert.deepEqual(rule.run(tight), []);
  assert.ok(tight.diagnostics.length);
});

test("baseline-incomplete entries and unresolved closures cannot certify structural absence", () => {
  withFiles({ "main.compact": "pragma language_version >= 0.26.0; export circuit quiet(): [] {}" }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    assert.throws(() => domainReviewScope(program, program.entries[0], () => false), /shared allowance/);
    const complete = observeDomainReview(program, rule, {});
    assert.equal(complete.coverage[0].status, "not-applicable");
    const unavailable = observeDomainReview(program, rule, {}, new Set());
    assert.deepEqual(unavailable.findings, []);
    assert.ok(unavailable.diagnostics.length);
    assert.equal(unavailable.coverage[0].status, "incomplete");
    assert.equal(unavailable.coverage[0].evidence, "unavailable");
    program.functions.get(program.entries[0])!.calls.add("owned-model-test::unresolved-helper");
    const missingClosure = observeDomainReview(program, rule, {});
    assert.deepEqual(missingClosure.findings, []);
    assert.ok(missingClosure.diagnostics.some(issue => issue.message.includes("closure is unresolved")));
    assert.equal(missingClosure.coverage[0].status, "incomplete");
  });
  const program = new Program(frozen("positive"));
  const node = program.functions.get(program.entries[0])!.cfg.nodes.find(node => node.expr)!;
  node.expr = { ...node.expr!, kind: "call", symbol: undefined, args: [] };
  const missingTarget = observeDomainReview(program, rule, {});
  assert.deepEqual(missingTarget.findings, []);
  assert.ok(missingTarget.diagnostics.some(issue => issue.message.includes("call target is unresolved")));
  assert.equal(missingTarget.coverage[0].evidence, "unavailable");
  withFiles({ "main.compact": "pragma language_version >= 0.26.0; import MissingModule; export circuit quiet(): [] {}" }, directory => {
    const result = scanFile(resolve(directory, "main.compact"), { detectors: [rule.id] });
    assert.equal(result.status, "incomplete");
    assert.deepEqual(result.findings, []);
    assert.ok(result.diagnostics.length);
  });
});
