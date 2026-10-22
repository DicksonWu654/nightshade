import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { Dataflow, Program, scanFile, scanFileIsolated } from "../src/index.js";
import { sourceClaimShieldedIssuanceReview as rule } from "../src/detectors/source-claims.js";
import { observeSourceClaims } from "../src/analysis/source-claims-observation.js";
import { resolvePolicies, validatePolicies, type Policies } from "../src/policies.js";
import { withFiles } from "./helpers.js";
import { validateWithCompiler } from "./compiler-fixtures.js";

const quote = "// Contract claim: recipients cannot transfer issued coins to other parties.";
const policies: Policies = { sourceClaims: [{ kind: "non-transferable-shielded-issuance", circuit: "issue", quote }] };
const frozen = (name: string) => resolve("tests/corpus/synthetic-regressions/state16", `source-claim-shielded-issuance-review-case-42-${name}.compact`);
const source = readFileSync(frozen("positive"), "utf8");
const options = { detectors: [rule.id], policies };
function check(text: string, count: number, status = "complete", selected = policies) {
  withFiles({ "main.compact": text }, directory => {
    const result = scanFile(resolve(directory, "main.compact"), { detectors: [rule.id], policies: selected });
    assert.equal(result.status, status, JSON.stringify(result.diagnostics));
    assert.equal(result.findings.length, count, JSON.stringify(result.diagnostics));
    if (status === "incomplete") assert.ok(result.diagnostics.some(issue => issue.code.startsWith("source-claim-")));
  });
}

test("identical explicit policy pairs the frozen positive and leaves exact-quote controls not applicable", () => {
  for (const name of ["positive", "corrected", "lookalike"]) {
    const result = scanFile(frozen(name), options);
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.equal(result.findings.length, name === "positive" ? 1 : 0);
    if (name === "positive") {
      assert.equal(result.findings[0].location.line, 6); assert.equal(result.findings[0].source?.line, 4);
      assert.equal(result.findings[0].metadata.claimMeaning, "explicit-policy");
      assert.equal(result.findings[0].metadata.transferability, "not-established");
    } else assert.equal(result.coverage.rules?.find(row => row.detectorId === rule.id)?.status, "not-applicable");
  }
  assert.equal(rule.defaultEnabled, false); assert.equal(rule.policyRequired, true);
  assert.equal(scanFile(frozen("positive")).findings.some(item => item.detectorId === rule.id), false);
  assert.deepEqual(scanFile(frozen("positive"), { detectors: [rule.id] }).findings, []);
});

test("quotes are exact complete adjacent parser comments and explicit arbitrary text is supported", () => {
  check(source.replace(quote, "// an arbitrary policy marker"), 1, "complete", { sourceClaims: [{ ...policies.sourceClaims![0], quote: "// an arbitrary policy marker" }] });
  for (const changed of [source.replace(quote, quote + " extra"), source.replace(quote, "/* " + quote.slice(3) + " */"),
    source.replace(quote, quote + "\n// intervening comment"), source.replace(quote, quote + "\ncircuit unrelated(): [] {}"),
    source.replace(quote, ""), source.replace(quote + "\nexport", "export").replace("  mintShieldedToken", "  " + quote + "\n  mintShieldedToken")]) check(changed, 0);
  check(source.replace(quote, quote + "\n \t\n"), 1);
  for (const newline of ["\r\n", "\u0085", "\r\u0085"]) {
    check(source.replace("Owned static", "Unicode 😀 é static").replaceAll("\n", newline), 1);
  }
});

const dynamic = source.replace("userKey: ZswapCoinPublicKey", "recipient: Either<ZswapCoinPublicKey, ContractAddress>")
  .replace("left<ZswapCoinPublicKey, ContractAddress>(disclose(userKey))", "disclose(recipient)");
test("native tags use final mandatory constraints and opaque tags remain incomplete", () => {
  check(source.replace("left<ZswapCoinPublicKey, ContractAddress>(disclose(userKey))", "right<ZswapCoinPublicKey, ContractAddress>(kernel.self())"), 0);
  check(dynamic, 0, "incomplete");
  for (const late of [false, true]) for (const left of [false, true]) {
    const assertion = `  assert(${left ? "" : "!"}disclose(recipient.is_left), "tag");\n`;
    check(late ? dynamic.replace("\n}\n", "\n" + assertion + "}\n") : dynamic.replace("  mintShieldedToken", assertion + "  mintShieldedToken"), left ? 1 : 0);
  }
  check(source.replace("\n}\n", '\n  assert(false, "abort");\n}\n'), 0);
});

test("helpers, import aliases and ordinary callback cardinality preserve canonical mint invocation", () => {
  const helper = 'circuit forward(userKey: ZswapCoinPublicKey): ShieldedCoinInfo { return mintShieldedToken(pad(32, "owned:claim"), 1, default<Bytes<32>>, left<ZswapCoinPublicKey, ContractAddress>(userKey)); }\n';
  const head = "pragma language_version >= 0.26.0;\nimport CompactStandardLibrary;\n";
  for (const size of [0, 1]) {
    const values = size ? "[default<ZswapCoinPublicKey>]" : "[]";
    check(head + helper + quote + `\nexport circuit issue(): [] { const values: Vector<${size}, ZswapCoinPublicKey> = ${values}; map(forward, values); }`, size);
  }
  check(head + helper + quote + "\nexport circuit issue(): [] { forward(default<ZswapCoinPublicKey>); }", 1);
  const renamed = source.replace("import CompactStandardLibrary;", "import CompactStandardLibrary prefix L_;")
    .replaceAll("Uint<", "L_Uint<"); // Uint is a language type, not an imported name.
  const alias = renamed.replaceAll("L_Uint<", "Uint<").replaceAll("ZswapCoinPublicKey", "L_ZswapCoinPublicKey")
    .replaceAll("ContractAddress", "L_ContractAddress").replaceAll("mintShieldedToken", "L_mintShieldedToken").replaceAll("left<", "L_left<");
  check(alias, 1);
});

test("selected observation is identical across instruction/reference engines and caches", () => {
  for (const text of [source, dynamic.replace("\n}\n", '\n  assert(disclose(recipient.is_left), "left");\n}\n')]) withFiles({ "main.compact": text }, directory => {
    const program = new Program(resolve(directory, "main.compact")); let expected: unknown;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const result = observeSourceClaims(program, rule, resolvePolicies(program, policies), {}, new Set(program.entries), { engine, cached });
      assert.deepEqual(result.diagnostics, [], `${engine}/${cached}`); assert.equal(result.findings.length, 1);
      expected ??= result.findings; assert.deepEqual(result.findings, expected);
    }
  });
});

test("policy validation rejects malformed dense records, accessors, sizes and resolved duplicates", () => {
  const location = new Program(frozen("positive")).rootSource.ast.span;
  const entry = policies.sourceClaims![0];
  const accessor = Object.defineProperty({}, "sourceClaims", { get() { throw new Error("getter evaluated"); }, enumerable: true });
  assert.throws(() => validatePolicies(accessor, location), /sourceClaims/);
  assert.throws(() => resolvePolicies(new Program(frozen("positive")), accessor), /sourceClaims/);
  const inherited = Object.create(accessor);
  assert.throws(() => validatePolicies(inherited, location), /sourceClaims/);
  assert.throws(() => resolvePolicies(new Program(frozen("positive")), inherited), /sourceClaims/);
  for (const value of [Array(1), Array(65).fill(entry), [{ ...entry, kind: "other" }], [{ ...entry, extra: "x" }],
    [{ ...entry, quote: "é".repeat(1025) }], [{ ...entry, circuit: "a".repeat(1025) }],
    [Object.defineProperty({ ...entry }, "quote", { get() { throw new Error("getter evaluated"); }, enumerable: true })]]) {
    assert.throws(() => validatePolicies({ sourceClaims: value }, location), /sourceClaims/);
    assert.throws(() => resolvePolicies(new Program(frozen("positive")), { sourceClaims: value } as Policies), /sourceClaims/);
  }
  for (const selected of [{ sourceClaims: [entry, { ...entry }] }, { sourceClaims: [{ ...entry, circuit: "missing" }] }]) {
    const result = scanFile(frozen("positive"), { detectors: [rule.id], policies: selected });
    assert.equal(result.status, "incomplete"); assert.ok(result.diagnostics.some(issue => issue.code === "invalid-policy"));
  }
  withFiles({ "main.compact": source.replace("import CompactStandardLibrary;", 'import CompactStandardLibrary;\nimport "other" prefix Other_;'),
    "other.compact": 'pragma language_version >= 0.26.0;\nmodule other { export circuit issue(): [] {} }\n' }, directory => {
    const file = resolve(directory, "main.compact");
    const ambiguous = scanFile(file, options);
    assert.equal(ambiguous.status, "incomplete"); assert.ok(ambiguous.diagnostics.some(issue => issue.code === "invalid-policy"));
    const canonical = scanFile(file, { detectors: [rule.id], policies: { sourceClaims: [{ ...entry, circuit: file + "::issue" }] } });
    assert.equal(canonical.status, "complete", JSON.stringify(canonical.diagnostics)); assert.equal(canonical.findings.length, 1);
  });
  withFiles({ "main.compact": source + '\ncircuit hidden(): [] {}\n' }, directory => {
    const result = scanFile(resolve(directory, "main.compact"), { detectors: [rule.id], policies: { sourceClaims: [{ ...entry, circuit: "hidden" }] } });
    assert.equal(result.status, "incomplete"); assert.ok(result.diagnostics.some(issue => issue.code === "invalid-policy"));
  });
});

test("shared budgets, lost carrier and incomplete baseline refuse evidence with bounded diagnostics", () => {
  const program = new Program(frozen("positive")), entry = program.entries[0], resolved = resolvePolicies(program, policies);
  for (const limits of [{ maxSteps: 1 }, { maxValues: 1 }, { maxPaths: 0 }]) {
    const result = observeSourceClaims(program, rule, resolved, limits, new Set(program.entries));
    assert.deepEqual(result.findings, []); assert.ok(result.diagnostics.length > 0 && result.diagnostics.length <= 16);
  }
  const result = observeSourceClaims(program, rule, resolved, {}, new Set());
  assert.equal(result.coverage[0].status, "incomplete"); assert.deepEqual(result.findings, []);
  const facts = new Dataflow(program).analyzeSourceClaimEntry(entry);
  facts.sourceClaimEvidence!.claims = [{ ...policies.sourceClaims![0], circuit: entry, source: program.rootSource.comments![1].span }];
  facts.paths[0].sourceClaimHistory = undefined;
  assert.deepEqual(rule.run(facts, resolved), []); assert.ok(facts.diagnostics.some(issue => issue.code === "source-claim-evidence-unavailable"));
});

test("writing histories reserve shared retained writes and refuse the value allowance before allocation", () => {
  const writing = source.replace(quote, "ledger issued: Uint<64>;\n" + quote)
    .replace("  mintShieldedToken", "  issued = disclose(amount);\n  mintShieldedToken");
  check(writing, 1);
  withFiles({ "main.compact": writing }, directory => {
    const program = new Program(resolve(directory, "main.compact")), entry = program.entries[0];
    const complete = new Dataflow(program).analyzeSourceClaimEntry(entry);
    assert.deepEqual(complete.diagnostics, []); assert.equal(complete.paths[0].writes.length, 1);
    assert.equal(complete.paths[0].sourceClaimHistory?.writes, 1);
    // This allowance admits all entry inputs and reaches the assignment, then
    // refuses its copied write metadata before retaining the write record.
    const refused = new Dataflow(program, 40000, 256, 140).analyzeSourceClaimEntry(entry);
    assert.deepEqual(refused.completedEntries, []);
    assert.ok(refused.diagnostics.some(issue => issue.code === "source-claim-retention-budget"
      && issue.location.start === complete.paths[0].writes[0].location.start));
    assert.ok(refused.metrics.abstractValues > 140);
  });
});

test("unsupported applicable profiles and experimental Counter mode are explicitly incomplete", () => {
  const profile = scanFile(frozen("positive"), { ...options, compilerVersion: "0.31.1" });
  assert.equal(profile.status, "incomplete"); assert.deepEqual(profile.findings, []);
  const counter = scanFile(frozen("positive"), { ...options, experimentalCounterQueries: true });
  assert.equal(counter.status, "incomplete"); assert.deepEqual(counter.findings, []);
  if (counter.schemaVersion === "1.7.0") assert.ok(counter.analysis.coverage.every(row => row.status === "incomplete"));
});

test("direct and supervised workers preserve the complete output contract", async () => {
  const direct = scanFile(frozen("positive"), options), isolated = await scanFileIsolated(frozen("positive"), options);
  const normalize = (value: unknown): unknown => JSON.parse(JSON.stringify(value), (key, item) => ["analysisMs", "detectorMs", "parseMs", "totalMs", "elapsedMs", "frontendMs", "workerMs"].includes(key) ? 0 : item);
  assert.deepEqual(normalize(isolated), normalize(direct));
});

test("focused owned inline controls compile with the supported offline compiler", { skip: !process.env.COMPACTC_TEST }, () => {
  withFiles({ "main.compact": source }, directory => {
    const result = validateWithCompiler(process.env.COMPACTC_TEST!, resolve(directory, "main.compact"), [], 30000, 2, "0.34.0");
    assert.equal(result.valid, true, result.error);
  });
});
