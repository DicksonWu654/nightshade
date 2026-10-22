import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { Ajv } from "ajv";
import AjvDraft04 from "ajv-draft-04";
import { withFiles } from "./helpers.js";
import { scanFile, Policies, SEMANTIC_PROFILE } from "../src/index.js";
import { human, sarif } from "../src/reporting/index.js";
import { applyWorkflow, readConfiguration } from "../src/config.js";

const binary = resolve("dist/src/cli.js");
const corpus = resolve("tests/corpus");
const run = (...args: string[]) => spawnSync(process.execPath, [binary, ...args], { encoding: "utf8", timeout: 10000 });
const positive = resolve(corpus, "vulnerable/direct.compact");

test("all report formats identify the qualified semantic profile, including incomplete scans", () => {
  for (const path of [positive, resolve(corpus, "missing.compact")]) {
    const report = JSON.parse(run(path, "--json").stdout);
    assert.equal(report.schemaVersion, "1.6.0");
    assert.equal(report.semanticProfile, SEMANTIC_PROFILE);
    assert.match(human(report), /Semantic profile: compact-0\.34\.0-zkir2/);
    const formatted = sarif(report) as { runs: { properties: { semanticProfile: string } }[] };
    assert.equal(formatted.runs[0].properties.semanticProfile, SEMANTIC_PROFILE);
  }
});

test("CLI thresholds keep findings visible while controlling CI status", () => {
  for (const [flags, code] of [[[], 1], [["--fail-on", "high"], 0], [["--min-confidence", "high"], 0], [["--fail-on", "none"], 0]] as [string[], number][]) {
    const result = run(positive, "--json", ...flags);
    assert.equal(result.status, code);
    assert.equal(JSON.parse(result.stdout).findings.length, 1);
  }
});

test("CLI errors preserve machine-readable output and cannot become success", () => {
  for (const flags of [["--nonsense"], ["--max-steps", "0"], ["--max-paths", "NaN"], ["--detectors", "unknown-rule"], ["--fail-on", "nonsense"], ["--compact-path"]]) {
    const result = run(positive, "--json", ...flags);
    assert.equal(result.status, 2);
    assert.equal(JSON.parse(result.stdout).status, "incomplete");
  }
  assert.equal(run(positive, "--fail-on", "none", "--max-steps", "1").status, 2);
});

test("CLI detector details and structural printers have explicit scope", () => {
  assert.equal(run("--version").stdout.trim(), "Nightshade 0.1.0");
  const detector = run("detector", "show", "declared-secret-publication", "--json");
  assert.equal(JSON.parse(detector.stdout)[0].policyRequired, true);
  for (const printer of ["cfg", "ir", "call-graph", "state", "entrypoints"]) {
    const result = run("print", printer, positive);
    assert.equal(result.status, 0);
    assert.equal(JSON.parse(result.stdout).analysisKind, "structural-printer");
  }
});

test("baseline records are explicit, portable, and do not erase findings", () => {
  withFiles({ "main.compact": readFileSync(positive, "utf8") }, directory => {
    const source = resolve(directory, "main.compact");
    const baseline = resolve(directory, "baseline.json");
    assert.equal(run(source, "--write-baseline", baseline, "--json").status, 1);
    assert.equal(existsSync(baseline), true);
    const result = run(source, "--baseline", baseline, "--json");
    assert.equal(result.status, 0);
    assert.equal(JSON.parse(result.stdout).findings[0].baselineState, "unchanged");
    assert.equal(run(source, "--write-baseline", baseline, "--json").status, 2);
  });
});

test("incomplete analysis cannot create a baseline", () => {
  withFiles({ "main.compact": readFileSync(positive, "utf8") }, directory => {
    const baseline = resolve(directory, "baseline.json");
    assert.equal(run(resolve(directory, "main.compact"), "--max-steps", "1", "--write-baseline", baseline).status, 2);
    assert.equal(existsSync(baseline), false);
  });
});

test("configured roots, policies and import paths are relative to the config", () => {
  withFiles({
    "contracts/main.compact": readFileSync(resolve(corpus, "vulnerable/declared-secret.compact"), "utf8"),
    "nightshade.json": JSON.stringify({ version: 1, roots: ["contracts/main.compact"], policies: { secrets: [{ witness: "secret" }] } }),
  }, directory => {
    const result = run("--config", resolve(directory, "nightshade.json"), "--json");
    assert.equal(result.status, 1);
    assert.equal(JSON.parse(result.stdout).findings[0].detectorId, "declared-secret-publication");
    assert.equal(run(directory, "--json").status, 1);
  });
});

test("a config cannot silently select executable code or unknown options", () => {
  for (const configuration of [{ version: 1, compiler: "/untrusted" }, { version: 1, detectors: [] }, { version: 1, policies: { secrets: [{ witness: "secret", typo: true }] } }, { version: 1, budgets: { maxPaths: -1 } }, { version: 1, execution: { timeoutMs: 0 } }, { version: 1, execution: { module: "/untrusted" } }]) {
    withFiles({ "config.json": JSON.stringify(configuration) }, directory => assert.throws(() => readConfiguration(resolve(directory, "config.json"))));
  }
});

test("suppression needs an exact fingerprint and records a reason in SARIF", () => {
  const result = scanFile(positive);
  const config = readConfiguration();
  config.suppressions = [{ fingerprint: result.findings[0].fingerprint, reason: "Intentional reveal after authority is retired" }];
  applyWorkflow(result, config);
  assert.ok(result.findings[0].suppression);
  const output = sarif(result) as { runs: { results: { suppressions: { justification: string }[] }[] }[] };
  assert.equal(output.runs[0].results[0].suppressions[0].justification, config.suppressions[0].reason);
  config.suppressions = [{ fingerprint: "0".repeat(64), reason: "Old entry no longer present" }];
  applyWorkflow(result, config);
  assert.equal(result.status, "incomplete");
  assert.equal(result.diagnostics[0].code, "unused-suppression");
});

test("SARIF preserves static finding identities, evidence and impact", () => {
  withFiles({ "main.compact": `pragma language_version >= 0.26.0;
import CompactStandardLibrary;
export ledger ownerHash: Bytes<32>;
export ledger published: Field;
witness ownerSecret(): Field;
constructor(initialHash: Bytes<32>) { ownerHash = disclose(initialHash); }
export circuit update(): [] { const secret = ownerSecret(); assert(persistentHash<Field>(secret) == ownerHash, "not authorized"); published = disclose(secret); }` }, root => {
    const report = scanFile(resolve(root, "main.compact"), { compilerVersion: "0.34.0", zkirVersion: 3 });
    assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
    assert.ok(report.findings.length > 0);
    const rows = (sarif(report) as { runs: { results: {
      ruleId: string;
      partialFingerprints: Record<string, string>;
      properties: { findingId: string; evidenceChain: string; whyItMatters: string; confidence: string; severity: string; remediation: string };
    }[] }[] }).runs[0].results;
    for (const finding of report.findings) {
      assert.ok(finding.evidenceChain);
      assert.ok(!/[\r\n]/.test(finding.evidenceChain!));
      assert.ok(finding.whyItMatters);
      assert.ok(!/[\r\n]/.test(finding.whyItMatters!));
      const row = rows.find(candidate => candidate.properties.findingId === finding.fingerprint);
      assert.ok(row, finding.fingerprint);
      assert.equal(row.ruleId, finding.detectorId);
      assert.equal(row.partialFingerprints["nightshade/v1"], finding.fingerprint);
      for (const key of ["evidenceChain", "whyItMatters", "confidence", "severity", "remediation"] as const) {
        assert.equal(row.properties[key], finding[key]);
      }
    }
  });
});

test("coverage distinguishes parsing, resolving and completed entry analysis", () => {
  const incomplete = scanFile(positive, { maxSteps: 1 });
  assert.equal(incomplete.coverage.attempted.length, 1);
  assert.equal(incomplete.coverage.parsed.length, 2);
  assert.ok(incomplete.coverage.parsed.some(file => file.endsWith("/stdlib/standard-library.compact")));
  assert.equal(incomplete.coverage.resolved.length, 1);
  assert.equal(incomplete.coverage.completedEntries.length, 0);
  assert.ok(incomplete.metrics.steps > 0);
  withFiles({ "main.compact": "export circuit entry(): [] { missing(); }" }, directory => {
    const result = scanFile(resolve(directory, "main.compact"));
    assert.equal(result.coverage.parsed.length, 1);
    assert.equal(result.coverage.resolved.length, 0);
  });
});

test("JSON schema validates every rule and incomplete reports", () => {
  const ajv = new Ajv({ strict: false, allErrors: true });
  const validate = ajv.compile(JSON.parse(readFileSync("docs/schema/report.schema.json", "utf8")));
  const manifest = JSON.parse(readFileSync(resolve(corpus, "policies-manifest.json"), "utf8")) as { cases: { name: string; policies: Policies }[] };
  const reports = [scanFile(positive), scanFile("missing.compact"), ...manifest.cases.map(fixture => scanFile(resolve(corpus, "vulnerable", `${fixture.name}.compact`), { policies: fixture.policies }))];
  for (const report of reports) assert.equal(validate(JSON.parse(JSON.stringify(report))), true, JSON.stringify(validate.errors));
});

test("official SARIF schema validates all rule outputs", { skip: !process.env.SARIF_SCHEMA }, () => {
  const ajv = new AjvDraft04.default({ strict: false, allErrors: true, validateFormats: false });
  const validate = ajv.compile(JSON.parse(readFileSync(process.env.SARIF_SCHEMA!, "utf8")));
  const manifest = JSON.parse(readFileSync(resolve(corpus, "policies-manifest.json"), "utf8")) as { cases: { name: string; policies: Policies }[] };
  for (const fixture of manifest.cases) {
    const result = scanFile(resolve(corpus, "vulnerable", `${fixture.name}.compact`), { policies: fixture.policies });
    const config = readConfiguration();
    config.suppressions = result.findings.map(finding => ({ fingerprint: finding.fingerprint, reason: "Synthetic schema validation case" }));
    applyWorkflow(result, config, new Set(result.findings.map(finding => finding.fingerprint)));
    assert.equal(validate(sarif(result)), true, JSON.stringify(validate.errors));
  }
  assert.equal(validate(sarif(scanFile("missing.compact"))), true, JSON.stringify(validate.errors));
  assert.equal(validate({ ...sarif(scanFile(positive)), version: "0.0.0" }), false,
    "The official schema must reject an invalid SARIF version");
});

test("a library-only CLI scan reports that no entrypoints were analyzed", () => {
  withFiles({ "main.compact": "module Helper { export circuit helper(): [] {} }" }, directory => {
    const result = run(resolve(directory, "main.compact"), "--json");
    assert.equal(result.status, 0, result.stdout);
    const report = JSON.parse(result.stdout);
    assert.equal(report.status, "complete");
    assert.deepEqual(report.coverage.noEntrypointRoots, [resolve(directory, "main.compact")]);
    assert.deepEqual(report.diagnostics.map((issue: { code: string }) => issue.code), ["no-entrypoints-analyzed"]);
  });
});

test("critical authorization severity survives CLI filtering, failure thresholds and SARIF", () => {
  withFiles({ "main.compact": `import CompactStandardLibrary;
export ledger owner: Field;
witness approved(): Boolean;
export circuit grant(next: Field): [] { assert(approved(), "authorization"); owner = disclose(next); }
` }, directory => {
    const source = resolve(directory, "main.compact");
    const output = run(source, "--detectors", "spoofable-authorization", "--min-severity", "critical", "--fail-on", "critical", "--json");
    assert.equal(output.status, 1, output.stderr);
    const report = JSON.parse(output.stdout);
    assert.equal(report.status, "complete");
    assert.equal(report.findings.length, 1);
    assert.equal(report.findings[0].severity, "critical");
    const validate = new Ajv({ strict: false, allErrors: true }).compile(JSON.parse(readFileSync("docs/schema/report.schema.json", "utf8")));
    assert.equal(validate(report), true, JSON.stringify(validate.errors));
    assert.match(human(report), /CRITICAL/);
    const formatted = sarif(report) as { runs: { results: { level: string; properties: { severity: string } }[] }[] };
    assert.equal(formatted.runs[0].results[0].level, "error");
    assert.equal(formatted.runs[0].results[0].properties.severity, "critical");
    assert.equal(run(source, "--fail-on", "none").status, 0);
  });
});
