import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { Ajv } from "ajv";
import { auditFile, auditFileIsolated } from "../src/reporting/auditor.js";
import { excludedRoot, validateExclusions } from "../src/reporting/selection.js";
import { scanFile, detectors, Dataflow, Program } from "../src/index.js";
import { applyWorkflow, readConfiguration, configLocation } from "../src/config.js";
import { sarif } from "../src/reporting/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const cli = resolve("dist/src/cli.js");
const run = (...args: string[]) => spawnSync(process.execPath, [cli, ...args], { encoding: "utf8", timeout: 20000 });
const direct = readFileSync("tests/corpus/vulnerable/direct.compact", "utf8");
const rule = "ledger-bound-preimage-publication";
const library = "module lib {\n" + direct.replace(/pragma[^;]*;/, "").replace("constructor(initialHash: Bytes<32>) {\n  ownerHash = disclose(initialHash);\n}", "") + "\n}";
const directive = `// nightshade-disable-next-line ${rule} -- Intentional fixture publication`;
const qualified = (file: string): void => {
  if (process.env.COMPACTC_TEST) {
    const result = validateWithCompiler(process.env.COMPACTC_TEST, file);
    assert.equal(result.valid, true, result.error);
  }
};
function expandEvidence(input: unknown, data: Record<string, any>): unknown {
  if (Array.isArray(input)) return input.map(item => expandEvidence(item, data));
  if (!input || typeof input !== "object") return input;
  const object = input as Record<string, unknown>;
  if (Object.keys(object).length === 1) {
    if (typeof object.value === "string") return expandEvidence(data.values[object.value], data);
    if (typeof object.source === "string") return data.sources[object.source];
    if ("trace" in object && (object.trace === null || typeof object.trace === "string")) {
      const steps = [];
      for (let id = object.trace; id !== null; id = data.traces[id].prefix) steps.push(data.traces[id].step);
      return steps.reverse();
    }
  }
  return Object.fromEntries(Object.entries(object).map(([key, value]) => [key, expandEvidence(value, data)]));
}
const guardSource = `pragma language_version 0.26.0;
ledger authority: Field;
ledger saved: Field;
circuit guard(key: Field): [] { assert(key == authority, "guard"); }
circuit harmless(): [] {}
circuit store(key: Field): [] { saved = disclose(key); }
export circuit guarded(key: Field): [] { harmless(); guard(key); store(key); }
export circuit conditional(key: Field, flag: Boolean): [] { if (disclose(flag)) { guard(key); } store(key); }
export circuit late(key: Field): [] { store(key); guard(key); }
export circuit invalidated(key: Field): [] { guard(key); authority = 7 as Field; store(key); }
export circuit repeated(key: Field): [] { guard(key); store(key); authority = 7 as Field; store(key); }
export circuit rejected(key: Field): [] { store(key); assert(false, "disabled"); }
`;

test("auditor guards retain successful history order, alternatives, call sites and invalidations", () => {
  withFiles({ "main.compact": guardSource }, directory => {
    const file = resolve(directory, "main.compact"); qualified(file);
    const report = auditFile(file, "ledger-access");
    assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
    const data = JSON.parse(JSON.stringify(report.data));
    const name = (id: string) => data.symbols.find((symbol: { id: string }) => symbol.id === id)?.name;
    const sites = (entry: string) => data.sites.filter((site: { entry: string; ledger: string }) => name(site.entry) === entry && name(site.ledger) === "saved");
    assert.equal(sites("guarded").length, 1);
    assert.equal(sites("guarded")[0].requiredPredicates.length, 1);
    assert.deepEqual(sites("guarded")[0].requiredCompletedCalls.map(name).sort(), ["guard", "harmless"]);
    assert.equal(sites("conditional")[0].occurrences, 2);
    assert.deepEqual(sites("conditional")[0].requiredPredicates, []);
    assert.deepEqual(sites("conditional")[0].requiredCompletedCalls, []);
    assert.deepEqual(sites("late")[0].requiredPredicates, []);
    assert.deepEqual(sites("late")[0].requiredCompletedCalls, []);
    assert.deepEqual(sites("invalidated")[0].requiredCompletedCalls, []);
    // The old check remains historical evidence, with an entry-storage identity.
    const old = data.predicates[sites("invalidated")[0].requiredPredicates[0]];
    assert.equal(old.writesBefore, 0);
    const value = data.values[old.value.value];
    assert.equal(data.values[value.comparison.right.value].region.revision, 0);
    assert.equal(sites("repeated").length, 2);
    assert.equal(sites("repeated").filter((site: { requiredCompletedCalls: string[] }) => site.requiredCompletedCalls.some(id => name(id) === "guard")).length, 1);
    assert.equal(sites("rejected").length, 0);
    assert.equal(report.entries.find(entry => entry.name === "rejected")?.histories, 0);
    assert.match(report.scope, /Completed calls are not security guards/);
    const facts = new Dataflow(new Program(file), undefined, undefined, undefined, "instructions", true, true, "equivalent-states", false, true, "all").analyze();
    const plain = (value: unknown) => JSON.parse(JSON.stringify(value, (_key, item) => item instanceof Set || item instanceof Map ? [...item] : item));
    assert.equal(data.histories.length, facts.paths.length);
    for (const [index, path] of facts.paths.entries()) {
      const history = data.histories[index];
      assert.deepEqual(expandEvidence(history.trace, data), plain(path.path));
      for (const [ordinal, write] of path.writes.entries()) {
        assert.deepEqual(expandEvidence(history.writes[ordinal].before, data), plain(write.before));
        assert.deepEqual(expandEvidence(history.writes[ordinal].after, data), plain(write.after));
        assert.deepEqual(history.writes[ordinal].enforcedBeforeWrite.map((id: string) => expandEvidence(data.predicates[id], data)),
          plain(path.predicates!.filter(predicate => predicate.writesBefore <= ordinal)));
      }
    }
  });
});

test("FT and NFT auditor writes fit unchanged worker and serialization budgets", { skip: !process.env.OZ_COMPACT_TEST }, async () => {
  for (const [name, entries] of [["FungibleToken", 19], ["NonFungibleToken", 26]] as const) {
    const root = process.env.OZ_COMPACT_TEST!;
    const report = await auditFileIsolated(resolve(root, `contracts/src/token/test/mocks/Mock${name}.compact`), "ledger-access", { searchPaths: [resolve(root, "contracts/src")] });
    assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
    assert.equal(report.entries.length, entries);
    assert.ok(report.entries.every(entry => entry.status === "complete"));
  }
});

test("disclosure and dependency views use actual sinks and retain private provenance", () => {
  withFiles({ "main.compact": `import CompactStandardLibrary;
witness secret(): Field;
circuit permissionOnly(): Field { return disclose(secret()); }
export circuit unusedPermission(): [] { permissionOnly(); }
export circuit reveal(): Field { return disclose(secret()); }
export circuit digest(): Bytes<32> { return disclose(persistentHash<Field>(secret())); }
` }, directory => {
    const file = resolve(directory, "main.compact"); qualified(file);
    for (const printer of ["disclosure-map", "data-dependency"] as const) {
      const report = auditFile(file, printer);
      assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
      const data = JSON.parse(JSON.stringify(report.data));
      const history = (entry: string) => data.histories.find((path: { entry: string }) => path.entry === report.entries.find(item => item.name === entry)!.id);
      const observations = printer === "disclosure-map" ? "sinks" : "dependencies";
      assert.ok(history("unusedPermission")[observations].every((sink: { value: { value: string } }) => data.values[sink.value.value].flows.length === 0));
      for (const [entry, form] of [["reveal", "raw"], ["digest", "hash"]]) {
        const sink = history(entry)[observations].find((item: { kind?: string; target?: string }) => (item.kind ?? item.target) === "exported-return");
        const flows = data.values[sink.value.value].flows;
        assert.equal(flows.length, 1); assert.equal(flows[0].form, form);
        assert.equal(data.sources[flows[0].source.source].name, "secret"); assert.ok(data.traces[flows[0].trace.trace].step);
      }
    }
  });
});

test("auditor views expose incomplete coverage and never infer required guards from partial paths", () => {
  withFiles({ "main.compact": guardSource }, directory => {
    const file = resolve(directory, "main.compact");
    const report = auditFile(file, "ledger-access", { maxPaths: 1 });
    assert.equal(report.status, "incomplete");
    assert.ok(report.diagnostics.some(item => item.code.includes("budget")));
    const data = JSON.parse(JSON.stringify(report.data));
    for (const site of data.sites) if (report.entries.find(entry => entry.id === site.entry)?.status === "incomplete") {
      assert.equal(site.requiredPredicates, null); assert.equal(site.requiredCompletedCalls, null);
    }
    assert.equal(auditFile(file, "human-summary", { maxSteps: 0 }).status, "incomplete");
    const result = run("print", "ledger-access", file, "--max-steps", "1");
    assert.equal(result.status, 2); assert.equal(JSON.parse(result.stdout).status, "incomplete");
    const summary = run("print", "human-summary", file);
    assert.equal(summary.status, 0); assert.match(summary.stdout, /guarded: complete/);
    assert.equal(JSON.parse(run("print", "human-summary", file, "--json").stdout).entries.length, 6);
  });
});

test("auditor workers preserve output exhaustion and library-only diagnostics", async () => {
  const report = await auditFileIsolated(resolve("tests/corpus/vulnerable/direct.compact"), "ledger-access", {}, { maxOutputBytes: 1024 });
  assert.equal(report.status, "incomplete");
  assert.equal(report.diagnostics[0].code, "worker-output-budget");
  withFiles({ "main.compact": "module Library { export circuit f(): [] {} }" }, directory => {
    const library = auditFile(resolve(directory, "main.compact"), "human-summary");
    assert.equal(library.status, "incomplete"); assert.equal(library.diagnostics[0].code, "no-entrypoints");
  });
});

test("auditor CLI selects legacy profiles and preserves explicit failure profiles", () => {
  withFiles({ "main.compact": "pragma language_version 0.22; export circuit entry(x: Uint<8>): Field { return x; }" }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_030_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_030_TEST, file, [], 30000, 2, "0.30.0");
      assert.equal(compiled.valid, true, compiled.error);
    }
    const result = run("print", "human-summary", file, "--json");
    assert.equal(result.status, 0, result.stdout);
    assert.equal(JSON.parse(result.stdout).semanticProfile, "compact-0.30.0-zkir2");
    assert.match(run("print", "human-summary", file).stdout, /^Nightshade auditor:/);
    const failed = run("print", "human-summary", resolve(directory, "absent.compact"), "--json", "--compiler-version", "0.31.1");
    assert.equal(failed.status, 2);
    assert.equal(JSON.parse(failed.stdout).semanticProfile, "compact-0.31.1-zkir2");
  });
});

test("inline suppression uses owned comments, preserves Unicode/CRLF and leaves evidence visible", () => {
  for (const newline of ["\n", "\r\n"]) withFiles({ "main.compact": direct.replace("  published =", `  // unicode 😀\n  ${directive}\n  published =`).replaceAll("\n", newline) }, directory => {
    const file = resolve(directory, "main.compact"); qualified(file);
    const report = scanFile(file);
    assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
    assert.equal(report.findings.length, 1);
    assert.deepEqual(report.findings[0].suppression, { reason: "Intentional fixture publication", kind: "inSource" });
    const formatted = JSON.parse(JSON.stringify(sarif(report)));
    assert.equal(formatted.runs[0].results[0].suppressions[0].kind, "inSource");
    const result = run(file, "--json"); assert.equal(result.status, 0);
    const ajv = new Ajv({ strict: false });
    const validate = ajv.compile(JSON.parse(readFileSync("docs/schema/report.schema.json", "utf8")));
    assert.equal(validate(JSON.parse(result.stdout)), true, JSON.stringify(validate.errors));
  });
});

test("same-line and multi-rule directives are narrow; malformed/stale directives stay incomplete", () => {
  const cases = [
    [direct.replace("published = disclose(secret);", `published = disclose(secret); // nightshade-disable-line ${rule} -- Reviewed publication in fixture`), "complete", true],
    [direct.replace("not authorized", directive), "complete", false],
    [direct.replace("  published =", `  // nightshade-disable-next-line ${rule} -- short\n  published =`), "incomplete", false],
    [direct.replace("  published =", `  // nightshade-disable-next-line unknown-rule -- Reviewed fixture\n  published =`), "incomplete", false],
    [direct + `\n${directive}\n`, "incomplete", false],
    [direct.replace("  published =", `  ${directive.replace(rule, `${rule},${rule}`)}\n  published =`), "incomplete", false],
  ] as const;
  for (const [source, status, suppressed] of cases) withFiles({ "main.compact": source }, directory => {
    const result = scanFile(resolve(directory, "main.compact"), { profile: "hygiene" });
    assert.equal(result.status, status, JSON.stringify(result.diagnostics));
    assert.equal(!!result.findings[0].suppression, suppressed);
  });
  withFiles({ "main.compact": direct + "\n// nightshade-disable-next-line time-dependence -- Opt-in review annotation\n" }, directory => {
    assert.equal(scanFile(resolve(directory, "main.compact"), { profile: "hygiene" }).status, "incomplete");
  });
});

test("library suppressions apply across importing roots without spurious stale diagnostics", () => {
  withFiles({ "lib.compact": library.replace("  published =", `  ${directive}\n  published =`),
    "main.compact": 'import "./lib"; export circuit entry(): [] { update(); }',
    "other.compact": 'import "./lib"; export circuit entry(): [] {}' }, directory => {
    const file = resolve(directory, "main.compact"); qualified(file);
    const result = scanFile(file);
    assert.equal(result.status, "complete", JSON.stringify(result.diagnostics));
    assert.equal(result.findings[0].suppression?.kind, "inSource");
    assert.equal(scanFile(resolve(directory, "other.compact")).status, "complete");
  });
});

test("exclusions filter roots, retain imported dependencies and record scope", () => {
  withFiles({ "lib/helper.compact": library.replace("module lib", "module helper"), "main.compact": 'import "./lib/helper"; export circuit entry(): [] { update(); }', "skip/bad.compact": "bad syntax" }, directory => {
    qualified(resolve(directory, "main.compact"));
    const result = run(directory, "--exclude", "lib/", "--exclude", "skip/**", "--json");
    assert.equal(result.status, 1, result.stdout);
    const report = JSON.parse(result.stdout);
    assert.equal(report.status, "complete"); assert.equal(report.findings.length, 1);
    assert.equal(report.selection.excludedRoots.length, 2);
    assert.ok(report.coverage.parsed.includes(resolve(directory, "lib/helper.compact")));
    assert.deepEqual(report.coverage.attempted, [resolve(directory, "main.compact")]);
    assert.equal(run(directory, "--exclude", "**", "--json").status, 2);
  });
  for (const [path, pattern, expected] of [["a.compact", "**/*.compact", true], ["x/a.compact", "*.compact", false], ["x/a.compact", "x/?*.compact", true], ["lib2/a.compact", "lib/", false]] as const)
    assert.equal(excludedRoot(resolve("/fixture", path), "/fixture", [pattern]), expected);
  for (const pattern of ["/abs", "x\\y", "x[ab]", "a**b", "x//y", "!x", "", "../x", "./x", "C:/x"])
    assert.throws(() => validateExclusions([pattern], configLocation(".")));
});

test("severity filters preserve incomplete status and explain hidden findings in JSON/SARIF", () => {
  withFiles({ "main.compact": direct }, directory => {
    const file = resolve(directory, "main.compact");
    const result = run(file, "--json", "--min-severity", "high");
    assert.equal(result.status, 0);
    const report = JSON.parse(result.stdout); assert.equal(report.findings.length, 0);
    assert.deepEqual(report.selection, { minimumSeverity: "high", findingsBeforeFilter: 1 });
    assert.equal(JSON.parse(JSON.stringify(sarif(report))).runs[0].properties.selection.minimumSeverity, "high");
    assert.equal(run(file, "--json", "--min-severity", "high", "--max-steps", "1").status, 2);
    const baseline = resolve(directory, "baseline.json");
    assert.equal(run(file, "--json", "--min-severity", "high", "--write-baseline", baseline).status, 0);
    assert.equal(JSON.parse(readFileSync(baseline, "utf8")).fingerprints.length, 1);
    const config = readConfiguration(); config.minSeverity = "high";
    const inline = scanFile(file); config.suppressions = [{ fingerprint: inline.findings[0].fingerprint, reason: "Reviewed before filtering" }];
    applyWorkflow(inline, config); assert.equal(inline.status, "complete"); assert.equal(inline.findings.length, 0);
    writeFileSync(resolve(directory, "config.json"), JSON.stringify({ version: 1, minSeverity: "urgent" }));
    assert.throws(() => readConfiguration(resolve(directory, "config.json")));
  });
});

test("every detector ships CLI documentation while list JSON remains lightweight", () => {
  const listed = JSON.parse(run("detector", "list", "--json").stdout);
  assert.equal(listed.length, detectors.length); assert.equal(listed[0].documentation, undefined);
  for (const detector of detectors) {
    const result = run("detector", "show", detector.id, "--json");
    assert.equal(result.status, 0, result.stdout);
    const documentation = JSON.parse(result.stdout)[0].documentation;
    assert.equal(documentation, readFileSync(`docs/detectors/${detector.id}.md`, "utf8"));
  }
});
