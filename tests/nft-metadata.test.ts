import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Dataflow, Program, scanFile, scanFileIsolated } from "../src/index.js";
import type { AnalysisFacts } from "../src/dataflow/index.js";
import { nftMetadataObservations } from "../src/analysis/nft-metadata.js";
import { staleNftMetadata as rule, staleNftMetadataFindings } from "../src/detectors/nft-metadata.js";
import { resolvePolicies, validatePolicies, type Policies } from "../src/policies.js";
import { human, sarif } from "../src/reporting/index.js";
import { validateWithCompiler } from "./compiler-fixtures.js";
import { withFiles } from "./helpers.js";

const external = process.env.OZ_COMPACT_TEST;
const searchPaths = external ? [resolve(external, "contracts/src")] : [];
const policies: Policies = { currentNftMetadata: [{ owners: "_owners", metadata: "cachedURI", consumer: "replaceToken" }] };
const fixture = (kind: string) => readFileSync(`tests/corpus/known-bugs/library-nft-cache-lifecycle-${kind}.compact`, "utf8");
const positive = fixture("positive");
const namesake = positive.replace('import "token/NonFungibleToken" prefix NFT_;', `module NonFungibleToken {
  import CompactStandardLibrary;
  export ledger _owners: Map<Uint<128>, Either<Bytes<32>, ContractAddress>>;
  export circuit initialize(name: Opaque<"string">, symbol: Opaque<"string">): [] {}
  export circuit _mint(to: Either<Bytes<32>, ContractAddress>, tokenId: Uint<128>): [] {}
  export circuit _burn(tokenId: Uint<128>): [] {}
}
import NonFungibleToken prefix NFT_;`);
const terminal = "return cachedURI.lookup(disclose(tokenId));";
const replace = (source: string, text: string) => source.replace(terminal, text);

function analyze(program: Program, engine: "instructions" | "expressions" = "instructions", cached = true) {
  const resolved = resolvePolicies(program, policies);
  const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached,
    "equivalent-states", false, true, "all", false, true).analyzeSubset([resolved.currentNftMetadata![0].consumer]);
  assert.deepEqual(facts.diagnostics, []);
  assert.deepEqual(facts.completedEntries, [resolved.currentNftMetadata![0].consumer]);
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
      const { facts, resolved } = analyze(program, engine, cached);
      const observation = nftMetadataObservations(facts, resolved);
      assert.equal(observation.complete, !code);
      const findings = rule.run(facts, resolved);
      assert.equal(findings.length, expected);
      assert.deepEqual(facts.diagnostics.map(item => item.code), code ? [code] : []);
      assert.ok(facts.diagnostics.every(item => item.scope?.detectorId === rule.id));
      previous ??= findings; assert.deepEqual(findings, previous);
      for (const finding of findings) {
        assert.equal(finding.severity, "low"); assert.equal(finding.confidence, "high");
        assert.equal(finding.metadata.crossEntryCoverage, false);
        assert.equal(finding.metadata.pathFeasibility, "not-proven");
        assert.equal(source.split("\n")[finding.location.line - 1].trim(), terminal);
      }
    }
    const scan = scanFile(file, { searchPaths, policies, detectors: [rule.id] });
    assert.equal(scan.status, code ? "incomplete" : "complete", JSON.stringify(scan.diagnostics));
    assert.deepEqual(scan.findings, previous);
    assert.deepEqual(scan.diagnostics.map(item => item.code), code ? [code] : []);
    assert.equal(scan.coverage.baselineStatus, "complete");
  });
}

const metadataCore = JSON.parse(readFileSync("tests/corpus/manifest.json", "utf8")).metadataCorePattern34 as {
  policies: Policies; cases: { file: string; lines: number[] }[];
};
for (const boundary of metadataCore.cases) test(`owned metadata canonical composition: ${boundary.file}`, { skip: !external }, async () => {
  assert.deepEqual(metadataCore.policies, policies);
  const file = resolve("tests/corpus", boundary.file);
  if (process.env.COMPACTC_TEST) {
    const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file, searchPaths);
    assert.equal(compiled.valid, true, compiled.error);
  }
  const program = new Program(file, searchPaths);
  for (const name of ["mint", "burn", "remint", "replaceToken"]) {
    assert.ok(program.entries.some(entry => entry.endsWith(`::${name}`)), name);
  }
  let oracle: unknown;
  for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
    const { facts, resolved } = analyze(program, engine, cached), findings = rule.run(facts, resolved);
    assert.deepEqual(facts.diagnostics, []);
    assert.deepEqual(findings.map(item => item.location.line), boundary.lines);
    oracle ??= findings;
    assert.deepEqual(findings, oracle, `${engine}/${cached}`);
  }
  const options = { searchPaths, policies, detectors: [rule.id] };
  const selected = scanFile(file, options);
  assert.equal(selected.status, "complete", JSON.stringify(selected.diagnostics));
  assert.deepEqual(selected.findings, oracle);
  const supervised = await scanFileIsolated(file, options);
  assert.equal(supervised.status, "complete", JSON.stringify(supervised.diagnostics));
  assert.deepEqual(supervised.findings, selected.findings);
  assert.deepEqual(supervised.coverage, selected.coverage);
  const unconfigured = scanFile(file, { searchPaths, detectors: [rule.id] });
  assert.equal(unconfigured.status, "complete", JSON.stringify(unconfigured.diagnostics));
  assert.deepEqual(unconfigured.findings, []);
});

test("explicit current-incarnation cache: authenticated stale/corrected/distinct-ID triple", { skip: !external }, () => {
  check(positive, 1); check(fixture("corrected"), 0); check(fixture("lookalike"), 0);
  const manifest = JSON.parse(readFileSync("tests/corpus/manifest.json", "utf8")).nftAuxiliaryMetadata;
  assert.deepEqual(manifest.policies, policies);
  withFiles({ "main.compact": positive }, directory => {
    const file = resolve(directory, "main.compact");
    const ordinary = scanFile(file, { searchPaths, policies, detectors: [rule.id] });
    const experimental = scanFile(file, { searchPaths, policies, detectors: [rule.id], experimentalCounterQueries: true });
    // Schema 1.2 does not use entry-isolated observation passes. Missing
    // collection evidence must be explicit, never an apparent clean scan.
    assert.equal(experimental.status, "incomplete");
    assert.deepEqual(experimental.findings, []);
    assert.ok(experimental.diagnostics.some(item => item.code === "nft-metadata-observation-unavailable" && item.scope?.detectorId === rule.id));
    assert.deepEqual(ordinary.findings.map(item => item.location.line), manifest.cases[0].lines);
    assert.deepEqual(ordinary.findings[0].trace.map(step => step.location.line), [23, 24, 25, 26]);
  });
});

test("opt-in intent and provider bytes are required; intentional archives remain unconfigured", { skip: !external }, () => {
  assert.equal(rule.defaultEnabled, false); assert.equal(rule.policyRequired, true);
  withFiles({ "main.compact": positive }, directory => {
    const file = resolve(directory, "main.compact"), { facts } = analyze(new Program(file, searchPaths));
    assert.deepEqual(rule.run(facts), []);
    const scan = scanFile(file, { searchPaths, detectors: [rule.id] });
    assert.equal(scan.status, "complete"); assert.deepEqual(scan.findings, []);
    assert.ok(scan.coverage.rules!.every(row => row.status === "not-applicable"));
  });
  check(namesake, 0, "nft-metadata-provider-unavailable");
  check(positive, 0, "nft-metadata-provider-unavailable", {
    "token/NonFungibleToken.compact": readFileSync(resolve(external!, "contracts/src/token/NonFungibleToken.compact"), "utf8") + "\n// Modified bytes.\n",
    "utils/Utils.compact": readFileSync(resolve(external!, "contracts/src/utils/Utils.compact"), "utf8"),
  });
});

test("configured untrusted providers are scoped incomplete and preserve unrelated baseline findings", { skip: !external }, () => {
  const library = readFileSync(resolve(external!, "contracts/src/token/NonFungibleToken.compact"), "utf8");
  const utils = readFileSync(resolve(external!, "contracts/src/utils/Utils.compact"), "utf8");
  for (const [source, extras] of [
    [namesake, {}],
    [positive, { "token/NonFungibleToken.compact": library + "\n// Modified provider.\n", "utils/Utils.compact": utils }],
    [positive, { "token/NonFungibleToken.compact": library, "utils/Utils.compact": utils + "\n// Untrusted dependency.\n" }],
  ] as const) withFiles({ "main.compact": source + "\nexport ledger unrelatedUnused: Boolean;\n", ...extras }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file, searchPaths);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const baseline = scanFile(file, { searchPaths, detectors: ["unused-declaration"] });
    assert.equal(baseline.status, "complete"); assert.ok(baseline.findings.length > 0);
    const report = scanFile(file, { searchPaths, policies, detectors: [rule.id, "unused-declaration"] });
    assert.equal(report.status, "incomplete"); assert.equal(report.coverage.baselineStatus, "complete");
    assert.deepEqual(report.findings, baseline.findings);
    assert.deepEqual(report.diagnostics.map(item => item.code), ["nft-metadata-provider-unavailable"]);
    assert.ok(report.diagnostics.every(item => item.scope?.detectorId === rule.id && item.scope?.entry?.endsWith("::replaceToken")));
    const rows = report.coverage.rules!.filter(row => row.detectorId === rule.id);
    assert.equal(rows.find(row => row.entry.endsWith("::replaceToken"))!.status, "incomplete");
    assert.ok(rows.filter(row => !row.entry.endsWith("::replaceToken")).every(row => row.status === "not-applicable"));
    assert.ok(report.coverage.rules!.filter(row => row.detectorId !== rule.id).every(row => row.status === "complete"));
    const unconfigured = scanFile(file, { searchPaths, detectors: [rule.id, "unused-declaration"] });
    assert.equal(unconfigured.status, "complete"); assert.deepEqual(unconfigured.findings, baseline.findings);
    assert.deepEqual(unconfigured.diagnostics, []);
    assert.ok(unconfigured.coverage.rules!.filter(row => row.detectorId === rule.id).every(row => row.status === "not-applicable"));
  });
});

test("saved reads, helper returns, effectful keys and control flow do not establish terminal observation order", { skip: !external }, () => {
  const saved = positive.replace("  NFT__burn(tokenId);", "  const saved = cachedURI.lookup(disclose(tokenId));\n  NFT__burn(tokenId);").replace(terminal, "return saved;");
  check(saved, 0, "nft-metadata-consumer-unavailable");
  check(replace(positive, "return readCache(tokenId);") + '\ncircuit readCache(tokenId: Uint<128>): Opaque<"string"> { return cachedURI.lookup(disclose(tokenId)); }', 0, "nft-metadata-consumer-unavailable");
  check(replace(positive, "return cachedURI.lookup(disclose(refresh(tokenId, newURI)));") + '\ncircuit refresh(tokenId: Uint<128>, value: Opaque<"string">): Uint<128> { cachedURI.insert(disclose(tokenId), disclose(value)); return tokenId; }', 0, "nft-metadata-consumer-unavailable");
  check(replace(positive, "if (disclose(tokenId == 0)) { return cachedURI.lookup(disclose(tokenId)); } else { return cachedURI.lookup(disclose(tokenId)); }"), 0, "nft-metadata-consumer-unavailable");
});

test("later auxiliary mutations and final owner deletion withhold preservation", { skip: !external }, () => {
  check(replace(positive, "cachedURI.insert(disclose(tokenId), disclose(oldURI));\n  " + terminal), 0);
  check(replace(positive, "cachedURI.resetToDefault();\n  cachedURI.insert(disclose(tokenId), disclose(newURI));\n  " + terminal), 0);
  check(replace(positive, "NFT__burn(tokenId);\n  " + terminal), 0);
  // Different dynamic keys may overlap even though their immutable identities differ.
  check(replace(positive.replace("oldURI: Opaque", "otherId: Uint<128>, oldURI: Opaque"), "cachedURI.insert(disclose(otherId), disclose(newURI));\n  " + terminal), 0);
});

test("different IDs cannot pair a cache payload with a lifecycle; literal disjoint writes are allowed", { skip: !external }, () => {
  check(positive.replace("NFT__burn(tokenId);", "NFT__burn(1);").replace("NFT__mint(owner, tokenId);\n  return", "NFT__mint(owner, 1);\n  return"), 0);
  const literal = positive.replaceAll("disclose(tokenId)", "0").replaceAll("NFT__mint(owner, tokenId)", "NFT__mint(owner, 0)").replaceAll("NFT__burn(tokenId)", "NFT__burn(0)");
  const source = literal.replace("return cachedURI.lookup(0);", "cachedURI.insert(1, disclose(newURI));\n  return cachedURI.lookup(0);");
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact");
    if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, file, searchPaths).valid, true);
    const program = new Program(file, searchPaths);
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const { facts, resolved } = analyze(program, engine, cached);
      assert.equal(rule.run(facts, resolved).length, 1); assert.deepEqual(facts.diagnostics, []);
    }
  });
});

test("custom owner updates are explicitly outside the authenticated lifecycle", { skip: !external }, () => {
  check(replace(positive, "NFT__owners.insert(disclose(tokenId), owner);\n  " + terminal), 0, "nft-metadata-lifecycle-unavailable");
});

test("separate authenticated NFT instances cannot exchange lifecycle evidence", { skip: !external }, () => {
  const library = readFileSync(resolve(external!, "contracts/src/token/NonFungibleToken.compact"), "utf8");
  const utils = readFileSync(resolve(external!, "contracts/src/utils/Utils.compact"), "utf8");
  const source = positive.replace('import "token/NonFungibleToken" prefix NFT_;',
    'import "A/token/NonFungibleToken" prefix NFT_;\nimport "B/token/NonFungibleToken" prefix Other_;')
    .replace("NFT_initialize(name, symbol);", "NFT_initialize(name, symbol); Other_initialize(name, symbol);")
    .replace("NFT__burn(tokenId);", "Other__burn(tokenId);")
    .replace("NFT__mint(owner, tokenId);\n  return", "Other__mint(owner, tokenId);\n  return");
  withFiles({ "main.compact": source, "A/token/NonFungibleToken.compact": library, "A/utils/Utils.compact": utils,
    "B/token/NonFungibleToken.compact": library, "B/utils/Utils.compact": utils }, directory => {
    const file = resolve(directory, "main.compact"), program = new Program(file);
    if (process.env.COMPACTC_TEST) {
      const result = validateWithCompiler(process.env.COMPACTC_TEST, file);
      assert.equal(result.valid, true, result.error);
    }
    assert.throws(() => resolvePolicies(program, policies), /resolves to 2/);
    const owners = program.activeSymbols().find(symbol => symbol.name === "_owners" && symbol.span.file === resolve(directory, "A/token/NonFungibleToken.compact"))!;
    const selected = { currentNftMetadata: [{ ...policies.currentNftMetadata![0], owners: owners.id }] };
    const resolved = resolvePolicies(program, selected), consumer = resolved.currentNftMetadata![0].consumer;
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached,
        "equivalent-states", false, true, "all", false, true).analyzeSubset([consumer]);
      assert.deepEqual(facts.diagnostics, []); assert.deepEqual(facts.completedEntries, [consumer]);
      assert.deepEqual(rule.run(facts, resolved), []); assert.deepEqual(facts.diagnostics, []);
    }
    const report = scanFile(file, { policies: selected, detectors: [rule.id] });
    assert.equal(report.status, "complete", JSON.stringify(report.diagnostics)); assert.deepEqual(report.findings, []);
  });
});

test("missing collection evidence, unknown key/payload and budget exhaustion are rule-scoped", { skip: !external }, () => {
  withFiles({ "main.compact": positive }, directory => {
    const { facts, resolved } = analyze(new Program(resolve(directory, "main.compact"), searchPaths));
    const full = nftMetadataObservations(facts, resolved);
    assert.equal(full.complete, true); assert.ok(full.observations.length > 0);
    assert.deepEqual(nftMetadataObservations(facts, resolved, full.work), full);
    const exhausted = nftMetadataObservations(facts, resolved, full.work - 1);
    assert.equal(exhausted.complete, false); assert.deepEqual(exhausted.observations, []);
    assert.equal(exhausted.diagnostics[0].code, "nft-metadata-observation-budget");
    const missing: AnalysisFacts = { ...facts, diagnostics: [], collectionEvidence: false };
    assert.equal(nftMetadataObservations(missing, resolved).complete, false);
    assert.deepEqual(rule.run(missing, resolved), []);
    assert.equal(missing.diagnostics[0].code, "nft-metadata-observation-unavailable");
    const missingOperations: AnalysisFacts = { ...facts, diagnostics: [], paths: facts.paths.map(path => ({ ...path, operations: undefined })) };
    assert.equal(nftMetadataObservations(missingOperations, resolved).complete, false);
    assert.deepEqual(rule.run(missingOperations, resolved), []);
    assert.equal(missingOperations.diagnostics[0].code, "nft-metadata-observation-unavailable");
    const unknown = structuredClone(facts.paths);
    for (const path of unknown) for (const sink of path.sinks) if (sink.kind === "exported-return") {
      delete sink.value.identity; delete sink.value.constant; delete sink.value.constantKind;
    }
    const unavailable: AnalysisFacts = { ...facts, diagnostics: [], paths: unknown };
    assert.equal(nftMetadataObservations(unavailable, resolved).complete, false);
    assert.deepEqual(rule.run(unavailable, resolved), []);
    assert.equal(unavailable.diagnostics[0].code, "nft-metadata-key-unavailable");
    const unknownMutation = structuredClone(facts.paths);
    for (const path of unknownMutation) for (const operation of path.operations ?? []) if (operation.kind === "collection-write" && operation.args[0]?.region?.root === resolved.currentNftMetadata![0].metadata) {
      delete operation.args[1].identity; delete operation.args[1].constant; delete operation.args[1].constantKind;
    }
    const mutation: AnalysisFacts = { ...facts, diagnostics: [], paths: unknownMutation };
    assert.equal(nftMetadataObservations(mutation, resolved).complete, false);
    assert.deepEqual(rule.run(mutation, resolved), []);
    assert.equal(mutation.diagnostics[0].code, "nft-metadata-key-unavailable");
    assert.ok([...missing.diagnostics, ...unavailable.diagnostics, ...exhausted.diagnostics].every(item => item.scope?.detectorId === rule.id));
  });
});

test("a supported history survives unsupported duplicate histories for the same relation", { skip: !external }, () => {
  withFiles({ "main.compact": positive }, directory => {
    const file = resolve(directory, "main.compact"), program = new Program(file, searchPaths);
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file, searchPaths);
      assert.equal(compiled.valid, true, compiled.error);
    }
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const { facts, resolved } = analyze(program, engine, cached), relation = resolved.currentNftMetadata![0];
      const supported = facts.paths[0];
      const baseline = nftMetadataObservations({ ...facts, paths: [supported] }, resolved);
      assert.equal(baseline.complete, true); assert.ok(baseline.observations.length > 0);
      const context = structuredClone(supported);
      context.operations!.push({ ...structuredClone(context.operations![0]), kind: "kernel-read", name: "blockTime" });
      const key = structuredClone(supported);
      const sink = key.sinks.find(item => item.kind === "exported-return")!;
      delete sink.value.identity; delete sink.value.constant; delete sink.value.constantKind;
      const lifecycle = structuredClone(supported);
      lifecycle.writes.find(write => write.ledger === relation.owners)!.callPath = [relation.consumer];
      for (const [unsupported, code] of [[context, "nft-metadata-context-unavailable"], [key, "nft-metadata-key-unavailable"], [lifecycle, "nft-metadata-lifecycle-unavailable"]] as const) {
        for (const paths of [[supported, unsupported, structuredClone(unsupported)], [unsupported, structuredClone(unsupported), supported]]) {
          const mixed: AnalysisFacts = { ...facts, paths, diagnostics: [] };
          const result = nftMetadataObservations(mixed, resolved);
          assert.equal(result.complete, false); assert.deepEqual(result.observations, baseline.observations);
          assert.deepEqual(result.diagnostics.map(item => item.code), [code]);
          assert.ok(result.diagnostics.every(item => item.scope?.detectorId === rule.id && item.scope?.entry === relation.consumer));
          for (const selector of [relation.owners, relation.metadata, relation.consumer]) assert.ok(result.diagnostics[0].message.includes(selector));
          assert.equal(rule.run(mixed, resolved).length, 1);
          assert.deepEqual(nftMetadataObservations(mixed, resolved, 1).observations, []);
        }
      }
    }
  });
});

test("helper diagnostics mark overall incompleteness while preserving unaffected consumers", { skip: !external }, () => {
  const source = positive + `
export ledger customOwners: Map<Uint<128>, Either<Bytes<32>, ContractAddress>>;
export circuit untrustedConsumer(tokenId: Uint<128>): Opaque<"string"> {
  return cachedURI.lookup(disclose(tokenId));
}
export circuit savedConsumer(tokenId: Uint<128>): Opaque<"string"> {
  const saved = cachedURI.lookup(disclose(tokenId));
  return saved;
}`;
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact"), program = new Program(file, searchPaths);
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file, searchPaths);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const selected = { currentNftMetadata: [
      { owners: "customOwners", metadata: "cachedURI", consumer: "untrustedConsumer" },
      policies.currentNftMetadata![0],
      { owners: "_owners", metadata: "cachedURI", consumer: "savedConsumer" },
    ] };
    const resolved = resolvePolicies(program, selected), consumers = resolved.currentNftMetadata!.map(policy => policy.consumer);
    for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
      const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached,
        "equivalent-states", false, true, "all", false, true).analyzeSubset(consumers);
      assert.deepEqual(facts.diagnostics, []); assert.deepEqual([...facts.completedEntries].sort(), [...consumers].sort());
      const result = nftMetadataObservations(facts, resolved);
      assert.equal(result.complete, false); assert.ok(result.observations.length > 0);
      assert.ok(result.observations.every(item => item.consumer === consumers[1]));
      assert.deepEqual(result.diagnostics.map(item => item.code), ["nft-metadata-provider-unavailable", "nft-metadata-consumer-unavailable"]);
      assert.deepEqual(result.diagnostics.map(item => item.scope?.entry), [consumers[0], consumers[2]]);
      assert.equal(rule.run(facts, resolved).length, 1);
    }
    const report = scanFile(file, { searchPaths, policies: selected, detectors: [rule.id] });
    assert.equal(report.status, "incomplete"); assert.equal(report.coverage.baselineStatus, "complete");
    assert.equal(report.findings.length, 1);
    assert.equal(report.coverage.rules!.find(row => row.entry === consumers[1])!.status, "complete");
    assert.ok(report.coverage.rules!.filter(row => row.entry === consumers[0] || row.entry === consumers[2]).every(row => row.status === "incomplete"));
  });
});

test("mixed providers sharing one consumer retain the supported relation in all four modes", { skip: !external }, () => {
  const source = positive + `
module UntrustedNft {
  import CompactStandardLibrary;
  export ledger _owners: Map<Uint<128>, Either<Bytes<32>, ContractAddress>>;
  export ledger backupOwners: Map<Uint<128>, Either<Bytes<32>, ContractAddress>>;
}
import UntrustedNft prefix Other_;`;
  withFiles({ "main.compact": source }, directory => {
    const file = resolve(directory, "main.compact"), program = new Program(file, searchPaths);
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, file, searchPaths);
      assert.equal(compiled.valid, true, compiled.error);
    }
    const owners = program.activeSymbols().filter(symbol => symbol.name === "_owners");
    assert.equal(owners.length, 2);
    const trusted = owners.find(symbol => symbol.span.file !== file)!;
    const untrusted = owners.find(symbol => symbol.span.file === file)!;
    const good = { ...policies.currentNftMetadata![0], owners: trusted.id };
    const bad = { ...policies.currentNftMetadata![0], owners: untrusted.id };
    for (const relations of [[bad, good], [good, bad]]) {
      const selected = { currentNftMetadata: relations }, resolved = resolvePolicies(program, selected);
      const consumer = resolved.currentNftMetadata![0].consumer;
      for (const engine of ["instructions", "expressions"] as const) for (const cached of [false, true]) {
        const facts = new Dataflow(program, 40000, 256, 50000, engine, cached, cached,
          "equivalent-states", false, true, "all", false, true).analyzeSubset([consumer]);
        assert.deepEqual(facts.diagnostics, []); assert.deepEqual(facts.completedEntries, [consumer]);
        const result = nftMetadataObservations(facts, resolved);
        assert.equal(result.complete, false); assert.ok(result.observations.length > 0);
        assert.ok(result.observations.every(item => item.owners === trusted.id));
        assert.deepEqual(result.diagnostics.map(item => item.code), ["nft-metadata-provider-unavailable"]);
        assert.ok(result.diagnostics.every(item => item.scope?.entry === consumer));
        const findings = rule.run(facts, resolved);
        assert.equal(findings.length, 1); assert.equal(findings[0].metadata.owners, trusted.id);
        const exhausted = nftMetadataObservations(facts, resolved, 1);
        assert.equal(exhausted.complete, false); assert.deepEqual(exhausted.observations, []);
      }
      const report = scanFile(file, { searchPaths, policies: selected, detectors: [rule.id] });
      assert.equal(report.status, "incomplete"); assert.equal(report.coverage.baselineStatus, "complete");
      assert.equal(report.findings.length, 1); assert.equal(report.findings[0].metadata.owners, trusted.id);
      assert.equal(report.coverage.rules!.find(row => row.entry === consumer)!.status, "incomplete");
    }
    const backup = program.activeSymbols().find(symbol => symbol.name === "backupOwners")!;
    const distinct = { ...bad, owners: backup.id };
    const resolved = resolvePolicies(program, { currentNftMetadata: [bad, distinct, bad, good] });
    const consumer = resolved.currentNftMetadata![0].consumer;
    const facts = new Dataflow(program, 40000, 256, 50000, "instructions", true, true,
      "equivalent-states", false, true, "all", false, true).analyzeSubset([consumer]);
    assert.deepEqual(facts.diagnostics, []);
    const result = nftMetadataObservations(facts, resolved);
    assert.equal(result.complete, false); assert.ok(result.observations.length > 0);
    assert.deepEqual(result.diagnostics.map(item => item.code), ["nft-metadata-provider-unavailable", "nft-metadata-provider-unavailable"]);
    assert.equal(new Set(result.diagnostics.map(item => item.message)).size, 2);
    for (const [index, relation] of resolved.currentNftMetadata!.slice(0, 2).entries()) {
      for (const selector of [relation.owners, relation.metadata, relation.consumer]) assert.ok(result.diagnostics[index].message.includes(selector));
    }
    assert.equal(rule.run(facts, resolved).length, 1);
  });
});

test("unsupported profile and isolated rule budgets preserve baseline/unrelated coverage", { skip: !external }, () => {
  withFiles({ "main.compact": positive }, directory => {
    const file = resolve(directory, "main.compact");
    const profile = scanFile(file, { searchPaths, policies, detectors: [rule.id], zkirVersion: 3 });
    assert.equal(profile.status, "incomplete"); assert.equal(profile.coverage.baselineStatus, "complete");
    assert.deepEqual(profile.findings, []); assert.equal(profile.diagnostics[0].code, "nft-metadata-profile-unavailable");
    const unqualified = new Program(file, searchPaths, undefined, undefined, 3);
    const { facts, resolved } = analyze(unqualified);
    assert.equal(nftMetadataObservations(facts, resolved).complete, false);
    const original = rule.run;
    try {
      rule.run = (facts, resolved) => staleNftMetadataFindings(facts, resolved, 1);
      const report = scanFile(file, { searchPaths, policies, detectors: [rule.id, "ignored-validation-result"] });
      assert.equal(report.status, "incomplete"); assert.equal(report.coverage.baselineStatus, "complete");
      assert.ok(report.coverage.rules!.filter(row => row.detectorId === rule.id && row.root !== "constructor").some(row => row.status === "incomplete"));
      assert.ok(report.coverage.rules!.filter(row => row.detectorId !== rule.id).every(row => row.status === "complete"));
      assert.ok(report.diagnostics.every(item => item.scope?.detectorId === rule.id));
      assert.match(human(report), /Baseline analysis: complete; selected rules: incomplete/);
      assert.match(JSON.stringify(sarif(report)), /nft-metadata-observation-budget/);
    } finally { rule.run = original; }
  });
});

test("current NFT metadata policy selectors and shapes are strictly validated", () => {
  withFiles({ "main.compact": namesake }, directory => {
    const program = new Program(resolve(directory, "main.compact"));
    const location = program.rootSource.ast.span;
    assert.deepEqual(validatePolicies(policies, location), policies);
    assert.equal(resolvePolicies(program, policies).currentNftMetadata!.length, 1);
    assert.equal("currentNftMetadata" in resolvePolicies(program), false);
    for (const value of [
      { currentNftMetadata: [{}] }, { currentNftMetadata: [{ ...policies.currentNftMetadata![0], archive: true }] },
      { currentNftMetadata: [{ owners: "", metadata: "cachedURI", consumer: "replaceToken" }] },
      { currentNftMetadata: Array(1) }, { currentNftMetadata: Array(65).fill(policies.currentNftMetadata![0]) },
    ]) assert.throws(() => validatePolicies(value, location), /policy|policies|Missing|Invalid/);
    assert.throws(() => resolvePolicies(program, { currentNftMetadata: [{ owners: "_owners", metadata: "_owners", consumer: "replaceToken" }] }), /Map/);
    assert.throws(() => resolvePolicies(program, { currentNftMetadata: [{ owners: "missing", metadata: "cachedURI", consumer: "replaceToken" }] }), /resolves to 0/);
    assert.throws(() => resolvePolicies(program, { currentNftMetadata: [{ owners: "_owners", metadata: "cachedURI", consumer: "initialize" }] }), /exported/);
  });
});
