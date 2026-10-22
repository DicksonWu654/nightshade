import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { validateWithCompiler } from "../dist/src/compiler/index.js";

const root = process.cwd();
const temporary = realpathSync(mkdtempSync(resolve(tmpdir(), "nightshade-package-")));
const run = (command, args, cwd, env = process.env) => {
  const result = spawnSync(command, args, { cwd, env, encoding: "utf8", timeout: 120000, maxBuffer: 4 * 1024 * 1024 });
  assert.equal(result.status, 0, `${command} ${args.join(" ")} failed: ${result.error ?? result.stderr}`);
  return result.stdout;
};
try {
  const packed = JSON.parse(run("npm", ["pack", "--json", "--pack-destination", temporary], root))[0];
  assert.ok(packed.files.every(file => !/(^|\/)(tests|node_modules|benchmarks|\.git)(\/|$)/.test(file.path)));
  assert.ok(packed.files.some(file => file.path === "dist/parser/LICENSE.upstream"));
  assert.ok(packed.files.some(file => file.path === "dist/parser/LICENSE.tree-sitter"));
  assert.ok(packed.files.some(file => file.path === "LICENSE"));
  const nativeFiles = packed.files.filter(file => file.path.endsWith(".node"));
  assert.equal(nativeFiles.length, 1);
  assert.ok(nativeFiles[0].path.startsWith(`prebuilds/${process.platform}-${process.arch}/`));
  const consumer = resolve(temporary, "consumer");
  mkdirSync(consumer);
  writeFileSync(resolve(consumer, "package.json"), JSON.stringify({ name: "nightshade-smoke", version: "1.0.0", private: true, type: "module" }));
  writeFileSync(resolve(consumer, "main.compact"), "export new type Tag<T> = T; export struct Box<T,#N> { values: Vector<N,T>; } export circuit entry(): Field { const value = (0 as Field, 1 as Field); return value as Tag<Field> as Field; }");
  const blockedTools = resolve(temporary, "blocked-tools"), invoked = resolve(temporary, "compiler-invocations.log");
  mkdirSync(blockedTools);
  const windows = process.platform === "win32";
  for (const name of ["cc", "c++", "gcc", "g++", "clang", "clang++", "cl", "make", "nmake", "cmake", "python", "python3", "node-gyp"]) {
    const file = resolve(blockedTools, name + (windows ? ".cmd" : ""));
    writeFileSync(file, windows ? `@echo ${name}>>"${invoked}"\r\n@exit /b 86\r\n` : `#!/bin/sh\nprintf '%s\\n' '${name}' >> '${invoked.replaceAll("'", "'\\''")}'\nexit 86\n`);
    chmodSync(file, 0o755);
  }
  const installEnv = { ...process.env, PATH: blockedTools + (windows ? ";" : ":") + process.env.PATH,
    CC: resolve(blockedTools, windows ? "cl.cmd" : "cc"), CXX: resolve(blockedTools, windows ? "cl.cmd" : "c++"),
    npm_config_python: resolve(blockedTools, windows ? "python.cmd" : "python3") };
  run("npm", ["install", "--omit=dev", "--no-audit", "--no-fund", resolve(temporary, packed.filename)], consumer, installEnv);
  assert.equal(existsSync(invoked), false, "Production install must not invoke a compiler toolchain");
  const installed = resolve(consumer, "node_modules/nightshade-compact");
  assert.equal(existsSync(resolve(installed, "build")), false);
  assert.equal(existsSync(resolve(consumer, "node_modules/tree-sitter-runtime/build")), false);
  renameSync(resolve(installed, "prebuilds"), resolve(installed, "prebuilds-saved"));
  const missing = spawnSync(process.execPath, [resolve(installed, "scripts/build-parser.mjs"), "--install"], { cwd: consumer, env: installEnv, encoding: "utf8", timeout: 10000 });
  assert.notEqual(missing.status, 0);
  assert.match(missing.stderr, /No matching prebuilt Compact parser/);
  assert.equal(existsSync(invoked), false, "Missing prebuild must fail explicitly without compiling");
  renameSync(resolve(installed, "prebuilds-saved"), resolve(installed, "prebuilds"));
  assert.equal(JSON.parse(readFileSync(resolve(installed, "package.json"), "utf8")).license, "Apache-2.0");
  assert.notEqual(JSON.parse(readFileSync(resolve(installed, "package.json"), "utf8")).private, true);
  assert.equal(readFileSync(resolve(installed, "LICENSE"), "utf8"), readFileSync(resolve(root, "LICENSE"), "utf8"));
  for (const dependency of ["tree-sitter-cli", "tree-sitter-compact", "typescript"]) assert.equal(existsSync(resolve(consumer, "node_modules", dependency)), false, dependency);
  const executable = resolve(consumer, "node_modules/.bin/nightshade");
  const metadata = JSON.parse(readFileSync(resolve(installed, "package.json"), "utf8"));
  assert.equal(metadata.name, "nightshade-compact");
  assert.deepEqual(metadata.bin, { nightshade: "dist/src/cli.js" });
  assert.equal(run(executable, ["--version"], consumer).trim(), "Nightshade 0.1.0");
  assert.match(run(process.execPath, [resolve(installed, "scripts/demo.mjs")], consumer), /Demo passed: expected finding and corrected control verified/);
  const report = JSON.parse(run(executable, ["main.compact", "--json"], consumer));
  assert.equal(report.status, "complete");
  assert.equal(report.schemaVersion, "1.6.0");
  assert.equal(report.semanticProfile, "compact-0.34.0-zkir2");
  assert.equal(report.entrypoints.length, 1);
  const project = resolve(consumer, "project"), projectSources = resolve(project, "contract/src");
  mkdirSync(projectSources, { recursive: true });
  mkdirSync(resolve(project, "node_modules/@owned/library"), { recursive: true });
  writeFileSync(resolve(projectSources, "main.compact"), 'import "@owned/library/helper"; export circuit entry(): Field { return number(); }');
  writeFileSync(resolve(projectSources, "unused.compact"), 'module unused { export circuit unused(): [] {} }');
  writeFileSync(resolve(project, "node_modules/@owned/library/helper.compact"), 'module helper { export circuit number(): Field { return 7 as Field; } }');
  const discovered = JSON.parse(run(executable, [project, "--json"], consumer, { ...process.env, COMPACT_PATH: "" }));
  assert.equal(discovered.status, "complete");
  assert.equal(discovered.entrypoints.length, 1);
  assert.deepEqual(discovered.selection.discovery.omittedLibraries, [resolve(projectSources, "unused.compact")]);
  assert.ok(discovered.coverage.parsed.includes(resolve(project, "node_modules/@owned/library/helper.compact")));
  for (const printer of ["human-summary", "ledger-access", "disclosure-map", "data-dependency"]) {
    const audit = JSON.parse(run(executable, ["print", printer, "main.compact", "--json"], consumer));
    assert.equal(audit.schemaVersion, "nightshade-auditor-1");
    assert.equal(audit.status, "complete");
    assert.equal(audit.entries.length, 1);
  }
  const detectorList = JSON.parse(run(executable, ["detector", "list", "--json"], consumer));
  const customModule = resolve(installed, "examples/zero-total-detector.cjs");
  assert.ok(existsSync(customModule));
  writeFileSync(resolve(consumer, "custom.compact"), 'export ledger total: Field; export circuit clear(): [] { total = 0 as Field; }');
  if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, resolve(consumer, "custom.compact")).valid, true);
  const customResult = spawnSync(executable, ["custom.compact", "--json", "--detector-module", customModule], { cwd: consumer, encoding: "utf8", timeout: 10000 });
  assert.equal(customResult.status, 1, customResult.stderr);
  const customReport = JSON.parse(customResult.stdout);
  assert.equal(customReport.status, "complete");
  assert.equal(customReport.customDetectors[0].factsVersion, 1);
  assert.deepEqual(customReport.findings.map(finding => finding.detectorId), ["custom-zero-total-write"]);
  assert.equal(JSON.parse(run(executable, ["custom.compact", "--json"], consumer)).customDetectors, undefined);
  for (const detector of detectorList) {
    const details = JSON.parse(run(executable, ["detector", "show", detector.id, "--json"], consumer))[0];
    assert.equal(details.documentation, readFileSync(resolve(installed, "docs/detectors", `${detector.id}.md`), "utf8"), detector.id);
  }
  for (const [version, language, compiler] of [["0.30.0", "0.22", process.env.COMPACTC_030_TEST], ["0.31.1", "0.23", process.env.COMPACTC_031_TEST]]) {
    const file = resolve(consumer, `legacy-${version}.compact`);
    writeFileSync(file, `pragma language_version ${language}; import CompactStandardLibrary; export ledger total: Field; export circuit entry(x: Uint<8>): JubjubPoint { total = disclose(x); return ecMulGenerator(x); }`);
    if (compiler) assert.equal(validateWithCompiler(compiler, file, [], 30000, 2, version).valid, true);
    const legacy = JSON.parse(run(executable, [file, "--json"], consumer));
    assert.equal(legacy.status, "complete");
    assert.equal(legacy.semanticProfile, `compact-${version}-zkir2`);
    assert.deepEqual(legacy.findings, []);
  }
  const eitherFile = resolve(consumer, "either-payload.compact");
  writeFileSync(eitherFile, `import CompactStandardLibrary;
export ledger stored: Field;
export circuit wrong(value: Either<Field,Field>): [] { assert(!value.is_left,"right"); stored = disclose(value.left); }
export circuit corrected(value: Either<Field,Field>): [] { assert(!value.is_left,"right"); stored = disclose(value.right); }`);
  if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, eitherFile).valid, true);
  assert.equal(run(process.execPath, ["--input-type=module", "-e", `
    import assert from 'node:assert/strict';
    import {scanFileIsolated} from 'nightshade-compact';
    const scan = await scanFileIsolated('either-payload.compact',{detectors:['either-payload-mismatch']});
    assert.equal(scan.status,'complete');
    assert.deepEqual(scan.diagnostics,[]);
    assert.deepEqual(scan.findings.map(finding=>finding.metadata.entry),['wrong']);
    console.log('receiver-snapshot');
  `], consumer).trim(), "receiver-snapshot");
  assert.match(run(executable, ["detector", "show", "either-payload-mismatch"], consumer), /inactive|Either/);
  const hashDomainFile = resolve(consumer, "hash-domain.compact");
  writeFileSync(hashDomainFile, `import CompactStandardLibrary;
export ledger digest: Bytes<32>;
export circuit small(value: Boolean): [] { digest = disclose(persistentHash<Boolean>(value)); }
export circuit salted(value: Boolean, opening: Bytes<32>): [] { digest = persistentCommit<Boolean>(value,opening); }`);
  if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, hashDomainFile).valid, true);
  assert.equal(run(process.execPath, ["--input-type=module", "-e", `
    import assert from 'node:assert/strict';
    import {scanFileIsolated} from 'nightshade-compact';
    const scan = await scanFileIsolated('hash-domain.compact',{detectors:['low-entropy-hash-disclosure']});
    const defaults = await scanFileIsolated('hash-domain.compact');
    assert.equal(defaults.status,'complete');
    assert.deepEqual(defaults.findings.filter(finding=>finding.detectorId==='low-entropy-hash-disclosure').map(finding=>finding.metadata.entry),['small']);
    assert.equal(scan.status,'complete');
    assert.deepEqual(scan.findings.map(finding=>[finding.metadata.entry,finding.metadata.inputDomainUpperBound]),[['small',2]]);
    console.log('typed-domain');
  `], consumer).trim(), "typed-domain");
  assert.match(run(executable, ["detector", "show", "low-entropy-hash-disclosure"], consumer), /65,536/);
  writeFileSync(resolve(consumer, "quantity.compact"), 'export circuit entry(left: Uint<8>, right: Uint<8>): Field { return disclose((left as Field)-(right as Field)); }');
  if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, resolve(consumer, "quantity.compact")).valid, true);
  const quantity = JSON.parse(run(executable, ["quantity.compact", "--json", "--detectors", "field-arithmetic-wraparound", "--fail-on", "critical"], consumer));
  assert.equal(quantity.status, "complete");
  assert.deepEqual(quantity.findings.map(finding=>finding.detectorId), ["field-arithmetic-wraparound"]);
  assert.ok(JSON.parse(run(executable, ["quantity.compact", "--json", "--fail-on", "critical"], consumer)).findings.every(finding=>finding.detectorId!=="field-arithmetic-wraparound"));
  assert.equal(JSON.parse(run(executable, ["detector", "show", "field-arithmetic-wraparound", "--json"], consumer))[0].defaultEnabled, false);
  writeFileSync(resolve(consumer, "duplicate-mint.compact"), 'import CompactStandardLibrary; export circuit repeated(nonce: Bytes<32>): [] { const saved = persistentHash<Bytes<32>>(evolveNonce(0,nonce)); mintShieldedToken(default<Bytes<32>>,1,disclose(saved),shieldedBurnAddress()); mintShieldedToken(default<Bytes<32>>,1,disclose(saved),shieldedBurnAddress()); }');
  if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, resolve(consumer, "duplicate-mint.compact")).valid, true);
  const duplicateMint = JSON.parse(run(executable, ["duplicate-mint.compact", "--json", "--fail-on", "critical"], consumer));
  assert.equal(duplicateMint.status, "complete");
  assert.deepEqual(duplicateMint.findings.filter(finding=>finding.detectorId==="duplicate-shielded-mint").map(finding=>finding.metadata.entry), ["repeated"]);
  assert.ok(duplicateMint.coverage.rules.some(row=>row.detectorId==="duplicate-shielded-mint" && row.status==="complete"));
  assert.notEqual(JSON.parse(run(executable, ["detector", "show", "duplicate-shielded-mint", "--json"], consumer))[0].defaultEnabled, false);
  writeFileSync(resolve(consumer, "mint-limit.compact"), 'import CompactStandardLibrary; export circuit reward(amount: Uint<64>, nonce: Bytes<32>): [] { assert(amount>0,"positive"); mintShieldedToken(default<Bytes<32>>,disclose(amount),disclose(nonce),shieldedBurnAddress()); }');
  if (process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST, resolve(consumer, "mint-limit.compact")).valid, true);
  const mintLimit = JSON.parse(run(executable, ["mint-limit.compact", "--json", "--detectors", "unbounded-mint", "--fail-on", "critical"], consumer));
  assert.equal(mintLimit.status,"complete");
  assert.deepEqual(mintLimit.findings.map(finding=>finding.detectorId),["unbounded-mint"]);
  assert.ok(JSON.parse(run(executable,["mint-limit.compact","--json","--fail-on","critical"],consumer)).findings.every(finding=>finding.detectorId!=="unbounded-mint"));
  assert.equal(JSON.parse(run(executable,["detector","show","unbounded-mint","--json"],consumer))[0].defaultEnabled,false);
  writeFileSync(resolve(consumer, "witness-state.compact"), 'import CompactStandardLibrary; export ledger stored:Uint<64>; witness amount():Uint<64>; export circuit save():[]{stored=disclose(amount());}');
  if(process.env.COMPACTC_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_TEST,resolve(consumer,"witness-state.compact")).valid,true);
  const witnessState=JSON.parse(run(executable,["witness-state.compact","--json","--detectors","unconstrained-witness-to-state","--fail-on","critical"],consumer));
  assert.equal(witnessState.status,"complete");
  assert.deepEqual(witnessState.findings.map(finding=>finding.detectorId),["unconstrained-witness-to-state"]);
  assert.ok(JSON.parse(run(executable,["witness-state.compact","--json","--fail-on","critical"],consumer)).findings.every(finding=>finding.detectorId!=="unconstrained-witness-to-state"));
  assert.equal(JSON.parse(run(executable,["detector","show","unconstrained-witness-to-state","--json"],consumer))[0].defaultEnabled,false);
  const rc2File = resolve(consumer, "rc2.compact");
  writeFileSync(rc2File, 'pragma language_version 0.25; export struct Box<T> { value: JubjubScalar, other: T } export circuit entry(x: JubjubScalar): JubjubScalar { return x; }');
  if (process.env.COMPACTC_033_RC2_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_033_RC2_TEST, rc2File, [], 30000, 2, "0.33.0-rc.2").valid, true);
  const rc2 = JSON.parse(run(executable, [rc2File, "--json", "--compiler-version", "0.33.0-rc.2"], consumer));
  assert.equal(rc2.status, "complete");
  assert.equal(rc2.semanticProfile, "compact-0.33.0-rc.2-zkir2");
  writeFileSync(rc2File, 'pragma language_version 0.25; import CompactStandardLibrary; export { JubjubPoint }; export circuit entry(x: JubjubPoint): JubjubPoint { return ecNeg(x); }');
  if (process.env.COMPACTC_033_RC2_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_033_RC2_TEST, rc2File, [], 30000, 2, "0.33.0-rc.2").valid, true);
  assert.equal(JSON.parse(run(executable, [rc2File, "--json"], consumer)).status, "complete");
  const prereleaseFile = resolve(consumer, "prerelease.compact");
  writeFileSync(prereleaseFile, 'pragma language_version 0.27; import CompactStandardLibrary; export ledger recipient: PublicAddress; export circuit entry(value: PublicAddress): PublicAddress { recipient = disclose(value); return recipient; }');
  if (process.env.COMPACTC_035_RC1_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_035_RC1_TEST, prereleaseFile, [], 30000, 2, "0.35.0-rc.1").valid, true);
  const prerelease = JSON.parse(run(executable, [prereleaseFile, "--json", "--compiler-version", "0.35.0-rc.1"], consumer));
  assert.equal(prerelease.status, "complete");
  assert.equal(prerelease.semanticProfile, "compact-0.35.0-rc.1-zkir2");
  if (process.env.COMPACTC_035_TEST) assert.equal(validateWithCompiler(process.env.COMPACTC_035_TEST, prereleaseFile, [], 30000, 2, "0.35.0").valid, true);
  const stable = JSON.parse(run(executable, [prereleaseFile, "--json"], consumer));
  assert.equal(stable.status, "complete");
  assert.equal(stable.semanticProfile, "compact-0.35.0-zkir2");
  if (process.env.OZ_COMPACT_TEST) {
    const searchPaths = [resolve(process.env.OZ_COMPACT_TEST, "contracts/src")];
    const policyFile = resolve(consumer, "oz.compact");
    writeFileSync(policyFile, 'import CompactStandardLibrary; import "access/Ownable" prefix O_; export circuit entry(): [] { O_initialize(left<Bytes<32>, ContractAddress>(pad(32, "owner"))); }');
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, policyFile, searchPaths);
      assert.equal(compiled.valid, true, compiled.error);
    }
    writeFileSync(resolve(consumer, "oz-policy.json"), JSON.stringify({ version: 1, searchPaths,
      policies: { builtins: ["openzeppelin-ownable"] } }));
    const policyResult = spawnSync(executable, ["oz.compact", "--json", "--config", "oz-policy.json"], { cwd: consumer, encoding: "utf8", timeout: 10000 });
    assert.equal(policyResult.status, 1, policyResult.error?.message ?? policyResult.stderr);
    const policyReport = JSON.parse(policyResult.stdout);
    assert.equal(policyReport.status, "complete");
    assert.deepEqual(policyReport.findings.map(finding => [finding.detectorId, finding.metadata.precondition]), [["openzeppelin-preconditions", "constructor-only"]]);
    writeFileSync(resolve(consumer, "role-bootstrap-config.json"), JSON.stringify({ version: 1, searchPaths }));
    for (const [kind, expected] of [["positive", 1], ["corrected", 0], ["lookalike", 0]]) {
      const filename = `role-bootstrap-${kind}.compact`;
      writeFileSync(resolve(consumer, filename), readFileSync(resolve(root, `tests/corpus/known-bugs/library-role-bootstrap-${kind}.compact`)));
      const role = JSON.parse(run(executable, [filename, "--json", "--config", "role-bootstrap-config.json", "--detectors", "missing-role-bootstrap", "--fail-on", "critical"], consumer));
      assert.equal(role.status, "complete");
      assert.equal(role.coverage.baselineStatus, "complete");
      assert.equal(role.findings.length, expected);
      assert.ok(role.coverage.rules.every(row => row.status === "complete"));
      assert.ok(role.findings.every(finding => finding.detectorId === "missing-role-bootstrap" && finding.severity === "low" && finding.confidence === "high"));
    }
    writeFileSync(resolve(consumer, "nft-metadata-config.json"), JSON.stringify({ version: 1, searchPaths,
      policies: { currentNftMetadata: [{ owners: "_owners", metadata: "cachedURI", consumer: "replaceToken" }] } }));
    for (const [kind, expected] of [["positive", 1], ["corrected", 0], ["lookalike", 0]]) {
      const filename = `nft-metadata-${kind}.compact`;
      writeFileSync(resolve(consumer, filename), readFileSync(resolve(root, `tests/corpus/known-bugs/library-nft-cache-lifecycle-${kind}.compact`)));
      const metadata = JSON.parse(run(executable, [filename, "--json", "--config", "nft-metadata-config.json",
        "--detectors", "stale-nft-metadata", "--fail-on", "critical"], consumer));
      assert.equal(metadata.status, "complete", JSON.stringify(metadata.diagnostics));
      assert.equal(metadata.coverage.baselineStatus, "complete");
      assert.equal(metadata.findings.length, expected);
      assert.ok(metadata.coverage.rules.every(row => ["complete", "not-applicable"].includes(row.status)));
      assert.ok(metadata.findings.every(finding => finding.detectorId === "stale-nft-metadata"
        && finding.severity === "low" && finding.confidence === "high" && finding.metadata.crossEntryCoverage === false));
      const ordinary = JSON.parse(run(executable, [filename, "--json", "--config", "nft-metadata-config.json", "--fail-on", "critical"], consumer));
      assert.ok(ordinary.findings.every(finding => finding.detectorId !== "stale-nft-metadata"));
    }
    assert.match(run(executable, ["detector", "show", "stale-nft-metadata"], consumer), /currentNftMetadata/);
    writeFileSync(resolve(consumer, "contract-owner-config.json"), JSON.stringify({ version: 1, searchPaths,
      policies: { callableOwnable: [{ owner: "_owner" }] } }));
    for (const [kind, expected] of [["positive", 1], ["corrected", 0], ["lookalike", 0]]) {
      const filename = `contract-owner-${kind}.compact`;
      writeFileSync(resolve(consumer, filename), readFileSync(resolve(root, `tests/corpus/known-bugs/library-contract-owner-${kind}.compact`)));
      const ownership = JSON.parse(run(executable, [filename, "--json", "--config", "contract-owner-config.json",
        "--detectors", "unsupported-contract-owner", "--fail-on", "critical"], consumer));
      assert.equal(ownership.status, "complete", JSON.stringify(ownership.diagnostics));
      assert.equal(ownership.coverage.baselineStatus, "complete");
      assert.equal(ownership.findings.length, expected);
      assert.ok(ownership.coverage.rules.every(row => ["complete", "not-applicable"].includes(row.status)));
      assert.ok(ownership.findings.every(finding => finding.detectorId === "unsupported-contract-owner"
        && finding.severity === "medium" && finding.confidence === "high"));
      const ordinary = JSON.parse(run(executable, [filename, "--json", "--config", "contract-owner-config.json", "--fail-on", "critical"], consumer));
      assert.ok(ordinary.findings.every(finding => finding.detectorId !== "unsupported-contract-owner"));
    }
    assert.match(run(executable, ["detector", "show", "unsupported-contract-owner"], consumer), /callableOwnable/);
    const ecdsa = JSON.parse(run(executable, [resolve(process.env.OZ_COMPACT_TEST, "contracts/src/crypto/test/mocks/MockEcdsa.compact"), "--zkir-version", "3", "--json"], consumer));
    assert.equal(ecdsa.status, "complete");
    assert.equal(ecdsa.entrypoints.length, 3);
    assert.deepEqual(ecdsa.coverage.completedEntries, ecdsa.entrypoints);
    assert.deepEqual(ecdsa.findings, []);
  }
  const inventory = JSON.parse(run(executable, ["print", "inventory", "main.compact"], consumer));
  assert.equal(inventory.schemaVersion, "nightshade-analysis-inventory-1");
  assert.equal(inventory.scope, "resolved-semantic-inventory");
  assert.equal(inventory.status, "complete");
  assert.equal(inventory.entrypoints.length, 1);
  assert.equal(run(process.execPath, ["--input-type=module", "-e", "import {buildAnalysisInventory,Program} from 'nightshade-compact'; const inventory = buildAnalysisInventory(new Program('main.compact')); console.log(inventory.schemaVersion + ':' + inventory.status)"], consumer).trim(), "nightshade-analysis-inventory-1:complete");
  writeFileSync(resolve(consumer, "inventory-opaque.compact"), 'export circuit entry(input: Opaque<"string">): Opaque<"string"> { return input; }');
  const incompleteInventory = spawnSync(executable, ["print", "inventory", "inventory-opaque.compact"], { cwd: consumer, encoding: "utf8", timeout: 10000 });
  assert.equal(incompleteInventory.status, 2, incompleteInventory.error?.message ?? incompleteInventory.stderr);
  assert.equal(JSON.parse(incompleteInventory.stdout).status, "incomplete");
  assert.ok(JSON.parse(incompleteInventory.stdout).gaps.every(gap => gap.code === "inventory-unsupported-type"));
  writeFileSync(resolve(consumer, "opaque.compact"), 'import { persistentHash } from CompactStandardLibrary; export circuit entry(input: Opaque<"string">): Bytes<32> { return persistentHash<Opaque<"string">>(input); }');
  assert.equal(run(process.execPath, ["--input-type=module", "-e", "import {scanFileIsolated} from 'nightshade-compact'; const result = await scanFileIsolated('opaque.compact'); console.log(result.status + ':' + result.diagnostics[0].code)"], consumer).trim(), "incomplete:unsupported-opaque-intrinsic");
  assert.match(report.grammarBuild, /^[a-f0-9]{64}$/);
  writeFileSync(resolve(consumer, "subset.compact"), "export circuit first(value: Field): Field { return disclose(value); } export circuit second(value: Field): Field { return disclose(value); }");
  assert.equal(run(process.execPath, ["--input-type=module", "-e", "import assert from 'node:assert/strict'; import {Dataflow,Program} from 'nightshade-compact'; const program = new Program('subset.compact'); const flow = new Dataflow(program); const entries = [...program.entries]; const subset = flow.analyzeSubset([entries[1]]); assert.deepEqual(subset.diagnostics,[]); assert.deepEqual(subset.completedEntries,[entries[1]]); assert.ok(subset.paths.every(path => path.entry === entries[1])); assert.throws(() => flow.analyzeSubset([entries[1],entries[1]])); assert.deepEqual(flow.analyzeSubset([]).paths,[]); assert.deepEqual(program.entries,entries); assert.deepEqual(flow.analyze().completedEntries,entries); console.log('subset')"], consumer).trim(), "subset");
  assert.equal(run(process.execPath, ["--input-type=module", "-e", "import {scanFile} from 'nightshade-compact'; console.log(scanFile('main.compact').status)"], consumer).trim(), "complete");
  assert.equal(run(process.execPath, ["--input-type=module", "-e", "import {scanFileIsolated} from 'nightshade-compact'; console.log((await scanFileIsolated('main.compact')).status)"], consumer).trim(), "complete");
  writeFileSync(resolve(consumer, "typed.compact"), "import { Counter, Map } from CompactStandardLibrary; export ledger table: Map<Field,Counter>; circuit widen(value: Uint<8>): Uint<16> { const result: Uint<16> = value; return result; } export circuit entry(): Uint<64> { table.insertDefault(0 as Field); table.lookup(0 as Field) += widen(1); return table.lookup(0 as Field).read(); }");
  const typed = JSON.parse(run(executable, ["typed.compact", "--json"], consumer));
  assert.equal(typed.status, "complete");
  assert.equal(run(process.execPath, ["--input-type=module", "-e", "import {Dataflow,Program} from 'nightshade-compact'; const facts = new Dataflow(new Program('typed.compact')).analyze(); console.log(facts.paths[0].sinks.find(sink => sink.kind === 'exported-return').value.constant)"], consumer).trim(), "1");
  writeFileSync(resolve(consumer, "collections.compact"), "import { Map } from CompactStandardLibrary; export ledger table: Map<Field,Field>; export circuit entry(): [Boolean,Uint<64>] { table.resetToDefault(); table.insert(1 as Field,2 as Field); table.insert(1 as Field,3 as Field); return [table.member(1 as Field),table.size()]; } export circuit absent(): Field { table.resetToDefault(); return table.lookup(1 as Field); }");
  assert.equal(run(process.execPath, ["--input-type=module", "-e", "import assert from 'node:assert/strict'; import {Dataflow,Program,scanFileIsolated} from 'nightshade-compact'; const facts = new Dataflow(new Program('collections.compact')).analyze(); assert.deepEqual(facts.diagnostics,[]); assert.equal(facts.completedEntries.length,2); assert.equal(facts.paths.length,1); assert.deepEqual(facts.paths[0].sinks.find(sink => sink.kind === 'exported-return').value.items.map(item => item.constant),['true','1']); console.log((await scanFileIsolated('collections.compact')).status)"], consumer).trim(), "complete");
  writeFileSync(resolve(consumer, "lists.compact"), "import { List } from CompactStandardLibrary; export ledger items: List<Field>; export circuit entry(): [Field,Field,Uint<64>] { items.resetToDefault(); items.pushFront(3 as Field); items.pushFront(9 as Field); const saved = items.head(); items.popFront(); return [saved.value,items.head().value,items.length()]; }");
  writeFileSync(resolve(consumer, "empty-list-pop.compact"), "import { List } from CompactStandardLibrary; export ledger items: List<Field>; export circuit entry(): [] { items.resetToDefault(); items.popFront(); }");
  writeFileSync(resolve(consumer, "guarded-list-pop.compact"), 'import { List } from CompactStandardLibrary; export ledger items: List<Field>; export circuit entry(): [Boolean,Uint<64>] { assert(!items.isEmpty(),"nonempty"); items.popFront(); return [items.isEmpty(),items.length()]; }');
  writeFileSync(resolve(consumer, "consumed-list-proof.compact"), 'import { List } from CompactStandardLibrary; export ledger items: List<Field>; export circuit entry(): [] { assert(!items.isEmpty(),"nonempty"); items.popFront(); items.popFront(); }');
  assert.equal(run(process.execPath, ["--input-type=module", "-e", `
    import assert from 'node:assert/strict';
    import {Dataflow,Program,scanFileIsolated} from 'nightshade-compact';
    const program = new Program('guarded-list-pop.compact');
    const facts = new Dataflow(program).analyze();
    assert.deepEqual(facts.diagnostics, []);
    assert.deepEqual(facts.completedEntries, program.entries);
    assert.deepEqual(facts.paths[0].sinks.find(sink => sink.kind === 'exported-return').value.items.map(item => item.constant), [undefined, undefined]);
    assert.equal((await scanFileIsolated('guarded-list-pop.compact')).status, 'complete');
    const consumed = await scanFileIsolated('consumed-list-proof.compact');
    assert.equal(consumed.status, 'incomplete');
    assert.ok(consumed.diagnostics.some(item => item.code === 'list-pop-outcome-unqualified'));
    assert.deepEqual(consumed.coverage.completedEntries, []);
    console.log('guarded-tail');
  `], consumer).trim(), "guarded-tail");
  writeFileSync(resolve(consumer, "path-budget.compact"), "pragma language_version 0.26.0; export circuit entry(flag: Boolean): Field { return disclose(flag) ? 1 as Field : 2 as Field; }");
  assert.equal(run(process.execPath, ["--input-type=module", "-e", "import assert from 'node:assert/strict'; import {Dataflow,Program} from 'nightshade-compact'; const program = new Program('path-budget.compact'); for (const engine of ['instructions','expressions']) { const limited = new Dataflow(program,20000,1,50000,engine).analyze(); assert.deepEqual(limited.completedEntries,[]); assert.ok(limited.diagnostics.some(item => item.code === 'analysis-budget')); assert.ok(limited.paths.length <= 1); const exact = new Dataflow(program,20000,2,50000,engine).analyze(); assert.deepEqual(exact.diagnostics,[]); assert.equal(exact.paths.length,2); } console.log('bounded')"], consumer).trim(), "bounded");
  writeFileSync(resolve(consumer, "counter-witness.compact"), "pragma language_version 0.26.0; import CompactStandardLibrary; export ledger count: Counter; export circuit entry(first: Boolean, second: Boolean): [] { count.resetToDefault(); if (disclose(first)) count.increment(1); if (disclose(second)) count.increment(2); }");
  const correlatedSource = `import CompactStandardLibrary; export ledger count: Counter; export circuit entry(${Array.from({ length: 10 }, (_, index) => `flag${index}: Boolean`).join(",")}): [] { ${Array.from({ length: 10 }, (_, index) => `if (disclose(flag${index})) { count.increment(1); }`).join(" ")} }`;
  writeFileSync(resolve(consumer, "correlated.compact"), correlatedSource);
  const predicateSource = correlatedSource.replace(/flag(\d+): Boolean/g, "value$1: Field").replace(/disclose\(flag(\d+)\)/g, "disclose(value$1) == (0 as Field)");
  writeFileSync(resolve(consumer, "correlated-predicates.compact"), predicateSource);
  const helperSource = predicateSource.replace("export circuit entry(", "circuit batch(") + ` export circuit entry(${Array.from({ length: 10 }, (_, i) => `value${i}: Field`).join(",")}): [] { batch(${Array.from({ length: 10 }, (_, i) => `value${i}`).join(",")}); }`;
  writeFileSync(resolve(consumer, "correlated-helpers.compact"), helperSource);
  const returnSource = `import CompactStandardLibrary; export ledger count: Counter;
circuit guard(): [] { const checked = count.read(); }
circuit bump(value: Field): Field { if (disclose(value) == (0 as Field)) { count.increment(1); return 0 as Field; } count.increment(2); return 1 as Field; }
export circuit entry(${Array.from({ length: 10 }, (_, i) => `value${i}: Field`).join(",")}): Uint<64> { count.resetToDefault(); ${Array.from({ length: 10 }, (_, i) => `bump(value${i});`).join(" ")} return count.read(); }`;
  writeFileSync(resolve(consumer, "correlated-returns.compact"), returnSource);
  const expressionSource = `import CompactStandardLibrary; export ledger count: Counter;
circuit guard(): [] { const checked = count.read(); }
circuit tick(value: Uint<8>): Boolean { count.increment(disclose((value + 1) as Uint<16>)); return value * 2 <= 2; }
export circuit entry(${Array.from({ length: 10 }, (_, i) => `value${i}: Uint<8>`).join(",")}): Uint<64> { count.resetToDefault(); ${Array.from({ length: 10 }, (_, i) => `disclose(value${i} == (0 as Uint<8>)) && tick(value${i});`).join(" ")} return count.read(); }`;
  writeFileSync(resolve(consumer, "correlated-expressions.compact"), expressionSource);
  if (process.env.COMPACTC_TEST) {
    for (const fixture of ["correlated.compact", "correlated-predicates.compact", "correlated-helpers.compact", "correlated-returns.compact", "correlated-expressions.compact"]) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, resolve(consumer, fixture));
      assert.equal(compiled.valid, true, compiled.error);
    }
  }
  const correlatedReport = JSON.parse(run(executable, ["correlated.compact", "--json"], consumer));
  assert.equal(correlatedReport.status, "complete");
  assert.equal(correlatedReport.coverage.completedEntries.length, 1);
  assert.equal(JSON.parse(run(executable, ["correlated-predicates.compact", "--json"], consumer)).status, "complete");
  assert.equal(JSON.parse(run(executable, ["correlated-helpers.compact", "--json"], consumer)).status, "complete");
  assert.equal(JSON.parse(run(executable, ["correlated-returns.compact", "--json", "--fail-on", "none"], consumer)).status, "complete");
  assert.equal(JSON.parse(run(executable, ["correlated-expressions.compact", "--json", "--fail-on", "none"], consumer)).status, "complete");
  assert.equal(run(process.execPath, ["--input-type=module", "-e", `
    import assert from 'node:assert/strict';
    import {Dataflow, Program, scanFile, scanFileIsolated} from 'nightshade-compact';
    const flow = new Dataflow(new Program('correlated.compact'));
    const exact = flow.analyze();
    assert.deepEqual(exact.completedEntries, []);
    assert.ok(exact.diagnostics.some(item => item.code === 'analysis-budget'));
    const analyzed = flow.analyzeWithCorrelatedQueries([]);
    assert.deepEqual(analyzed.exact.completedEntries, []);
    assert.equal(analyzed.correlated.length, 1);
    const policies = {secrets: Array.from({length:10},(_,index)=>({circuit:'entry',parameter:'flag'+index})), authorization:[{state:'count',guard:'entry'}]};
    const direct = scanFile('correlated.compact', {policies});
    const isolated = await scanFileIsolated('correlated.compact', {policies});
    assert.equal(direct.status, 'complete'); assert.equal(isolated.status, 'complete');
    assert.equal(direct.findings.length, 65);
    assert.deepEqual(isolated.findings, direct.findings);
    assert.equal(direct.coverage.completedEntries.length, 1);
    assert.ok(direct.metrics.steps <= 20000 && direct.metrics.abstractValues <= 50000);
    const predicatePolicies = {secrets: Array.from({length:10},(_,index)=>({circuit:'entry',parameter:'value'+index})), authorization:[{state:'count',guard:'entry'}]};
    for (const [file, guard, expected] of [['correlated-predicates.compact','entry',65], ['correlated-helpers.compact','entry',65], ['correlated-returns.compact','guard',33], ['correlated-expressions.compact','guard',32]]) {
      const policies = {...predicatePolicies, authorization:[{state:'count',guard}]};
      const predicateDirect = scanFile(file, {policies});
      const predicateIsolated = await scanFileIsolated(file, {policies});
      assert.equal(predicateDirect.status, 'complete'); assert.equal(predicateIsolated.status, 'complete');
      assert.equal(predicateDirect.findings.length, expected);
      assert.deepEqual(predicateDirect.findings, predicateIsolated.findings);
      assert.equal(predicateDirect.coverage.completedEntries.length, 1);
      assert.ok(predicateDirect.metrics.steps <= 20000 && predicateDirect.metrics.abstractValues <= 50000);
    }
    console.log('correlated-completion');
  `], consumer).trim(), "correlated-completion");
  assert.ok(packed.files.some(file => file.path === "docs/schema/report-counter.schema.json"));
  const predicateReport = JSON.parse(run(executable, ["counter-witness.compact", "--json", "--experimental-counter-queries"], consumer));
  assert.equal(predicateReport.schemaVersion, "1.7.0");
  assert.equal(predicateReport.scope, "selected-detector-predicates");
  assert.equal(predicateReport.status, "complete");
  assert.deepEqual(predicateReport.analysis.coverage.map(row => row.detector).sort(), [
    "ledger-bound-preimage-publication", "declared-secret-publication", "unguarded-sensitive-state-write",
    "forbidden-state-transition", "predictable-commitment-randomness", "impossible-assertion",
    "circuit-work-budget", "spoofable-authorization", "public-key-membership-authorization", "publicly-derivable-encryption-secret", "merkle-membership-not-enforced", "merkle-leaf-binding-review", "identity-signature-key",
    "ignored-validation-result", "discarded-comparison", "discarded-shielded-send-result", "either-payload-mismatch", "low-entropy-hash-disclosure", "duplicate-shielded-mint", "missing-role-bootstrap",
    "circuit-cost", "duplicated-branch-tail", "redundant-boolean-branch", "redundant-self-shielded-receive", "caller-supplied-deadline", "freshness-bound-caller-time",
    "field-recomposition-range-review", "zero-amount-set-consumption-review",
  ].sort());
  assert.match(run(executable, ["detector", "show", "zero-amount-set-consumption-review"], consumer), /default-on/);
  assert.ok(packed.files.some(file => file.path === "docs/detectors/zero-amount-set-consumption-review.md"));
  assert.ok(predicateReport.analysis.coverage.every(row => row.status === "covered"));
  assert.deepEqual(predicateReport.coverage.completedEntries, []);
  assert.equal(predicateReport.metrics.paths, 0);
  for (const kind of ["positive", "corrected", "lookalike"]) {
    const filename = `merkle-byte-${kind}.compact`;
    writeFileSync(resolve(consumer, filename), readFileSync(resolve(root, `tests/corpus/drafts/merkle-byte-binding/single-${kind}.compact`)));
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, resolve(consumer, filename));
      assert.equal(compiled.valid, true, compiled.error);
    }
    const report = JSON.parse(run(executable, [filename, "--detectors", "merkle-leaf-binding-review", "--json", "--fail-on", "none"], consumer));
    assert.equal(report.status, "complete");
    assert.deepEqual(report.findings.map(item => item.location.line), kind === "positive" ? [10] : []);
    assert.ok(report.findings.every(item => item.severity === "info" && item.metadata.argumentIndex === 0));
    if (kind === "positive") {
      const defaults = JSON.parse(run(executable, [filename, "--json", "--fail-on", "none"], consumer));
      assert.equal(defaults.status, "complete");
      assert.ok(defaults.coverage.detectors.includes("merkle-leaf-binding-review"));
      assert.deepEqual(defaults.findings.filter(item => item.detectorId === "merkle-leaf-binding-review"), report.findings);
    }
  }
  assert.ok(packed.files.some(file => file.path === "docs/detectors/merkle-leaf-binding-review.md"));
  assert.match(run(executable, ["detector", "show", "merkle-leaf-binding-review"], consumer), /default-on/);
  for (const kind of ["positive", "corrected", "lookalike"]) {
    const filename = `branch-tail-${kind}.compact`;
    writeFileSync(resolve(consumer, filename), readFileSync(resolve(root, `tests/corpus/known-bugs/counter-branch-tail-${kind}.compact`)));
    const report = JSON.parse(run(executable, [filename, "--detectors", "duplicated-branch-tail", "--json", "--fail-on", "none"], consumer));
    assert.equal(report.status, "complete");
    assert.equal(report.coverage.baselineStatus, "complete");
    assert.deepEqual(report.findings.map(item => item.location.line), kind === "positive" ? [30] : []);
  }
  assert.ok(packed.files.some(file => file.path === "docs/detectors/duplicated-branch-tail.md"));
  for (const kind of ["positive", "corrected", "lookalike"]) {
    const filename = `write-only-ledger-${kind}.compact`;
    writeFileSync(resolve(consumer, filename), readFileSync(resolve(root, `tests/corpus/known-bugs/counter-write-only-ledger-${kind}.compact`)));
    const report = JSON.parse(run(executable, [filename, "--detectors", "write-only-ledger", "--json", "--fail-on", "none"], consumer));
    assert.equal(report.status, "complete");
    assert.equal(report.coverage.baselineStatus, "complete");
    assert.deepEqual(report.findings.map(item => item.location.line), kind === "positive" ? [29] : []);
    assert.ok(report.findings.every(item => item.severity === "info" && item.confidence === "high" && item.metadata.offchainReads === "not-analyzed"));
    assert.ok(report.coverage.rules.every(row => row.status === "complete"));
  }
  assert.ok(packed.files.some(file => file.path === "docs/detectors/write-only-ledger.md"));
  assert.match(run(executable, ["detector", "show", "write-only-ledger"], consumer), /off-chain metadata/);
  writeFileSync(resolve(consumer, "atomic-policy.json"), JSON.stringify({ version: 1,
    detectors: ["checkpoint-splits-atomic-update"],
    policies: { atomicUpdates: [{ circuit: "increment", ledgers: ["primary", "mirror"] }] } }));
  for (const kind of ["positive", "corrected", "lookalike"]) {
    const filename = `checkpoint-atomic-${kind}.compact`;
    writeFileSync(resolve(consumer, filename), readFileSync(resolve(root, `tests/corpus/known-bugs/counter-checkpoint-atomic-${kind}.compact`)));
    const report = JSON.parse(run(executable, [filename, "--config", "atomic-policy.json", "--json", "--fail-on", "none"], consumer));
    assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
    assert.equal(report.coverage.baselineStatus, "complete");
    assert.deepEqual(report.findings.map(item => item.location.line), kind === "positive" ? [32] : []);
    assert.ok(report.findings.every(item => item.severity === "low" && item.confidence === "high" && item.metadata.partialFailure === "not-proven"));
    assert.ok(report.coverage.rules.every(row => row.status === "complete"));
  }
  assert.ok(packed.files.some(file => file.path === "docs/detectors/checkpoint-splits-atomic-update.md"));
  assert.match(run(executable, ["detector", "show", "checkpoint-splits-atomic-update"], consumer), /atomicUpdates/);
  for (const kind of ["positive", "corrected", "lookalike"]) {
    const filename = `balance-threshold-${kind}.compact`;
    writeFileSync(resolve(consumer, filename), readFileSync(resolve(root, `tests/corpus/known-bugs/counter-balance-threshold-${kind}.compact`)));
    const report = JSON.parse(run(executable, [filename, "--detectors", "exact-balance-threshold", "--json", "--fail-on", "none"], consumer));
    assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
    assert.deepEqual(report.findings.map(item => item.location.line), kind === "positive" ? [20] : []);
    assert.ok(report.findings.every(item => item.severity === "info" && item.confidence === "high"));
    const defaultReport = JSON.parse(run(executable, [filename, "--json", "--fail-on", "none"], consumer));
    assert.ok(defaultReport.findings.every(item => item.detectorId !== "exact-balance-threshold"));
  }
  assert.ok(packed.files.some(file => file.path === "docs/detectors/exact-balance-threshold.md"));
  assert.match(run(executable, ["detector", "show", "exact-balance-threshold"], consumer), /comparison helpers/);
  for (const kind of ["positive", "corrected", "lookalike"]) {
    const filename = `digest-narrowing-${kind}.compact`;
    writeFileSync(resolve(consumer, filename), readFileSync(resolve(root, `tests/corpus/known-bugs/counter-digest-narrowing-${kind}.compact`)));
    const report = JSON.parse(run(executable, [filename, "--detectors", "checked-digest-narrowing", "--json", "--fail-on", "none"], consumer));
    assert.equal(report.status, "complete", JSON.stringify(report.diagnostics));
    assert.deepEqual(report.findings.map(item => item.location.line), kind === "positive" ? [22] : []);
    assert.ok(report.findings.every(item => item.severity === "info" && item.confidence === "high" && item.metadata.runtimeFailure === "not-proven"));
    const defaultReport = JSON.parse(run(executable, [filename, "--json", "--fail-on", "none"], consumer));
    assert.ok(defaultReport.findings.every(item => item.detectorId !== "checked-digest-narrowing"));
  }
  assert.ok(packed.files.some(file => file.path === "docs/detectors/checked-digest-narrowing.md"));
  assert.match(run(executable, ["detector", "show", "checked-digest-narrowing"], consumer), /little-endian/);
  for (const kind of ["positive", "corrected", "lookalike"]) {
    const filename = `runtime-width-${kind}.compact`;
    writeFileSync(resolve(consumer, filename), readFileSync(resolve(root, `tests/corpus/known-bugs/counter-runtime-width-${kind}.compact`)));
    const report = JSON.parse(run(executable, [filename, "--detectors", "shielded-coin-runtime-width", "--json", "--fail-on", "none"], consumer));
    assert.equal(report.status, "complete");
    assert.equal(report.coverage.baselineStatus, "complete");
    assert.deepEqual(report.findings.map(item => item.location.line), kind === "positive" ? [34] : []);
    assert.ok(report.coverage.rules.every(row => row.status !== "incomplete"));
    for (const item of report.findings) {
      assert.equal(item.metadata.runtimeApplicability, "expressly-assumed-reference-runtime");
      assert.equal(item.metadata.referenceRuntimeVersion, "0.19.0");
      assert.equal(item.metadata.actualRuntime, "unverified");
    }
    const ordinary = JSON.parse(run(executable, [filename, "--json", "--fail-on", "none"], consumer));
    assert.ok(ordinary.findings.every(item => item.detectorId !== "shielded-coin-runtime-width"));
  }
  assert.ok(packed.files.some(file => file.path === "docs/detectors/shielded-coin-runtime-width.md"));
  assert.match(run(executable, ["detector", "show", "shielded-coin-runtime-width"], consumer), /expressly assumes that reference runtime/);
  for (const kind of ["positive", "corrected", "lookalike"]) {
    const filename = `guard-tag-${kind}.compact`;
    writeFileSync(resolve(consumer, filename), readFileSync(resolve(root, `tests/corpus/known-bugs/counter-guard-tag-${kind}.compact`)));
    const report = JSON.parse(run(executable, [filename, "--detectors", "publicly-derived-guard-tag", "--json", "--fail-on", "critical"], consumer));
    assert.equal(report.status, "complete");
    assert.equal(report.coverage.baselineStatus, "complete");
    assert.deepEqual(report.findings.map(item => item.location.line), kind === "positive" ? [32] : []);
    assert.ok(report.coverage.rules.filter(row => row.detectorId === "publicly-derived-guard-tag").every(row => row.status !== "incomplete"));
  }
  assert.ok(packed.files.some(file => file.path === "docs/detectors/publicly-derived-guard-tag.md"));
  assert.match(run(executable, ["detector", "show", "publicly-derived-guard-tag"], consumer), /Caller-supplied does not mean public/);
  for (const kind of ["positive", "corrected", "lookalike"]) {
    const filename = `transient-ledger-${kind}.compact`;
    writeFileSync(resolve(consumer, filename), readFileSync(resolve(root, `tests/corpus/known-bugs/counter-transient-ledger-${kind}.compact`)));
    const report = JSON.parse(run(executable, [filename, "--detectors", "transient-digest-to-ledger", "--json", "--fail-on", "critical"], consumer));
    assert.equal(report.status, "complete");
    assert.equal(report.coverage.baselineStatus, "complete");
    assert.deepEqual(report.findings.map(item => item.location.line), kind === "positive" ? [31] : []);
    assert.ok(report.coverage.rules.filter(row => row.detectorId === "transient-digest-to-ledger").every(row => row.status !== "incomplete"));
  }
  assert.ok(packed.files.some(file => file.path === "docs/detectors/transient-digest-to-ledger.md"));
  assert.match(run(executable, ["detector", "show", "transient-digest-to-ledger"], consumer), /upgrade stability/);
  for (const kind of ["positive", "corrected", "lookalike"]) {
    const filename = `caller-equality-${kind}.compact`;
    writeFileSync(resolve(consumer, filename), readFileSync(resolve(root, `tests/corpus/known-bugs/counter-caller-equality-${kind}.compact`)));
    const report = JSON.parse(run(executable, [filename, "--detectors", "caller-supplied-ledger-equality", "--json", "--fail-on", "critical"], consumer));
    assert.equal(report.status, "complete");
    assert.equal(report.coverage.baselineStatus, "complete");
    assert.deepEqual(report.findings.map(item => item.location.line), kind === "positive" ? [32] : []);
    assert.ok(report.coverage.rules.filter(row => row.detectorId === "caller-supplied-ledger-equality").every(row => row.status !== "incomplete"));
  }
  assert.ok(packed.files.some(file => file.path === "docs/detectors/caller-supplied-ledger-equality.md"));
  assert.match(run(executable, ["detector", "show", "caller-supplied-ledger-equality"], consumer), /record consistency/);
  writeFileSync(resolve(consumer, "zero-membership.json"), JSON.stringify({ version: 1,
    policies: { zeroAmountMembership: [{ circuit: "credit", amount: "amount", map: "balances" }] } }));
  for (const kind of ["positive", "corrected", "lookalike"]) {
    const filename = `zero-membership-${kind}.compact`;
    writeFileSync(resolve(consumer, filename), readFileSync(resolve(root, `tests/corpus/known-bugs/counter-zero-membership-${kind}.compact`)));
    const report = JSON.parse(run(executable, [filename, "--detectors", "zero-amount-initial-membership", "--config", "zero-membership.json", "--json", "--fail-on", "critical"], consumer));
    assert.equal(report.status, "complete");
    assert.equal(report.coverage.baselineStatus, "complete");
    assert.deepEqual(report.findings.map(item => item.location.line), kind === "positive" ? [31] : []);
    assert.ok(report.coverage.rules.filter(row => row.detectorId === "zero-amount-initial-membership").every(row => row.status !== "incomplete"));
  }
  assert.ok(packed.files.some(file => file.path === "docs/detectors/zero-amount-initial-membership.md"));
  assert.match(run(executable, ["detector", "show", "zero-amount-initial-membership"], consumer), /zeroAmountMembership/);
  for (const kind of ["positive", "corrected", "lookalike"]) {
    const filename = `public-key-membership-${kind}.compact`;
    writeFileSync(resolve(consumer, filename), readFileSync(resolve(root, `tests/corpus/known-bugs/sdk-public-key-membership-${kind}.compact`)));
    if (process.env.COMPACTC_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_TEST, resolve(consumer, filename));
      assert.equal(compiled.valid, true, compiled.error);
    }
    const report = JSON.parse(run(executable, [filename, "--json", "--fail-on", "critical"], consumer));
    assert.equal(report.status, "complete");
    assert.equal(report.coverage.baselineStatus, "complete");
    assert.equal(report.findings.filter(item => item.detectorId === "public-key-membership-authorization").length, kind === "positive" ? 1 : 0);
    assert.ok(report.coverage.rules.filter(row => row.detectorId === "public-key-membership-authorization").every(row => row.status !== "incomplete"));
    assert.equal(run(process.execPath, ["--input-type=module", "-e", `
      import assert from 'node:assert/strict';
      import {scanFile, scanFileIsolated} from 'nightshade-compact';
      const direct = scanFile(${JSON.stringify(filename)});
      const isolated = await scanFileIsolated(${JSON.stringify(filename)});
      assert.equal(direct.status, 'complete'); assert.equal(isolated.status, 'complete');
      assert.deepEqual(isolated.findings, direct.findings);
      assert.deepEqual(isolated.coverage, direct.coverage);
      console.log('membership-package');
    `], consumer).trim(), "membership-package");
  }
  // The installed parser/profile and worker must preserve the native-chain
  // input/result observations using the owned registration modules.
  mkdirSync(resolve(consumer, "digest-key"), { recursive: true });
  for (const module of ["KeyDerivation", "DomainKey", "PublicDigest"]) {
    writeFileSync(resolve(consumer, "digest-key", `${module}.compact`),
      readFileSync(resolve(root, "tests/corpus/known-bugs/digest-key", `${module}.compact`)));
  }
  for (const kind of ["positive", "corrected", "lookalike"]) {
    const filename = `encryption-secret-${kind}.compact`;
    writeFileSync(resolve(consumer, filename), readFileSync(resolve(root, `tests/corpus/known-bugs/library-public-encryption-secret-${kind}.compact`)));
    if (process.env.COMPACTC_031_TEST) {
      const compiled = validateWithCompiler(process.env.COMPACTC_031_TEST, resolve(consumer, filename));
      assert.equal(compiled.valid, true, compiled.error);
    }
    const report = JSON.parse(run(executable, [filename, "--compiler-version", "0.31.1", "--json", "--fail-on", "critical"], consumer));
    assert.equal(report.status, "complete");
    assert.equal(report.findings.filter(item => item.detectorId === "publicly-derivable-encryption-secret").length, kind === "positive" ? 1 : 0);
    assert.ok(report.coverage.rules.filter(row => row.detectorId === "publicly-derivable-encryption-secret").every(row => row.status !== "incomplete"));
  }
  assert.ok(packed.files.some(file => file.path === "docs/detectors/publicly-derivable-encryption-secret.md"));
  writeFileSync(resolve(consumer, "signature-key.compact"), 'import CompactStandardLibrary; export circuit entry(msg: Vector<1,Field>, sig: JubjubSchnorrSignature): Boolean { return jubjubSchnorrVerify<1>(msg,sig,default<JubjubPoint>); }');
  if (process.env.COMPACTC_TEST) {
    const compiled = validateWithCompiler(process.env.COMPACTC_TEST, resolve(consumer, "signature-key.compact"));
    assert.equal(compiled.valid, true, compiled.error);
  }
  const signatureReport = JSON.parse(run(executable, ["signature-key.compact", "--json", "--detectors", "identity-signature-key", "--fail-on", "critical"], consumer));
  assert.equal(signatureReport.status, "complete");
  assert.deepEqual(signatureReport.findings.map(item => item.detectorId), ["identity-signature-key"]);
  assert.equal(signatureReport.findings[0].metadata.key, "JubjubPoint:identity");
  assert.ok(packed.files.some(file => file.path === "docs/detectors/identity-signature-key.md"));
  const conventionReport = JSON.parse(run(executable, ["counter-witness.compact", "--json", "--experimental-counter-queries", "--detectors", "inconsistent-access-control"], consumer));
  assert.equal(conventionReport.status, "complete");
  assert.deepEqual(conventionReport.analysis.coverage.map(row => row.detector), ["inconsistent-access-control"]);
  assert.equal(conventionReport.analysis.coverage[0].method, "structural-absence");
  assert.equal(run(process.execPath, ["--input-type=module", "-e", `
    import assert from 'node:assert/strict';
    import {scanFile, scanFileIsolated} from 'nightshade-compact';
    import {human, sarif} from 'nightshade-compact/reporting';
    const policies = {secrets: [{circuit: 'entry', parameter: 'first'}, {circuit: 'entry', parameter: 'second'}], authorization: [{state: 'count', guard: 'entry'}]};
    const options = {experimentalCounterQueries: true, policies};
    const direct = scanFile('counter-witness.compact', options);
    const isolated = await scanFileIsolated('counter-witness.compact', options);
    assert.equal(direct.status, 'complete');
    assert.equal(isolated.schemaVersion, '1.7.0');
    assert.deepEqual(isolated.analysis, direct.analysis);
    assert.deepEqual(isolated.findings, direct.findings);
    assert.deepEqual(direct.findings, scanFile('counter-witness.compact', {policies}).findings);
    assert.ok(direct.findings.some(finding => finding.detectorId === 'declared-secret-publication'));
    assert.ok(direct.findings.some(finding => finding.detectorId === 'unguarded-sensitive-state-write'));
    assert.match(human(isolated), /selected detector predicate/);
    assert.equal(sarif(isolated).runs[0].properties.scope, 'selected-detector-predicates');
    const fallback = await scanFileIsolated('main.compact', {experimentalCounterQueries: true});
    assert.equal(fallback.status, 'complete');
    assert.deepEqual(fallback.coverage.completedEntries, fallback.entrypoints);
    assert.ok(fallback.analysis.coverage.every(row => row.status === 'covered'));
    const exhausted = await scanFileIsolated('counter-witness.compact', {...options, maxValues: 1});
    assert.equal(exhausted.status, 'incomplete');
    assert.equal(exhausted.schemaVersion, '1.7.0');
    assert.ok(exhausted.diagnostics.length > 0);
    assert.deepEqual(exhausted.coverage.completedEntries, []);
    assert.equal(scanFile('counter-witness.compact').schemaVersion, '1.6.0');
    console.log('predicate-scope');
  `], consumer).trim(), "predicate-scope");
  assert.equal(run(process.execPath, ["--input-type=module", "-e", "import assert from 'node:assert/strict'; import {Dataflow,Program} from 'nightshade-compact'; const program = new Program('counter-witness.compact'); for (const engine of ['instructions','expressions']) { const flow = new Dataflow(program,20000,1,50000,engine); const witness = flow.selectCounterWitness(program.entries[0],[false,true]); assert.equal(witness.status,'selected'); assert.equal('completedEntries' in witness,false); assert.deepEqual(witness.path.writes.map(write => write.after.constant),['0','2']); assert.deepEqual(witness.path.writes[1].after.flows.map(flow => flow.source.name),['first','second']); assert.ok(flow.analyze().diagnostics.some(item => item.code === 'analysis-budget')); } console.log('selected')"], consumer).trim(), "selected");
  if (process.env.COMPACTC_TEST) for (const fixture of ["lists.compact", "empty-list-pop.compact", "guarded-list-pop.compact", "consumed-list-proof.compact", "path-budget.compact", "counter-witness.compact", "subset.compact"]) {
    const compiled = validateWithCompiler(process.env.COMPACTC_TEST, resolve(consumer, fixture));
    assert.equal(compiled.valid, true, compiled.error);
  }
  assert.equal(run(process.execPath, ["--input-type=module", "-e", "import assert from 'node:assert/strict'; import {Dataflow,Program,scanFileIsolated} from 'nightshade-compact'; const facts = new Dataflow(new Program('lists.compact')).analyze(); assert.deepEqual(facts.diagnostics,[]); assert.deepEqual(facts.paths[0].sinks.find(sink => sink.kind === 'exported-return').value.items.map(item => item.constant),['9','3','1']); const unsupported = await scanFileIsolated('empty-list-pop.compact'); assert.equal(unsupported.status,'incomplete'); assert.ok(unsupported.diagnostics.some(item => item.code === 'list-pop-outcome-unqualified')); console.log((await scanFileIsolated('lists.compact')).status)"], consumer).trim(), "complete");
  const branchSource = "export ledger first: Field; export ledger second: Field; circuit select(flag: Boolean,value: Field): [] { if (disclose(flag)) { first = disclose(value); } else { second = disclose(value); } } export circuit entry(a: Uint<8>,b: Uint<8>,value: Field): Field { const flag = (a + 1) < (b + 1); select(flag,value); first = default<Field>; select(flag,value); return first; }";
  writeFileSync(resolve(consumer, "branch-summaries.compact"), branchSource);
  writeFileSync(resolve(consumer, "correlated-ordering.compact"), branchSource.replace("(a + 1) < (b + 1)", "a < b"));
  if (process.env.COMPACTC_TEST) for (const fixture of ["branch-summaries.compact", "correlated-ordering.compact"]) {
    const compiled = validateWithCompiler(process.env.COMPACTC_TEST, resolve(consumer, fixture));
    assert.equal(compiled.valid, true, compiled.error);
  }
  assert.equal(run(process.execPath, ["--input-type=module", "-e", `
    import assert from 'node:assert/strict';
    import {Dataflow,Program,scanFileIsolated} from 'nightshade-compact';
    const program = new Program('branch-summaries.compact');
    for (const engine of ['instructions','expressions']) {
      const cached = new Dataflow(program,20000,256,50000,engine,true,true).analyze();
      const expanded = new Dataflow(program,20000,256,50000,engine,false,false).analyze();
      assert.deepEqual(cached.diagnostics, []);
      assert.deepEqual(cached.paths, expanded.paths);
      assert.deepEqual(cached.completedEntries, program.entries);
      assert.equal(cached.metrics.statefulSummaryHits, 2);
      assert.equal(cached.paths.length, 4);
      for (const path of cached.paths) {
        const last = path.writes.at(-1), returned = path.sinks.at(-1).value;
        if (program.symbols.get(last.ledger).name === 'first') {
          assert.equal(last.before.constant, '0');
          assert.deepEqual([...new Set(returned.flows.map(flow => flow.source.name))].sort(), ['a','b','value']);
        } else { assert.equal(returned.constant, '0'); assert.deepEqual(returned.flows, []); }
      }
    }
    const report = await scanFileIsolated('branch-summaries.compact');
    assert.equal(report.status, 'complete');
    assert.equal(report.metrics.statefulSummaryHits, 2);
    console.log('branch-replay');
  `], consumer).trim(), "branch-replay");
  assert.equal(run(process.execPath, ["--input-type=module", "-e", `
    import assert from 'node:assert/strict';
    import {Dataflow,Program} from 'nightshade-compact';
    const program = new Program('correlated-ordering.compact');
    for (const engine of ['instructions','expressions']) for (const cached of [false,true]) {
      const facts = new Dataflow(program,20000,256,50000,engine,cached,cached).analyze();
      assert.deepEqual(facts.diagnostics, []);
      assert.deepEqual(facts.paths.map(path => path.writes.map(write => program.symbols.get(write.ledger).name)).sort(),
        [['first','first','first'],['second','first','second']]);
    }
    console.log('ordered-correlation');
  `], consumer).trim(), "ordered-correlation");
  writeFileSync(resolve(consumer, "read-summaries.compact"), "import { Set } from CompactStandardLibrary; export ledger seen: Set<Field>; export ledger unrelated: Field; circuit query(key: Field): Boolean { seen.member(disclose(key)); return seen.member(default<Field>); } export circuit entry(key: Field): [Boolean,Boolean] { seen.resetToDefault(); const before = query(key); unrelated = default<Field>; query(key); seen.insert(default<Field>); const after = query(key); query(key); return [before,after]; }");
  if (process.env.COMPACTC_TEST) {
    const compiled = validateWithCompiler(process.env.COMPACTC_TEST, resolve(consumer, "read-summaries.compact"));
    assert.equal(compiled.valid, true, compiled.error);
  }
  assert.equal(run(process.execPath, ["--input-type=module", "-e", "import assert from 'node:assert/strict'; import {Dataflow,Program,resolvePolicies,scanFileIsolated} from 'nightshade-compact'; const program = new Program('read-summaries.compact'); assert.deepEqual(resolvePolicies(program),{secrets:[],authorization:[],transitions:[],workBudgets:[]}); assert.equal(program.rootSource,program.files.get(program.rootSource.path)); const cached = new Dataflow(program).analyze(); const expanded = new Dataflow(program,20000,256,50000,'instructions',false).analyze(); assert.deepEqual(cached.diagnostics,[]); assert.deepEqual(cached.paths,expanded.paths); assert.equal(cached.metrics.readSummaryHits,2); assert.equal(cached.paths[0].sinks.filter(sink => sink.kind === 'ledger-operation').length,4); assert.deepEqual(cached.paths[0].sinks.at(-1).value.items.map(item => item.constant),['false','true']); const report = await scanFileIsolated('read-summaries.compact'); assert.equal(report.metrics.readSummaryHits,2); console.log(report.status)"], consumer).trim(), "complete");
  writeFileSync(resolve(consumer, "wildcards.compact"), 'import { Map } from CompactStandardLibrary; export ledger table: Map<Field,Field>; export circuit entry(first: Field,second: Field): Boolean { const left = table.lookup(disclose(first)); const right = table.lookup(disclose(second)); assert(left != right,"different entries"); return true; }');
  assert.equal(run(process.execPath, ["--input-type=module", "-e", "import assert from 'node:assert/strict'; import {scanFileIsolated} from 'nightshade-compact'; const result = await scanFileIsolated('wildcards.compact'); assert.deepEqual(result.findings,[]); console.log(result.status)"], consumer).trim(), "complete");
  writeFileSync(resolve(consumer, "invalid.compact"), "export circuit entry(): Field { return 1; }");
  assert.equal(run(process.execPath, ["--input-type=module", "-e", "import {scanFileIsolated} from 'nightshade-compact'; const result = await scanFileIsolated('invalid.compact'); console.log(result.status + ':' + result.diagnostics[0].code)"], consumer).trim(), "incomplete:return-type-mismatch");
  writeFileSync(resolve(consumer, "casts.compact"), 'import { persistentHash } from CompactStandardLibrary; export ledger digest: Bytes<32>; witness secret(): Uint<64>; export circuit entry(): Field { const value = secret(); assert(persistentHash<Uint<64>>(value) == digest,"bound"); return disclose(value as Field); }');
  const casts = JSON.parse(run(executable, ["casts.compact", "--json", "--fail-on", "none"], consumer));
  assert.equal(casts.status, "complete");
  assert.deepEqual(casts.findings.map(finding => finding.detectorId), ["ledger-bound-preimage-publication"]);
  writeFileSync(resolve(consumer, "sequences.compact"), 'circuit select([value]: [Uint<8>], value: Uint<8>): Uint<8> { return value; } export circuit entry(): [Bytes<1>,Uint<8>,Uint<8>] { const values = [..."ab"]; const [first] = values; return [slice<1>("ab",1),select([first],0),values[1]]; }');
  const sequences = JSON.parse(run(executable, ["sequences.compact", "--json", "--fail-on", "none"], consumer));
  assert.equal(sequences.status, "complete");
  assert.equal(run(process.execPath, ["--input-type=module", "-e", "import {Dataflow,Program} from 'nightshade-compact'; const facts = new Dataflow(new Program('sequences.compact')).analyze(); console.log(facts.paths[0].sinks.find(sink => sink.kind === 'exported-return').value.items.map(item => item.constant).join(','))"], consumer).trim(), "62,97,98");
  assert.equal(run(process.execPath, ["--input-type=module", "-e", "import {Dataflow,Program} from 'nightshade-compact'; console.log(new Dataflow(new Program('main.compact'),20000,256,50000,'instructions',true,true,'guard-cover').analyze().pathSemantics)"], consumer).trim(), "guard-cover");
  writeFileSync(resolve(consumer, "consumer.ts"), "import {scanFile, Dataflow, Program, buildAnalysisInventory, type AnalysisInventory, type InventoryOptions, type InventoryType, type AnalysisFacts, type ScanResult, type Detector} from 'nightshade-compact'; import {sarif} from 'nightshade-compact/reporting'; const result: ScanResult = scanFile('main.compact'); const facts: AnalysisFacts = new Dataflow(new Program('main.compact'),20000,256,50000,'instructions',true,true,'guard-cover').analyze(); const subset: AnalysisFacts = new Dataflow(facts.program).analyzeSubset(facts.program.entries); const mode: 'guard-cover' | 'equivalent-states' = facts.pathSemantics; const readHits: number = facts.metrics.readSummaryHits; const rootPath: string = facts.program.rootSource.path; const options: InventoryOptions = {maxTypeDepth: 4, maxTypeNodes: 100}; const inventory: AnalysisInventory = buildAnalysisInventory(facts.program,options); const shape: InventoryType = inventory.functions[0].result; const rule: Detector = {id: 'consumer', description: 'Type contract', requires: [], run: () => []}; sarif(result); rule.run; const selected = new Dataflow(facts.program).selectCounterWitness(facts.program.entries[0], [true]); if (selected.status === 'selected') { const choice: readonly boolean[] = selected.decisions; const count: number = selected.path.writes.length; }\n");
  writeFileSync(resolve(consumer, "counter-consumer.ts"), `
import {scanFile, scanFileIsolated, type ScanResult, type ExactScanResult, type ExperimentalCounterScanResult, type CounterScanAnalysis} from 'nightshade-compact';
const report: ScanResult = await scanFileIsolated('counter-witness.compact', {experimentalCounterQueries: true});
if (report.schemaVersion === '1.7.0') {
  const experimental: ExperimentalCounterScanResult = report;
  const analysis: CounterScanAnalysis = experimental.analysis;
  const scope: 'selected-detector-predicates' = report.scope;
  const expenditure: boolean = analysis.queryWork.expenditureKnown;
} else {
  const exact: ExactScanResult = report;
  const scope: 'experimental-subset' = exact.scope;
  // @ts-expect-error Exact reports cannot claim experimental predicate coverage.
  exact.analysis;
}
const sync: ScanResult = scanFile('counter-witness.compact', {experimentalCounterQueries: true});
`);
  writeFileSync(resolve(consumer, "detector-consumer.ts"), `
import {DETECTOR_API_VERSION, DETECTOR_FACTS_VERSION, type CustomDetector, type DetectorFinding} from 'nightshade-compact/detector-api';
import {scanFileIsolated} from 'nightshade-compact';
const custom: CustomDetector = {apiVersion: DETECTOR_API_VERSION, factsVersion: DETECTOR_FACTS_VERSION, id: 'custom-example', description: 'Consumer rule', requires: ['predicates'], run(context) {
  const completed: string[] = context.facts.completedEntries;
  if (!completed.length) context.incomplete('No complete entry is available');
  const findings: DetectorFinding[] = []; return findings;
}};
const result = await scanFileIsolated('custom.compact', {detectorModules: [${JSON.stringify(customModule)}]});
const version: 1 | undefined = result.customDetectors?.[0].apiVersion;
custom.run;
`);
  writeFileSync(resolve(consumer, "nft-metadata-consumer.ts"), `
import {scanFile, scanFileIsolated, type Policies, type ScanOptions} from 'nightshade-compact';
const policies: Policies = {currentNftMetadata: [{owners: '_owners', metadata: 'cachedURI', consumer: 'replaceToken'}]};
const options: ScanOptions = {policies, detectors: ['stale-nft-metadata']};
const scan = scanFile('nft-metadata-positive.compact', options);
const isolated = await scanFileIsolated('nft-metadata-positive.compact', options);
const incomplete: boolean = isolated.status === 'incomplete';
`);
  writeFileSync(resolve(consumer, "zero-membership-consumer.ts"), `
import {scanFile, scanFileIsolated, type Policies, type ScanOptions} from 'nightshade-compact';
const policies: Policies = {zeroAmountMembership: [{circuit: 'credit', amount: 'amount', map: 'balances'}]};
const options: ScanOptions = {policies, detectors: ['zero-amount-initial-membership']};
const direct = scanFile('zero-membership-positive.compact', options);
const isolated = await scanFileIsolated('zero-membership-positive.compact', options);
const incomplete: boolean = isolated.status === 'incomplete';
`);
  writeFileSync(resolve(consumer, "contract-owner-consumer.ts"), `
import {scanFile, scanFileIsolated, type Policies, type ScanOptions} from 'nightshade-compact';
const policies: Policies = {callableOwnable: [{owner: '_owner'}]};
const options: ScanOptions = {policies, detectors: ['unsupported-contract-owner']};
const scan = scanFile('contract-owner-positive.compact', options);
const isolated = await scanFileIsolated('contract-owner-positive.compact', options);
const incomplete: boolean = isolated.status === 'incomplete';
`);
  run(process.execPath, [resolve(root, "node_modules/typescript/bin/tsc"), "--noEmit", "--strict", "--target", "ES2022", "--module", "NodeNext", resolve(consumer, "consumer.ts"), resolve(consumer, "counter-consumer.ts"), resolve(consumer, "detector-consumer.ts"), resolve(consumer, "nft-metadata-consumer.ts"), resolve(consumer, "contract-owner-consumer.ts"), resolve(consumer, "zero-membership-consumer.ts")], consumer);
  console.log(JSON.stringify({ package: packed.filename, files: packed.entryCount, unpackedBytes: packed.unpackedSize, productionInstall: "passed", cli: "passed", library: "passed", typescriptConsumer: "passed" }, null, 2));
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
