#!/usr/bin/env node
import { delimiter, dirname, resolve } from "node:path";
import { readFileSync, statSync, writeFileSync } from "node:fs";
import { discover, scanFileIsolated, ScanResult, emptyResult, mergeResults, Program, buildAnalysisInventory } from "./index.js";
import { detectorMetadata } from "./detectors/metadata.js";
import { detectors, Severity, Confidence } from "./detectors/index.js";
import { human, sarif } from "./reporting/index.js";
import { Printer, printProgramDocument } from "./reporting/printers.js";
import { applyWorkflow, configLocation, confidenceRank, defaultConfigurationPath, exitStatus, readBaseline, readConfiguration, severityRank } from "./config.js";
import { AnalysisError } from "./model.js";
import { validCompilerVersion, type CompilerVersion, type ZkirVersion } from "./semantic/profile.js";
import { excludedRoot, validateExclusions } from "./reporting/selection.js";
import { auditorPrinters, auditFileIsolated, humanSummary, type AuditorPrinter } from "./reporting/auditor.js";
import { discoverProjectIsolated } from "./semantic/project.js";
import { reviewCommand } from "./reporting/review-cli.js";

const help = `nightshade [scan] [path] [options]
nightshade review ROOT --out NEW_DIRECTORY [--compiler-version V] [--compact-path PATHS]
nightshade detector list [--json]
nightshade detector show ID [--json]
nightshade print cfg|ir|call-graph|state|entrypoints|inventory FILE
nightshade print human-summary|ledger-access|disclosure-map|data-dependency FILE [options]

  --json | --sarif          Machine-readable output (stdout)
  --config FILE            Strict JSON configuration; default: nightshade.json
  --compact-path PATHS     Import/include search paths (${delimiter}-separated)
  --detectors ID,ID        Run only the specified detectors
  --profile audit|hygiene  Audit is the default; hygiene adds source-hygiene rules
  --detector-module FILE   Execute a trusted local .cjs detector (repeatable; explicit opt-in)
  --compiler-version V     Select pinned analysis profile (0.28.0, 0.29.0, 0.30.0, 0.31.1, 0.33.0-rc.2, 0.34.0, 0.35.0-rc.1, 0.35.0)
  --experimental-counter-queries  Experimental selected-detector predicate analysis
  --rule-incomplete error|warn  CI treatment of rule-only gaps (default: error)
  --fail-on LEVEL          info|low|medium|high|critical|none (default: info)
  --min-confidence LEVEL   low|medium|high (CI threshold; findings remain visible)
  --min-severity LEVEL     Show only info|low|medium|high|critical and above; diagnostics remain
  --exclude PATTERN        Exclude discovered roots (repeatable; imports still analyzed)
  --baseline FILE          Only new findings affect CI exit status
  --write-baseline FILE    Create fingerprint baseline; refuses overwrite
  --compiler EXECUTABLE    Explicitly execute a trusted pinned Compact compiler
  --zkir-version 2|3       Match the project's compiler profile (default: 2)
  --max-steps NUMBER       Per-entry analysis step budget (default: 40000)
  --max-paths NUMBER       Path expansion budget (default: 256)
  --timeout-ms NUMBER      Per-file isolated-worker timeout (default: 60000)
  --heap-mib NUMBER        Worker V8 heap limit (default: 512; not an RSS cap)
  --verbose                Include complete per-rule coverage in human output
  --stats                  Include phase timings in human output
  --version                Show tool version

Ordinary scans are offline and do not execute Compact code.
Inventory completeness covers semantic representation, not execution or analysis paths.
Policy rules need configured secrecy, guards, transitions, or work limits.
Exit: 0 threshold not exceeded; 1 findings; 2 incomplete/invalid analysis.
"complete" means the supported analysis finished, not proof of contract security.`;

let requestedCompilerVersion: CompilerVersion | undefined;
let requestedExperimentalMode = process.argv.slice(2).includes("--experimental-counter-queries");
let requestedZkirVersion: ZkirVersion = process.argv[process.argv.indexOf("--zkir-version") + 1] === "3" ? 3 : 2;

function output(result: ScanResult, format: string, stats = false, verbose = false, ruleIncomplete: "error" | "warn" = "error"): void {
  console.log(format === "json" ? JSON.stringify(result, null, 2) : format === "sarif" ? JSON.stringify(sarif(result, { ruleIncomplete }), null, 2) : human(result, { verbose, ruleIncomplete }) + (stats ? `\nMetrics: ${JSON.stringify(result.metrics)}` : ""));
}

async function main(input: string[]): Promise<number> {
  const args = [...input];
  let zkirVersion: ZkirVersion | undefined;
  let compilerVersion: CompilerVersion | undefined;
  const compilerIndex = args.indexOf("--compiler-version");
  if (compilerIndex >= 0) {
    if (args.lastIndexOf("--compiler-version") !== compilerIndex || !validCompilerVersion(args[compilerIndex + 1])) throw new AnalysisError({ code: "unsupported-compiler-version", message: "Supported compiler profiles: 0.28.0, 0.29.0, 0.30.0, 0.31.1, 0.33.0-rc.2, 0.34.0, 0.35.0-rc.1, 0.35.0", location: configLocation(process.cwd()) });
    compilerVersion = args[compilerIndex + 1] as CompilerVersion;
    requestedCompilerVersion = compilerVersion;
    args.splice(compilerIndex, 2);
  }
  const profileIndex = args.indexOf("--zkir-version");
  if (profileIndex >= 0) {
    if (!["2", "3"].includes(args[profileIndex + 1]) || args.lastIndexOf("--zkir-version") !== profileIndex) throw new Error("--zkir-version requires exactly one value: 2 or 3");
    zkirVersion = Number(args[profileIndex + 1]) as ZkirVersion;
    requestedZkirVersion = zkirVersion;
    args.splice(profileIndex, 2);
  }
  if (args.includes("--help") || args.includes("-h") || args.length === 1 && args[0] === "help") { console.log(help); return 0; }
  if (args.length === 1 && ["--version", "-V"].includes(args[0])) { console.log("Nightshade 0.1.0"); return 0; }
  if (args[0] === "review") return reviewCommand(args.slice(1), compilerVersion, zkirVersion);
  if (args[0] === "detector") {
    const json = args.includes("--json");
    const command = args.filter(arg => arg !== "--json");
    const selected = command[1] === "list" && command.length === 2 ? detectors : command[1] === "show" && command.length === 3 ? detectors.filter(detector => detector.id === command[2]) : [];
    if (!selected.length) throw new Error("Use detector list or detector show ID with a known detector ID");
    const catalog = selected.map(detector => ({ ...detector, ...detectorMetadata(detector.id),
      defaultEnabled: detector.defaultEnabled !== false, policyRequired: detector.policyRequired === true }));
    const detailed = command[1] === "show" ? catalog.map(detector => ({ ...detector, documentation: readFileSync(new URL(`../../docs/detectors/${detector.id}.md`, import.meta.url), "utf8") })) : catalog;
    console.log(json ? JSON.stringify(detailed, null, 2) : detailed.map(detector => "documentation" in detector ? detector.documentation : `${detector.id}${detector.policyRequired ? " (policy required)" : ""}${detector.defaultEnabled === false ? " (opt-in review)" : ""}\n  ${detector.description}\n  Facts: ${detector.requires.join(", ")}`).join("\n"));
    return 0;
  }
  if (args[0] === "print") {
    if (auditorPrinters.includes(args[1] as AuditorPrinter)) {
      const file = args[2];
      if (!file || file.startsWith("-")) throw new Error("Auditor printers require one Compact file");
      const values = new Map<string, string>();
      let json = false;
      const flags = ["--config", "--compact-path", "--max-steps", "--max-paths", "--timeout-ms", "--heap-mib"];
      for (let index = 3; index < args.length; index++) {
        const flag = args[index];
        if (flag === "--json" && !json) { json = true; continue; }
        const value = args[++index];
        if (!flags.includes(flag) || !value || value.startsWith("--") || values.has(flag)) throw new Error(`Invalid auditor option: ${flag}`);
        values.set(flag, value);
      }
      const config = readConfiguration(values.get("--config") ?? defaultConfigurationPath(file));
      const options = { searchPaths: config.options.searchPaths, sourceRoot: config.options.sourceRoot, compilerVersion: compilerVersion ?? config.options.compilerVersion,
        zkirVersion: zkirVersion ?? config.options.zkirVersion, maxSteps: config.options.maxSteps, maxPaths: config.options.maxPaths, maxValues: config.options.maxValues };
      if (values.has("--compact-path")) options.searchPaths = values.get("--compact-path")!.split(delimiter).filter(Boolean).map(value => resolve(value));
      const limits = { ...config.execution };
      for (const [flag, key] of [["--max-steps", "maxSteps"], ["--max-paths", "maxPaths"]] as const) if (values.has(flag)) {
        if (!/^\d+$/.test(values.get(flag)!)) throw new Error(`${flag} requires a positive integer`);
        options[key] = Number(values.get(flag));
      }
      for (const [flag, key] of [["--timeout-ms", "timeoutMs"], ["--heap-mib", "heapMiB"]] as const) if (values.has(flag)) {
        if (!/^\d+$/.test(values.get(flag)!)) throw new Error(`${flag} requires a positive integer`);
        limits[key] = Number(values.get(flag));
      }
      const report = await auditFileIsolated(resolve(file), args[1] as AuditorPrinter, options, limits);
      console.log(args[1] === "human-summary" && !json ? humanSummary(report) : JSON.stringify(report, null, 2));
      return report.status === "complete" ? 0 : 2;
    }
    if (args.length !== 3 || !["cfg", "ir", "call-graph", "state", "entrypoints", "inventory"].includes(args[1])) throw new Error("Use print cfg|ir|call-graph|state|entrypoints|inventory FILE");
    const program = new Program(resolve(args[2]), undefined, undefined, undefined, zkirVersion, compilerVersion);
    if (args[1] === "inventory") {
      const inventory = buildAnalysisInventory(program);
      console.log(JSON.stringify(inventory, null, 2));
      return inventory.status === "complete" ? 0 : 2;
    }
    console.log(JSON.stringify(printProgramDocument(program, args[1] as Printer), null, 2));
    return 0;
  }
  if (args[0] === "scan") args.shift();
  let format = "human";
  let path: string | undefined;
  let stats = false;
  let verbose = false;
  let experimentalCounterQueries = false;
  const values = new Map<string, string>();
  const excludes: string[] = [];
  const detectorModules: string[] = [];
  const valueFlags = ["--config", "--compact-path", "--detectors", "--profile", "--rule-incomplete", "--fail-on", "--min-confidence", "--min-severity", "--baseline", "--write-baseline", "--compiler", "--max-steps", "--max-paths", "--timeout-ms", "--heap-mib"];
  for (let index = 0; index < args.length; index++) {
    const argument = args[index];
    if (["--json", "--sarif"].includes(argument)) {
      if (format !== "human") throw new Error("Choose only one output format");
      format = argument.slice(2);
    } else if (argument === "--stats") stats = true;
    else if (argument === "--verbose") verbose = true;
    else if (argument === "--experimental-counter-queries") {
      if (experimentalCounterQueries) throw new Error("--experimental-counter-queries may be specified only once");
      experimentalCounterQueries = true;
    }
    else if (argument === "--detector-module") {
      const value = args[++index];
      if (!value || value.startsWith("--")) throw new Error("--detector-module requires a trusted local .cjs file");
      detectorModules.push(resolve(value));
    }
    else if (argument === "--exclude") {
      const value = args[++index];
      if (!value || value.startsWith("--")) throw new Error("--exclude requires a pattern");
      excludes.push(value);
    }
    else if (valueFlags.includes(argument)) {
      const value = args[++index];
      if (!value || value.startsWith("--") || values.has(argument)) throw new Error(`${argument} requires exactly one value`);
      values.set(argument, value);
    } else if (argument.startsWith("-")) throw new Error(`unknown option '${argument}'`);
    else if (path) throw new Error("Only one scan path is accepted; use configured roots for multiple contracts");
    else path = argument;
  }
  const configPath = values.get("--config") ?? defaultConfigurationPath(path ?? ".");
  const config = readConfiguration(configPath, enabled => { requestedExperimentalMode ||= enabled; }, version => { requestedZkirVersion = zkirVersion ?? version; });
  if (zkirVersion !== undefined) config.options.zkirVersion = zkirVersion;
  if (compilerVersion !== undefined) config.options.compilerVersion = compilerVersion;
  requestedCompilerVersion = config.options.compilerVersion;
  if (detectorModules.length) config.options.detectorModules = detectorModules;
  if (excludes.length) config.exclude = validateExclusions([...(config.exclude ?? []), ...excludes], configLocation(configPath ?? "."));
  if (values.has("--min-severity")) {
    const level = values.get("--min-severity")!;
    if (!Object.hasOwn(severityRank, level)) throw new Error("Unknown --min-severity");
    config.minSeverity = level as Severity;
  }
  if (experimentalCounterQueries) config.options.experimentalCounterQueries = true;
  if (values.has("--compact-path")) config.options.searchPaths = values.get("--compact-path")!.split(delimiter).filter(Boolean).map(value => resolve(value));
  if (values.has("--detectors")) config.options.detectors = values.get("--detectors")!.split(",");
  if (values.has("--profile")) {
    const profile = values.get("--profile");
    if (profile !== "audit" && profile !== "hygiene") throw new Error("Unknown --profile; expected audit or hygiene");
    config.options.profile = profile;
  }
  if (values.has("--rule-incomplete")) {
    const value = values.get("--rule-incomplete");
    if (value !== "error" && value !== "warn") throw new Error("--rule-incomplete requires error or warn");
    config.ruleIncomplete = value;
  }
  if (values.has("--compiler")) config.options.compiler = resolve(values.get("--compiler")!);
  if (values.has("--fail-on")) {
    const level = values.get("--fail-on")!;
    if (![...Object.keys(severityRank), "none"].includes(level)) throw new Error("Unknown --fail-on severity");
    config.failOn = level as Severity | "none";
  }
  if (values.has("--min-confidence")) {
    const level = values.get("--min-confidence")!;
    if (!Object.keys(confidenceRank).includes(level)) throw new Error("Unknown --min-confidence threshold");
    config.minConfidence = level as Confidence;
  }
  for (const [flag, option] of [["--max-steps", "maxSteps"], ["--max-paths", "maxPaths"]] as const) if (values.has(flag)) {
    if (!/^\d+$/.test(values.get(flag)!)) throw new Error(`${flag} requires a positive integer`);
    config.options[option] = Number(values.get(flag));
  }
  for (const [flag, option] of [["--timeout-ms", "timeoutMs"], ["--heap-mib", "heapMiB"]] as const) if (values.has(flag)) {
    if (!/^\d+$/.test(values.get(flag)!)) throw new Error(`${flag} requires a positive integer`);
    config.execution = { ...config.execution, [option]: Number(values.get(flag)) };
  }
  if (path && config.roots && (!statSync(resolve(path)).isDirectory() || resolve(path) !== dirname(resolve(configPath!)))) throw new Error("Choose a positional file or configured roots, not both");
  const roots = config.roots ?? [path ?? "."];
  const sourceRoot = config.roots ? dirname(resolve(configPath!)) : statSync(resolve(path ?? ".")).isDirectory() ? resolve(path ?? ".") : dirname(resolve(path!));
  const project = !config.roots && statSync(resolve(path ?? ".")).isDirectory() ? await discoverProjectIsolated(sourceRoot, config.exclude ?? [], config.execution) : undefined;
  if (project?.status === "incomplete") {
    const result = emptyResult(config.options.experimentalCounterQueries === true, config.options.zkirVersion, config.options.compilerVersion);
    result.status = "incomplete"; result.diagnostics = project.diagnostics; result.coverage.attempted = [sourceRoot];
    output(result, format, stats, verbose, config.ruleIncomplete); return 2;
  }
  const discovered = project?.files ?? [...new Set(roots.flatMap(discover))].sort();
  const excluded = project?.excluded ?? discovered.filter(file => excludedRoot(file, sourceRoot, config.exclude ?? []));
  const files = discovered.filter(file => !excluded.includes(file));
  if (!files.length) throw new Error(`No Compact application roots found${project?.libraries.length ? ` (${project.libraries.length} module-only library files omitted)` : ""}`);
  const reports: ScanResult[] = [];
  const inferPaths = project && config.options.searchPaths === undefined && !(process.env.COMPACT_PATH ?? "").split(delimiter).filter(Boolean).length;
  for (const file of files) {
    const report = await scanFileIsolated(file, { ...config.options, ...(inferPaths ? { searchPaths: project.searchPaths[file] } : {}), sourceRoot }, config.execution);
    reports.push(report);
    if (report.diagnostics.some(diagnostic => diagnostic.code === "worker-interrupted")) break;
  }
  const result = mergeResults(reports);
  if (excluded.length) result.selection = { excludedRoots: excluded, findingsBeforeFilter: result.findings.length };
  if (project) result.selection = { ...result.selection, findingsBeforeFilter: result.findings.length, discovery: { omittedLibraries: project.libraries, inferredSearchPaths: inferPaths ? project.searchPaths : {} } };
  if (!result.entrypoints.length && !result.diagnostics.length && !result.coverage.noEntrypointRoots.length) {
    result.status = "incomplete";
    result.diagnostics.push({ code: "no-entrypoints", message: "No application entrypoints found; scan an application root or use a structural printer for library templates", location: configLocation(roots[0]) });
  }
  const baselineFingerprints = result.findings.map(finding => finding.fingerprint).sort();
  applyWorkflow(result, config, values.has("--baseline") ? readBaseline(values.get("--baseline")!) : undefined);
  if (values.has("--write-baseline")) {
    if (result.status !== "complete") throw new Error("Refusing to write a baseline from incomplete analysis");
    writeFileSync(resolve(values.get("--write-baseline")!), JSON.stringify({ version: 1, fingerprints: baselineFingerprints }, null, 2) + "\n", { flag: "wx" });
  }
  output(result, format, stats, verbose, config.ruleIncomplete);
  return exitStatus(result, config);
}

try {
  process.exitCode = await main(process.argv.slice(2));
} catch (error) {
  const fileError = error instanceof Error ? error as NodeJS.ErrnoException : undefined;
  const missingPath = fileError?.code === "ENOENT" && typeof fileError.path === "string" ? fileError.path : undefined;
  const message = missingPath ? `path not found: ${missingPath}` : error instanceof Error ? error.message : String(error);
  const result = emptyResult(requestedExperimentalMode, requestedZkirVersion, requestedCompilerVersion);
  result.status = "incomplete";
  result.diagnostics.push(error instanceof AnalysisError ? error.diagnostic : { code: "input-error", message, location: configLocation(missingPath ?? ".") });
  if (process.argv.includes("--json") || process.argv.includes("--sarif")) output(result, process.argv.includes("--json") ? "json" : "sarif");
  else console.error(`nightshade: ${result.diagnostics[0].message} (see --help)`);
  process.exitCode = 2;
}
