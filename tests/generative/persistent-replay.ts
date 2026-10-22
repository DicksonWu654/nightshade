// Owned fixed-fixture evaluation only; sequence data cannot select source or state.
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { comparePersistentResults, makePersistentArtifact, persistentBuildIdentity, persistentIdentityChanges, readPersistentFile, runPersistentSequenceIsolated, validatePersistentArtifact, validatePersistentLimits, type PersistentArtifact } from "./persistent-artifacts.js";
import { PERSISTENT_LIMITS, persistentDigest, validatePersistentSequence } from "./persistent-model.js";

const save = (path: string, value: unknown) => writeFileSync(path, JSON.stringify(value, null, 2) + "\n", { flag: "wx" });

async function main(): Promise<number> {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === "--help") {
    console.log("Owned persistent evaluation: --sequence SEQUENCE.json --output NEW_DIRECTORY [--timeout-ms 1..60000]\nExact replay: --replay CASE.json --output NEW_DIRECTORY [--compare-build]\nRequires pinned COMPACTC_TEST and COMPACT_RUNTIME_TEST; run from repository root.\nFixed owned fixture, at most 32 operations and 4 snapshot slots. No arbitrary source/state/adapters.\nExit 0: model passed and replay matched; 1: property failure; 2: incomplete/input/replay drift.");
    return 0;
  }
  const flags = new Map<string, string>();
  let compareBuild = false;
  for (let index = 0; index < args.length; index++) {
    const flag = args[index];
    if (flag === "--compare-build" && !compareBuild) { compareBuild = true; continue; }
    if (!["--output", "--sequence", "--replay", "--timeout-ms"].includes(flag) || flags.has(flag) || !args[index + 1] || args[index + 1].startsWith("--")) throw new Error(`Invalid persistent replay argument ${flag}`);
    flags.set(flag, args[++index]);
  }
  if (!flags.has("--output") || flags.has("--sequence") === flags.has("--replay")) throw new Error("Require new --output directory and exactly one of --sequence or --replay");
  if (compareBuild && !flags.has("--replay")) throw new Error("--compare-build applies only to replay");
  if (flags.has("--replay") && flags.has("--timeout-ms")) throw new Error("Replay preserves recorded limits");
  const timeout = flags.get("--timeout-ms");
  if (timeout !== undefined && !/^\d+$/.test(timeout)) throw new Error("Invalid integer --timeout-ms");
  let limits = validatePersistentLimits({ ...PERSISTENT_LIMITS, timeoutMs: timeout === undefined ? PERSISTENT_LIMITS.timeoutMs : Number(timeout) });
  const contents = readPersistentFile(resolve(flags.get("--replay") ?? flags.get("--sequence")!));
  let previous: PersistentArtifact | undefined;
  if (flags.has("--replay")) { previous = validatePersistentArtifact(JSON.parse(contents.toString("utf8"))); limits = previous.limits; }
  const sequence = previous?.sequence ?? validatePersistentSequence(JSON.parse(contents.toString("utf8")));
  if (!process.env.COMPACTC_TEST || !process.env.COMPACT_RUNTIME_TEST) throw new Error("Pinned COMPACTC_TEST and COMPACT_RUNTIME_TEST inputs are mandatory");
  const compiler = resolve(process.env.COMPACTC_TEST), runtimeDirectory = resolve(process.env.COMPACT_RUNTIME_TEST);
  const identity = persistentBuildIdentity(compiler, runtimeDirectory);
  const changedIdentityFields = previous ? persistentIdentityChanges(previous.identity, identity) : [];
  if (changedIdentityFields.length && !compareBuild) throw new Error(`Persistent replay identity mismatch (${changedIdentityFields.join(", ")}); --compare-build records an explicit comparison`);
  const output = resolve(flags.get("--output")!);
  mkdirSync(output);
  const result = await runPersistentSequenceIsolated(sequence, compiler, runtimeDirectory, limits);
  const artifact = makePersistentArtifact(sequence, identity, limits, result);
  save(resolve(output, "case.json"), artifact);
  const comparison = previous ? comparePersistentResults(previous.result, result) : undefined;
  const matched = !comparison || comparison.sameStatus && comparison.sameSignature && comparison.sameObservation !== false && (compareBuild || comparison.sameCompiledJavaScript !== false);
  save(resolve(output, "summary.json"), {
    schemaVersion: "nightshade-owned-persistent-replay-1", recordedAt: new Date().toISOString(), identity, limits,
    scope: "compiled evaluation of one bounded sequence against the fixed owned Counter/witness fixture; no proof or transaction qualification",
    inputSha256: persistentDigest(contents), status: result.status, diagnostic: result.diagnostic, signature: result.signature,
    artifact: "case.json", artifactSha256: persistentDigest(readPersistentFile(resolve(output, "case.json"))),
    replay: previous ? { comparison: compareBuild, previousArtifactSha256: persistentDigest(contents), previousIdentity: previous.identity, changedIdentityFields, previousStatus: previous.result.status, previousSignature: previous.result.signature, ...comparison, matched } : undefined,
  });
  console.log(`${result.status} ${result.diagnostic}${previous ? `; replay ${matched ? "matched" : "drifted"}` : ""}`);
  return result.status === "incomplete" || !matched ? 2 : result.status === "failed" ? 1 : 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { process.exitCode = await main(); }
  catch (error) { console.error(error instanceof Error ? error.message : String(error)); process.exitCode = 2; }
}
