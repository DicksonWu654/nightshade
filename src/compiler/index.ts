import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, resolve } from "node:path";

import { COMPILER_PROFILES, validCompilerVersion, validZkirVersion, workingDirectorySearchProfile, type CompilerVersion, type ZkirVersion } from "../semantic/profile.js";

export interface CompilerValidation {
  valid: boolean;
  version: string;
  languageVersion: string;
  error?: string;
}

// RC2 reports an unstamped "0.33.0", although no stable release exists. Admit
// only the published Linux-musl artifact (direct binary or exact launcher), not
// arbitrary builds reporting the same pair. Other platforms remain unqualified.
function pinnedRc2(executable: string): boolean {
  try {
    let bytes = readFileSync(resolve(executable));
    const launcher = '#!/usr/bin/env bash\nthisdir="$(cd $(dirname $0) ; pwd -P)"\nPATH="$thisdir:$PATH"\nexec "$thisdir/compactc.bin" "$@"\n';
    if (bytes.length === Buffer.byteLength(launcher) && bytes.toString("utf8") === launcher) bytes = readFileSync(resolve(executable, "..", "compactc.bin"));
    return createHash("sha256").update(bytes).digest("hex") === "8f1622cb32b4e55343b02eb20ecac47be7f33f86acaf8b5a0cff79d046ddb38d";
  } catch { return false; }
}

export function compilerIdentity(executable: string, timeoutMs = 30000): CompilerValidation {
  const run = (args: string[]) => spawnSync(resolve(executable), args, { encoding: "utf8", timeout: timeoutMs, maxBuffer: 1024 * 1024, windowsHide: true });
  const versionProcess = run(["--version"]);
  const languageProcess = run(["--language-version"]);
  const reportedVersion = String(versionProcess.stdout ?? "").trim();
  // New releases print semver plus a commit/date stamp. Do not accept arbitrary
  // suffixes, dev builds or a stamp that disagrees with the bundled source pin.
  const parsed = /^(\d+\.\d+\.\d+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?)(?: \(([0-9a-f]{9,40}) (\d{4}-\d{2}-\d{2})\))?$/.exec(reportedVersion);
  const version = reportedVersion === "0.33.0" && pinnedRc2(executable) ? "0.33.0-rc.2" : parsed?.[1] ?? reportedVersion;
  const languageVersion = String(languageProcess.stdout ?? "").trim();
  const failure = (message: string): CompilerValidation => ({ valid: false, version, languageVersion, error: message });
  if (versionProcess.status !== 0 || languageProcess.status !== 0) return failure("Unable to read compiler versions: " + String(versionProcess.error ?? versionProcess.stderr ?? languageProcess.error ?? languageProcess.stderr).slice(0, 4000));
  if (!parsed || !validCompilerVersion(version) || languageVersion !== COMPILER_PROFILES[version].languageVersion) return failure(`Unsupported compiler/language pair ${version} / ${languageVersion}; supported compilers: ${Object.keys(COMPILER_PROFILES).join(", ")}`);
  if (version === "0.33.0-rc.2" && reportedVersion !== "0.33.0") return failure("Compiler RC2 requires the exact pinned Linux-musl release binary reporting 0.33.0");
  if ((version === "0.35.0-rc.1" || version === "0.35.0") && !parsed[2]) return failure("Compiler 0.35 profile must report its pinned build commit/date stamp");
  if (parsed[2] && !COMPILER_PROFILES[version].sourceCommit.startsWith(parsed[2])) return failure("Compiler build commit differs from the selected source pin");
  return { valid: true, version, languageVersion };
}

export function validateWithCompiler(executable: string, source: string, searchPaths: string[] = [], timeoutMs = 30000, zkirVersion: ZkirVersion = 2, expectedVersion?: CompilerVersion): CompilerValidation {
  if (!validZkirVersion(zkirVersion)) return { valid: false, version: "", languageVersion: "", error: "ZKIR version must be 2 or 3" };
  const identity = compilerIdentity(executable, timeoutMs);
  if (!identity.valid) return identity;
  const { version, languageVersion } = identity;
  const failure = (error: string): CompilerValidation => ({ valid: false, version, languageVersion, error });
  if (expectedVersion && version !== expectedVersion) return failure(`Selected compiler profile ${expectedVersion} differs from executable ${version}`);
  if (zkirVersion === 3 && version !== "0.34.0") return failure("ZKIR3 is qualified only with compiler 0.34.0");
  const temporary = mkdtempSync(resolve(tmpdir(), "nightshade-validation-"));
  // 0.28.0/0.29.0 predate --compact-path and first search the invocation
  // directory; run them from the empty temporary directory with COMPACT_PATH.
  const legacySearch = validCompilerVersion(version) && workingDirectorySearchProfile(version);
  const run = (args: string[]) => spawnSync(resolve(executable), args, { encoding: "utf8", timeout: timeoutMs, maxBuffer: 1024 * 1024, windowsHide: true,
    ...(legacySearch ? { cwd: temporary, env: { ...process.env, COMPACT_PATH: searchPaths.length ? searchPaths.join(delimiter) : process.env.COMPACT_PATH ?? "" } } : {}) });
  try {
    const result = run(["--skip-zk", ...(zkirVersion === 3 ? ["--feature-zkir-v3"] : []), ...(searchPaths.length && !legacySearch ? ["--compact-path", searchPaths.join(delimiter)] : []), resolve(source), resolve(temporary, "output")]);
    return result.status === 0 ? { valid: true, version, languageVersion } : failure(String(result.error ?? result.stderr ?? result.stdout).slice(0, 8000) || `Compiler exited with ${result.status ?? result.signal}`);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}
