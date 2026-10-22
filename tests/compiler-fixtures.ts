import { createHash } from "node:crypto";
import { accessSync, constants, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync, renameSync, statSync, writeFileSync } from "node:fs";
import { dirname, delimiter, isAbsolute, relative, resolve, sep } from "node:path";
import { GRAMMAR_BUILD, parseSource } from "../src/parser/index.js";
import type { ScopeAst } from "../src/model.js";
import { validateWithCompiler as freshValidation, type CompilerValidation } from "../src/compiler/index.js";
import { COMPILER_PROFILES, validCompilerVersion, type CompilerVersion, type ZkirVersion } from "../src/semantic/profile.js";
export * from "../src/compiler/index.js";

// Test-only acceptance reuse. Product compiler validation and code-generation /
// runtime probes remain fresh. Rejections, timeouts and unsupported closures
// cannot seed this cache. Timing runs disable it entirely.
const implementation = createHash("sha256");
for (const path of [import.meta.url, ...["compiler/index", "semantic/profile", "parser/index", "parser/strings", "parser/native", "source-text", "model"].map(name => new URL(`../src/${name}.js`, import.meta.url))]) implementation.update(readFileSync(typeof path === "string" ? new URL(path) : path));
const implementationHash = implementation.digest("hex");
const counts = { hits: 0, fresh: 0, bypass: 0 };
export const fixtureCacheStats = (): Readonly<typeof counts> => ({ ...counts });
if (process.env.NIGHTSHADE_FIXTURE_CACHE_STATS) process.on("exit", () => {
  const directory = process.env.NIGHTSHADE_FIXTURE_CACHE_STATS!;
  mkdirSync(directory, { recursive: true });
  writeFileSync(resolve(directory, `${process.pid}.json`), JSON.stringify({ node: process.version, ...counts }) + "\n");
});
const compilerMemo = new Map<string, { signature: string; hash: string }>();
function compilerHash(executable: string): string | undefined {
  const configured = ["COMPACTC_TEST", "COMPACTC_028_TEST", "COMPACTC_029_TEST", "COMPACTC_030_TEST", "COMPACTC_031_TEST", "COMPACTC_033_RC2_TEST", "COMPACTC_035_RC1_TEST", "COMPACTC_035_TEST"].map(name => process.env[name]).filter(Boolean);
  if (!configured.some(path => resolve(path!) === resolve(executable))) return;
  if (lstatSync(executable).isSymbolicLink()) return;
  const launcher = readFileSync(executable, "utf8");
  if (launcher !== '#!/usr/bin/env bash\nthisdir="$(cd $(dirname $0) ; pwd -P)"\nPATH="$thisdir:$PATH"\nexec "$thisdir/compactc.bin" "$@"\n') return;
  const directory = dirname(realpathSync(executable));
  const files = readdirSync(directory).sort().map(name => resolve(directory, name));
  if (files.length > 32 || !existsSync(resolve(directory, "compactc.bin")) || files.some(file => !lstatSync(file).isFile())) return;
  const stats = files.map(file => statSync(file, { bigint: true }));
  if (stats.reduce((bytes, stat) => bytes + stat.size, 0n) > 128n * 1024n * 1024n) return;
  const signature = stats.map(stat => [stat.dev, stat.ino, stat.size, stat.mtimeNs, stat.ctimeNs].join(":")).join("|");
  const prior = compilerMemo.get(directory);
  if (prior?.signature === signature) return prior.hash;
  const hash = createHash("sha256");
  for (const file of files) hash.update(relative(directory, file)).update("\0").update(String(statSync(file).mode)).update("\0").update(readFileSync(file));
  const digest = hash.digest("hex");
  compilerMemo.set(directory, { signature, hash: digest });
  return digest;
}

const commandMemo = new Map<string, { signature: string; hash: string }>();
function commandHash(executable: string): string | undefined {
  const locate = (name: string, path: string): string | undefined => {
    for (const directory of path.split(delimiter)) {
      const file = resolve(directory || ".", name);
      try { accessSync(file, constants.X_OK); if (statSync(file).isFile()) return realpathSync(file); } catch {}
    }
    return undefined;
  };
  const bash = locate("bash", process.env.PATH ?? "");
  const dirnameCommand = locate("dirname", process.env.PATH ?? "");
  // Arbitrary scripts/native wrappers can read untracked files. Reuse only
  // with the host system interpreter/helpers; other launch environments are fresh.
  if (!bash || !dirnameCommand || bash !== realpathSync("/bin/bash") || dirnameCommand !== realpathSync("/usr/bin/dirname")) return;
  const hash = createHash("sha256");
  for (const file of ["/usr/bin/env", bash, dirnameCommand]) {
    const stat = statSync(file, { bigint: true });
    const signature = [stat.dev, stat.ino, stat.size, stat.mode, stat.mtimeNs, stat.ctimeNs].join(":");
    const prior = commandMemo.get(file);
    const digest = prior?.signature === signature ? prior.hash : createHash("sha256").update(readFileSync(file)).digest("hex");
    commandMemo.set(file, { signature, hash: digest });
    hash.update(JSON.stringify([file, String(stat.mode), digest]));
  }
  return hash.digest("hex");
}

function inputHash(source: string, searchPaths: string[]): string | undefined {
  if (resolve(source) !== realpathSync(source)) return;
  const root = realpathSync(dirname(source));
  const paths = searchPaths.length ? searchPaths : (process.env.COMPACT_PATH ?? "").split(delimiter).filter(Boolean);
  if (paths.some(path => resolve(path) !== realpathSync(path))) return;
  const roots = [root, ...paths].map(path => realpathSync(path));
  const hash = createHash("sha256").update(relative(root, realpathSync(source)));
  let count = 0, bytes = 0;
  const hashed = new Set<string>(), dependencies = new Set<string>();
  const within = (file: string): boolean => roots.some(directory => { const path = relative(directory, file); return path !== ".." && !path.startsWith(".." + sep) && !isAbsolute(path); });
  const safePath = (path: string): boolean => !isAbsolute(path) && !path.split(/[\\/]/).includes("..");
  const checkScope = (scope: ScopeAst): boolean => {
    if (scope.imports.some(item => item.external && !safePath(item.name)) || scope.includes?.some(item => !safePath(item.path))) return false;
    return scope.declarations.every(declaration => !declaration.scope || checkScope(declaration.scope));
  };
  const visit = (directory: string, namespace: number): boolean => {
    for (const name of readdirSync(directory).sort()) {
      if (name === ".git" || name === "node_modules") continue;
      const file = resolve(directory, name), stat = lstatSync(file);
      if (stat.isSymbolicLink()) return false; // no alias-graph guessing
      if (stat.isDirectory()) { if (!visit(file, namespace)) return false; continue; }
      if (!name.endsWith(".compact")) continue;
      if (++count > 256 || (bytes += stat.size) > 16 * 1024 * 1024) return false;
      const content = readFileSync(file);
      const ast = parseSource(file, content.toString("utf8")).ast;
      if (!checkScope(ast)) return false;
      const check = (scope: ScopeAst): boolean => {
        for (const dependency of [...scope.imports.filter(item => item.external).map(item => item.name), ...scope.includes?.map(item => item.path) ?? []]) {
          const candidates = [dirname(file), ...roots].map(base => resolve(base, dependency + ".compact"));
          const found = candidates.find(path => existsSync(path));
          if (!found || found !== realpathSync(found) || !within(realpathSync(found))) return false;
          dependencies.add(realpathSync(found));
        }
        return scope.declarations.every(declaration => !declaration.scope || check(declaration.scope));
      };
      if (!check(ast)) return false;
      hashed.add(realpathSync(file));
      hash.update(JSON.stringify([namespace, relative(roots[namespace], file)])).update("\0").update(content);
    }
    return true;
  };
  for (let index = 0; index < roots.length; index++) if (!visit(roots[index], index)) return;
  if (!hashed.has(realpathSync(source)) || [...dependencies].some(path => !hashed.has(path))) return;
  return hash.digest("hex");
}

export function validateWithCompiler(executable: string, source: string, searchPaths: string[] = [], timeoutMs = 30000, zkirVersion: ZkirVersion = 2, expectedVersion?: CompilerVersion): CompilerValidation {
  const cache = process.env.NIGHTSHADE_FIXTURE_CACHE;
  let key: string | undefined;
  const computeKey = (): string | undefined => {
  if (cache && process.env.NIGHTSHADE_DISABLE_FIXTURE_CACHE !== "1" && !Object.keys(process.env).some(name => (name.startsWith("BASH_FUNC_") || ["BASH_ENV", "ENV", "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH"].includes(name)) && process.env[name])) try {
    const compiler = compilerHash(executable), commands = compiler && commandHash(executable), inputs = commands && inputHash(source, searchPaths);
    if (compiler && commands && inputs) return createHash("sha256").update(JSON.stringify([3, implementationHash, GRAMMAR_BUILD, COMPILER_PROFILES, compiler, commands, inputs, searchPaths, Object.entries(process.env).filter(([name]) => !name.startsWith("NIGHTSHADE_FIXTURE_CACHE") && !["NODE_TEST_WORKER_ID", "SHLVL", "_"].includes(name)).sort(), timeoutMs, zkirVersion, expectedVersion, process.platform, process.arch, process.cwd()])).digest("hex");
  } catch { /* An unknown closure always gets the real compiler. */ }
  return undefined;
  };
  // Node ordinal and shell nesting/last-command metadata cannot affect this
  // exact pinned launcher. Input, command, loader and profile state stays keyed.
  key = computeKey();
  const file = key && cache ? resolve(cache, key + ".json") : undefined;
  if (file) try {
    const stored = JSON.parse(readFileSync(file, "utf8"));
    const version: unknown = stored.result?.version;
    if (stored.key === key && stored.result?.valid === true && typeof version === "string" && validCompilerVersion(version) && stored.result.languageVersion === COMPILER_PROFILES[version].languageVersion && (!expectedVersion || expectedVersion === version)) { counts.hits++; return { ...stored.result }; }
  } catch { /* Missing/corrupt entries are misses. */ }
  counts.fresh++;
  if (!key) counts.bypass++;
  const result = freshValidation(executable, source, searchPaths, timeoutMs, zkirVersion, expectedVersion);
  if (file && result.valid && computeKey() === key) try {
    mkdirSync(dirname(file), { recursive: true });
    const temporary = `${file}.${process.pid}.tmp`;
    writeFileSync(temporary, JSON.stringify({ key, result }) + "\n");
    renameSync(temporary, file);
  } catch { /* Acceptance assertions do not depend on cache write permission. */ }
  return result;
}
