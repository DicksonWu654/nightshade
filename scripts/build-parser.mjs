import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
// Packed consumers receive generated sources and a matching prebuild. A source
// checkout retains the development build, which requires a compiler toolchain.
const packedInstall = process.argv.includes("--install") && !existsSync(resolve(root, "tsconfig.json"));
const require = createRequire(import.meta.url);
const config = JSON.parse(readFileSync(resolve(root, "src/parser/native/config.json"), "utf8"));
const digest = content => createHash("sha256").update(content).digest("hex");
const inputs = ["src/parser/native/config.json", "src/parser/native/grammar.cjs", "src/parser/native/binding.c", "binding.gyp", "scripts/build-parser.mjs"];
const identity = digest(Buffer.concat(inputs.flatMap(path => [Buffer.from(path + "\0"), readFileSync(resolve(root, path)), Buffer.from("\0")])));
const directory = resolve(root, "dist/parser");
const outputs = ["src/parser.c", "src/node-types.json", "src/grammar.json", "src/tree_sitter/parser.h", "src/tree_sitter/alloc.h", "src/tree_sitter/array.h", "identity.h", "upstream-grammar.js", "LICENSE.upstream", "LICENSE.tree-sitter", "NOTICE"];
let manifest;
try { manifest = JSON.parse(readFileSync(resolve(directory, "manifest.json"), "utf8")); } catch {}
const valid = manifest?.identity === identity && outputs.every(path => {
  try { return digest(readFileSync(resolve(directory, path))) === manifest.files[path]; } catch { return false; }
});

function run(command, args, cwd = root, env = process.env) {
  const result = spawnSync(command, args, { cwd, env, stdio: ["ignore", process.stderr, process.stderr], timeout: 120000 });
  if (result.status !== 0) throw new Error(`Parser build failed: ${command} (${result.error ?? result.signal ?? result.status})`);
}

if (!valid) {
  if (packedInstall) throw new Error("Packed parser sources are absent or stale; install a complete nightshade package from a qualified build");
  if (process.argv.includes("--verify")) throw new Error("Parser artifacts are absent or stale; run npm run build:parser");
  let generator;
  let upstream;
  try {
    generator = require.resolve("tree-sitter-cli/cli.js");
    upstream = require.resolve("tree-sitter-compact/grammar.js");
  } catch {
    throw new Error("Stale parser sources: regeneration requires development dependencies (npm ci --include=dev)");
  }
  if (require("tree-sitter-cli/package.json").version !== config.generatorVersion) throw new Error("Unexpected parser generator version");
  if (digest(readFileSync(upstream)) !== config.upstreamGrammarSha256) throw new Error("Upstream grammar integrity mismatch");
  mkdirSync(resolve(root, "dist"), { recursive: true });
  const staging = mkdtempSync(resolve(root, "dist/parser-staging-"));
  try {
    writeFileSync(resolve(staging, "package.json"), '{"type":"commonjs"}\n');
    writeFileSync(resolve(staging, "tree-sitter.json"), JSON.stringify({ grammars: [{ name: "compact", scope: "source.compact", path: ".", "file-types": ["compact"] }], metadata: { version: "0.1.0", license: "Apache-2.0" } }));
    writeFileSync(resolve(staging, "grammar.js"), `module.exports = require(${JSON.stringify(resolve(root, "src/parser/native/grammar.cjs"))});\n`);
    run(process.execPath, [generator, "generate", "--abi", String(config.abi)], staging);
    const parser = readFileSync(resolve(staging, "src/parser.c"), "utf8");
    if (!parser.includes(`#define LANGUAGE_VERSION ${config.abi}\n`)) throw new Error("Generated parser ABI mismatch");
    writeFileSync(resolve(staging, "identity.h"), `#define NIGHTSHADE_GRAMMAR_IDENTITY "${identity}"\n`);
    copyFileSync(upstream, resolve(staging, "upstream-grammar.js"));
    copyFileSync(resolve(dirname(upstream), "LICENSE"), resolve(staging, "LICENSE.upstream"));
    copyFileSync(require.resolve("tree-sitter-cli/LICENSE"), resolve(staging, "LICENSE.tree-sitter"));
    writeFileSync(resolve(staging, "NOTICE"), `Generated from midnightntwrk/compact-tree-sitter ${config.upstreamRevision} (Apache-2.0).\nUpstream grammar and its notices are preserved in upstream-grammar.js and LICENSE.upstream.\nModified by Nightshade: ${config.overlay} permits two-element expression sequences, empty import selections, escaped string line continuations, generic cast targets, omitted tuple pattern entries, empty struct patterns, nested generic calls, empty struct declarations and emit expressions.\nThe original overlay source is distributed in src/parser/native/grammar.cjs.\nGenerated with tree-sitter-cli ${config.generatorVersion}; runtime headers are MIT (LICENSE.tree-sitter).\n`);
    rmSync(resolve(staging, "grammar.js"));
    rmSync(resolve(staging, "package.json"));
    rmSync(resolve(staging, "tree-sitter.json"));
    manifest = { ...config, identity, files: Object.fromEntries(outputs.map(path => [path, digest(readFileSync(resolve(staging, path)))])) };
    writeFileSync(resolve(staging, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n");
    rmSync(directory, { recursive: true, force: true });
    renameSync(staging, directory);
  } finally {
    rmSync(staging, { recursive: true, force: true });
  }
}

let binding;
try { binding = require("node-gyp-build")(root); } catch {}
if (binding?.identity !== identity) {
  if (packedInstall) throw new Error(`No matching prebuilt Compact parser for ${process.platform}/${process.arch}; install a package built for this platform. Source builds require development dependencies and a C/C++ toolchain.`);
  if (process.argv.includes("--verify")) throw new Error("Native parser is absent or stale; run npm run build:parser");
  run(process.execPath, [require.resolve("node-gyp-build/bin.js")], root, { ...process.env, npm_config_build_from_source: "true" });
  run(process.execPath, ["-e", `const parser = require('node-gyp-build')(process.cwd()); if (parser.identity !== ${JSON.stringify(identity)}) throw new Error('Native parser identity mismatch');`]);
}
console.error(`Compact parser: ${config.upstreamRevision} + ${config.overlay} (ABI ${config.abi}, ${identity})`);
