import { createRequire } from "node:module";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// A release builder packages its own target. Native output stays ignored in Git;
// other targets require their own build/qualification, never a renamed binary.
const require = createRequire(import.meta.url);
const root = fileURLToPath(new URL("../", import.meta.url));
const manifest = JSON.parse(readFileSync(resolve(root, "dist/parser/manifest.json"), "utf8"));
const source = require("node-gyp-build").path(root);
if (require(source).identity !== manifest.identity) throw new Error("Refusing to package a stale native parser");
const libc = process.platform === "linux" ? process.report.getReport().header.glibcVersionRuntime ? "glibc" : "musl" : undefined;
const target = resolve(root, "prebuilds", `${process.platform}-${process.arch}`, `nightshade-parser.napi${libc ? `.${libc}` : ""}.node`);
const binary = readFileSync(source);
// A per-target package must not accidentally retain another build's binaries.
rmSync(resolve(root, "prebuilds"), { recursive: true, force: true });
mkdirSync(dirname(target), { recursive: true });
writeFileSync(target, binary);
console.error(`Packaged N-API 8 parser for ${process.platform}/${process.arch}${libc ? `/${libc}` : ""}; grammar ${manifest.identity}`);
