import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type Parser from "tree-sitter-runtime";

const require = createRequire(import.meta.url);
const root = fileURLToPath(new URL("../../../", import.meta.url));
const manifest = JSON.parse(readFileSync(new URL("../../parser/manifest.json", import.meta.url), "utf8")) as { identity: string; upstreamRevision: string; overlay: string; abi: number };
const binding = require("node-gyp-build")(root) as Parser.Language & { identity: string };
if (binding.identity !== manifest.identity) throw new Error("Native Compact grammar identity mismatch; rebuild the parser");
binding.nodeTypeInfo = JSON.parse(readFileSync(new URL("../../parser/src/node-types.json", import.meta.url), "utf8"));

export const grammarMetadata = { revision: manifest.upstreamRevision, overlay: manifest.overlay, identity: manifest.identity, abi: manifest.abi };
export default binding;
