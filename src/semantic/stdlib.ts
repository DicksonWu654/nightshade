import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { parseSource } from "../parser/index.js";
import { substituteType, typeArguments } from "./types.js";

// Unmodified Apache-2.0 sources from compactc-v0.34.0, commit
// 1f671fc27818df2b2676b3a97f85b2b821756243. Keep the experimental ZKIR3
// surface separate from the qualified default ZKIR2 semantic profile.
function source(name: string) {
  const path = fileURLToPath(new URL(`../stdlib/${name}.compact`, import.meta.url));
  return parseSource(path, readFileSync(path, "utf8"));
}

export const standardLibrary = source("standard-library");
// Byte-identical compiler source in pinned releases 0.30.0 and 0.31.1.
export const legacyStandardLibrary = source("standard-library-0.30");
// Exact compactc 0.29.0 source (tag v0.29.0, f17a98c): struct-backed NativePoint.
export const nativePointStandardLibrary = source("standard-library-0.29");
// Exact compactc 0.28.0 source (tag v0.28.0, dce2f11). Its thirteen body-less
// `export circuit` native declarations are blanked byte-for-byte before parsing;
// the same natives are injected from INTRINSICS (or rejected per profile).
export const LEGACY_EXTERNAL_NATIVES = ["transientHash", "transientCommit", "persistentHash", "persistentCommit", "degradeToTransient", "upgradeFromTransient",
  "ecAdd", "ecMul", "ecMulGenerator", "hashToCurve", "ownPublicKey", "createZswapInput", "createZswapOutput"];
export const externalNativeStandardLibrary = (() => {
  const path = fileURLToPath(new URL("../stdlib/standard-library-0.28.compact", import.meta.url));
  const found: string[] = [];
  const text = readFileSync(path, "utf8").replace(/^export circuit (\w+)(?:<\w+>)?\([^)\n]*\)\s*:\s*[^;{\n]+;$/gm, (line, name: string) => { found.push(name); return " ".repeat(line.length); });
  if (found.join() !== LEGACY_EXTERNAL_NATIVES.join()) throw new Error(`Unexpected 0.28 external native declarations: ${found.join(", ")}`);
  return parseSource(path, text);
})();
// Exact compactc-v0.33.0-rc.2 source: nominal opaque points and Schnorr helper.
export const rc2StandardLibrary = source("standard-library-0.33-rc.2");
// Stable 0.35.0 and 0.35.0-rc.1 share this source pin and identical library bytes.
export const prereleaseStandardLibrary = source("standard-library-0.35-rc.1");
export const zkir3Library = source("zkir-v3-library");
export const standardStructs = standardLibrary.ast.declarations.filter(declaration => declaration.exported && declaration.typeKind === "struct");
export const zkir3Structs = zkir3Library.ast.declarations.filter(declaration => declaration.exported && declaration.typeKind === "struct");

// Compatibility identities for intrinsic/ADT signatures; schemas come from
// the parsed source, not an independently maintained structural type table.
export const standardStructFields: Record<string, Record<string, string>> = Object.fromEntries([...standardStructs, ...zkir3Structs].map(declaration => {
  const bindings = new Map(typeArguments(declaration.generics).map((parameter, index) => [parameter.replace(/^#/, ""), `$${index}`]));
  return [declaration.name, Object.fromEntries(declaration.parameters.map(field => [field.name, substituteType(field.type, bindings)]))];
}));
