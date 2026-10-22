import { createHash } from "node:crypto";
import type { Span } from "../model.js";
import type { BuiltinPolicy } from "../policies.js";
import type { Program } from "./index.js";

/** Exact upstream bytes plus resolved dependency edges. No network, names-only
 * authorization inference, installed package paths or caller-provided hashes. */
export const OZ_POLICY_REVISION = "ec1331cd8195694c747d291e8fc8ab6d2914a976";
const modules: { policy: BuiltinPolicy; name: string; hash: string }[] = [
  { policy: "openzeppelin-ownable", name: "Ownable", hash: "65d0676f30c74a1347d96cc339a438608c8f880004e77752b4373e40a0ea9a87" },
  { policy: "openzeppelin-access-control", name: "AccessControl", hash: "f7b933efe8db565b5fd44a4dd2688ed3c1d4ccf3e99e6a43c256db204b15df3b" },
  { policy: "openzeppelin-pausable", name: "Pausable", hash: "70239e8058f7522f61c6319249808989cf2c19be1febae02238cbe777dfe31db" },
  { policy: "openzeppelin-initializable", name: "Initializable", hash: "792f9ffe72099d90471aa1a4d5e83b0d145eccef736ee73cffc706be9b0ce33c" },
];
const utilsHash = "215d6374bb22a7c950bb43d046f6380f2c432fb841a2fcead2a35766d159f314";
export const SHIELDED_ACCESS_CONTROL_IDENTITY = { name: "ShieldedAccessControl", hash: "5378eee4a986e5f77749fdd544aad6ead5b832bd0281f429e0b8d06271f901af" } as const;
export const NON_FUNGIBLE_TOKEN_IDENTITY = { name: "NonFungibleToken", hash: "fe4d2b77a34d3f05a3b351d590ad55b2af5ca903c765bcd6946dceedbeecaed1" } as const;

export function openzeppelinIdentities(program: Program, enabled: readonly BuiltinPolicy[]) {
  return pinnedIdentities(program, modules, [...modules.map(module => module.hash), utilsHash], module => enabled.includes(module.policy));
}

/** The published role-bootstrap requirement is attached to authenticated
 * library bytes, rather than an application-supplied authorization policy. */
export function shieldedAccessControlIdentities(program: Program) {
  return pinnedIdentities(program, [SHIELDED_ACCESS_CONTROL_IDENTITY], [SHIELDED_ACCESS_CONTROL_IDENTITY.hash, utilsHash]);
}

export function nonFungibleTokenIdentities(program: Program) {
  return pinnedIdentities(program, [NON_FUNGIBLE_TOKEN_IDENTITY], [NON_FUNGIBLE_TOKEN_IDENTITY.hash, utilsHash]);
}

function pinnedIdentities<M extends { name: string; hash: string }>(program: Program, selected: readonly M[], dependencies: readonly string[], active: (module: M) => boolean = () => true) {
  const hashes = new Map([...program.files].map(([file, source]) => [file, createHash("sha256").update(source.text).digest("hex")]));
  const authenticated = (location: Span) => selected.find(module => module.hash === hashes.get(location.file));
  const allowed = new Set(dependencies);
  const edges = new Map<string, Program["imports"]>();
  for (const edge of program.imports) edges.set(edge.owner, [...(edges.get(edge.owner) ?? []), edge]);
  const trusted = (scope: string, seen = new Set<string>()): boolean => {
    if (seen.has(scope)) return true;
    seen.add(scope);
    return (edges.get(scope) ?? []).every(edge => allowed.has(hashes.get(edge.declaration.file) ?? "") && trusted(edge.target, seen));
  };
  const instances = program.imports.filter(edge => {
    const module = authenticated(edge.declaration);
    return module && active(module) && trusted(edge.target);
  });
  const functions = new Map<string, M>();
  for (const fn of program.functions.values()) {
    const module = authenticated(fn.declaration.span);
    if (module && active(module) && fn.declaration.exported && instances.some(edge => fn.symbol.id.startsWith(`${edge.target}::`) && edge.declaration.file === fn.declaration.span.file)) functions.set(fn.symbol.id, module);
  }
  return { authenticated, functions, instances, hashes };
}
