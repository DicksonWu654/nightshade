import type { Program } from "./index.js";

export const EXPORTED_SHIELDED_DESCRIPTOR_RULE = "exported-shielded-descriptor";
export const SHIELDED_DESCRIPTOR_PRODUCERS = new Set([
  "standard-library::sendShielded", "standard-library::sendImmediateShielded", "standard-library::mintShieldedToken",
]);
/** Canonical identities survive aliases/imports; user names supply no evidence. */
export function shieldedDescriptorType(program: Program, type: string): boolean {
  return ["ShieldedCoinInfo", "QualifiedShieldedCoinInfo"].includes(program.nativeTypeOf(type) ?? "");
}
