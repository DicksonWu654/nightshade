import type { Program } from "./index.js";
import type { ResolvedPolicies } from "../policies.js";

/** May-write admission includes untrusted providers: a declared obligation
 * cannot become a clean absence merely because authentication is unavailable. */
export function hasContractOwnerEffects(program: Program, entry: string, policies?: ResolvedPolicies): boolean {
  const writes = program.functions.get(entry)?.writesState;
  return !!policies?.callableOwnable?.some(policy => writes?.has(policy.owner));
}
