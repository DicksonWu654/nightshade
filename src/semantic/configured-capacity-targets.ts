import type { Program } from "./index.js";
import { collectionTargets } from "./collection-targets.js";
/** Canonical resolved ordinary/callback reachability; no initializer names. */
export function configuredCapacityTargets(program: Program, entry: string, allowance = 20000) {
  if (program.symbols.get(entry)?.kind === "constructor") return { complete: true, applicable: false, work: 1 };
  return collectionTargets(program, allowance, [entry]);
}
