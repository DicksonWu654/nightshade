import type { AbstractValue, AnalysisFacts, RuntimeOperation, StateWrite } from "./index.js";
import { mayOverlap, type Region } from "./regions.js";
import { SHIELDED_MINT } from "../semantic/mint-targets.js";

/** Exact derivations only. No dependency union, selector equality, or inferred
 * secret/role semantics licenses this cross-entry source relationship. */
export function resettableNoncePairs(facts: AnalysisFacts, entries: readonly string[], allowance = 100000): {
  complete: boolean; work: number; pairs: { entry: string; operation: RuntimeOperation; root: string; selectedPath: string[]; exactRegion: boolean; resetEntry: string; reset: StateWrite }[];
} {
  let work = 0, complete = true;
  const charge = (depth = 0) => complete &&= ++work <= allowance && depth <= 32;
  const extent = (value: AbstractValue, depth = 0): Region | undefined => {
    if (!charge(depth)) return;
    if (value.listLengthSnapshot) return { ...value.listLengthSnapshot, type: "List" };
    if (value.nonceEvolution && value.nonceEvolution.nonce.constant !== undefined) return extent(value.nonceEvolution.index, depth + 1);
    if (value.listLengthEncoding) return extent(value.listLengthEncoding, depth + 1);
    if (value.directDigest && ["persistentHash", "transientHash", "keccak256"].includes(value.directDigest.primitive))
      return extent(value.directDigest.input, depth + 1);
    return undefined;
  };
  const resets: { entry: string; write: StateWrite }[] = [];
  for (const path of facts.paths) if (facts.completedEntries.includes(path.entry)
    && facts.program.functions.get(path.entry)?.symbol.kind !== "constructor") for (const write of path.writes) {
    if (!charge()) break;
    if (write.after.emptyList) resets.push({ entry: path.entry, write });
  }
  const pairs: ReturnType<typeof resettableNoncePairs>["pairs"] = [];
  for (const path of facts.paths) if (entries.includes(path.entry) && facts.completedEntries.includes(path.entry))
    for (const operation of path.operations ?? []) {
      if (!charge()) break;
      const nonce = operation.kind === "shielded-mint" && operation.name === SHIELDED_MINT ? operation.args[2]
        : undefined;
      if (!nonce) continue;
      const region = extent(nonce);
      if (!region) continue;
      for (const reset of resets) {
        if (!charge()) break;
        if (reset.entry !== path.entry && mayOverlap(region, { root: reset.write.ledger, path: reset.write.region, type: "List" })) pairs.push({ entry: path.entry, operation, root: region.root, selectedPath: region.path, exactRegion: !region.path.some(p => p.startsWith("key:identity:") || p === "key:*") && JSON.stringify(region.path) === JSON.stringify(reset.write.region), resetEntry: reset.entry, reset: reset.write });
      }
    }
  return { complete, work, pairs: complete ? pairs : [] };
}
