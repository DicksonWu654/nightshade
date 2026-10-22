import type { AbstractValue, AnalysisFacts, RuntimeOperation, StateWrite } from "./index.js";
import { SHIELDED_MINT } from "../semantic/mint-targets.js";
import { parseType, printType } from "../semantic/types.js";
import { immutableEqualities } from "./immutable-equalities.js";
import { successfulConstants } from "./successful-constants.js";
import { mayOverlap } from "./regions.js";
import { listResetPreservesExtent } from "./list-reset.js";

export interface MemoNoncePair {
  entry: string; mint: RuntimeOperation; append: RuntimeOperation;
  root: string; selectedPath: string[]; revision: number;
  resetEntry: string; reset: StateWrite; exactResetRegion: boolean;
}

/** Paired canonical coin and stored payload consumers. Only direct
 * evolveNonce(exact selected List extent, constant seed) qualifies. No crypto
 * meaning is inferred from a name, dependency union or stored arbitrary hash. */
export function memoNoncePairs(facts: AnalysisFacts, entries = facts.completedEntries, allowance = 100000) {
  let work = 0, complete = true;
  const charge = (units = 1) => { work += units; return complete &&= work <= allowance; };
  const pairs: MemoNoncePair[] = [];
  const resets: { entry: string; write: StateWrite }[] = [];
  for (const path of facts.paths) if (facts.completedEntries.includes(path.entry)
    && facts.program.functions.get(path.entry)?.symbol.kind !== "constructor") for (const write of path.writes) {
    if (!charge()) break;
    if (write.after.emptyList) {
      const checked = listResetPreservesExtent(write,path,Math.max(0,allowance-work));
      charge(checked.work); complete &&= checked.complete;
      if (!checked.preservesExtent) resets.push({ entry: path.entry, write });
    }
  }
  for (const path of facts.paths) {
    if (!charge()) break;
    if (!entries.includes(path.entry) || !facts.completedEntries.includes(path.entry)) continue;
    const equality = immutableEqualities(path, Math.max(0, allowance - work), undefined, facts.program.meteringIdentity);
    const constants = successfulConstants(path, Math.max(0, allowance - work - equality.work), facts.program.meteringIdentity);
    let equalityWork = 0, constantsWork = 0;
    const account = () => { charge(equality.work - equalityWork + constants.work - constantsWork);
      equalityWork = equality.work; constantsWork = constants.work; complete &&= equality.complete && constants.complete; return complete; };
    const extent = (value: AbstractValue | undefined) => {
      if (!charge() || !value?.nonceEvolution || value.nonceEvolution.nonce.constantKind !== "bytes"
        || value.nonceEvolution.nonce.constant === undefined) return undefined;
      const snapshot = value.nonceEvolution.index.listLengthSnapshot;
      if (!snapshot?.receiver || snapshot.path.length !== 1 || snapshot.receiver.region?.collectionSelectors?.length !== 1) return undefined;
      const address = equality.address(snapshot.receiver);
      return account() && address ? { snapshot, address } : undefined;
    };
    const operations = path.operations ?? [];
    for (const mint of operations) {
      if (!charge()) break;
      if (mint.kind !== "shielded-mint" || mint.name !== SHIELDED_MINT) continue;
      const coin = extent(mint.args[2]);
      if (!coin) continue;
      const ledger = facts.program.symbols.get(coin.snapshot.root);
      const shape = ledger && parseType(facts.program.representationOf(ledger.type));
      if (!shape || shape.name !== "Map" || shape.args.length !== 2
        || facts.program.representationOf(printType(shape.args[0])) !== "Bytes<32>"
        || facts.program.representationOf(printType(shape.args[1])) !== "List<Bytes<32>>") continue;
      const recipient = constants.refine(mint.args[3]);
      const tag = recipient.fields?.is_left;
      // This initial contract supports account recipients with represented
      // ZswapCoinPublicKey.bytes, not ContractAddress or unconstrained arms.
      if (!tag || tag.constantKind !== "boolean" || tag.constant !== "true") { account(); continue; }
      const recipientBytes = recipient.fields?.left?.fields?.bytes;
      const selector = coin.snapshot.receiver!.region!.collectionSelectors![0].value;
      const recipientKey = recipientBytes && equality.key(recipientBytes), selectedKey = equality.key(selector);
      if (!account() || !recipientKey || recipientKey !== selectedKey) continue;
      for (const append of operations) {
        if (!charge()) break;
        if (append.kind !== "list-append" || append.name !== "pushFront") continue;
        const memo = extent(append.args[1]);
        if (!memo || memo.address !== coin.address || memo.snapshot.revision !== coin.snapshot.revision) continue;
        const receiver = equality.address(append.args[0]);
        if (!account() || receiver !== coin.address || append.args[0].region?.revision !== coin.snapshot.revision) continue;
        for (const reset of resets) {
          if (!charge()) break;
          if (reset.entry === path.entry || !mayOverlap({ ...coin.snapshot, type: "List" }, { root: reset.write.ledger, path: reset.write.region, type: "List" })) continue;
          const exactResetRegion = !coin.snapshot.path.some(part => part === "key:*" || part.startsWith("key:identity:"))
            && JSON.stringify(coin.snapshot.path) === JSON.stringify(reset.write.region);
          pairs.push({ entry: path.entry, mint, append, root: coin.snapshot.root, selectedPath: coin.snapshot.path,
            revision: coin.snapshot.revision, resetEntry: reset.entry, reset: reset.write, exactResetRegion });
        }
      }
    }
    account();
  }
  return { complete, work, pairs: complete ? pairs : [] };
}
