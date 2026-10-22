import { mayCallCircuits, RECEIVE_SHIELDED } from "./value-transfers.js";
import type { Program } from "./index.js";
export const REDUNDANT_RECEIVE_RULE = "redundant-self-shielded-receive";
export const SELF_COIN_PRODUCERS = new Set(["mintShieldedToken", "sendShielded", "sendImmediateShielded"].map(name => `standard-library::${name}`));
export const SELF_COIN_TARGETS = new Set([...SELF_COIN_PRODUCERS, RECEIVE_SHIELDED]);
export function redundantReceiveScope(program: Program, entries = program.entries) {
  return mayCallCircuits(program, new Set([RECEIVE_SHIELDED]), 20000, entries);
}

/** Native checkpoint prefixes do not retain selected return snapshots. Reject
 * only reachable canonical kernel boundaries, without inventing prefix evidence. */
export function redundantReceiveCheckpoints(program: Program, entries = program.entries) {
  let work = 0, complete = true, present = false;
  const charge = () => { if (++work > 20000) complete = false; return complete; };
  const expression = (expr: import("../model.js").Expr, depth = 0): void => {
    if (!charge() || depth > 128) { complete = false; return; }
    if (expr.kind === "member" && expr.name === "checkpoint" && expr.ledgerRoot === "standard-library::kernel") present = true;
    for (const arg of expr.args) { if (!complete) break; expression(arg, depth + 1); }
  };
  const pending = [...entries], visited = new Set<string>();
  while (pending.length && charge() && !present) {
    const id = pending.pop()!; if (visited.has(id)) continue; visited.add(id);
    const fn = program.functions.get(id); if (!fn) continue;
    for (const node of fn.cfg.nodes) { if (!charge()) break; if (node.expr) expression(node.expr); }
    for (const target of fn.calls) { if (!charge()) break; pending.push(target); }
  }
  return { complete, present, work };
}
