import type { Program } from "./index.js";
import { numericBound } from "./types.js";
import { ZERO_SEND_TARGET } from "./zero-send-targets.js";

export const COMPLEMENTARY_SEND_RULE = "zero-amount-complementary-send-review";
export const COMPLEMENTARY_SEND_TARGET = ZERO_SEND_TARGET;
export type ComplementaryCharge = (work?: number, values?: number) => boolean;

export function complementarySendProfile(program: Program): boolean {
  return program.compilerVersion === "0.34.0" && [2, 3].includes(program.zkirVersion)
    || program.compilerVersion === "0.31.1" && program.zkirVersion === 2;
}

/** A may-count of canonical sends in the owned callable closure, saturated at
 * two. Repeated helpers, loops and callbacks can supply both calls; exclusive
 * branches only admit observation and never donate a pair to the matcher. */
export function complementarySendScope(program: Program, entry: string, charge: ComplementaryCharge): boolean {
  charge(0, 5);
  const pending = [entry], graph = new Map<string, { calls: Map<string, number>; repeated: boolean }>();
  let checkpoint = false, subtraction = false;
  while (pending.length) {
    charge(); const id = pending.pop()!;
    if (graph.has(id)) continue;
    charge(0, 3); const calls = new Map<string, number>();
    const row = { calls, repeated: false }; graph.set(id, row);
    if (id === COMPLEMENTARY_SEND_TARGET) continue;
    const fn = program.functions.get(id);
    if (!fn) {
      const symbol = program.symbols.get(id);
      if (!symbol || symbol.kind !== "intrinsic" && symbol.kind !== "witness")
        throw new Error("Complementary send callable closure is unresolved");
      continue;
    }
    const add = (callee: string) => {
      charge(1, 2); calls.set(callee, Math.min(2, (calls.get(callee) ?? 0) + 1)); pending.push(callee);
    };
    for (const node of fn.cfg.nodes) {
      charge(1, 1); const expressions = node.expr ? [node.expr] : [];
      for (const edge of node.edges) charge();
      while (expressions.length) {
        charge(); const expr = expressions.pop()!;
        if (expr.contractCall || expr.kind === "call" && (!expr.symbol || !program.symbols.has(expr.symbol)))
          throw new Error("Complementary send external composition or call identity is unavailable");
        if (expr.kind === "binary" && expr.name === "-") {
          charge(); subtraction ||= numericBound(program.representationOf(expr.numericType ?? expr.inferredType ?? "unknown")) !== undefined;
        }
        checkpoint ||= expr.kind === "member" && expr.name === "checkpoint" && expr.ledgerRoot === "standard-library::kernel";
        if ((expr.kind === "call" || expr.kind === "lambda") && expr.symbol) add(expr.symbol);
        row.repeated ||= expr.kind === "map" || expr.kind === "fold";
        for (const child of expr.args) { charge(1, 1); expressions.push(child); }
      }
    }
    // Actual CFG cycles can repeat a single call. Node numbering alone does
    // not prove a cycle: exit and join nodes can precede their incoming nodes.
    charge(0, 2 + fn.cfg.nodes.length * 2);
    const incoming = new Array<number>(fn.cfg.nodes.length).fill(0), ready: number[] = [];
    for (const node of fn.cfg.nodes) for (const edge of node.edges) { charge(); incoming[edge.target]++; }
    for (const node of fn.cfg.nodes) { charge(); if (!incoming[node.id]) ready.push(node.id); }
    let visited = 0;
    while (ready.length) {
      charge(); const node = fn.cfg.nodes[ready.pop()!]; visited++;
      for (const edge of node.edges) { charge(); if (!--incoming[edge.target]) ready.push(edge.target); }
    }
    row.repeated ||= visited !== fn.cfg.nodes.length;
    // Resolved callback references may be carried outside call expressions.
    for (const callee of fn.calls) if (!calls.has(callee)) add(callee);
  }
  charge(0, 1 + graph.size); const counts = new Map<string, number>();
  for (const id of graph.keys()) { charge(); counts.set(id, id === COMPLEMENTARY_SEND_TARGET ? 1 : 0); }
  let changed = true;
  while (changed) {
    changed = false;
    for (const [id, row] of graph) {
      charge(); if (id === COMPLEMENTARY_SEND_TARGET) continue;
      let count = 0;
      for (const [callee, occurrences] of row.calls) { charge(); count = Math.min(2, count + (counts.get(callee) ?? 0) * occurrences); }
      if (row.repeated && count) count = 2;
      if (count !== counts.get(id)) { counts.set(id, count); changed = true; }
    }
  }
  const applicable = subtraction && (counts.get(entry) ?? 0) >= 2;
  if (applicable && checkpoint) throw new Error("Complementary send checkpoint histories are unavailable");
  return applicable;
}
