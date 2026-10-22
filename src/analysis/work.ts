import { Expr } from "../model.js";
import { Program } from "../semantic/index.js";
import { sequenceLength } from "../semantic/types.js";

export interface WorkEstimate {
  units: number;
  model: "expanded-syntax-upper-bound-v1";
}

export function estimateWork(program: Program, circuit: string, maxVisits = Infinity): WorkEstimate | undefined {
  let visits = 0;
  const cache = new Map<string, number | undefined>();
  const active = new Set<string>();
  const functionCost = (id: string): number | undefined => {
    if (++visits > maxVisits) return undefined;
    if (active.has(id)) return undefined;
    if (cache.has(id)) return cache.get(id);
    const fn = program.functions.get(id);
    if (!fn) return 1;
    active.add(id);
    let total = 0;
    const reachable = fn.cfg.reachableFrom(fn.cfg.entry);
    for (const node of fn.cfg.nodes) {
      if (++visits > maxVisits) { active.delete(id); return undefined; }
      if (!reachable.has(node.id) || !node.expr) continue;
      const amount = expressionCost(node.expr);
      if (amount === undefined || !Number.isSafeInteger(total + amount)) { active.delete(id); cache.set(id, undefined); return undefined; }
      total += amount;
    }
    active.delete(id);
    cache.set(id, total);
    return total;
  };
  const expressionCost = (expr: Expr): number | undefined => {
    if (++visits > maxVisits) return undefined;
    const children = expr.args.map(expressionCost);
    if (children.some(cost => cost === undefined)) return undefined;
    let total = 1 + (children as number[]).reduce((sum, cost) => sum + cost, 0);
    if (expr.kind === "call") {
      const callee = functionCost(expr.symbol!);
      if (callee === undefined) return undefined;
      total += callee;
    }
    if (expr.kind === "map" || expr.kind === "fold") {
      const length = sequenceLength(program.representationOf(expr.args[expr.kind === "fold" ? 2 : 1].inferredType ?? "unknown"));
      const callee = functionCost(expr.args[0].symbol!);
      if (length === undefined || callee === undefined) return undefined;
      total += length * callee;
    }
    return Number.isSafeInteger(total) ? total : undefined;
  };
  const units = functionCost(circuit);
  return units === undefined ? undefined : { units, model: "expanded-syntax-upper-bound-v1" };
}
