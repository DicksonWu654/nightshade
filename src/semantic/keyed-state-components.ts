import type { Expr, Statement } from "../model.js";
import type { Program } from "./index.js";
import { parseType } from "./types.js";

export interface KeyedStateComponent {
  entries: string[];
  roots: string[];
  applicable: boolean;
}

/** A conservative may-dependency partition, never a value-equality proof.
 * Every represented read/write connects its entire canonical ledger root.
 * Source bodies include pruned statements and zero-iteration callbacks; calls
 * retain resolved specialization/module identities. Unknown effect scopes or
 * unfinished traversal prevent *any* disjointness certificate. */
export function keyedStateComponents(program: Program, allowance = 20000): {
  complete: boolean; components: KeyedStateComponent[]; work: number; reason?: string;
} {
  let work = 0;
  class Unavailable extends Error {}
  const charge = () => { if (++work > allowance) throw new Unavailable("Keyed-state component dependencies exhausted their work allowance"); };
  const summaries = new Map<string, { roots: Set<string>; calls: Set<string>; applicable: boolean }>();
  const ledger = (id: string) => {
    charge();
    if (program.symbols.get(id)?.kind !== "ledger") throw new Unavailable("Keyed-state dependency lacks a canonical ledger identity");
    return id;
  };
  try {
    const dependencies = program.entries.map(entry => {
      const roots = new Set<string>(), seen = new Set<string>(), pending = [entry];
      let applicable = false;
      while (pending.length) {
        charge(); const id = pending.pop()!;
        if (seen.has(id)) continue;
        seen.add(id);
        let summary = summaries.get(id);
        if (!summary) {
          const fn = program.functions.get(id);
          if (!fn) {
            if (!["intrinsic", "witness"].includes(program.symbols.get(id)?.kind ?? ""))
              throw new Unavailable("Keyed-state dependency has an unresolved callable body");
            summary = { roots: new Set(), calls: new Set(), applicable: false };
          } else {
            summary = { roots: new Set(), calls: new Set(fn.calls), applicable: false };
            for (const root of [...fn.readsState, ...fn.writesState]) summary.roots.add(ledger(root));
            if (!fn.declaration.body) throw new Unavailable("Keyed-state dependency has no represented callable body");
            const source: { item: Statement | Expr; expression: boolean; depth: number }[] = [{ item: fn.declaration.body, expression: false, depth: 0 }];
            while (source.length) {
              charge(); const { item, expression, depth } = source.pop()!;
              if (depth > 64) throw new Unavailable("Keyed-state dependency exceeds its structural depth allowance");
              if (expression) {
                const expr = item as Expr;
                if (expr.contractCall) throw new Unavailable("External-contract callee effects have unknown ledger scope");
                if (expr.kind === "call" || expr.kind === "lambda" || expr.kind === "map" || expr.kind === "fold") {
                  const callee = expr.kind === "map" || expr.kind === "fold" ? expr.args[0]?.symbol : expr.symbol;
                  if (!callee) throw new Unavailable("Keyed-state dependency has an unresolved call identity");
                  summary.calls.add(callee);
                }
                if (expr.ledgerRoot) summary.roots.add(ledger(expr.ledgerRoot));
                if (expr.symbol && program.symbols.get(expr.symbol)?.kind === "ledger") summary.roots.add(ledger(expr.symbol));
                if (expr.kind === "member" && expr.value === "call") {
                  if (!expr.ledgerRoot) throw new Unavailable("Ledger operation has unknown canonical root scope");
                  const receiver = expr.args[0];
                  if (["member", "insert"].includes(expr.name ?? "") && ["Map", "Set"].includes(
                    parseType(program.representationOf(receiver.ledgerType ?? receiver.inferredType ?? "unknown")).name)) summary.applicable = true;
                }
                for (const arg of expr.args) source.push({ item: arg, expression: true, depth: depth + 1 });
                if (expr.body) source.push({ item: expr.body, expression: false, depth: depth + 1 });
              } else {
                const statement = item as Statement;
                if (statement.kind === "block" || statement.kind === "bindings") {
                  for (const child of statement.body) source.push({ item: child, expression: false, depth: depth + 1 });
                } else if (statement.kind === "if") {
                  source.push({ item: statement.condition, expression: true, depth: depth + 1 }, { item: statement.then, expression: false, depth: depth + 1 });
                  if (statement.otherwise) source.push({ item: statement.otherwise, expression: false, depth: depth + 1 });
                } else if (statement.kind === "for") {
                  if (statement.sequence) source.push({ item: statement.sequence, expression: true, depth: depth + 1 });
                  source.push({ item: statement.body, expression: false, depth: depth + 1 });
                } else source.push({ item: statement.expr, expression: true, depth: depth + 1 });
              }
            }
          }
          summaries.set(id, summary);
        }
        applicable ||= summary.applicable;
        for (const root of summary.roots) { charge(); roots.add(root); }
        for (const call of summary.calls) { charge(); pending.push(call); }
      }
      return { entry, roots, applicable };
    });
    const parents = dependencies.map((_, index) => index), owners = new Map<string, number>();
    const find = (index: number): number => {
      charge(); while (parents[index] !== index) { charge(); index = parents[index]; } return index;
    };
    for (const [index, dependency] of dependencies.entries()) for (const root of dependency.roots) {
      charge(); const owner = owners.get(root);
      if (owner === undefined) owners.set(root, index);
      else parents[find(index)] = find(owner);
    }
    const groups = new Map<number, { entries: string[]; roots: Set<string>; applicable: boolean }>();
    for (const [index, dependency] of dependencies.entries()) {
      const parent = find(index), group = groups.get(parent) ?? { entries: [], roots: new Set<string>(), applicable: false };
      group.entries.push(dependency.entry); group.applicable ||= dependency.applicable;
      for (const root of dependency.roots) { charge(); group.roots.add(root); }
      groups.set(parent, group);
    }
    return { complete: true, components: [...groups.values()].map(group => ({ ...group, roots: [...group.roots] })), work };
  } catch (error) {
    if (!(error instanceof Unavailable)) throw error;
    return { complete: false, components: [], work, reason: error.message };
  }
}
