import type { Expr, Statement } from "../model.js";

/** Resolved source uses of local results. An identity alias is not a terminal
 * use: it retains a result only if that alias eventually has a non-alias use.
 * All other references (including assignments, captures and dead-source uses)
 * conservatively retain the result. This does not prove validation enforcement.
 * Work/depth exhaustion belongs to the caller's existing source allowance. */
export class LocalResultUses {
  private readonly terminal = new Set<string>();
  private readonly predecessors = new Map<string, Set<string>>();
  private readonly aliased = new Set<string>();
  private readonly owners = new Map<string, string>();

  constructor(private readonly charge: (depth: number) => boolean) {}

  reference(symbol: string): void { this.terminal.add(symbol); }

  /** Return true only when the entire initializer is a resolved identity alias
   * into a single local binding. Aggregate/destructured/computed aliases remain
   * ordinary may-uses; no source value or equality is invented for them. */
  bindAlias(statement: Statement, owner?: string): boolean {
    if (statement.kind !== "bind" || !statement.symbol) return false;
    if (owner) this.owners.set(statement.symbol, owner);
    if (statement.pattern && statement.pattern.kind !== "name") return false;
    let expr: Expr | undefined = statement.expr, depth = 0;
    while (expr && this.charge(depth++)) {
      if (expr.kind === "ref" && expr.symbol) {
        const predecessors = this.predecessors.get(statement.symbol) ?? new Set<string>();
        predecessors.add(expr.symbol); this.predecessors.set(statement.symbol, predecessors);
        this.aliased.add(expr.symbol);
        return true;
      }
      if (expr.kind !== "disclose" && !(expr.kind === "cast" && expr.castKind === "identity")) return false;
      expr = expr.args[0];
    }
    return false;
  }

  hasAlias(symbol: string): boolean { return this.aliased.has(symbol); }

  /** Linear backwards closure: fan-out retains a result if any alias is used.
   * The visited set also bounds cycles in caller-supplied resolved models. */
  retained(): Set<string> {
    const retained = new Set(this.terminal);
    // Declaration order/function materialization order need not agree. Resolve
    // captures after collecting every binding owner, without parsing symbol IDs.
    // An unknown owner is also a conservative capture, never a local-use proof.
    for (const [target, sources] of this.predecessors) {
      if (!this.charge(0)) return retained;
      for (const source of sources) {
        if (!this.charge(0)) return retained;
        if (!this.owners.has(source) || this.owners.get(source) !== this.owners.get(target)) retained.add(source);
      }
    }
    const pending = [...retained];
    while (pending.length && this.charge(0)) {
      for (const source of this.predecessors.get(pending.pop()!) ?? []) {
        if (!this.charge(0)) return retained;
        if (!retained.has(source)) { retained.add(source); pending.push(source); }
      }
    }
    return retained;
  }
}
