import type { Program } from "./index.js";
import { openzeppelinIdentities } from "./openzeppelin-identities.js";
import { VALUE_TRANSFER_CIRCUITS } from "./value-transfers.js";

/** Exact pinned Ownable declarations/dependencies; application names are not evidence. */
export function defaultAddressTargets(program: Program) {
  const identity = openzeppelinIdentities(program, ["openzeppelin-ownable"]);
  const owners = new Set([...program.symbols.values()].filter(symbol => symbol.kind === "ledger"
    && symbol.name === "_owner" && !!symbol.declaration && identity.authenticated(symbol.declaration.span)?.name === "Ownable"
    && identity.instances.some(edge => symbol.id.startsWith(`${edge.target}::`)))
    .map(symbol => symbol.id));
  const renounce = new Set([...identity.functions].filter(([id]) => program.symbols.get(id)?.name === "renounceOwnership").map(([id]) => id));
  const functions = new Set(identity.functions.keys());
  const targets = new Set([...VALUE_TRANSFER_CIRCUITS, ...functions]);
  // Direct native/kernel output calls are not materialized application circuits.
  const nativeOutputs = new Set(["createZswapOutput", "claimUnshieldedCoinSpend"]);
  return { owners, renounce, functions, targets, nativeOutputs };
}

export function hasDefaultAddressEffects(program: Program, entry: string, allowance = 20000): boolean {
  const scope = defaultAddressTargets(program);
  const pending = [entry], seen = new Set<string>();
  let work = 0;
  while (pending.length) {
    if (++work > allowance) return true; // No absence certificate after exhaustion.
    const id = pending.pop()!;
    if (seen.has(id)) continue;
    seen.add(id);
    if (scope.targets.has(id)) return true;
    const fn = program.functions.get(id);
    if ([...fn?.writesState ?? []].some(ledger => scope.owners.has(ledger))) return true;
    for (const callee of fn?.calls ?? []) {
      if (++work > allowance) return true;
      const symbol = program.symbols.get(callee);
      if (symbol?.kind === "intrinsic" && scope.nativeOutputs.has(symbol.name)) return true;
      pending.push(callee);
    }
    // Kernel operations are resolved ledger calls rather than circuit edges.
    for (const node of fn?.cfg.nodes ?? []) {
      if (++work > allowance) return true;
      const expressions = node.expr ? [node.expr] : [];
      while (expressions.length) {
        if (++work > allowance) return true;
        const expr = expressions.pop()!;
        if (expr.kind === "member" && expr.value === "call" && expr.name === "claimUnshieldedCoinSpend"
          && expr.args[0]?.inferredType && program.nativeTypeOf(expr.args[0].inferredType) === "Kernel") return true;
        if (expr.kind === "lambda" && expr.symbol) pending.push(expr.symbol);
        expressions.push(...expr.args);
      }
    }
  }
  return false;
}
