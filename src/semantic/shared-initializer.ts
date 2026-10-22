import { onceGateShape } from "../dataflow/once-gate-shape.js";
import type { Expr, Span } from "../model.js";
import { spanId } from "../model.js";
import type { Program } from "./index.js";

export const SHARED_INITIALIZER_RULE = "shared-module-once-gate";
export interface SharedGate { gate: string; ledger: string; guard: Span; write: Span;
  wrappers: { circuit: string; scope: string; call: Span; imports: Span[]; entries: string[] }[] }
/** Bounded resolved source fact. No initializer naming, inferred protocol role,
 * constant-path pruning or source-file equality establishes canonical state. */
export function sharedInitializerTargets(program: Program, allowance = 20000) {
  let work = 0;
  const groups: SharedGate[] = [], gaps: { entry: string; location: Span; message: string }[] = [];
  const charge = () => { if (++work > allowance) throw new Error("Shared-gate source traversal exhausted its allowance"); };
  try {
    const reachable = new Map<string, Set<string>>();
    for (const entry of program.entries) {
      const pending = [entry], seen = new Set<string>();
      while (pending.length) {
        charge(); const id = pending.pop()!; if (seen.has(id)) continue; seen.add(id);
        const entries = reachable.get(id) ?? new Set(); entries.add(entry); reachable.set(id, entries);
        const fn = program.functions.get(id);
        if (!fn) {
          const symbol = program.symbols.get(id);
          if (!symbol || !["intrinsic", "witness"].includes(symbol.kind)) gaps.push({ entry, location: program.functions.get(entry)!.declaration.span, message: "Reachable callable has no represented body" });
          continue;
        }
        pending.push(...fn.calls);
      }
    }
    for (const [gateId, entries] of reachable) {
      charge(); const fn = program.functions.get(gateId), scope = program.definingScope(gateId);
      if (!fn || !scope?.module) continue;
      const booleanWrites = [...fn.writesState].filter(id => { charge(); return program.symbols.get(id)?.kind === "ledger" && program.symbols.get(id)?.type === "Boolean"; });
      if (!booleanWrites.length) continue;
      const ledger = booleanWrites[0];
      const wrappers: SharedGate["wrappers"] = [];
      const importerScopes = new Set<string>(), wrapperGaps: typeof gaps = [];
      for (const [id, callers] of reachable) {
        charge(); const caller = program.functions.get(id), owner = program.definingScope(id);
        if (!caller || !owner?.module || owner.id === scope.id || !caller.calls.has(gateId)) continue;
        const imports = program.imports.filter(imported => { charge(); return imported.owner === owner.id && imported.target === scope.id; }).map(imported => imported.location);
        if (!imports.length) continue;
        importerScopes.add(owner.id);
        const body = caller.declaration.body;
        const expressions = body?.kind === "block" ? body.body.filter(item => item.kind === "expr" || item.kind === "return").map(item => (item as { expr: Expr }).expr) : [];
        const direct = expressions.length === 1 && body?.kind === "block" && body.body.length === 1
          && expressions[0].kind === "call" && expressions[0].symbol === gateId && expressions[0].args.length === 0
          && caller.declaration.parameters.length === 0 && caller.declaration.type === "[]";
        if (!direct) {
          for (const entry of callers) wrapperGaps.push({ entry, location: caller.declaration.span, message: "Multiple modules share a Boolean-writing gate but a wrapper has additional or conditional effects" });
          continue;
        }
        wrappers.push({ circuit: id, scope: owner.id, call: expressions[0].span, imports, entries: [...callers] });
      }
      if (importerScopes.size < 2) continue;
      gaps.push(...wrapperGaps);
      if (new Set(wrappers.map(wrapper => wrapper.scope)).size < 2) continue;
      const shape = fn.writesState.size === 1 && fn.declaration.parameters.length === 0 && fn.declaration.type === "[]"
        ? onceGateShape(fn.declaration.body, ledger) : undefined;
      if (!shape) {
        for (const entry of entries) gaps.push({ entry, location: fn.declaration.span, message: "Shared Boolean-writing callable is outside the exact false-guard then true-write gate shape" });
        continue;
      }
      groups.push({ gate: gateId, ledger, guard: shape.guard, write: shape.write, wrappers });
    }
  } catch (error) {
    groups.length = 0;
    for (const entry of program.entries) gaps.push({ entry, location: program.functions.get(entry)!.declaration.span, message: String((error as Error).message) });
  }
  return { groups, gaps: [...new Map(gaps.map(gap => [JSON.stringify([gap.entry, spanId(gap.location), gap.message]), gap])).values()], work };
}
