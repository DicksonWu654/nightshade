import { Expr, Pattern, fail } from "../model.js";
import { FunctionInfo, Program } from "../semantic/index.js";

/** Read-only indexed sets keep large instruction graphs from retaining millions
 * of individually allocated Set entries. All rows share one symbol vocabulary. */
export class LiveSet implements Iterable<string> {
  constructor(private readonly symbols: readonly string[], private readonly indices: ReadonlyMap<string, number>, private readonly bits: Uint32Array) {}

  has(symbol: string): boolean {
    const index = this.indices.get(symbol);
    return index !== undefined && (this.bits[index >>> 5] & (1 << (index & 31))) !== 0;
  }

  *[Symbol.iterator](): IterableIterator<string> {
    for (let word = 0; word < this.bits.length; word++) {
      let remaining = this.bits[word];
      while (remaining) {
        const bit = 31 - Math.clz32(remaining & -remaining);
        yield this.symbols[(word << 5) + bit];
        remaining = (remaining & (remaining - 1)) >>> 0;
      }
    }
  }
}

export interface LiveVariables {
  owned: Set<string>;
  liveIn: Map<number, LiveSet>;
  joins: Set<number>;
  storageBytes: number;
}

const patterns = (pattern?: Pattern): string[] => pattern ? [...(pattern.symbol ? [pattern.symbol] : []), ...pattern.children.flatMap(patterns)] : [];

export function ownedVariables(fn: FunctionInfo): Set<string> {
  return new Set([...fn.declaration.parameters.flatMap(parameter => [parameter.symbol!, ...patterns(parameter.pattern)]), ...fn.cfg.nodes.flatMap(node => [...(node.binding ? [node.binding] : []), ...(node.instruction?.result ? [node.instruction.result] : []), ...patterns(node.pattern)])]);
}

export const MAX_LIVENESS_STORAGE_BYTES = 64 * 1024 * 1024;

export function liveVariables(program: Program, fn: FunctionInfo, maxStorageBytes = MAX_LIVENESS_STORAGE_BYTES): LiveVariables {
  const captures = new Map<string, Set<string>>();
  const free = (callee: FunctionInfo): Set<string> => {
    const cached = captures.get(callee.symbol.id);
    if (cached) return cached;
    const result = new Set<string>();
    captures.set(callee.symbol.id, result);
    const declared = ownedVariables(callee);
    for (const node of callee.cfg.nodes) for (const symbol of node.expr ? used(node.expr) : []) if (!declared.has(symbol)) result.add(symbol);
    return result;
  };
  const used = (expr: Expr): Set<string> => {
    const result = new Set(expr.args.flatMap(arg => [...used(arg)]));
    const symbol = program.symbols.get(expr.symbol ?? "");
    if (expr.kind === "ref" && symbol && ["parameter", "local"].includes(symbol.kind)) result.add(symbol.id);
    const callee = symbol ? program.functions.get(symbol.id) : undefined;
    if (callee) for (const capture of free(callee)) result.add(capture);
    return result;
  };
  const uses = new Map(fn.cfg.nodes.map(node => [node.id, new Set([...(node.instruction?.inputs ?? []), ...(node.expr ? used(node.expr) : []), ...(node.instruction?.kind === "evaluate" ? used({ ...node.instruction.expression, args: node.instruction.deferred ? node.instruction.expression.args : node.instruction.expression.kind === "map" || node.instruction.expression.kind === "fold" ? node.instruction.expression.args.slice(0, 1) : [] }) : [])])]));
  const definitions = new Map(fn.cfg.nodes.map(node => [node.id, new Set([...(node.binding ? [node.binding] : []), ...(node.instruction?.result ? [node.instruction.result] : []), ...patterns(node.pattern)])]));
  const symbols = [...new Set([...uses.values(), ...definitions.values()].flatMap(values => [...values]))];
  const indices = new Map(symbols.map((symbol, index) => [symbol, index]));
  const words = Math.ceil(symbols.length / 32);
  const storageBytes = words * Uint32Array.BYTES_PER_ELEMENT * fn.cfg.nodes.length;
  // Fail before allocating the matrix. The Dataflow caller supplies its shared
  // remaining allowance; this is representation storage, not a path/step increase.
  if (storageBytes > maxStorageBytes) fail("liveness-budget", "Live-variable representation exceeds its 64 MiB shared storage allowance; results are incomplete", fn.declaration.span);
  const bitset = (values: Iterable<string>): Uint32Array => {
    const result = new Uint32Array(words);
    for (const value of values) { const index = indices.get(value)!; result[index >>> 5] |= 1 << (index & 31); }
    return result;
  };
  const liveBits = new Map<number, Uint32Array>();
  const incoming = new Map(fn.cfg.nodes.map(node => [node.id, [] as number[]]));
  for (const node of fn.cfg.nodes) for (const edge of node.edges) incoming.get(edge.target)!.push(node.id);
  const remaining = new Map(fn.cfg.nodes.map(node => [node.id, node.edges.length]));
  const pending = fn.cfg.nodes.filter(node => !node.edges.length).map(node => node.id);
  while (pending.length) {
    const node = pending.pop()!;
    const result = bitset(uses.get(node)!);
    const killed = bitset(definitions.get(node)!);
    for (const successor of fn.cfg.successors(node)) {
      const next = liveBits.get(successor)!;
      for (let word = 0; word < words; word++) result[word] |= next[word] & ~killed[word];
    }
    liveBits.set(node, result);
    for (const predecessor of incoming.get(node)!) {
      const count = remaining.get(predecessor)! - 1;
      remaining.set(predecessor, count);
      if (count === 0) pending.push(predecessor);
    }
  }
  const liveIn = new Map(fn.cfg.nodes.map(node => [node.id, new LiveSet(symbols, indices, liveBits.get(node.id) ?? new Uint32Array(words))]));
  return { storageBytes, owned: ownedVariables(fn), liveIn, joins: new Set([...incoming].filter(([, predecessors]) => predecessors.length > 1).map(([node]) => node)) };
}
