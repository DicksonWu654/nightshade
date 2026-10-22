import type { HashBinding, PublicSink, RuntimeOperation, StateWrite, SuccessfulPredicate, TraceStep } from "./index.js";
import { spanId, type Span } from "../model.js";
import { ValueFingerprints } from "./fingerprints.js";

/** These are observations made on conservative current states. Choices preserve
 * their separate order and scope; payloads after a join can be may-values. Only
 * ordinary selected replay supplies a successful abstract history. */
export interface SourceHistorySegment {
  bindings: readonly HashBinding[];
  predicates: readonly SuccessfulPredicate[];
  sinks: readonly PublicSink[];
  writes: readonly StateWrite[];
  operations: readonly RuntimeOperation[];
  path: readonly TraceStep[];
}

export type SourceHistoryNode =
  | { kind: "start"; id: number }
  | { kind: "segment"; id: number; prefix: number; observations: SourceHistorySegment }
  | { kind: "alternatives"; id: number; left: number; right: number; location: Span };

export interface SourceHistory {
  kind: "conservative-source-alternatives";
  root: number;
  nodes: readonly SourceHistoryNode[];
}

/** Persistent prefix sharing, without concatenating mutually exclusive effects.
 * Segment positions are relative to that segment, never whole-path offsets. */
export class SourceHistories {
  private readonly nodes: SourceHistoryNode[] = [{ kind: "start", id: 0 }];
  private refused = false;
  constructor(private readonly charge: (work: number, values: number) => boolean) {}
  get exhausted(): boolean { return this.refused; }
  private retain(node: Omit<Extract<SourceHistoryNode, { kind: "segment" }>, "id"> | Omit<Extract<SourceHistoryNode, { kind: "alternatives" }>, "id">, size = 0): number | undefined {
    if (this.refused || !this.charge(1 + size, 1 + size)) { this.refused = true; return; }
    const id = this.nodes.length;
    this.nodes.push({ ...node, id }); return id;
  }
  append(prefix: number, observations: SourceHistorySegment): number | undefined {
    const size = Object.values(observations).reduce((sum, items) => sum + items.length, 0);
    if (!size) return this.refused ? undefined : prefix;
    return this.retain({ kind: "segment", prefix, observations }, size);
  }
  alternatives(left: number, right: number, location: Span): number | undefined {
    if (left === right) return this.refused ? undefined : left;
    return this.retain({ kind: "alternatives", left, right, location });
  }
  snapshot(root: number): SourceHistory | undefined {
    const reachable = new Set<number>(), pending = [root];
    while (pending.length) {
      const id = pending.pop()!;
      if (reachable.has(id)) continue;
      if (this.refused || !this.charge(1, 0)) { this.refused = true; return; }
      reachable.add(id);
      const node = this.nodes[id];
      if (node.kind === "segment") pending.push(node.prefix);
      if (node.kind === "alternatives") pending.push(node.left, node.right);
    }
    return { kind: "conservative-source-alternatives", root,
      nodes: structuredClone(this.nodes.filter(node => reachable.has(node.id))) };
  }
}

export interface SourceHistoryFacts<T = SuccessfulPredicate> {
  /** Unions describe possible observations, never a combined successful path. */
  possible: SourceHistorySegment;
  /** Every retained route to the root enforces each of these predicates. Their
   * positions remain segment-relative and must not be used as path positions. */
  requiredPredicates: readonly T[];
  effects: readonly { key: string; requiredPredicates: readonly T[]; possiblePredicates: readonly T[] }[];
}

export function sourceEffectKey(kind: "ledger-write" | "kernel-write", effect: Pick<StateWrite, "location" | "callPath" | "callSites">): string | undefined {
  return effect.callSites && JSON.stringify([kind, spanId(effect.location), effect.callPath, effect.callSites.map(spanId)]);
}

/** Shared-prefix query: union possible observations; intersect required guards.
 * Bitsets retain the full alternatives without enumerating their Cartesian
 * product. Exact replay is still required for an existence claim. */
export function sourceHistoryFacts(history: SourceHistory, charge: (work: number, values: number) => boolean):
  { status: "available"; facts: SourceHistoryFacts } | { status: "incomplete"; reason: string } {
  const fingerprints = new ValueFingerprints();
  return querySourceHistory(history, charge, predicate => {
    const { writesBefore: _, operationsBefore: __, ...guard } = predicate;
    return [{ key: fingerprints.key(guard), value: predicate }];
  });
}

/** Project each enforced predicate to necessary atomic facts before intersecting
 * alternatives. A consumer can query equality keys without retaining unrelated
 * operand trees; returning undefined refuses the entire projection. */
export interface PredicateProjection<T> {
  possible: readonly { key: string; value: T }[];
  required: readonly { key: string; value: T }[];
}

export function querySourceHistory<T>(history: SourceHistory, charge: (work: number, values: number) => boolean,
  project: (predicate: SuccessfulPredicate) => readonly { key: string; value: T }[] | PredicateProjection<T> | undefined):
  { status: "available"; facts: SourceHistoryFacts<T> } | { status: "incomplete"; reason: string } {
  const incomplete = (reason: string) => ({ status: "incomplete" as const, reason });
  const possible = { bindings: [] as HashBinding[], predicates: [] as SuccessfulPredicate[], sinks: [] as PublicSink[],
    writes: [] as StateWrite[], operations: [] as RuntimeOperation[], path: [] as TraceStep[] };
  type Masks = { required: bigint; possible: bigint };
  type Summary = Masks & { effects: Map<string, Masks> };
  const summaries = new Map<number, Summary>(), predicates = new Map<string, number>(), values: T[] = [];
  let words = 1;
  for (const node of history.nodes) {
    if (!charge(1, 1)) return incomplete("Source-history query exhausted its shared allowance");
    if (summaries.has(node.id)) return incomplete("Duplicate source-history node");
    let summary: Summary = { required: 0n, possible: 0n, effects: new Map() };
    if (node.kind === "segment") {
      const prefix = summaries.get(node.prefix);
      if (prefix === undefined) return incomplete("Missing source-history prefix");
      let added = 0n, possibleAdded = 0n;
      for (const field of ["bindings", "predicates", "sinks", "writes", "operations", "path"] as const) {
        if (!charge(node.observations[field].length, node.observations[field].length)) return incomplete("Source-history observation query exhausted its shared allowance");
        // Each field retains its own order; there is deliberately no path union.
        (possible[field] as unknown[]).push(...node.observations[field]);
      }
      for (const predicate of node.observations.predicates) {
        const projected = project(predicate);
        if (!projected) return incomplete("Source-history predicate projection is unresolved");
        const projection = "possible" in projected ? projected : { possible: projected, required: projected };
        for (const { key, value } of projection.possible) {
          let index = predicates.get(key);
          if (index === undefined) { index = predicates.size; predicates.set(key, index); values.push(value); }
          words = Math.max(1, Math.ceil(predicates.size / 64));
          if (!charge(words, 1)) return incomplete("Source-history guard query exhausted its shared allowance");
          possibleAdded |= 1n << BigInt(index);
          if (projection.possible === projection.required) added |= 1n << BigInt(index);
        }
        if (projection.possible !== projection.required) for (const { key } of projection.required) {
          if (!charge(words, 1)) return incomplete("Source-history required projection exhausted its shared allowance");
          const index = predicates.get(key);
          if (index === undefined) return incomplete("Required projection has no possible origin");
          added |= 1n << BigInt(index);
        }
      }
      summary = { required: prefix.required | added, possible: prefix.possible | possibleAdded, effects: prefix.effects };
      const current = [...node.observations.writes.map(effect => sourceEffectKey("ledger-write", effect)),
        ...node.observations.operations.filter(effect => effect.kind === "kernel-write").map(effect => sourceEffectKey("kernel-write", effect))];
      if (current.some(key => key === undefined)) return incomplete("Source effect lacks invocation identity");
      if (possibleAdded || current.length) {
        summary.effects = new Map();
        for (const [key, mask] of prefix.effects) {
          if (!charge(words, words)) return incomplete("Source-history effect guard query exhausted its shared allowance");
          summary.effects.set(key, { required: mask.required | added, possible: mask.possible | possibleAdded });
        }
        for (const key of current) {
          if (!charge(words, words)) return incomplete("Source-history effect query exhausted its shared allowance");
          // This occurrence is on every route through the segment, including
          // routes that lacked an earlier occurrence of the same source site.
          summary.effects.set(key!, { required: summary.required, possible: summary.possible });
        }
      }
    } else if (node.kind === "alternatives") {
      const left = summaries.get(node.left), right = summaries.get(node.right);
      if (left === undefined || right === undefined) return incomplete("Missing source-history alternative");
      summary = { required: left.required & right.required, possible: left.possible | right.possible, effects: new Map() };
      for (const key of new Set([...left.effects.keys(), ...right.effects.keys()])) {
        if (!charge(words, words)) return incomplete("Source-history effect intersection exhausted its shared allowance");
        const a = left.effects.get(key), b = right.effects.get(key);
        summary.effects.set(key, a && b ? { required: a.required & b.required, possible: a.possible | b.possible } : (a ?? b)!);
      }
    }
    if (!charge(words, words)) return incomplete("Source-history guard intersection exhausted its shared allowance");
    summaries.set(node.id, summary);
  }
  const root = summaries.get(history.root);
  if (root === undefined) return incomplete("Missing source-history root");
  const requiredPredicates: T[] = [];
  const effects = [...root.effects].map(([key, mask]) => ({ key, mask, requiredPredicates: [] as T[], possiblePredicates: [] as T[] }));
  for (let index = 0; index < values.length; index++) {
    if (!charge(1, 0)) return incomplete("Source-history required-guard query exhausted its shared allowance");
    const bit = 1n << BigInt(index);
    if ((root.required & bit) !== 0n) {
      if (!charge(0, 1)) return incomplete("Source-history required-guard values exhausted their shared allowance");
      requiredPredicates.push(values[index]);
    }
    for (const effect of effects) {
      if (!charge(1, 0)) return incomplete("Source-history per-effect guard query exhausted its shared allowance");
      if ((effect.mask.required & bit) !== 0n) {
        if (!charge(0, 1)) return incomplete("Source-history per-effect required values exhausted their shared allowance");
        effect.requiredPredicates.push(values[index]);
      }
      if ((effect.mask.possible & bit) !== 0n) {
        if (!charge(0, 1)) return incomplete("Source-history per-effect possible values exhausted their shared allowance");
        effect.possiblePredicates.push(values[index]);
      }
    }
  }
  return { status: "available", facts: { possible, requiredPredicates,
    effects: effects.map(({ mask: _, ...effect }) => effect) } };
}
