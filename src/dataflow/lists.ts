import { Region, mayOverlap, regionKey } from "./regions.js";

/** Revision-specific query identity shared with consumers. Unknown selectors
 * cannot establish must-equality merely by naming a wildcard storage region. */
export function listQueryIdentity(region: Region, revision: number, query: string): string | undefined {
  return region.path.includes("key:*") ? undefined : `list:${regionKey(region)}:${revision}:${query}`;
}

interface Cell<Value> {
  value: Value;
  previousStructure: Value;
}

type Tail = "empty" | "unknown" | "nonempty";

interface ListState<Value> {
  region: Region;
  prefix: Cell<Value>[];
  tail: Tail;
  structure: Value;
}

export interface ListView<Value> {
  head: Value | undefined;
  empty: boolean | undefined;
  length: number | undefined;
  structure: Value;
}

export interface ListFactsSnapshot<Value> {
  exhausted: boolean;
  lists: { region: Region; prefix: { value: Value; previousStructure: Value }[]; tail: Tail; structure: Value }[];
}

/**
 * A finite known prefix over an empty, unknown or proven nonempty tail. Payloads are
 * immutable by contract, like the analyzer's other AbstractValues. Container
 * snapshots and clones are detached; no operation mutates a retained payload.
 * Popping a nonempty unknown tail consumes that proof without inventing a head.
 * False means unmodeled, not abort. Facts assume well-formed typed List storage.
 */
export class ListFacts<Value> {
  private readonly lists = new Map<string, ListState<Value>>();
  private cells = 0;
  exhausted = false;

  constructor(readonly limit = 256) {
    this.limit = Number.isFinite(limit) ? Math.max(0, Math.floor(limit)) : 0;
  }

  clone(): ListFacts<Value> {
    const result = new ListFacts<Value>(this.limit);
    result.cells = this.cells;
    result.exhausted = this.exhausted;
    for (const [key, state] of this.lists) result.lists.set(key, {
      region: { ...state.region, path: [...state.region.path] }, prefix: state.prefix.map(cell => ({ ...cell })),
      tail: state.tail, structure: state.structure,
    });
    return result;
  }

  view(region: Region): ListView<Value> | undefined {
    if (region.path.includes("key:*")) return undefined;
    const state = this.lists.get(regionKey(region));
    if (!state) return undefined;
    return {
      head: state.prefix[0]?.value,
      empty: state.prefix.length || state.tail === "nonempty" ? false : state.tail === "empty" ? true : undefined,
      length: state.tail === "empty" ? state.prefix.length : undefined,
      structure: state.structure,
    };
  }

  /** The caller must check the query's storage revision before refining. */
  assumeEmpty(region: Region, empty: boolean, unknownStructure: Value): boolean {
    if (region.path.includes("key:*")) return true;
    const known = this.view(region)?.empty;
    // Nonemptiness of a known prefix says nothing about its tail.
    if (known !== undefined) return known === empty;
    const state = this.lists.get(regionKey(region)) ?? this.create(region, "unknown", unknownStructure);
    if (state) state.tail = empty ? "empty" : "nonempty";
    return true;
  }

  reset(region: Region, structure: Value): void {
    this.invalidateWrite(region);
    if (!region.path.includes("key:*")) this.create(region, "empty", structure);
  }

  push(region: Region, value: Value, structure: Value, unknownStructure: Value): void {
    if (region.path.includes("key:*")) { this.invalidateWrite(region); return; }
    this.forgetOverlaps(region, true);
    const state = this.lists.get(regionKey(region)) ?? this.create(region, "unknown", unknownStructure);
    if (!state) return;
    if (this.cells >= this.limit) {
      this.exhausted = true;
      this.invalidateWrite(region);
      return;
    }
    state.prefix.unshift({ value, previousStructure: state.structure });
    state.structure = structure;
    this.cells++;
  }

  pop(region: Region, updateStructure: (previous: Value) => Value = value => value): boolean {
    if (region.path.includes("key:*")) { this.invalidateWrite(region); return false; }
    this.forgetOverlaps(region, true);
    const state = this.lists.get(regionKey(region));
    const first = state?.prefix.shift();
    if (!state || !first && state.tail !== "nonempty") { this.invalidateWrite(region); return false; }
    if (first) {
      this.cells--;
      state.structure = updateStructure(first.previousStructure);
    } else {
      state.tail = "unknown";
      state.structure = updateStructure(state.structure);
    }
    return true;
  }

  invalidateWrite(region: Region): void {
    this.forgetOverlaps(region, false);
  }

  private forgetOverlaps(region: Region, preserveExact: boolean): void {
    const exact = preserveExact ? regionKey(region) : undefined;
    for (const [key, state] of this.lists) if (key !== exact && state.region.path.length >= region.path.length && mayOverlap(region, state.region)) {
      this.cells -= state.prefix.length;
      this.lists.delete(key);
    }
  }

  visitValues(visit: (value: Value) => void): void {
    for (const state of this.lists.values()) {
      visit(state.structure);
      for (const cell of state.prefix) { visit(cell.value); visit(cell.previousStructure); }
    }
  }

  snapshot(): ListFactsSnapshot<Value> {
    return {
      exhausted: this.exhausted,
      lists: [...this.lists].sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0).map(([, state]) => ({
        region: { ...state.region, path: [...state.region.path] }, prefix: state.prefix.map(cell => ({ ...cell })),
        tail: state.tail, structure: state.structure,
      })),
    };
  }

  private create(region: Region, tail: Tail, structure: Value): ListState<Value> | undefined {
    if (this.lists.size >= this.limit) { this.exhausted = true; return undefined; }
    const state = { region: { ...region, path: [...region.path] }, prefix: [], tail, structure };
    this.lists.set(regionKey(region), state);
    return state;
  }
}
