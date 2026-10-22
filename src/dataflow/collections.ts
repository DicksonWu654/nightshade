import { Region, mayOverlap, regionFromKey, regionKey } from "./regions.js";

interface CollectionState {
  region: Region;
  defaultMember: boolean | undefined;
  members: Map<string, boolean | undefined>;
  exactSize: number | undefined;
  upperBound?: number;
}

export interface CollectionFactsSnapshot {
  exhausted: boolean;
  collections: {
    region: { root: string; path: string[] };
    defaultMember: boolean | null;
    members: { key: string; present: boolean | null }[];
    size: number | null;
    upperBound?: number | null;
  }[];
}

function hasWildcard(region: Region): boolean {
  return region.path.includes("key:*");
}

/** Immutable identities are useful for correlating repeated dynamic operands,
 * but they are still may-aliases of every concrete key in the collection. */
function mayAliasKey(first: string, second: string): boolean {
  return first === second || first.startsWith("identity:") || second.startsWith("identity:");
}

function possibleDescendant(ancestor: Region, candidate: Region): boolean {
  return candidate.path.length >= ancestor.path.length && mayOverlap(ancestor, candidate);
}

export class CollectionFacts {
  private readonly collections = new Map<string, CollectionState>();
  private keyEntries = 0;
  exhausted = false;

  constructor(readonly limit = 256, readonly trackCardinality = false) {
    this.limit = Number.isFinite(limit) ? Math.max(0, Math.floor(limit)) : 0;
  }

  clone(): CollectionFacts {
    const result = new CollectionFacts(this.limit, this.trackCardinality);
    result.exhausted = this.exhausted;
    result.keyEntries = this.keyEntries;
    for (const [key, state] of this.collections) result.collections.set(key, {
      region: { ...state.region, path: [...state.region.path] },
      defaultMember: state.defaultMember,
      members: new Map(state.members),
      exactSize: state.exactSize,
      ...(this.trackCardinality ? { upperBound: state.upperBound } : {}),
    });
    return result;
  }

  /** Facts valid in both current stores. This is only the eager must-view of a
   * conditional store: callers must retain the original stores with their
   * selector to recover a successful history. It is not a union of effects or
   * permission to replace a selected store with this intersection.
   */
  common(other: CollectionFacts): CollectionFacts {
    const result = new CollectionFacts(Math.min(this.limit, other.limit), this.trackCardinality && other.trackCardinality);
    result.exhausted = this.exhausted || other.exhausted;
    for (const [key, left] of this.collections) {
      const right = other.collections.get(key);
      if (!right) continue; // An unobserved receiver is unknown, never empty.
      const fallback = left.defaultMember === right.defaultMember ? left.defaultMember : undefined;
      const size = left.exactSize === right.exactSize ? left.exactSize : undefined;
      const state = result.createState(left.region, fallback, size);
      if (!state) break;
      if (result.trackCardinality) state.upperBound = left.upperBound === undefined || right.upperBound === undefined ? undefined : Math.max(left.upperBound, right.upperBound);
      const common = [...new Set([...left.members.keys(), ...right.members.keys()])].sort().map(memberKey => {
        const a = this.membership(left, memberKey), b = other.membership(right, memberKey);
        return [memberKey, a === b ? a : undefined] as const;
      });
      // First retain exceptions, including unknown may-alias identities. Only
      // then can a fact equal to the fallback be safely omitted: a later alias
      // exception must not erase an explicit fact agreed by both stores.
      for (const exception of [true, false]) {
        for (const [memberKey, present] of common) {
          if ((present !== fallback) !== exception) continue;
          if (!result.setMembership(state, memberKey, present)) break;
        }
        // setMembership discards an over-budget receiver as a whole; retaining
        // its default with only some exceptions would invent absence facts.
        if (!result.collections.has(key)) break;
      }
    }
    return result;
  }

  member(region: Region, key: string | undefined): boolean | undefined {
    if (hasWildcard(region)) return undefined;
    const state = this.collections.get(regionKey(region));
    if (!state) return undefined;
    if (key === undefined) return state.exactSize === 0 ? false : undefined;
    return this.membership(state, key);
  }

  size(region: Region): number | undefined {
    return hasWildcard(region) ? undefined : this.collections.get(regionKey(region))?.exactSize;
  }

  upperBound(region: Region): number | undefined {
    return this.trackCardinality && !hasWildcard(region) ? this.collections.get(regionKey(region))?.upperBound : undefined;
  }

  isEmpty(region: Region): boolean | undefined {
    if (hasWildcard(region)) return undefined;
    const state = this.collections.get(regionKey(region));
    if (!state) return undefined;
    if (state.exactSize !== undefined) return state.exactSize === 0;
    return [...state.members.values()].some(present => present === true) ? false : undefined;
  }

  assumeMember(region: Region, key: string | undefined, present: boolean): boolean {
    if (hasWildcard(region)) return true;
    if (key === undefined) return !(present && this.isEmpty(region) === true);
    const known = this.member(region, key);
    if (known !== undefined) return known === present;
    const state = this.stateForMutation(region);
    if (state) this.setMembership(state, key, present);
    return true;
  }

  assumeEmpty(region: Region, empty: boolean): boolean {
    if (hasWildcard(region)) return true;
    const known = this.isEmpty(region);
    if (known !== undefined) return known === empty;
    if (!empty) return true;
    const state = this.collections.get(regionKey(region)) ?? this.createState(region, false, 0);
    if (!state) return true;
    this.keyEntries -= state.members.size;
    state.members.clear();
    state.defaultMember = false;
    state.exactSize = 0;
    if (this.trackCardinality) state.upperBound = 0;
    return true;
  }

  reset(region: Region): void {
    this.invalidateWrite(region);
    if (hasWildcard(region)) return;
    const state = this.createState(region, false, 0);
    if (!state) this.exhausted = true;
  }

  insert(region: Region, key: string | undefined): void {
    this.invalidateEntry(region, key);
    for (const state of this.matchingReceivers(region)) if (hasWildcard(region) || regionKey(state.region) !== regionKey(region)) this.weakInsert(state, key);
    if (hasWildcard(region)) return;
    if (key === undefined) {
      const state = this.collections.get(regionKey(region));
      if (state) this.weakInsert(state, key);
      return;
    }
    const state = this.stateForMutation(region);
    if (!state) return;
    this.strongInsert(state, key);
  }

  remove(region: Region, key: string | undefined): void {
    this.invalidateEntry(region, key);
    for (const state of this.matchingReceivers(region)) if (hasWildcard(region) || regionKey(state.region) !== regionKey(region)) this.weakRemove(state, key);
    if (hasWildcard(region)) return;
    if (key === undefined) {
      const state = this.collections.get(regionKey(region));
      if (state) this.weakRemove(state, key);
      return;
    }
    const state = this.stateForMutation(region);
    if (!state) return;
    this.strongRemove(state, key);
  }

  invalidateWrite(region: Region): void {
    for (const [key, state] of [...this.collections]) if (possibleDescendant(region, state.region)) this.deleteState(key, state);
  }

  snapshot(): CollectionFactsSnapshot {
    return {
      exhausted: this.exhausted,
      collections: [...this.collections.entries()].sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0).map(([key, state]) => ({
        region: (() => {
          const restored = regionFromKey(key, state.region.type);
          return { root: restored.root, path: restored.path };
        })(),
        defaultMember: state.defaultMember ?? null,
        members: [...state.members.entries()].sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0).map(([memberKey, present]) => ({ key: memberKey, present: present ?? null })),
        size: state.exactSize ?? null,
        ...(this.trackCardinality ? { upperBound: state.upperBound ?? null } : {}),
      })),
    };
  }

  private stateForMutation(region: Region): CollectionState | undefined {
    return this.collections.get(regionKey(region)) ?? this.createState(region, undefined, undefined);
  }

  private createState(region: Region, defaultMember: boolean | undefined, exactSize: number | undefined): CollectionState | undefined {
    const key = regionKey(region);
    const existing = this.collections.get(key);
    if (existing) return existing;
    if (this.collections.size >= this.limit) {
      this.exhausted = true;
      return undefined;
    }
    const state = { region: { ...region, path: [...region.path] }, defaultMember, members: new Map<string, boolean | undefined>(), exactSize, ...(this.trackCardinality ? { upperBound: exactSize } : {}) };
    this.collections.set(key, state);
    return state;
  }

  private membership(state: CollectionState, key: string): boolean | undefined {
    if (state.members.has(key)) return state.members.get(key);
    // The default only describes keys outside tracked exceptions. A dynamic
    // identity can denote a literal key or another identity in either direction.
    if (this.hasAliasException(state, key)) return undefined;
    return state.defaultMember;
  }

  private hasAliasException(state: CollectionState, key: string): boolean {
    return [...state.members].some(([other, present]) => other !== key && mayAliasKey(key, other) && present !== state.defaultMember);
  }

  private setMembership(state: CollectionState, key: string, present: boolean | undefined): boolean {
    if (present === state.defaultMember && !this.hasAliasException(state, key)) {
      if (state.members.delete(key)) this.keyEntries--;
      return true;
    }
    if (state.members.has(key)) {
      state.members.set(key, present);
      return true;
    }
    if (this.keyEntries >= this.limit) {
      this.exhausted = true;
      this.deleteState(regionKey(state.region), state);
      return false;
    }
    state.members.set(key, present);
    this.keyEntries++;
    return true;
  }

  private strongInsert(state: CollectionState, key: string): void {
    const previous = this.membership(state, key);
    if (this.trackCardinality && state.upperBound !== undefined && previous !== true) state.upperBound = Number.isSafeInteger(state.upperBound + 1) ? state.upperBound + 1 : undefined;
    this.weakenAliases(state, key, true);
    if (!this.setMembership(state, key, true)) return;
    if (previous === false && state.exactSize !== undefined) state.exactSize++;
    else if (previous === undefined) state.exactSize = undefined;
  }

  private strongRemove(state: CollectionState, key: string): void {
    const previous = this.membership(state, key);
    this.weakenAliases(state, key, false);
    if (!this.setMembership(state, key, false)) return;
    if (previous === true && state.exactSize !== undefined) state.exactSize--;
    else if (previous === undefined) state.exactSize = undefined;
  }

  private weakenAliases(state: CollectionState, key: string, inserted: boolean): void {
    // A may-write preserves facts already equal to the new membership and
    // weakens only opposing facts. This applies to literal and dynamic writes.
    for (const [memberKey, present] of [...state.members]) {
      if (memberKey !== key && mayAliasKey(memberKey, key) && present === !inserted) this.setMembership(state, memberKey, undefined);
    }
  }

  private weakInsert(state: CollectionState, key: string | undefined): void {
    if (this.trackCardinality && state.upperBound !== undefined) state.upperBound = Number.isSafeInteger(state.upperBound + 1) ? state.upperBound + 1 : undefined;
    state.exactSize = undefined;
    if (key !== undefined) {
      this.weakenAliases(state, key, true);
      if (this.membership(state, key) !== true) this.setMembership(state, key, undefined);
      return;
    }
    state.defaultMember = undefined;
    for (const [memberKey, present] of [...state.members]) if (present !== true) {
      state.members.delete(memberKey);
      this.keyEntries--;
    }
  }

  private weakRemove(state: CollectionState, key: string | undefined): void {
    if (state.exactSize === 0) return;
    state.exactSize = undefined;
    if (key !== undefined) {
      this.weakenAliases(state, key, false);
      if (this.membership(state, key) !== false) this.setMembership(state, key, undefined);
      return;
    }
    for (const [memberKey, present] of [...state.members]) if (present === true) this.setMembership(state, memberKey, undefined);
  }

  private matchingReceivers(region: Region): CollectionState[] {
    return [...this.collections.values()].filter(state => state.region.path.length === region.path.length && mayOverlap(region, state.region));
  }

  private invalidateEntry(region: Region, key: string | undefined): void {
    this.invalidateWrite({ root: region.root, path: [...region.path, `key:${key ?? "*"}`], type: "unknown" });
  }

  private deleteState(key: string, state: CollectionState): void {
    if (!this.collections.delete(key)) return;
    this.keyEntries -= state.members.size;
  }
}
