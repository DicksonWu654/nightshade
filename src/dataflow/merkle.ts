import { mayOverlap, regionKey, type Region } from "./regions.js";

interface MonotonicTruth { trueSince?: number; falseThrough?: number }

function truthAt(fact: MonotonicTruth, epoch: number): boolean | undefined {
  if (fact.falseThrough !== undefined && epoch <= fact.falseThrough) return false;
  if (fact.trueSince !== undefined && epoch >= fact.trueSince) return true;
  return undefined;
}

function assumeTruth(fact: MonotonicTruth, epoch: number, truth: boolean): boolean {
  const known = truthAt(fact, epoch);
  if (known !== undefined && known !== truth) return false;
  if (truth) fact.trueSince = Math.min(fact.trueSince ?? epoch, epoch);
  else fact.falseThrough = Math.max(fact.falseThrough ?? epoch, epoch);
  return true;
}

interface Tree<Value> {
  region: Region;
  /** Explicitly cleared history at this exact receiver. Unknown entry storage
   * and fresh bookkeeping epochs do not establish this certificate. */
  currentOnly?: true;
  rootEpoch: number;
  capacityEpoch: number;
  capacityStart: number;
  capacity: MonotonicTruth;
  historyEpoch: number;
  next?: number;
  minimumNext: number;
  full?: boolean;
  roots: Map<string, MonotonicTruth>;
  structure: Value;
}

/** Finite root-query facts and first-free indices; payload hashes stay abstract. */
export class MerkleFacts<Value> {
  private readonly trees = new Map<string, Tree<Value>>();
  exhausted = false;
  private nextEpoch = 0;
  constructor(readonly limit = 256) {}

  clone(): MerkleFacts<Value> {
    const result = new MerkleFacts<Value>(this.limit);
    result.exhausted = this.exhausted;
    result.nextEpoch = this.nextEpoch;
    for (const [key, tree] of this.trees) result.trees.set(key, { ...tree, region: { ...tree.region, path: [...tree.region.path] }, capacity: { ...tree.capacity }, roots: new Map([...tree.roots].map(([key, fact]) => [key, { ...fact }])) });
    return result;
  }

  view(region: Region): Tree<Value> | undefined {
    return region.path.includes("key:*") ? undefined : this.trees.get(regionKey(region));
  }

  currentOnly(region: Region): boolean { return this.view(region)?.currentOnly === true; }

  reset(region: Region, structure: Value): void {
    this.invalidateWrite(region);
    const tree = this.ensure(region, structure);
    if (tree) { tree.currentOnly = true; tree.next = 0; tree.full = false; assumeTruth(tree.capacity, tree.capacityEpoch, false); }
  }

  queryEpoch(region: Region, structure: Value, full: boolean): number | undefined {
    const tree = this.ensure(region, structure);
    return full ? tree?.capacityEpoch : tree?.rootEpoch;
  }

  root(region: Region, key?: string, exclusive = false, epoch = this.view(region)?.rootEpoch): boolean | undefined {
    if (key === undefined) return undefined;
    const roots = this.view(region)?.roots;
    if (epoch === undefined) return undefined;
    const fact = roots?.get(key);
    const known = fact && truthAt(fact, epoch);
    if (known !== undefined) return known;
    if (exclusive && key.startsWith("integer:") && [...(roots ?? [])].some(([other, fact]) => truthAt(fact, epoch) === true && other.startsWith("integer:") && other !== key)) return false;
    return undefined;
  }
  full(region: Region): boolean | undefined { return this.view(region)?.full; }

  /** Capacity is monotonic within a tree lifetime. A later proof of space also
   * refutes every earlier full observation, without retaining a query journal. */
  fullAt(region: Region, epoch: number): boolean | undefined {
    const tree = this.view(region);
    if (!tree || epoch < tree.capacityStart || epoch > tree.capacityEpoch) return undefined;
    return truthAt(tree.capacity, epoch);
  }

  assumeFullAt(region: Region, epoch: number, truth: boolean): boolean {
    const tree = this.view(region);
    if (!tree || epoch < tree.capacityStart || epoch > tree.capacityEpoch) return true;
    if (!assumeTruth(tree.capacity, epoch, truth)) return false;
    tree.full = truthAt(tree.capacity, tree.capacityEpoch);
    return true;
  }

  assumeRoot(region: Region, key: string | undefined, truth: boolean, structure: Value, exclusive: boolean | undefined, epoch: number): boolean {
    const known = this.root(region, key, exclusive, epoch);
    if (known !== undefined) return known === truth;
    if (key === undefined) return true;
    const tree = this.ensure(region, structure);
    if (tree) {
      if (!tree.roots.has(key) && this.rootCount() >= this.limit) { this.exhausted = true; return true; }
      const fact = tree.roots.get(key) ?? {};
      if (!assumeTruth(fact, epoch, truth)) return false;
      tree.roots.set(key, fact);
    }
    return true;
  }

  /** False means a definite capacity/index failure, not an unsupported transfer. */
  insert(region: Region, capacity: number, historic: boolean, indexed: boolean, index: bigint | undefined, structure: Value): boolean {
    if (indexed && index !== undefined && (index < 0n || index >= BigInt(capacity))) return false;
    const current = this.view(region);
    if (!indexed && current?.full === true) return false;
    if (region.path.includes("key:*")) { this.invalidateWrite(region); return true; }
    this.forgetOverlaps(region, true);
    const tree = this.ensure(region, structure);
    if (!tree) return true;
    // Inserting into a historic tree can retain its previous root. Forget this
    // proof for every insertion form; ordinary trees are exclusive by type.
    delete tree.currentOnly;
    tree.structure = structure;
    tree.rootEpoch = this.nextEpoch++;
    // An indexed replacement below the last slot cannot change isFull, even
    // when the previous first-free index is unknown. Appends can fill the tree.
    if (!indexed || index === undefined || index === BigInt(capacity - 1)) tree.capacityEpoch = tree.rootEpoch;
    if (!historic) tree.roots.clear();
    tree.minimumNext = indexed ? Math.max(tree.minimumNext, index === undefined ? 1 : Number(index) + 1) : tree.minimumNext + 1;
    const next = indexed ? index === undefined ? undefined : Number(index) + 1 : tree.next === undefined ? undefined : tree.next + 1;
    if (next === capacity || tree.minimumNext === capacity || tree.full === true) { tree.next = capacity; tree.full = true; }
    else if (next !== undefined && tree.next !== undefined) {
      tree.next = Math.max(tree.next, next); tree.full = tree.next === capacity;
    } else {
      tree.next = undefined;
      // Replacing an in-bounds index below the last slot preserves !full.
      if (!(indexed && next !== undefined && tree.full === false)) tree.full = undefined;
    }
    if (tree.full !== undefined && !assumeTruth(tree.capacity, tree.capacityEpoch, tree.full)) return false;
    return true;
  }

  resetHistory(region: Region, structure: Value): void {
    if (region.path.includes("key:*")) { this.invalidateWrite(region); return; }
    this.forgetOverlaps(region, true);
    const tree = this.ensure(region, structure);
    if (tree) { tree.currentOnly = true; tree.roots.clear(); tree.historyEpoch = tree.rootEpoch = this.nextEpoch++; }
  }

  invalidateWrite(region: Region): void {
    this.forgetOverlaps(region, false);
  }

  private forgetOverlaps(region: Region, preserveExact: boolean): void {
    const exact = preserveExact ? regionKey(region) : undefined;
    for (const [key, tree] of this.trees) if (key !== exact && tree.region.path.length >= region.path.length && mayOverlap(region, tree.region)) this.trees.delete(key);
  }

  visitValues(visit: (value: Value) => void): void { for (const tree of this.trees.values()) visit(tree.structure); }

  snapshot() {
    return { exhausted: this.exhausted, nextEpoch: this.nextEpoch, trees: [...this.trees].sort(([a], [b]) => a.localeCompare(b)).map(([, tree]) => ({ ...tree, roots: [...tree.roots].sort(([a], [b]) => a.localeCompare(b)) })) };
  }

  private rootCount(): number { return [...this.trees.values()].reduce((total, tree) => total + tree.roots.size, 0); }
  private ensure(region: Region, structure: Value): Tree<Value> | undefined {
    if (region.path.includes("key:*")) return undefined;
    const key = regionKey(region), existing = this.trees.get(key);
    if (existing) return existing;
    if (this.trees.size >= this.limit) { this.exhausted = true; return undefined; }
    const epoch = this.nextEpoch++;
    const tree: Tree<Value> = { region: { ...region, path: [...region.path] }, rootEpoch: epoch, capacityEpoch: epoch, capacityStart: epoch, capacity: {}, historyEpoch: epoch, minimumNext: 0, roots: new Map<string, MonotonicTruth>(), structure };
    this.trees.set(key, tree); return tree;
  }
}
