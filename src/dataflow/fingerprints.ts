import { createHash } from "node:crypto";
import type { AbstractValue, Flow } from "./index.js";

/** Structural-key acceleration. State keys ignore diagnostic traces; summary
 * keys opt in to retaining them. Retained abstract
 * values (including nested provenance, sets and predicates) are immutable during
 * analysis. Mutable state containers must never enter this cache. Create a fresh
 * instance for each synchronous analysis; callers may mutate returned facts. */
export class ValueFingerprints {
  private readonly values = new WeakMap<AbstractValue, string>();
  private readonly records = new WeakMap<object, string>();
  private readonly unguardedRecords = new WeakMap<object, string>();
  private readonly flows = new WeakMap<Flow, string>();
  private readonly roots = new WeakMap<AbstractValue, string>();
  private readonly flowVariants = new WeakMap<Flow["source"], Map<string, string>>();

  constructor(private readonly includeTraces = false) {}

  key(payload: unknown): string {
    if (payload && typeof payload === "object" && "flows" in payload && Array.isArray(payload.flows)
      && "ledger" in payload && payload.ledger instanceof Set) {
      const value = payload as AbstractValue;
      let key = this.roots.get(value);
      if (key === undefined) this.roots.set(value, key = this.digest(value));
      return key;
    }
    return this.digest(payload);
  }

  /** Flow and ordered write/sink records are detached when appended and immutable until
   * analysis returns. Clone/replay shares them, but never their mutable history
   * arrays. Only typed flow/event positions may use these digests;
   * arbitrary objects and state containers must still use key(). */
  record(payload: object, withoutGuards = false): string {
    const cache = withoutGuards ? this.unguardedRecords : this.records;
    let key = cache.get(payload);
    if (key === undefined) {
      const { guards, ...unguarded } = payload as object & { guards?: unknown };
      key = this.key(withoutGuards ? unguarded : payload);
      cache.set(payload, key);
    }
    return key;
  }

  private flow(flow: Flow): string {
    let key = this.flows.get(flow);
    if (key === undefined) {
      // Steps create new Flow objects whose only change is diagnostic trace.
      // Reuse that normalized shape without hashing the same source/form again.
      // Preserve property order and decline unfamiliar metadata rather than
      // silently dropping a future provenance field.
      const fields = !this.includeTraces ? Object.keys(flow).filter(name => name !== "trace" && flow[name as keyof Flow] !== undefined) : undefined;
      const signature = fields?.every(name => name === "source" || name === "form" || name === "directPreimage")
        ? `${fields.join(",")}:${flow.form}:${flow.directPreimage}` : undefined;
      const variants = signature === undefined ? undefined : this.flowVariants.get(flow.source) ?? new Map<string, string>();
      if (signature !== undefined && variants?.has(signature)) {
        key = variants.get(signature)!;
        this.flows.set(flow, key);
        return key;
      }
      const { trace, ...rest } = flow;
      key = this.key({ ...(this.includeTraces ? flow : rest), source: this.record(flow.source) });
      this.flows.set(flow, key);
      if (signature !== undefined && variants) {
        variants.set(signature, key);
        this.flowVariants.set(flow.source, variants);
      }
    }
    return key;
  }

  private digest(payload: unknown, root?: AbstractValue): string {
    const fingerprints = this;
    const serialized = JSON.stringify(payload, function (key, value) {
      // Ignore only diagnostic trace metadata, never user fields named trace.
      if (!fingerprints.includeTraces && key === "trace" && typeof this.source?.id === "string"
        && (typeof this.form === "string" || typeof this.ledger === "string")) return undefined;
      if (value && Array.isArray(value.flows) && value.ledger instanceof Set
        && !(key === "" && value === root)) {
        let digest = fingerprints.values.get(value);
        if (digest === undefined) {
          digest = fingerprints.digest(value, value);
          fingerprints.values.set(value, digest);
        }
        return ["value", digest];
      }
      // Provenance is repeatedly shared by new value envelopes. These are typed
      // immutable Flow records; keep their complete source/form metadata while
      // normalizing diagnostic traces exactly as for the enclosing value.
      if (key === "flows" && Array.isArray(value) && this.ledger instanceof Set) {
        return ["array", ...value.map(flow => fingerprints.flow(flow))];
      }
      // Tag every original array (and normalized Set). A raw array can never
      // impersonate the value-digest token returned above by the replacer.
      if (value instanceof Set) return ["array", ...[...value].sort()];
      if (Array.isArray(value)) return ["array", ...value];
      return value;
    });
    return createHash("sha256").update(serialized).digest("hex");
  }
}
