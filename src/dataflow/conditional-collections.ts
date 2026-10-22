import { CollectionFacts } from "./collections.js";
import { ConditionalStateGraph, type ConditionalTerm } from "./conditional-state.js";
import type { Region } from "./regions.js";

/** A conditional current-membership domain for the default engine's forthcoming
 * state join. The leaves and transfers use the ordinary collection semantics.
 * An eager intersection is not a successful history; selection must also satisfy
 * every intervening assumption/lookup. No source predicates are solved here.
 */
type Operation =
  | { kind: "reset" | "invalidate"; region: Region }
  | { kind: "insert" | "remove" | "lookup"; region: Region; key: string | undefined }
  | { kind: "member"; region: Region; key: string | undefined; present: boolean }
  | { kind: "empty"; region: Region; empty: boolean };

type Store = CollectionFacts | undefined; // undefined is a rejected alternative.
/** Opaque handles cannot be mixed between construction arenas. */
export type ConditionalCollectionState = ConditionalTerm<Store>;
export type CollectionProjection =
  | { status: "selected"; facts: CollectionFacts; work: number }
  | { status: "rejected"; work: number }
  | { status: "incomplete"; reason: string; work: number };
export type CommonCollectionView =
  | { status: "available"; facts: CollectionFacts }
  | { status: "all-rejected" }
  | { status: "incomplete"; reason: string };

function transfer(previous: Store, operation: Operation): Store {
  if (!previous) return;
  const facts = previous.clone();
  switch (operation.kind) {
    case "reset": facts.reset(operation.region); break;
    case "invalidate": facts.invalidateWrite(operation.region); break;
    case "insert": facts.insert(operation.region, operation.key); break;
    case "remove": facts.remove(operation.region, operation.key); break;
    case "member": if (!facts.assumeMember(operation.region, operation.key, operation.present)) return; break;
    case "empty": if (!facts.assumeEmpty(operation.region, operation.empty)) return; break;
    case "lookup": if (!facts.assumeMember(operation.region, operation.key, true)) return; break;
    default: throw new Error("Unsupported conditional collection operation");
  }
  return facts;
}

/** Immutable graph nodes, mutable caller-owned handles. A caller supplies the
 * existing shared step/value charger; there is no separate allowance that can
 * silently increase an entry's budget. Collection fact limits remain unchanged.
 */
export class ConditionalCollections {
  private readonly graph: ConditionalStateGraph;
  constructor(charge: (work: number, values: number) => boolean) { this.graph = new ConditionalStateGraph(charge); }

  get incompleteReason(): string | undefined { return this.graph.incompleteReason; }

  private checked(facts: Store): Store {
    if (facts?.exhausted) this.graph.refuse("Conditional collection fact capacity exhausted");
    return facts;
  }

  initial(facts: CollectionFacts): ConditionalCollectionState | undefined {
    return this.graph.atom(this.checked(facts.clone()));
  }

  apply(state: ConditionalCollectionState, operation: Operation): ConditionalCollectionState | undefined {
    // The caller cannot rewrite a retained address after creating a transfer.
    const saved = { ...operation, region: { ...operation.region, path: [...operation.region.path] } } as Operation;
    return this.graph.apply([state], previous => this.checked(transfer(previous, saved)));
  }

  choose(selector: string, yes: ConditionalCollectionState, no: ConditionalCollectionState): ConditionalCollectionState | undefined {
    // Keep rejected arms: deleting one would lose its selector restriction.
    return this.graph.choose(selector, yes, no,
      (left, right) => this.checked(left && right ? left.common(right) : left ?? right));
  }

  /** Detached conservative facts, never proof of successful completion. */
  common(state: ConditionalCollectionState): CommonCollectionView {
    const view = this.graph.common(state, facts => facts?.clone());
    if (view.status === "incomplete") return view;
    return view.value ? { status: "available", facts: view.value } : { status: "all-rejected" };
  }

  select(state: ConditionalCollectionState, decisions: ReadonlyMap<string, boolean>, maxWork: number): CollectionProjection {
    const result = this.graph.select(state, decisions, maxWork, facts => facts?.clone());
    if (result.status === "incomplete") return result;
    return result.value ? { status: "selected", facts: result.value, work: result.work } : { status: "rejected", work: result.work };
  }
}
