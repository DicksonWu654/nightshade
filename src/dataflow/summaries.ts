import type { Expr, Span } from "../model.js";
import type { AbstractValue, PublicSink } from "./index.js";
import type { Region } from "./regions.js";

export type MutationEffect =
  | { kind: "assignment"; region: Region; value: AbstractValue; location: Span }
  | { kind: "ledger-operation"; region: Region; expression: Expr; args: AbstractValue[] }
  | { kind: "completion"; circuit: string };

export type ReadonlyEffect =
  | { kind: "completion"; circuit: string }
  | { kind: "public-sink"; sink: Omit<PublicSink, "callPath"> };

export interface RecordedEffect<Effect = MutationEffect> {
  effect: Effect;
  callSuffix: string[];
  /** Nested sites only; the summary's own invocation site belongs to its caller. */
  locationSuffix?: Span[];
}

export interface MutationSummary {
  value: AbstractValue;
  effects: RecordedEffect[];
}

export interface ReadonlySummary {
  value: AbstractValue;
  effects: RecordedEffect<ReadonlyEffect>[];
}

export interface Recording {
  callerDepth: number;
  mode: "mutation" | "readonly";
  effects: RecordedEffect<MutationEffect | ReadonlyEffect>[];
  complete: boolean;
}

export class EffectRecorder {
  private readonly active: Recording[] = [];

  begin(callerDepth: number, mode: Recording["mode"] = "mutation"): Recording {
    const recording = { callerDepth, mode, effects: [] as RecordedEffect<MutationEffect | ReadonlyEffect>[], complete: true };
    this.active.push(recording);
    return recording;
  }

  end(recording: Recording): void {
    if (this.active.pop() !== recording) throw new Error("Unbalanced summary recording");
  }

  invalidateActive(): void {
    for (const recording of this.active) { recording.complete = false; recording.effects.length = 0; }
  }

  record(effect: MutationEffect | ReadonlyEffect, stack: string[], callSites: Span[] = []): void {
    for (const recording of this.active) {
      if (recording.mode === "mutation" && effect.kind === "public-sink") continue;
      if (!recording.complete) continue;
      // Mutations or constraining ledger operations must never disappear from a
      // readonly summary, even if eligibility becomes less restrictive later.
      const unexpected = recording.mode === "readonly" && effect.kind !== "completion" && effect.kind !== "public-sink";
      if (unexpected || recording.effects.length >= 256) {
        recording.complete = false;
        recording.effects.length = 0;
      } else recording.effects.push({ effect, callSuffix: stack.slice(recording.callerDepth), locationSuffix: callSites.slice(recording.callerDepth + 1) });
    }
  }
}

/** Per-path journals keep mutually exclusive scalar effects separate. */
export type BranchMutationEffect =
  | { kind: "node"; node: number; previous: number }
  | { kind: "choice"; node: number; value: AbstractValue; selected: boolean; location: Span; until: number; owner: string }
  | Extract<MutationEffect, { kind: "assignment" | "completion" }>;
export interface BranchJournalNode {
  readonly effect: BranchMutationEffect;
  readonly previous: BranchJournalNode | null;
}
export interface BranchJournalCursor {
  readonly recording: BranchRecording;
  readonly tail: BranchJournalNode | null;
}
export interface BranchMutationSummary {
  readonly alternatives: readonly { readonly tail: BranchJournalNode; readonly value: AbstractValue }[];
  readonly effects: number;
}

/**
 * Cursors and journal links are immutable; scalar abstract operands follow the
 * engine's ordinary immutable-value contract. No State or guard/storage snapshot
 * is retained here. Saturation invalidates the entire candidate, never one arm.
 */
export class BranchRecording {
  private retained = 0;
  private valid = true;
  private readonly choices = new Set<boolean>();
  constructor(private readonly owner?: string, private readonly branch?: number) {}
  get complete(): boolean { return this.valid; }
  get effects(): number { return this.retained; }
  get observedChoices(): number { return this.choices.size; }
  begin(): BranchJournalCursor { return Object.freeze({ recording: this, tail: null }); }
  invalidate(): void { this.valid = false; }
  append(cursor: BranchJournalCursor, effect: BranchMutationEffect): BranchJournalCursor {
    if (cursor.recording !== this || !this.valid || this.retained >= 256) { this.invalidate(); return cursor; }
    if (!["node", "choice", "assignment", "completion"].includes(effect.kind) || effect.kind === "choice" && (this.owner !== undefined && effect.owner !== this.owner || this.branch !== undefined && effect.node !== this.branch) || effect.kind === "completion" && this.owner !== undefined && effect.circuit !== this.owner) { this.invalidate(); return cursor; }
    if (effect.kind === "choice") this.choices.add(effect.selected);
    this.retained++;
    return Object.freeze({ recording: this, tail: Object.freeze({ effect: Object.freeze(effect), previous: cursor.tail }) });
  }
}

/** Bounded transient expansion preserving shared-node identity for prefix replay. */
export function branchJournalNodes(tail: BranchJournalNode): readonly BranchJournalNode[] | undefined {
  const result: BranchJournalNode[] = [];
  const seen = new Set<BranchJournalNode>();
  let node: BranchJournalNode | null = tail;
  while (node) {
    if (result.length >= 256 || seen.has(node)) return undefined;
    seen.add(node); result.push(node); node = node.previous;
  }
  return result.reverse();
}

export function branchJournalEvents(tail: BranchJournalNode): readonly BranchMutationEffect[] | undefined {
  return branchJournalNodes(tail)?.map(node => node.effect);
}
