import type { AuditedGuidedCampaign } from "./runtime-guided.js";
import { compareRuntimeResults, validateRuntimeResult, type RuntimeCheckResult } from "./runtime-artifacts.js";
import { RuntimeSchedule, sameScheduleData, type RuntimeDecision, type ScheduleOutcome, type ScheduleRow } from "./runtime-schedule.js";

/** Compiled-code changes never excuse observation, feedback or admission drift. */
export function compareGuidedResults(before: RuntimeCheckResult, after: RuntimeCheckResult, originalRow: ScheduleRow, currentRow: ScheduleRow, compareBuild: boolean) {
  const compared = compareRuntimeResults(before, after);
  const semanticFeedback = (result: RuntimeCheckResult) => {
    if (!result.feedback) return null;
    const { compiledJavaScriptSha256: _compiledIdentity, ...feedback } = result.feedback;
    return feedback;
  };
  const sameFeedback = sameScheduleData(semanticFeedback(after), semanticFeedback(before));
  const sameAdmission = sameScheduleData(currentRow.admission, originalRow.admission);
  const sameOutcome = sameScheduleData(currentRow, originalRow);
  return { ...compared, sameFeedback, sameAdmission, sameOutcome,
    matched: compared.sameStatus && compared.sameSignature && compared.sameObservation !== false && (compareBuild || compared.sameCompiledJavaScript !== false)
      && sameFeedback && sameAdmission && sameOutcome };
}

export interface ReplayProposal {
  decision: RuntimeDecision;
  originalDecisionSha256: string;
  originalArtifactSha256: string;
  sameDecision: boolean;
}
export interface ReplayStepResult {
  row: ScheduleRow;
  comparison: ReturnType<typeof compareGuidedResults>;
}

/**
 * Re-derive a schedule from new checked observations against an audited transcript.
 * The caller supplies only results of the fixed owned worker, not an adapter.
 * This state machine itself executes nothing and is not runtime attestation.
 */
export class RuntimeCampaignReplay {
  private readonly saved: AuditedGuidedCampaign;
  private readonly schedule: RuntimeSchedule;
  private pending?: ReplayProposal;
  private completed = 0;
  private measured = 0;
  private proposed = 0;
  private matches: boolean[] = [];
  private artifactHashes = new Map<number, string>();
  private outcome: ScheduleOutcome = { status: "running", category: "running" };
  private finalComparison: { sameCounts: boolean; sameCorpus: boolean; sameScheduleOutcome: boolean | null } | null = null;
  constructor(saved: AuditedGuidedCampaign, readonly compareBuild = false) {
    if (typeof compareBuild !== "boolean" || saved.audit !== "consistent" || saved.executionReplay !== false || saved.steps.length !== saved.manifest.completed || saved.steps.length > 68) throw new Error("Replay requires a bounded audited campaign");
    this.saved = structuredClone(saved);
    this.schedule = new RuntimeSchedule(saved.manifest.options);
    this.finish();
  }

  next(): ReplayProposal | undefined {
    if (this.outcome.status !== "running") return undefined;
    if (this.pending) return structuredClone(this.pending);
    const original = this.saved.steps[this.completed];
    const decision = this.schedule.next();
    if (!decision || !original) throw new Error("Replay schedule stopped without an explicit outcome");
    const normalized = structuredClone(decision);
    let linked = true;
    if (normalized.parent) {
      const parent = normalized.parent;
      linked = parent.ordinal <= this.completed && parent.artifactSha256 === this.artifactHashes.get(parent.ordinal);
      // Current decisions retain NEW artifact links. Only the comparison maps
      // those links into the original artifact namespace, using exact ordinals.
      parent.artifactSha256 = this.saved.steps[parent.ordinal - 1]?.artifactSha256 ?? "missing-parent";
    }
    const sameDecision = linked && sameScheduleData(normalized, original.decision);
    this.pending = { decision, originalDecisionSha256: original.decisionSha256, originalArtifactSha256: original.artifactSha256, sameDecision };
    this.proposed++;
    if (!sameDecision) this.outcome = { status: "incomplete", category: "runtime-replay-decision-drift" };
    return structuredClone(this.pending);
  }

  record(value: unknown, artifactSha256: string): ReplayStepResult {
    if (!this.pending || !this.pending.sameDecision || this.outcome.status !== "running") throw new Error("No executable replay proposal");
    const original = this.saved.steps[this.completed];
    const result = validateRuntimeResult(this.pending.decision.case, value);
    const row = this.schedule.record(result, artifactSha256);
    const { decision: _decision, decisionSha256: _decisionHash, artifact: _artifact, artifactSha256: _artifactHash, ...originalRow } = this.saved.manifest.rows[this.completed];
    const comparison = compareGuidedResults(original.artifact.result, result, originalRow, row, this.compareBuild);
    this.artifactHashes.set(row.ordinal, artifactSha256);
    this.completed++;
    this.measured += result.observation ? 1 : 0;
    this.matches.push(comparison.matched);
    this.pending = undefined;
    // Infrastructure/resource failure stays incomplete even if it also differs
    // from the saved result. Detailed drift remains visible in comparison flags.
    if (result.status === "incomplete") this.outcome = { status: "incomplete", category: result.category };
    else if (!comparison.matched) this.outcome = { status: "incomplete", category: "runtime-replay-result-drift" };
    else if (row.status !== "passed") this.outcome = { status: row.status, category: row.category };
    else if (this.schedule.snapshot().outcome.status === "incomplete") this.outcome = this.schedule.snapshot().outcome;
    this.finish();
    return { row, comparison };
  }

  interrupt(): void {
    if (this.pending) throw new Error("Pending replay needs an explicit worker result");
    if (this.outcome.status === "running") this.outcome = { status: "incomplete", category: "runtime-replay-interrupted" };
  }

  private finish(): void {
    if (this.completed !== this.saved.steps.length) return;
    const state = this.schedule.snapshot();
    const original = this.saved.manifest;
    const recordedInterruption = original.outcome.category === "runtime-campaign-interrupted";
    this.finalComparison = { sameCounts: sameScheduleData(state.counts, original.counts), sameCorpus: sameScheduleData(state.corpus, original.corpus),
      // Replaying the recorded prefix does not re-enact an external signal.
      sameScheduleOutcome: recordedInterruption ? null : sameScheduleData(state.outcome, original.outcome) };
    if (this.outcome.status !== "running") return;
    if (Object.values(this.finalComparison).includes(false)) this.outcome = { status: "incomplete", category: "runtime-replay-summary-drift" };
    else if (original.outcome.status === "incomplete") this.outcome = { status: "incomplete", category: "runtime-replay-saved-incomplete" };
    else if (state.outcome.status === "passed") this.outcome = { status: "passed", category: "runtime-campaign-replay-matched" };
    else this.outcome = { status: "incomplete", category: "runtime-replay-prefix" };
  }

  snapshot() {
    const state = this.schedule.snapshot();
    const recordedPrefixMatched = this.completed === this.saved.steps.length && this.matches.every(Boolean) && this.finalComparison !== null
      && !Object.values(this.finalComparison).includes(false);
    return { outcome: { ...this.outcome }, declaredSlots: this.saved.manifest.planned, recordedAttempts: this.saved.steps.length, proposed: this.proposed,
      attempted: this.completed, measured: this.measured, executionReplay: this.completed > 0, recordedPrefixMatched,
      fullPassingScheduleReplayed: recordedPrefixMatched && this.outcome.status === "passed" && this.saved.manifest.outcome.status === "passed",
      finalComparison: this.finalComparison && { ...this.finalComparison }, currentSchedule: state };
  }
}
