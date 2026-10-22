import type { AnalysisFacts } from "./dataflow/index.js";
import type { Finding } from "./detectors/types.js";
import type { ResolvedPolicies } from "./policies.js";
import type { Span } from "./model.js";

export const DETECTOR_API_VERSION = 1 as const;
export const DETECTOR_FACTS_VERSION = 1 as const;
export type FactCapability = "predicates" | "calls" | "merkle" | "collections" | "initialization";

/** Inputs are read-only by contract. Trusted modules execute ordinary JavaScript. */
export interface DetectorContext {
  readonly factsVersion: typeof DETECTOR_FACTS_VERSION;
  readonly facts: Readonly<AnalysisFacts>;
  readonly policies: Readonly<ResolvedPolicies>;
  /** Mark unsupported custom-rule semantics or a rule's own exhausted work allowance. */
  incomplete(message: string, location?: Span): void;
}
export type DetectorFinding = Omit<Finding, "detectorId" | "fingerprint" | "suppression" | "baselineState"> & {
  /** Distinguish independent observations at the same location; paths are normalized. */
  discriminator?: string;
};
export interface CustomDetector {
  apiVersion: typeof DETECTOR_API_VERSION;
  factsVersion: typeof DETECTOR_FACTS_VERSION;
  id: `custom-${string}`;
  description: string;
  /** Exact paths, sources, sinks, writes and owned Program queries are always available. */
  requires: FactCapability[];
  run(context: DetectorContext): DetectorFinding[];
}
export type CustomDetectorDefinition = Omit<CustomDetector, "run">;
export type { AnalysisFacts, AbstractValue, SuccessfulPath, StateWrite, PublicSink, SuccessfulPredicate, TraceStep } from "./dataflow/index.js";
export type { Span, Diagnostic } from "./model.js";
export type { Severity, Confidence } from "./detectors/types.js";
