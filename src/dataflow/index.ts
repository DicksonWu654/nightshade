import { withIdentityMeter } from "../semantic/metering.js";
import { membershipIdentityList } from "../semantic/membership-identity.js";
import { LIST_GROWTH_APPEND } from "../semantic/list-growth.js";
import { COMPLEMENTARY_SEND_TARGET } from "../semantic/complementary-send-targets.js";
import { directZeroRejection } from "./zero-rejection.js";
import { CONTRACT_RECIPIENT_SENDS, contractRecipientType } from "../semantic/contract-recipient.js";
import { PUBLIC_SCALAR_CAST } from "../semantic/public-scalar-targets.js";
import { transientDependencies, uncertainTransientDependencies, type TransientOrigin } from "./transient-origins.js";
import { SHIELDED_MINT, EVOLVE_NONCE } from "../semantic/mint-targets.js";
import { MEMO_NONCE_APPEND } from "../semantic/memo-nonce-targets.js";
import { Diagnostic, Expr, Pattern, Span, spanId } from "../model.js";
import { FunctionInfo, Program } from "../semantic/index.js";
import { intrinsicModel, standardType } from "../semantic/intrinsics.js";
import { TUPLE_TYPE, elementType, parseType, printType, sequenceLength, typeArguments } from "../semantic/types.js";
import { Constant, MAX_LITERAL_BYTES, castConstant, literalConstant } from "./constants.js";
import { createHash } from "node:crypto";
import { rememberReportIdentity } from "../semantic/metering.js";
import { LiveVariables, liveVariables, MAX_LIVENESS_STORAGE_BYTES } from "../analysis/liveness.js";
import { overwriteFoldPlan, type OverwriteFoldPlan } from "../analysis/overwrite-fold.js";
import { Region, regionFromKey, regionKey } from "./regions.js";
import { Instruction, sameTotalValueArms } from "../ir/index.js";
import type { CFG, CFGNode } from "../cfg/index.js";
import { BranchMutationEligibility, MutationCircuitEligibility, PureCircuitEligibility, ReadCircuitEligibility } from "../analysis/summaries.js";
import { BranchRecording, branchJournalNodes, EffectRecorder, MutationSummary, ReadonlySummary, type BranchJournalCursor, type BranchJournalNode, type BranchMutationEffect, type BranchMutationSummary } from "./summaries.js";
import { GuardCover } from "./guard-cover.js";
import { CollectionFacts } from "./collections.js";
import { ConditionalStateGraph, type ConditionalTerm } from "./conditional-state.js";
import { commonScalarConstraints } from "./common-constraints.js";
import { SourceHistories, type SourceHistory } from "./source-history.js";
import { querySourceEntry, repeatedCallCandidate, sourceQueryCandidate, type SourceQueryEvidence, type SourceQueryResult } from "./source-queries.js";
import { readStorageRegion, writeStorageRegion, recordStorageWrite, selectStorageValue, type StorageServices } from "./storage.js";
import { ListFacts, listQueryIdentity } from "./lists.js";
import { containsObservedMerkleCheck } from "./merkle-freshness.js";
import { MerkleFacts } from "./merkle.js";
import { immutableCollectionAddress, immutableOperandKey } from "./immutable-key.js";
import { HashRecipes } from "./hash-recipes.js";
import { hashChoiceCandidate } from "../analysis/hash-choice.js";
import { MERKLE_INSERT_OBSERVER, merklePureRootSummaryTarget, merkleRootCircuit } from "../semantic/merkle-targets.js";
import { finiteDomain } from "../semantic/domains.js";
import { schnorrVerifier, signatureVerifierCurve, type SignatureCurve } from "../semantic/signature-targets.js";
import { initializerEntries } from "../semantic/initializers.js";
import { enforcedEqualities, rawPublicPredicate } from "./predicates.js";
import { MAX_EITHER_READS, markPayload, payloadDependencies, reconstructedPayload, type EitherPayloadRead } from "./either-payloads.js";
import { ValueFingerprints } from "./fingerprints.js";
import { digestInputCandidate, eitherReadCandidate, type RuleCertificate } from "./rule-certificates.js";
import { nativeIdentity, nativeValue, pointIdentity } from "./natives.js";
import { canonicalSelfRead } from "../semantic/domain-review.js";
import { foreignField, SECP256K1_SCALAR_MODULUS } from "../semantic/fields.js";
import { extractTerminalCounterRegion, type CounterRegionLimits } from "../analysis/counter-regions.js";
import { buildCounterHistoryGraph, projectCounterHistory, type CounterHistoryProjection } from "./counter-histories.js";
import { integerEnvelope } from "./integer-envelope.js";
import { numericBound } from "../semantic/types.js";
import { combine, step, controlled, ControlDependencies, counterMutation, binaryValue, logicalValue, negateValue, refineScalar, assumeScalar, valueIdentity, directPreimageSource, MAX_AGGREGATE_EXCLUSION_LEAVES, MAX_ORDERED_PREDICATES, type ScalarConstraints } from "./transfers.js";
import { analyzeCorrelatedEntry, correlatedBranchCount, selectCorrelatedObservation, type CorrelatedGraph } from "./correlated.js";
import { queryCorrelatedGraph, type CorrelatedPredicate, type CorrelatedQueryResult } from "./correlated-queries.js";

export interface TraceStep {
  kind: string;
  label: string;
  location: Span;
}

export interface PrivateSource {
  id: string;
  kind: "witness" | "entry-parameter";
  name: string;
  location: Span;
  symbol?: string;
  /** A canonical supplied digest, including one inside an application wrapper.
   * Merkle-path auxiliary nodes are ingredients of a proof, not supplied roots. */
  merkleDigest?: true;
  invocation?: { site: string; occurrence: number; leaf: number };
  /** Stable parameter leaf for direct-digest finding identity, separate from run-local value identity. */
  declarationLeaf?: number;
  /** Only in bounded consecutive-invocation evidence: construction, first, second.
   * Historical dependencies retain their original step; they are not fresh inputs. */
  sequenceStep?: 0 | 1 | 2;
}

export interface Flow {
  source: PrivateSource;
  form: "raw" | "derived" | "hash" | "commitment";
  trace: TraceStep[];
  directPreimage?: boolean;
}

export interface HashBinding {
  source: PrivateSource;
  ledger: string;
  location: Span;
  trace: TraceStep[];
}

export interface AbstractValue {
  /** Digest-certificate-only proof that every alternative of a joined leaf
   * has this same represented type and no nested aggregate leaves. */
  digestJoinedLeafType?: string;
  /** Selected enrollment observer: exact canonical verifier outcome occurrence. */
  enrollmentSignatureOutcome?: string;
  /** Selected-only original conjunction operands. Their truth/parity and nested
   * verifier dependencies must survive selection of the RHS result. */
  enrollmentConjunctionInputs?: readonly AbstractValue[];
  /** Selected-only opaque dependencies, never value-equality evidence. */
  enrollmentPointInputs?: readonly AbstractValue[];
  /** Opt-in exact canonical kernel.self result; transformations discard it. */
  kernelSelf?: true;
  /** Compact 0.35 invocation caller query; the address is unknown statically. */
  kernelCaller?: true;
  /** Exact immutable selected-list length snapshot; never a may-alias storage identity. */
  listLengthSnapshot?: { root: string; path: string[]; revision: number;
    /** Opt-in exact receiver operands for memo/recipient source review. */
    receiver?: AbstractValue };
  /** Full scalar-to-Bytes encoding retained only for resettable nonce observation. */
  listLengthEncoding?: AbstractValue;
  /** Optional exact syntactic data origins; excludes ambient guards and witness arguments. */
  transientOrigins?: readonly TransientOrigin[];
  transientOriginsUnavailable?: true;
  /** Latest ledger segment needed for this immutable proof value. Present only
   * when checkpoints are reachable; pure input/witness constraints have none. */
  proofLedgerEpoch?: number;
  /** Exact pinned nonce derivation; observer-only, never a dependency union. */
  nonceEvolution?: { index: AbstractValue; nonce: AbstractValue };
  /** Observer-only immutable scalar snapshot; never a storage region identity. */
  mintSnapshot?: string;
  /** Selected-only arithmetic lineage lost at a may-alias value join. */
  complementaryLineageLost?: true;
  /** Exact numeric operands for public-bound review; no ledger origin or value equality. */
  numericExpression?: { operator: "+" | "-" | "*"; operands: AbstractValue[]; numericType?: string };
  /** Observer-only occurrence of a numeric Map lookup; repeated reads of one
   * revision have equal values but are not the same source occurrence. */
  mapDebitLookupOrigin?: string;
  /** Optional native-arm selection dependencies; never receiver equality. */
  eitherPayloads?: readonly string[];
  eitherSelection?: string;
  /** Control origins require both directions at their exact observed branch. */
  eitherControls?: readonly { branches: readonly string[]; payloads: readonly string[] }[];
  /** A payload-dependent decision made while evaluating this Boolean. */
  eitherLogicalGate?: true;
  eitherEvidenceLost?: true;
  flows: Flow[];
  ledger: Set<string>;
  /** Definite unchanged entry-storage value; unlike ledger/flows, never a union
   * of possible origins. Retained snapshots keep it; may-alias joins drop it. */
  preexistingLedger?: Set<string>;
  /** Observer-only native relation: this output is identity when this exact
   * input is identity. Neither equality nor a subgroup certificate. */
  pointIdentityInput?: AbstractValue;
  pointIdentityDepth?: number;
  pointIdentityEvidenceLost?: true;
  /** Exact nonidentity native output; never inverted to validate its inputs. */
  pointIdentityExcluded?: true;
  /** Exact digest of one private source, optionally with public aggregate
   * components; distinct from a hash dependency in a may-value join. */
  directHash?: { source: PrivateSource; primitive: string };
  /** Exact native digest input snapshot; transformed/control-only values drop it. */
  directDigest?: { primitive: string; input: AbstractValue; inputType?: string };
  /** Exact final transientHash of a qualified nonzero-depth pure Merkle root.
   * Its conditional preimage is deliberately not represented as a digest input. */
  summarizedMerkleHash?: true;
  /** Exact canonical commitment operand snapshots, retained only for requested digest observations. */
  directCommit?: { primitive: string; input: AbstractValue; randomness: AbstractValue };
  /** Successful integer envelope, retained through value-preserving numeric casts. */
  integerRange?: { minimum: string; maximum: string };
  /** A scalar preserved through a numeric conversion from an unsigned integer. */
  uintOrigin?: true;
  /** Exact shallow numeric operands before modular reduction, observed on request. */
  fieldArithmetic?: { operator: "+" | "-" | "*"; operands: readonly AbstractValue[]; location: Span };
  constant?: string;
  constantKind?: Constant["kind"];
  type?: string;
  items?: AbstractValue[];
  fields?: Record<string, AbstractValue>;
  region?: Region & { selection?: AbstractValue; revision?: number;
    /** Exact lookup operands, distinct from their combined may-dependencies. */
    collectionSelectors?: { index: number; value: AbstractValue }[] };
  equalities?: HashBinding[];
  identity?: string;
  /** Checked Counter updates by fixed amounts, relative to an immutable value.
   * Fixed-size metadata; unknown updates and may-alias unions drop the relation. */
  counterOffset?: { identity: string; offset: string };
  /** Conservative Boolean value alternatives, never a selected history. */
  predicateAlternatives?: readonly [AbstractValue, AbstractValue];
  /** A transfer erased Boolean structure needed by source-query absence proofs. */
  predicateStructureLost?: true;
  /** Compositional marker for alternatives nested in retained predicate trees. */
  predicateHasAlternatives?: true;
  negated?: AbstractValue;
  comparison?: { operator: string; left: AbstractValue; right: AbstractValue };
  ordering?: { operator: string; left: AbstractValue; right: AbstractValue; numericType: string;
    /** Exact alternate representation of the left operand, retained so later
     * byte constraints also refine the composed scalar predicate. */
    leftBytes?: readonly AbstractValue[] };
  /** Exact pinned native scalar encoding; the item identities must still match
   * this full 32-byte little-endian view before any transfer consumes it. */
  byteEncoding?: { scalar: AbstractValue; identity: string };
  commitments?: Commitment[];
  emptyCollection?: boolean;
  emptyMerkle?: boolean;
  merklePredicate?: { region: Region; revision: number; key?: string; full: boolean; exclusive?: boolean; historyEpoch?: number; structure: AbstractValue };
  emptyList?: boolean;
  collectionPredicate?: { region: Region; key?: string; empty: boolean; revision: number; upperBound?: number; /** Optional exact query snapshot for zero-entry observation. */ writesBefore?: number };
  listPredicate?: { region: Region; revision: number; structure: AbstractValue };
}

export interface Commitment {
  location: Span;
  primitive: string;
  input: AbstractValue;
  randomness: AbstractValue;
}

export interface StateWrite {
  /** Selected enrollment observer: retained write from the complete atomic history. */
  enrollmentWriteObserved?: true;
  ledger: string;
  region: string[];
  location: Span;
  before: AbstractValue;
  after: AbstractValue;
  excludedBefore: string[];
  guards: string[];
  callPath: string[];
  callSites?: Span[];
}

/** Ordered transaction/context observations, distinct from persistent writes.
 * Optional Merkle computations/queries are evidence, not transaction writes. */
export interface RuntimeOperation {
  kind: "kernel-read" | "kernel-write" | "native-witness" | "coin-qualification" | "event" | "merkle-root" | "merkle-check" | "merkle-insert" | "collection-query" | "collection-write" | "map-lookup" | "signature-verification" | "shielded-mint" | "circuit-invocation" | "list-append";
  event?: Expr["event"];
  name: string;
  location: Span;
  args: AbstractValue[];
  result: AbstractValue;
  guards: string[];
  control: AbstractValue[];
  callPath: string[];
  callSites?: Span[];
  /** For collection/Merkle observations, orders receiver invalidations against writes. */
  writesBefore?: number;
  /** Selected invocation/insertion boundary before its body performs effects.
   * This is an ordering index in this original history, not an effect union. */
  operationsBefore?: number;
  /** Successful Map.lookup precondition, captured before membership refinement. */
  membership?: { region: Region; key?: string; revision: number; before?: boolean };
  /** Exact operand exclusion after the canonical verifier body succeeds.
   * Includes caller constraints and source-pinned internal verifier guards. */
  signatureKeyExcludesIdentity?: boolean;
  signatureCurve?: SignatureCurve;
}

export interface FailedAssertion {
  location: Span;
  condition: AbstractValue;
  message: string;
  callPath: string[];
  path: TraceStep[];
}

/** Reaches include paths that abort later; absence of a terminal path is not
 * evidence that an earlier assertion could not succeed. One row per site/entry. */
export interface AssertionReach {
  location: Span;
  entry: string;
  owner: string;
  literalFalse: boolean;
  maySucceed: boolean;
  /** Observed before this assertion refines the state; unknown is not true. */
  mayFail: boolean;
}

/** Optional call observations survive later caller rejection. Failures are retained
 * as evidence, independently of terminal successful paths and assertion-site proof. */
export interface CallReach {
  location: Span;
  entry: string;
  owner: string;
  callee: string;
  callPath: string[];
  maySucceed: boolean;
  failedWithoutAssertion: boolean;
  failure?: FailedAssertion;
}

export interface PublicSink {
  kind: "ledger-write" | "exported-return" | "ledger-operation" | "event";
  name: string;
  location: Span;
  value: AbstractValue;
  callPath: string[];
}

/** A condition enforced on this successful history, with immutable operands.
 * Positions count effects already observed, not effects protected by dominance.
 * Later checks may constrain successful completion of earlier atomic effects. */
export interface SuccessfulPredicate {
  /** Optional Either observer: a non-tautological explicit assertion. Branch
   * choices alone do not enforce an unrelated post-join effect. */
  assertionGate?: true;
  value: AbstractValue;
  truth: boolean;
  location: Span;
  callPath: string[];
  callSites: Span[];
  writesBefore: number;
  operationsBefore: number;
}

interface State extends ScalarConstraints {
  sourceHistory?: number;
  /** Monotone: an enforced check or implicit rejection is unclassified. */
  otherChecks?: true;
  /** Writes after the latest dynamic call can re-establish known storage. */
  externalCallWriteIndex?: number;
  witnessCalls?: Map<string, number>;
  predicates?: SuccessfulPredicate[];
  /** Immutable snapshot identities needed to preserve pure-fold partitions
   * across caller liveness cleanup and repeated evaluations. */
  foldIdentities?: Set<string>;
  eitherReads?: EitherPayloadRead[];
  operations?: RuntimeOperation[];
  /** Guaranteed-segment snapshots at each reached kernel checkpoint. A later
   * fallible-segment failure commits only that prefix, without later checks. */
  checkpoints?: { state: State; key: string; site?: { location: Span; callPath: string[]; callSites: Span[] } }[];
  merkle?: MerkleFacts<AbstractValue>;
  branchJournal?: BranchJournalCursor;
  env: Map<string, AbstractValue>;
  ledger: Map<string, AbstractValue>;
  ledgerVersions: Map<string, number>;
  collections: CollectionFacts;
  lists: ListFacts<AbstractValue>;
  bindings: HashBinding[];
  sinks: PublicSink[];
  path: TraceStep[];
  control: { value: AbstractValue; until: number; owner: string }[];
  guards: Set<string>;
  writes: StateWrite[];
}

interface Evaluation {
  state: State;
  value: AbstractValue;
}

/** Conservative source observations cannot certify a successful history. */
export interface ConservativeSourceView {
  status: "available" | "incomplete";
  diagnostics: Diagnostic[];
  mayReachAssertions: AssertionReach[];
  mayReturn: boolean;
  history?: SourceHistory;
  /** A dropped Boolean expression can hide equalities from history queries. */
  predicateStructureComplete: boolean;
  /** Both selector polarities of compressed hash-order choices. Ordinary
   * histories branch there; they are possible guards, never required ones. */
  choicePredicates: readonly SuccessfulPredicate[];
  witnessCalls?: ReadonlyMap<string, number>;
  otherChecks?: boolean;
  current?: { ledger: ReadonlyMap<string, AbstractValue>; guards: readonly string[]; value: AbstractValue };
  work: { steps: number; values: number; sources: number; joins: number };
}

/** Complementary witness-leaf choices keep repeated reads correlated even when
 * unrelated branches change the number/order of preceding decisions. */
export type SourcePreference = boolean | { first: boolean; alternateWitnessLeaves?: true; preferPresentCollections?: true; evaluateBooleanRhs?: true; witnessPhase?: true };

export interface SuccessfulPath {
  sourceClaimHistory?: { operations: number; predicates: number; writes: number };
  complementaryHistory?: { operations: number; predicates: number; writes: number };
  contractRecipientHistory?: { operations: number; predicates: number };
  /** Selected enrollment observer: retained original-history row counts. */
  enrollmentHistory?: { writes: number; operations: number; predicates: number };
  /** Optional direct linkage from one complete proof history to each committed
   * checkpoint prefix. Prefixes remain linked even when flat outcomes deduplicate. */
  checkpointOutcomes?: { ordinal: number; location: Span; callPath: string[]; callSites: Span[]; history: SuccessfulPath }[];
  /** Expected reached boundaries before observer extraction; truncation cannot
   * certify a finding-free view. Present only on full observer histories. */
  checkpointCount?: number;
  /** Exact immutable result domains enforced by successful numeric casts. */
  integerDomains?: ReadonlyMap<string, { minimum: string; maximum: string }>;
  /** Ordinary interpreter coverage for histories with actual witness calls,
   * including predicates omitted from the public history. Absence (e.g. another engine/consumer) supplies no sole-gate proof. */
  checkCoverage?: "raw-witness-only" | "unclassified";
  witnessCalls?: ReadonlyMap<string, number>;
  predicates?: SuccessfulPredicate[];
  eitherReads?: EitherPayloadRead[];
  operations?: RuntimeOperation[];
  entry: string;
  bindings: HashBinding[];
  sinks: PublicSink[];
  path: TraceStep[];
  writes: StateWrite[];
}

export interface CapacityPrefix { construction: SuccessfulPath; gate: SuccessfulPath; location: Span }

export interface AnalysisFacts {
  refundEndpointEvidence?: { version: 1; program: Program; compilerVersion: string; zkirVersion: number; certificates: readonly import("./refund-endpoint.js").RefundEndpointCertificate[] };
  contractRecipientEvidence?: { entry: string; parameter?: string; histories: number; maxSteps: number; maxValues: number;
    /** A pipeline-only pass can defer these exact tags. This carrier never
     * certifies that their separate specializations have completed. */
    pendingTagParameters?: readonly string[] };
  enrollmentReviewEvidence?: import("./enrollment-review.js").EnrollmentReviewEvidence;
  domainReviewEvidence?: { entry: string; maxSteps: number; maxValues: number };
  zeroDefaultEvidence?: { getters: readonly import("./zero-default.js").ZeroDefaultGetter[] };
  closedCapacity?: { writers: ReadonlySet<string> };
  configuredCapacity?: { entry: string; constructor: string; prefixes: CapacityPrefix[]; constructions: number; successfulInvocations: number; maxSteps: number; maxValues: number };
  keyedStateEvidence?: { entries: readonly string[]; maxSteps: number; maxValues: number };
  program: Program;
  pathSemantics: "equivalent-states" | "guard-cover";
  /** Cross-entry caller conventions require all private inputs. Predicate-cover
   * consumers additionally need public conditions to retain their correlation. */
  predicateScope?: "witness" | "all-private" | "all";
  merkleEvidence?: boolean;
  /** Exact policy observation with complete predicates and no compressed histories. */
  currentRootEvidence?: { entry: string; maxSteps: number; maxValues: number };
  /** Entry-isolated exact linkage; no selected or compressed histories. */
  checkpointEvidence?: { entry: string; fullHistories: number; maxSteps: number; maxValues: number };
  collectionEvidence?: boolean;
  /** Opt-in ordinary exact operands for literal-zero caller-key review. */
  callerZeroEvidence?: { entry: string; maxSteps: number; maxValues: number };
  mapDebitEvidence?: { entry: string; maxSteps: number; maxValues: number };
  /** Isolated ordinary abstract interpretation with only this entry input fixed. */
  zeroEntry?: { entry: string; parameter: string; maxSteps: number; maxValues: number; rejection?: { kind: "direct-nonzero-input"; ordinarySuccesses: number } };
  mintQuantityEvidence?: true;
  mintEvidence?: boolean;
  operationIntentEvidence?: { entry: string; maxSteps: number; maxValues: number };
  signatureEvidence?: boolean;
  listGrowthEvidence?: { entry: string; maxSteps: number; maxValues: number; maxPaths: number; histories: number };
  sourceMapGetterEvidence?: { claim: import("../semantic/source-map-getters.js").ResolvedSourceMapGetter; setterPaths: SuccessfulPath[]; setterHistories: number; getterClosure: "complete-without-selected-root-read"; maxSteps: number; maxValues: number };
  sourceClaimEvidence?: { entry: string; maxSteps: number; maxValues: number; maxPaths: number; histories: number; claims?: readonly import("../semantic/source-claims.js").ResolvedSourceClaim[] };
  complementarySendEvidence?: { entry: string; maxSteps: number; maxValues: number; maxPaths: number; histories: number };
  signatureIdentityEvidence?: { entry: string; maxSteps: number; maxValues: number; maxPaths: number; histories: number };
  /** Selected binding limits and cumulative per-entry execution/matching work. */
  secretBindingEvidence?: { maxSteps: number; maxValues: number; maxPaths: number; entrySteps: Map<string, number> };
  /** Selected scalar source limits and cumulative per-entry execution/matching work. */
  publicScalarEvidence?: { maxSteps: number; maxValues: number; maxPaths: number; entrySteps: Map<string, number> };
  digestEvidence?: boolean;
  /** Exact commitment operands, isolated from ordinary digest observation. */
  commitEvidence?: boolean;
  transientEvidence?: true;
  /** Optional exact input/result snapshots for selected canonical circuits. */
  invocationEvidence?: readonly string[];
  arithmeticEvidence?: boolean;
  eitherEvidence?: boolean;
  eitherBranches?: readonly { id: string; mayTrue: boolean; mayFalse: boolean }[];
  /** Separate histories; never mix these with the ordinary entry-state paths. */
  initialization?: InitializationEvidence[];
  paths: SuccessfulPath[];
  /** Detector-specific coverage. These witness paths are not exhaustive paths. */
  sourceQueries?: readonly SourceQueryEvidence[];
  diagnostics: Diagnostic[];
  failedAssertions: FailedAssertion[];
  assertionReaches: AssertionReach[];
  callReaches?: CallReach[];
  metrics: { steps: number; sources: number; paths: number; abstractValues: number; summaryHits: number; summaryEntries: number; statefulSummaryHits: number; readSummaryHits: number; summaryEffects: number; guardSubsumptions: number };
  completedEntries: string[];
}

export interface InitializationEvidence {
  entry: string;
  firstSuccesses: number;
  secondSuccesses: number;
  pairs: { construction?: SuccessfulPath; first: SuccessfulPath; second: SuccessfulPath;
    changes: { ledger: string; before: AbstractValue; after: AbstractValue }[] }[];
}

/** Exact paths and bounded graph observations have separate coverage contracts. */
export interface CorrelatedAnalysis {
  exact: AnalysisFacts;
  correlated: { graph: CorrelatedGraph; query: Extract<CorrelatedQueryResult, { status: "complete" }> }[];
  sources: SourceQueryEvidence[];
}

/** Internal selected-witness API: none of these outcomes attest whole-entry coverage. */
export type CounterWitnessResult =
  | { status: "ineligible"; reason: string; location: Span }
  | { status: "incomplete"; diagnostics: Diagnostic[] }
  | { status: "no-surviving-path"; decisions: readonly boolean[]; metrics: AnalysisFacts["metrics"] }
  | { status: "selected"; decisions: readonly boolean[]; projection: CounterHistoryProjection; path: SuccessfulPath; metrics: AnalysisFacts["metrics"] };

export interface CounterWitnessLimits {
  region?: CounterRegionLimits;
  maxGraphNodes?: number;
  maxProjectionWork?: number;
}

/** Internal source-replay evidence; a selected history never attests entry coverage. */
export type ConditionalSourceSelection =
  | { status: "selected"; path: SuccessfulPath; assertions: AssertionReach[]; calls: CallReach[]; metrics: AnalysisFacts["metrics"] }
  | { status: "rejected"; assertions: AssertionReach[]; calls: CallReach[]; metrics: AnalysisFacts["metrics"] }
  | { status: "incomplete"; diagnostics: Diagnostic[]; metrics: AnalysisFacts["metrics"] };

export function dependsOn(value: AbstractValue, source: string): boolean {
  return value.flows.some(flow => flow.source.id === source);
}

function empty(): AbstractValue {
  return { flows: [], ledger: new Set() };
}

/** Declaration-level class of a private source (all leaves of one parameter or
 * witness site share it), never a run-local identity. */
function certificateSourceClass(source: PrivateSource): string {
  return JSON.stringify([source.kind, source.symbol ?? source.name, spanId(source.location)]);
}

/** Provenance labels and source locations; compressed-fold dependency checks
 * inspect immutable identities, relations and storage keys instead. */
/** Oracle switch for tests: when false, the pure-fold provenance prefix uses
 * only the per-step serialized comparison (the shared-marker shortcut is off).
 * Both settings produce identical values; only the work differs. */
export const foldProvenance = { shareMarkers: true };
const COMPRESSION_PROVENANCE_KEYS = new Set(["flows", "trace", "location", "callPath", "callSites", "source", "ledger", "preexistingLedger"]);

function clone(state: State): State {
  // Keep the shape stable across forks; conditional spreads otherwise dominate
  // branch-heavy execution. Every mutable container still receives its own copy.
  const result: State = {
    scalarMeter: state.scalarMeter, identityText: state.identityText, hashRecipes: state.hashRecipes, otherChecks: state.otherChecks,
    externalCallWriteIndex: state.externalCallWriteIndex,
    witnessCalls: state.witnessCalls ? new Map(state.witnessCalls) : undefined,
    predicates: state.predicates?.slice(), integerDomains: state.integerDomains ? new Map(state.integerDomains) : undefined,
    scalarEqualities: state.scalarEqualities ? new Map(state.scalarEqualities) : undefined,
    scalarEqualitiesExhausted: state.scalarEqualities ? state.scalarEqualitiesExhausted : undefined,
    foldIdentities: state.foldIdentities ? new Set(state.foldIdentities) : undefined,
    orderings: state.orderings ? new Map(state.orderings) : undefined,
    orderingsExhausted: state.orderings ? state.orderingsExhausted : undefined,
    merkle: state.merkle?.clone(), eitherReads: state.eitherReads?.slice(), operations: state.operations?.slice(),
    checkpoints: state.checkpoints?.slice(), branchJournal: state.branchJournal,
    env: new Map(state.env), ledger: new Map(state.ledger), ledgerVersions: new Map(state.ledgerVersions),
    collections: state.collections.clone(), lists: state.lists.clone(), bindings: [...state.bindings], sinks: [...state.sinks],
    path: [...state.path], control: [...state.control], truths: new Map(state.truths), known: new Map(state.known),
    excluded: new Map([...state.excluded].map(([key, values]) => [key, new Set(values)])),
    aggregateExclusions: new Map(state.aggregateExclusions), aggregateExclusionLeaves: state.aggregateExclusionLeaves,
    aggregateExclusionsExhausted: state.aggregateExclusionsExhausted, guards: new Set(state.guards), writes: [...state.writes],
  };
  state.hashRecipes?.fork(state, result);
  if (state.sourceHistory !== undefined) result.sourceHistory = state.sourceHistory;
  return result;
}

export class Dataflow {
  private domainReviewObservation = false;
  private contractRecipientObservation?: { parameter?: string };
  private operationIntentObservation = false;
  private sourceClaimObservation = false;
  private complementarySendObservation = false;
  private listGrowthObservation = false;
  private complementaryRetentionExhausted = false;
  private secretBindingObservation = false;
  private membershipIdentityObservation = false;
  private enrollmentReviewObservation = false;
  private enrollmentSignatureOccurrence = 0;
  private enrollmentRetentionExhausted = false;
  private sequenceStep?: 0 | 1 | 2;
  private observeCapacity = false;
  private capacityConstruction?: SuccessfulPath;
  private capacityPrefixes: CapacityPrefix[] = [];
  private callSites: Span[] = [];
  private observePreimageInputs = false;
  private counterSelection?: { entry: string; branches: Map<number, boolean>; visited: Set<number> };
  private conditionalSelection?: { entry: string; decisions: ReadonlyMap<number, boolean> };
  private sourcePreference?: SourcePreference;
  private conservative = false;
  /** Isolated conservative rule certificate: may-observations of every hash
   * input or native Either payload selection, never AnalysisFacts. */
  private ruleCertificate?: { kind: "digest" | "either"; candidates: string[]; domains: Map<string, boolean | undefined>;
    /** Digest inputs, decided after the run. Sink values and constraint operands
     * are walked for raw source classes only if a digest needs that refinement. */
    digests: { input: AbstractValue; location: Span }[]; sinks: { value: AbstractValue; location: Span }[]; constraints: { value: AbstractValue; location: Span }[];
    classes?: { published: Set<string>; constrained: Set<string> } };
  private conservativeJoins = 0;
  private predicateStructureComplete = true;
  private sourceHistories?: SourceHistories;
  /** Conservative source view only: selector checks of compressed hash choices. */
  private readonly choicePredicates: SuccessfulPredicate[] = [];
  private steps = 0;
  private sourceCount = 0;
  private abstractValues = 0;
  private totalSteps = 0;
  private writeCount = 0;
  private snapshotCount = 0;
  private nativeCount = 0;
  private currentEntry = "";
  private readonly incompleteEntries = new Set<string>();
  private readonly liveness = new Map<string, LiveVariables>();
  private readonly summaryEligibility: PureCircuitEligibility;
  private readonly mutationEligibility: MutationCircuitEligibility;
  private readonly readEligibility: ReadCircuitEligibility;
  private readonly branchEligibility: BranchMutationEligibility;
  private readonly branchScopeSafety = new Map<string, boolean>();
  private readonly branchSummaries = new Map<string, BranchMutationSummary>();
  private readonly summaries = new Map<string, { value: AbstractValue; completions: string[][] }>();
  private readonly mutationSummaries = new Map<string, MutationSummary>();
  private readonly readSummaries = new Map<string, ReadonlySummary>();
  private readonly effectRecorder = new EffectRecorder();
  private summaryHits = 0;
  /** Checkpoint prefixes are path state; summaries do not replay them. */
  private checkpointCount = 0;
  private readonly checkpointProofTracking: boolean;
  private statefulSummaryHits = 0;
  private readSummaryHits = 0;
  private summaryEffects = 0;
  private guardSubsumptions = 0;
  readonly diagnostics: Diagnostic[] = [];
  readonly failedAssertions: FailedAssertion[] = [];
  private readonly eitherBranches = new Map<string, { id: string; mayTrue: boolean; mayFalse: boolean }>();
  private readonly assertionReaches = new Map<string, AssertionReach>();
  private readonly callReaches = new Map<string, CallReach>();
  private valueFingerprints = new ValueFingerprints();
  /** Summary equivalence retains diagnostic provenance as well as value data. */
  private summaryFingerprints = new ValueFingerprints(true);
  private controlDependencies = new ControlDependencies();
  /** State-independent structural identities of retained immutable values.
   * Null also memoizes a failed identity query; no state constraint is cached. */
  private liveValueIdentities = new WeakMap<AbstractValue, string | null>();
  private hashRecipes: HashRecipes;
  /** Exact-observation modes may use the total scalar comparison fold only while
   * no later evidence can observe its elided byte partitions. These entry-local
   * immutable identities/sources name that compressed disjunction. */
  private compressionTokens = new Set<string>();
  private compressionTouchCache = new WeakMap<object, true | number>();
  private observationCompressions = 0;

  /** A report-only digest of the same owned identity slots. The ordinary key
   * remains byte-for-byte unchanged for analysis, caches and equality. */
  private derivedIdentity(prefix: string, inputs: unknown[]): string {
    const digest = (parts: unknown[]) => `${prefix}:${createHash("sha256").update(JSON.stringify(parts)).digest("hex")}`;
    const canonical = (value: unknown): unknown => typeof value === "string" ? this.program.reportIdentity(value)
      : Array.isArray(value) ? value.map(canonical) : value;
    return rememberReportIdentity(digest(inputs), digest(inputs.map(canonical)), this.program.meteringIdentity);
  }

  private newHashRecipes(): HashRecipes {
    return new HashRecipes((work, values) => {
      this.steps += work; this.abstractValues += values;
      if (this.steps <= this.maxSteps && this.abstractValues <= this.maxValues) return true;
      this.issue("analysis-budget", "Hash-choice representation exhausted the shared analysis allowance; results are incomplete", this.program.functions.get(this.currentEntry)?.declaration.span ?? this.program.rootSource.ast.span);
      return false;
    }, () => this.issue("predicate-budget", "Hash-choice identity traversal exceeds 256 levels; results are incomplete", this.program.functions.get(this.currentEntry)?.declaration.span ?? this.program.rootSource.ast.span), true, this.program.meteringIdentity);
  }

  constructor(readonly program: Program, readonly maxSteps = 40000, readonly maxPaths = 256, readonly maxValues = 50000, readonly engine: "instructions" | "expressions" = "instructions", readonly useSummaries = engine === "instructions", readonly useStatefulSummaries = useSummaries && engine === "instructions", readonly pathSemantics: AnalysisFacts["pathSemantics"] = "equivalent-states", readonly observeCalls = false, readonly useFoldPartitions = true, readonly predicateScope: NonNullable<AnalysisFacts["predicateScope"]> = "witness", readonly observeMerkle = false, readonly observeCollections = false, readonly observeInitialization = false, readonly useHashChoices = true, readonly observeSignatures = false, readonly observeEither = false, readonly observeDigestInputs = false, readonly observeArithmetic = false, readonly observeMints = false, readonly observeMintQuantities = false, readonly observeInvocations: ReadonlySet<string> = new Set(), readonly observeTransientOrigins = false, readonly observeCommitInputs = false, readonly observeSignatureKeyIdentity = false, readonly observeSecpSignatures = false) {
    this.hashRecipes = this.newHashRecipes();
    this.summaryEligibility = new PureCircuitEligibility(program);
    this.mutationEligibility = new MutationCircuitEligibility(program);
    this.readEligibility = new ReadCircuitEligibility(program);
    this.branchEligibility = new BranchMutationEligibility(program);
    const checkpoint = (expr: Expr): boolean => expr.kind === "member" && expr.name === "checkpoint" || expr.args.some(checkpoint);
    this.checkpointProofTracking = [...program.functions.values()].some(fn => fn.cfg.nodes.some(node => node.expr && checkpoint(node.expr)));
  }

  analyze(): AnalysisFacts {
    return this.analyzeEntries(this.program.entries);
  }

  /** Exact selected histories with a carried entry meter; no fallback/retry. */
  analyzeSecretBindingEntry(entry: string): AnalysisFacts {
    if (!this.program.entries.includes(entry)) throw new Error("Secret binding observation requires an exported entry");
    const previous = this.secretBindingObservation;
    this.secretBindingObservation = true;
    try { return this.analyzeSubset([entry]); }
    finally { this.secretBindingObservation = previous; }
  }

  /** Reuse the exact-history carrier while metering additional query retention. */
  analyzeMembershipIdentityEntry(entry: string): AnalysisFacts {
    this.membershipIdentityObservation = true;
    try { return this.analyzeSecretBindingEntry(entry); }
    finally { this.membershipIdentityObservation = false; }
  }

  private secretBindingCharge(work: number, values: number, location: Span): boolean {
    if (!this.secretBindingObservation) return true;
    this.steps += work; this.abstractValues += values;
    if (this.steps > this.maxSteps || this.abstractValues > this.maxValues) {
      this.issue("secret-binding-retention-budget", "Secret binding capture exhausted its shared allowance", location);
      return false;
    }
    return true;
  }

  /** Selected exact send operands on original, uncompressed atomic histories. */
  analyzeComplementarySendEntry(entry: string): AnalysisFacts {
    return this.analyzeAtomicSendEntry(entry, false);
  }

  /** Shared exact call/collection transfers and retention meter, with no retry. */
  analyzeZeroTransferListEntry(entry: string): AnalysisFacts {
    return this.analyzeAtomicSendEntry(entry, true);
  }

  analyzeSourceClaimEntry(entry: string): AnalysisFacts {
    return this.analyzeAtomicSendEntry(entry, false, true);
  }

  analyzeMapGetterEntry(entry: string): AnalysisFacts {
    return this.analyzeAtomicSendEntry(entry, false, true, true);
  }

  private analyzeAtomicSendEntry(entry: string, listGrowth: boolean, sourceClaim = false, mapGetter = false): AnalysisFacts {
    if (!this.program.entries.includes(entry)) throw new Error("Complementary send review requires an exported entry");
    // Reserve the fixed failure envelope before execution. Refusal never calls
    // another analysis, which would reset diagnostics and spent counters.
    const reservedSteps = 2, reservedValues = 16;
    const flow = new Dataflow(this.program, Math.max(0, this.maxSteps - reservedSteps), this.maxPaths,
      Math.max(0, this.maxValues - reservedValues), this.engine,
      this.useSummaries, this.useStatefulSummaries, "equivalent-states", false, false, "all",
      false, listGrowth || mapGetter, false, false, false, false, false, false, listGrowth, true,
      new Set(mapGetter ? [entry] : sourceClaim ? [SHIELDED_MINT] : [COMPLEMENTARY_SEND_TARGET, ...(listGrowth ? [LIST_GROWTH_APPEND] : [])]));
    flow.complementarySendObservation = true;
    flow.listGrowthObservation = listGrowth;
    flow.sourceClaimObservation = sourceClaim;
    const refused = (): AnalysisFacts => ({ program: this.program, pathSemantics: "equivalent-states", predicateScope: "all",
      paths: [], completedEntries: [], diagnostics: flow.diagnostics, failedAssertions: flow.failedAssertions, assertionReaches: [],
      metrics: { steps: flow.totalSteps + flow.steps, abstractValues: flow.abstractValues, paths: 0, sources: flow.sourceCount,
        summaryHits: flow.summaryHits, summaryEntries: flow.summaries.size + flow.mutationSummaries.size + flow.readSummaries.size + flow.branchSummaries.size,
        statefulSummaryHits: flow.statefulSummaryHits, readSummaryHits: flow.readSummaryHits,
        summaryEffects: flow.summaryEffects, guardSubsumptions: flow.guardSubsumptions } });
    let facts: AnalysisFacts;
    if (this.maxSteps < reservedSteps || this.maxValues < reservedValues) {
      flow.currentEntry = entry;
      flow.issue(sourceClaim ? "source-claim-retention-budget" : listGrowth ? "list-growth-retention-budget" : "complementary-send-retention-budget", sourceClaim ? "Source claim failure envelope exhausted the shared allowance" : listGrowth ? "Retained List-growth failure envelope exhausted the shared allowance" : "Complementary send failure envelope exhausted the shared allowance", this.program.functions.get(entry)!.declaration.span);
      facts = refused();
    } else {
      try { facts = flow.analyzeSubset([entry]); }
      catch (error) {
        if (!flow.complementaryRetentionExhausted) throw error;
        facts = refused();
      }
      const beforeSteps = flow.steps, beforeValues = flow.abstractValues;
      if (flow.complementaryCharge(5, 5, this.program.functions.get(entry)!.declaration.span))
        facts[sourceClaim ? "sourceClaimEvidence" : listGrowth ? "listGrowthEvidence" : "complementarySendEvidence"] = { entry, maxSteps: this.maxSteps, maxValues: this.maxValues,
          maxPaths: this.maxPaths, histories: facts.paths.length };
      facts.metrics.steps += flow.steps - beforeSteps; facts.metrics.abstractValues += flow.abstractValues - beforeValues;
      if (flow.complementaryRetentionExhausted) {
        facts.paths.length = 0; facts.completedEntries.length = 0; facts.metrics.paths = 0;
      }
    }
    facts.metrics.steps += reservedSteps; facts.metrics.abstractValues += reservedValues;
    return facts;
  }

  private complementaryCharge(work: number, values: number, location: Span): boolean {
    if (this.complementaryRetentionExhausted) return false;
    this.steps += work; this.abstractValues += values;
    if (this.steps > this.maxSteps || this.abstractValues > this.maxValues) {
      this.complementaryRetentionExhausted = true;
      this.issue(this.sourceClaimObservation ? "source-claim-retention-budget" : this.listGrowthObservation ? "list-growth-retention-budget" : "complementary-send-retention-budget", this.sourceClaimObservation ? "Source claim observation exhausted the shared allowance" : this.listGrowthObservation ? "Retained List-growth observation exhausted the shared allowance" : "Complementary send observation exhausted the shared allowance", location);
      return false;
    }
    return true;
  }

  private cloneState(state: State): State {
    if (this.complementarySendObservation && !this.complementaryCharge(1,
      2 + (state.predicates?.length ?? 0) + (state.operations?.length ?? 0),
      this.program.functions.get(this.currentEntry)!.declaration.span)) throw new Error("Complementary history allocation refused");
    return clone(state);
  }

  /** Cache records cannot reuse a fresh computed scalar occurrence. Exact
   * argument/ledger identities and ordinary storage transfers remain cacheable. */
  private complementaryCacheValue(value: AbstractValue, location: Span, depth = 0): boolean {
    if (!this.complementarySendObservation) return true;
    if (!this.complementaryCharge(1, 0, location)) return false;
    if (depth > 32) {
      this.issue("complementary-send-summary-unavailable", "Selected summary operand depth is unavailable", location); return false;
    }
    if (value.mintSnapshot || value.numericExpression || value.complementaryLineageLost) return false;
    for (const name in value.fields) if (Object.hasOwn(value.fields, name))
      if (!this.complementaryCacheValue(value.fields[name], location, depth + 1)) return false;
    if (value.items) for (const item of value.items) if (!this.complementaryCacheValue(item, location, depth + 1)) return false;
    return true;
  }

  private complementaryHistory(state: State): Pick<SuccessfulPath, "complementaryHistory" | "sourceClaimHistory"> {
    if (!this.complementarySendObservation || !this.complementaryCharge(4, 4,
      this.program.functions.get(this.currentEntry)!.declaration.span)) return {};
    return { [this.sourceClaimObservation ? "sourceClaimHistory" : "complementaryHistory"]: { operations: state.operations?.length ?? 0,
      predicates: state.predicates?.length ?? 0, writes: state.writes.length } };
  }

  analyzeOperationIntentEntry(entry: string): AnalysisFacts {
    if (!this.program.entries.includes(entry)) throw new Error("Operation-intent requires an exported entry");
    const flow = new Dataflow(this.program, this.maxSteps, this.maxPaths, this.maxValues, this.engine,
      this.useSummaries, this.useStatefulSummaries, "equivalent-states", false, false, "all",
      false, false, false, false, false, false, true, false, false, false,
      new Set(["standard-library::secp256k1EcdsaVerify"].filter(id => this.program.functions.has(id))));
    flow.operationIntentObservation = true;
    const facts = flow.analyzeSubset([entry]);
    facts.metrics.steps++; facts.metrics.abstractValues++;
    if (facts.metrics.steps > this.maxSteps || facts.metrics.abstractValues > this.maxValues)
      facts.diagnostics.push({ code: "operation-intent-budget", message: "Operation-intent evidence exhausted its shared allowance", location: this.program.functions.get(entry)!.declaration.span });
    else facts.operationIntentEvidence = { entry, maxSteps: this.maxSteps, maxValues: this.maxValues };
    return facts;
  }

  /** Selected-only original write/outcome observations; caller meters entries together. */
  analyzeEnrollmentReviewEntry(entry: string): AnalysisFacts {
    if (!this.program.entries.includes(entry)) throw new Error("Enrollment review requires an exported entry");
    const flow = new Dataflow(this.program, this.maxSteps, this.maxPaths, this.maxValues, this.engine,
      this.useSummaries, this.useStatefulSummaries, "equivalent-states", false, false, "all",
      false, false, false, false, true, false, false, false, false, false, new Set(), false, false, true);
    flow.enrollmentReviewObservation = true;
    return flow.analyzeSubset([entry]);
  }

  /** Selected exact native verifier snapshots. Enrollment metadata supplies
   * bounded point dependencies/history completeness, without an enrollment claim. */
  analyzeSignatureIdentityEntry(entry: string): AnalysisFacts {
    if (!this.program.entries.includes(entry)) throw new Error("Signature identity review requires an exported entry");
    const flow = new Dataflow(this.program, this.maxSteps, this.maxPaths, this.maxValues, this.engine,
      this.useSummaries, this.useStatefulSummaries, "equivalent-states", false, false, "all",
      false, false, false, false, true, false, false, false, false, false, new Set(), false, false, true, true);
    flow.enrollmentReviewObservation = true;
    const facts = flow.analyzeSubset([entry]);
    const admitted = flow.enrollmentCharge(5, 5, this.program.functions.get(entry)!.declaration.span);
    facts.metrics.steps += 5; facts.metrics.abstractValues += 5;
    if (admitted) {
      facts.signatureIdentityEvidence = { entry, maxSteps: this.maxSteps, maxValues: this.maxValues, maxPaths: this.maxPaths, histories: facts.paths.length };
    }
    return facts;
  }

  /** Exact entry-local preimages and predicates, with no compressed histories. */
  analyzeDomainReviewEntry(entry: string): AnalysisFacts {
    if (!this.program.entries.includes(entry)) throw new Error("Domain review requires an exported entry");
    const flow = new Dataflow(this.program, this.maxSteps, this.maxPaths, this.maxValues, this.engine,
      this.useSummaries, this.useStatefulSummaries, "equivalent-states", false, false, "all",
      false, false, false, false, false, false, true);
    flow.domainReviewObservation = true;
    const facts = flow.analyzeSubset([entry]);
    facts.metrics.steps++;
    facts.metrics.abstractValues++;
    if (facts.metrics.steps > this.maxSteps || facts.metrics.abstractValues > this.maxValues)
      facts.diagnostics.push({ code: "domain-review-evidence-budget", message: "Domain review evidence carrier exhausted its shared allowance", location: this.program.functions.get(entry)!.declaration.span });
    else facts.domainReviewEvidence = { entry, maxSteps: this.maxSteps, maxValues: this.maxValues };
    return facts;
  }

  private currentRootObservation = false;
  /** Ordinary interpretation with one supplied native recipient tag fixed to
   * right. All payloads, other inputs and entry storage remain unknown. */
  analyzeContractRecipientEntry(entry: string, parameter?: string): AnalysisFacts {
    const fn = this.program.functions.get(entry);
    if (!fn || !this.program.entries.includes(entry) || parameter && !fn.declaration.parameters.some(
      part => part.symbol === parameter && contractRecipientType(this.program, part.type)))
      throw new Error("Contract recipient observation requires an exported entry and native recipient parameter");
    const flow = new Dataflow(this.program, this.maxSteps, this.maxPaths, this.maxValues, this.engine,
      this.useSummaries, this.useStatefulSummaries, "equivalent-states", false, false, "all",
      false, false, false, false, false, false, false, false, false, false, CONTRACT_RECIPIENT_SENDS);
    flow.contractRecipientObservation = { parameter };
    const facts = flow.analyzeSubset([entry]);
    facts.metrics.steps += 5; facts.metrics.abstractValues += 5;
    if (facts.metrics.steps > this.maxSteps || facts.metrics.abstractValues > this.maxValues)
      facts.diagnostics.push({ code: "contract-recipient-evidence-budget", message: "Recipient evidence carrier exhausted its shared allowance", location: fn.declaration.span });
    else facts.contractRecipientEvidence = { entry, parameter, histories: facts.paths.length, maxSteps: this.maxSteps, maxValues: this.maxValues };
    return facts;
  }
  private leafBindingObservation = false;
  private pureMerkleRootSummary = false;
  private checkpointObservation = false;
  private checkpointFullHistories = 0;
  analyzeAtomicUpdateEntry(entry: string): AnalysisFacts {
    if (!this.program.entries.includes(entry) || this.pathSemantics !== "equivalent-states"
      || this.predicateScope !== "all" || this.useFoldPartitions || this.useHashChoices || this.observeInitialization)
      throw new Error("Atomic-update observation requires an exported entry, all predicates and uncompressed histories");
    this.checkpointObservation = true;
    this.checkpointFullHistories = 0;
    try {
      const facts = this.analyzeSubset([entry]);
      facts.checkpointEvidence = { entry, fullHistories: this.checkpointFullHistories, maxSteps: this.maxSteps, maxValues: this.maxValues };
      return facts;
    } finally { this.checkpointObservation = false; }
  }
  analyzeCurrentRootEntry(entry: string): AnalysisFacts {
    if (!this.program.entries.includes(entry) || !this.observeMerkle || this.predicateScope !== "all" || this.useFoldPartitions || this.useHashChoices)
      throw new Error("Current-root observation requires an exported entry, all predicates, Merkle operations and uncompressed histories");
    this.currentRootObservation = true;
    try {
      const facts = this.analyzeSubset([entry]);
      facts.currentRootEvidence = { entry, maxSteps: this.maxSteps, maxValues: this.maxValues };
      return facts;
    } finally { this.currentRootObservation = false; }
  }

  /** Rule-isolated exact histories. The ordinary interpreter remains available
   * as an oracle by disabling only the pinned pure-root summary. */
  analyzeMerkleLeafBindingEntry(entry: string, summarizePureRoots = true): AnalysisFacts {
    if (!this.program.entries.includes(entry) || !this.observeMerkle || !this.observeDigestInputs
      || !this.observeMintQuantities || this.predicateScope !== "all" || this.useFoldPartitions || this.useHashChoices
      || this.pathSemantics !== "equivalent-states")
      throw new Error("Merkle leaf-binding observation requires an exported entry, exact all-predicate histories and required observers");
    this.leafBindingObservation = true;
    this.pureMerkleRootSummary = summarizePureRoots;
    try { return this.analyzeSubset([entry]); }
    finally { this.leafBindingObservation = false; this.pureMerkleRootSummary = false; }
  }

  private zeroInput?: { entry: string; parameter: string };
  private mapDebitObservation = false;

  /** Exact ordinary debit operands select actual entry amounts before any
   * zero specialization. Numeric expression trees stay observer-local. */
  analyzeMapDebitCandidates(entry: string): AnalysisFacts {
    const flow = new Dataflow(this.program, this.maxSteps, this.maxPaths, this.maxValues, this.engine,
      this.useSummaries, this.useStatefulSummaries, "equivalent-states", false, false, "all", false, true, false, false);
    flow.mapDebitObservation = true;
    const facts = flow.analyzeSubset([entry]);
    facts.mapDebitEvidence = { entry, maxSteps: this.maxSteps, maxValues: this.maxValues };
    return facts;
  }

  /** Isolated ordinary collection operands for caller-zero candidate discovery.
   * This does not alter ordinary analysis or specialize any input. */
  analyzeCallerZeroCandidates(entry: string): AnalysisFacts {
    const facts = new Dataflow(this.program, this.maxSteps, this.maxPaths, this.maxValues, this.engine,
      this.useSummaries, this.useStatefulSummaries, "equivalent-states", false, false, "all", false, true, false, false)
      .analyzeSubset([entry]);
    facts.callerZeroEvidence = { entry, maxSteps: this.maxSteps, maxValues: this.maxValues };
    return facts;
  }

  analyzeZeroMapDebitEntry(entry: string, parameter: string): AnalysisFacts {
    return this.analyzeZeroEntryObserved(entry, parameter, true);
  }

  /** A policy-selected scalar zero, not a path/solver query. Other inputs and
   * initial storage remain unknown. No compressed or selected histories, and
   * storage summaries stay off until they replay the precondition snapshots. */
  analyzeZeroEntry(entry: string, parameter: string): AnalysisFacts {
    return this.analyzeZeroEntryObserved(entry, parameter, false);
  }

  private analyzeZeroEntryObserved(entry: string, parameter: string, mapDebit: boolean): AnalysisFacts {
    const fn = this.program.functions.get(entry);
    const input = fn?.declaration.parameters.find(item => item.symbol === parameter);
    if (!fn || !this.program.entries.includes(entry) || fn.symbol.kind !== "circuit" || !input
      || !/^(Field|Uint<\d+>)$/.test(this.program.representationOf(input.type)))
      throw new Error("Zero-entry observation requires an exported circuit and scalar numeric parameter");
    const flow = new Dataflow(this.program, this.maxSteps, this.maxPaths, this.maxValues, this.engine,
      this.useSummaries, this.useStatefulSummaries, "equivalent-states", false, false, "all", false, true, false, false);
    flow.zeroInput = { entry, parameter };
    flow.mapDebitObservation = mapDebit;
    const facts = flow.analyzeSubset([entry]);
    if (mapDebit) facts.mapDebitEvidence = { entry, maxSteps: this.maxSteps, maxValues: this.maxValues };
    if (directZeroRejection(facts)) {
      // An ordinary complete invocation must also survive. A later unrelated
      // unconditional failure cannot turn this guard into an applicability proof.
      const ordinary = new Dataflow(this.program, Math.max(0, this.maxSteps - facts.metrics.steps), this.maxPaths,
        Math.max(0, this.maxValues - facts.metrics.abstractValues), this.engine,
        false, false, "equivalent-states", false, false, "all", false, true, false, false).analyzeSubset([entry]);
      facts.metrics.steps += ordinary.metrics.steps;
      facts.metrics.abstractValues += ordinary.metrics.abstractValues;
      facts.metrics.sources += ordinary.metrics.sources;
      if (ordinary.completedEntries.includes(entry) && !ordinary.diagnostics.length && ordinary.paths.length)
        facts.zeroEntry!.rejection = { kind: "direct-nonzero-input", ordinarySuccesses: ordinary.paths.length };
    }
    return facts;
  }

  /** An isolated may-view of current values, never AnalysisFacts. In particular
   * eager assertion observations must not contaminate exact selected replay. */
  conservativeSourceView(entry: string): ConservativeSourceView {
    if (!this.program.entries.includes(entry)) throw new Error("Expected a canonical entrypoint");
    const flow = new Dataflow(this.program, this.maxSteps, this.maxPaths, this.maxValues, this.engine,
      false, false, "equivalent-states", false, this.useFoldPartitions, "all-private",
      this.observeMerkle, this.observeCollections, false, this.useHashChoices);
    flow.conservative = true;
    flow.currentEntry = entry;
    flow.sourceHistories = new SourceHistories((work, values) => {
      flow.steps += work; flow.abstractValues += values;
      if (flow.steps <= flow.maxSteps && flow.abstractValues <= flow.maxValues) return true;
      flow.issue("analysis-budget", "Source effect history exhausted the shared allowance; view is incomplete", this.program.functions.get(entry)!.declaration.span);
      return false;
    });
    flow.hashRecipes = flow.newHashRecipes();
    flow.observePreimageInputs = this.predicateScope !== "witness" || flow.entryNeedsPreimagePredicates(entry);
    const fn = this.program.functions.get(entry)!, state = flow.entryState(fn.symbol.kind === "constructor");
    const args = fn.declaration.parameters.map(parameter => flow.typedValue(parameter.type,
      (_type, digest) => flow.source("entry-parameter", parameter.name, parameter.span, parameter.symbol, undefined, digest)));
    const results = flow.invoke(fn, args, state, [], fn.declaration.span);
    const result = flow.commonEvaluations(results, fn.declaration.span)[0];
    const history = result && flow.flushSourceHistory(result.state) ? flow.sourceHistories.snapshot(result.state.sourceHistory!) : undefined;
    return { status: flow.diagnostics.length ? "incomplete" : "available", diagnostics: structuredClone(flow.diagnostics),
      mayReachAssertions: structuredClone([...flow.assertionReaches.values()]), mayReturn: !!result,
      predicateStructureComplete: flow.predicateStructureComplete,
      choicePredicates: flow.choicePredicates.slice(),
      ...(result ? { witnessCalls: new Map(result.state.witnessCalls), otherChecks: !!result.state.otherChecks } : {}),
      ...(history && !flow.diagnostics.length ? { history } : {}),
      ...(result && !flow.diagnostics.length ? { current: { ledger: structuredClone(result.state.ledger),
        guards: [...result.state.guards], value: structuredClone(result.value) } } : {}),
      work: { steps: flow.steps, values: flow.abstractValues, sources: flow.sourceCount, joins: flow.conservativeJoins } };
  }

  /** Rule-scoped absence certificate from an isolated conservative may-view.
   * Every hash input and native Either payload selection that an exact
   * successful history can evaluate is evaluated here over joined current
   * values (see rule-certificates.ts). Only "absent" is a claim: a digest or
   * Either consumer has no finding on any successful history of this entry.
   * Candidates or diagnostics certify nothing and are not findings. */
  conservativeRuleCertificate(entry: string, kind: "digest" | "either", allowance = { steps: this.maxSteps, values: this.maxValues }): RuleCertificate {
    if (!this.program.entries.includes(entry) || !["digest", "either"].includes(kind)) throw new Error("Expected a canonical entrypoint and certificate kind");
    if (![allowance.steps, allowance.values].every(value => Number.isSafeInteger(value) && value >= 0)) throw new Error("Expected nonnegative certificate allowances");
    const flow = new Dataflow(this.program, Math.min(this.maxSteps, allowance.steps), this.maxPaths, Math.min(this.maxValues, allowance.values), this.engine,
      false, false, "equivalent-states", false, this.useFoldPartitions, "all-private",
      this.observeMerkle, this.observeCollections, false, this.useHashChoices);
    flow.conservative = true;
    flow.currentEntry = entry;
    flow.ruleCertificate = { kind, candidates: [], domains: new Map(), digests: [], sinks: [], constraints: [] };
    flow.hashRecipes = flow.newHashRecipes();
    flow.observePreimageInputs = this.predicateScope !== "witness" || flow.entryNeedsPreimagePredicates(entry);
    const fn = this.program.functions.get(entry)!, state = flow.entryState(fn.symbol.kind === "constructor");
    const args = fn.declaration.parameters.map(parameter => flow.typedValue(parameter.type,
      (_type, digest) => flow.source("entry-parameter", parameter.name, parameter.span, parameter.symbol, undefined, digest)));
    flow.commonEvaluations(flow.invoke(fn, args, state, [], fn.declaration.span), fn.declaration.span);
    if (!flow.diagnostics.length) for (const { input, location } of flow.ruleCertificate.digests) flow.certifyDigestInput(input, location);
    // A final domain projection can consume work after its last traversal check.
    // Finishing the view never permits a certificate beyond the shared allowance.
    if (flow.steps > flow.maxSteps || flow.abstractValues > flow.maxValues)
      flow.issue("analysis-budget", "Conservative certificate exhausted the shared work/value allowance; results are incomplete", fn.declaration.span);
    const work = { steps: flow.steps, values: flow.abstractValues };
    if (flow.diagnostics.length) return { status: "incomplete", reason: flow.diagnostics[0].message, work };
    const candidates = flow.ruleCertificate.candidates;
    if (candidates.length) return { status: "candidate", reason: `${candidates.length} possible ${kind === "digest" ? "small-domain digest input" : "Either selection"} observation(s), first at ${candidates[0]}`, work };
    return { status: "absent", work };
  }

  /** Coarse declaration classes of raw private sources anywhere in a value graph
   * (nested items/fields and comparison, ordering or negated operands). */
  private rawSourceClasses(root: unknown, into: Set<string>, location: Span): void {
    const pending: unknown[] = [root], seen = new Set<object>();
    while (pending.length) {
      const item = pending.pop();
      if (!item || typeof item !== "object" || seen.has(item)) continue;
      seen.add(item);
      if (++this.steps > this.maxSteps) { this.issue("analysis-budget", "Digest certificate traversal exhausted its allowance; results are incomplete", location); return; }
      if (Array.isArray(item)) { pending.push(...item); continue; }
      const value = item as AbstractValue;
      for (const flow of value.flows ?? []) if (flow.form === "raw") into.add(certificateSourceClass(flow.source));
      pending.push(value.items, value.fields && Object.values(value.fields), value.comparison?.left, value.comparison?.right,
        value.ordering?.left, value.ordering?.right, value.ordering?.leftBytes, value.negated, value.predicateAlternatives);
    }
  }

  private certifyDigestInput(input: AbstractValue, location: Span): void {
    const certificate = this.ruleCertificate!;
    const smallDomain = (type: string): boolean | undefined => {
      if (!certificate.domains.has(type)) {
        const domain = finiteDomain(this.program, type, 65536, 4096);
        this.steps += domain.work;
        certificate.domains.set(type, !domain.complete ? undefined : domain.upperBound !== undefined && domain.upperBound >= 2);
      }
      return certificate.domains.get(type);
    };
    const candidate = digestInputCandidate(input, smallDomain, () => ++this.steps <= this.maxSteps);
    if (candidate === undefined) { this.issue("analysis-budget", "Digest certificate traversal exhausted its allowance; results are incomplete", location); return; }
    if (!candidate) return;
    // Two distinct represented raw leaves whose declarations are never published
    // raw and never constrained anywhere stay private and non-constant on every
    // history, so the digest never has exactly one unpublished private leaf.
    if (!certificate.classes) {
      const classes = { published: new Set<string>(), constrained: new Set<string>() };
      for (const sink of certificate.sinks) this.rawSourceClasses(sink.value, classes.published, sink.location);
      for (const constraint of certificate.constraints) this.rawSourceClasses(constraint.value, classes.constrained, constraint.location);
      certificate.classes = classes;
    }
    const { published, constrained } = certificate.classes;
    const stable = new Set<string>(), pending = [input];
    while (pending.length && stable.size < 2) {
      const part = pending.pop()!;
      if (++this.steps > this.maxSteps) { this.issue("analysis-budget", "Digest certificate traversal exhausted its allowance; results are incomplete", location); return; }
      if (part.constant !== undefined) continue;
      if (part.items || part.fields) { pending.push(...part.items ?? [], ...Object.values(part.fields ?? {})); continue; }
      const own = part.flows.find(flow => flow.form === "raw" && flow.source.id === part.identity)?.source;
      const kind = own && certificateSourceClass(own);
      if (own && !published.has(kind!) && !constrained.has(kind!)) stable.add(own.id);
    }
    if (stable.size < 2) certificate.candidates.push(`${location.file.replace(/.*\//, "")}:${location.line}`);
  }

  /** Select one ordinary abstract history, including nested calls and expression
   * branches. Known conditions override the preference. No backtracking or
   * concrete feasibility claim, and never a whole-entry coverage certificate. */
  selectSourceWitness(entry: string, prefer: SourcePreference, allowance = { steps: this.maxSteps, values: this.maxValues }): ConditionalSourceSelection {
    if (!this.program.entries.includes(entry) || typeof prefer !== "boolean" && (!prefer || typeof prefer.first !== "boolean" || prefer.alternateWitnessLeaves !== true && prefer.preferPresentCollections !== true && prefer.evaluateBooleanRhs !== true)) throw new Error("Expected a canonical entrypoint and source preference");
    if (![allowance.steps, allowance.values].every(value => Number.isSafeInteger(value) && value >= 0)) throw new Error("Expected nonnegative source-evidence allowances");
    // Summaries/fold partitions/hash choices can retain several alternatives.
    // Run ordinary transfers in an isolated instance so selected observations
    // cannot pollute a later exhaustive scan or conservative view.
    const flow = new Dataflow(this.program, Math.min(this.maxSteps, allowance.steps), this.maxPaths, Math.min(this.maxValues, allowance.values), this.engine,
      false, false, "equivalent-states", this.observeCalls, false, this.predicateScope,
      this.observeMerkle, this.observeCollections, false, false, this.observeSignatures, this.observeEither, this.observeDigestInputs, this.observeArithmetic, this.observeMints, this.observeMintQuantities, this.observeInvocations, this.observeTransientOrigins, this.observeCommitInputs, this.observeSignatureKeyIdentity, this.observeSecpSignatures);
    flow.sourcePreference = prefer;
    const facts = flow.analyzeEntries([entry]);
    if (facts.diagnostics.length) return { status: "incomplete", diagnostics: structuredClone(facts.diagnostics), metrics: { ...facts.metrics } };
    const evidence = { assertions: structuredClone(facts.assertionReaches), calls: structuredClone(facts.callReaches ?? []), metrics: { ...facts.metrics } };
    if (!facts.paths.length) return { status: "rejected", ...evidence };
    if (facts.paths.length !== 1) throw new Error("Selected source witness returned multiple histories");
    return { status: "selected", path: structuredClone(facts.paths[0]), ...evidence };
  }

  private selectedSourceBranch(value: AbstractValue, state: State, rhsTruth?: boolean): { truth: boolean; state: State } | undefined {
    const leafPreference = (value: AbstractValue, depth = 0): boolean | undefined => {
      if (++this.steps > this.maxSteps) {
        this.issue("analysis-budget", "Source preference exhausted the shared allowance", this.program.functions.get(this.currentEntry)!.declaration.span); return;
      }
      if (depth > 16) return;
      if (value.negated) { const preference = leafPreference(value.negated, depth + 1); return preference === undefined ? undefined : !preference; }
      const source = value.type === "Boolean" && !value.comparison && !value.ordering
        ? value.flows.find(flow => flow.source.id === value.identity)?.source : undefined;
      const preference = this.sourcePreference as Exclude<SourcePreference, boolean>;
      return source?.invocation ? (preference.first !== (source.invocation.leaf % 2 === 1)) !== !!preference.witnessPhase : undefined;
    };
    const preference = typeof this.sourcePreference === "boolean" ? this.sourcePreference
      : rhsTruth !== undefined && this.sourcePreference?.evaluateBooleanRhs ? rhsTruth
      : value.collectionPredicate && this.sourcePreference?.preferPresentCollections ? !value.collectionPredicate.empty
      : this.sourcePreference?.alternateWitnessLeaves ? leafPreference(value) ?? this.sourcePreference.first : this.sourcePreference!.first;
    const choices = value.constantKind === "boolean" && value.constant !== undefined
      ? [value.constant === "true"] : [preference, !preference];
    for (const truth of choices) {
      const next = this.cloneState(state), possible = this.assume(value, truth, next);
      if (this.incompleteEntries.has(this.currentEntry)) return;
      if (possible) return { truth, state: next };
    }
  }

  /** Scanner-only alternative; the ordinary exact APIs remain reference oracles.
   * With `merkleEvidence` (the scan reviews Merkle membership), correlated graphs,
   * which have no Merkle certificate, stay off. Source queries certify Merkle
   * findings, but an enforced proof root cannot be certified, so they run only
   * after an exhaustive attempt exhausts its path allowance (see analyzeEntries). */
  analyzeWithCorrelatedQueries(predicates: readonly CorrelatedPredicate[], requireSuccessfulEntry = false, sourceQueries = false, merkleEvidence = false): CorrelatedAnalysis {
    const correlated: CorrelatedAnalysis["correlated"] = [];
    const sources: SourceQueryEvidence[] = [];
    // This observer has no certificate for may-joined source histories.
    if (this.observeEither || this.observeDigestInputs || this.observeCommitInputs || this.observeArithmetic || this.observeMints) return { exact: this.analyze(), correlated, sources };
    const exact = this.analyzeEntries(this.program.entries, { predicates, results: correlated, requireSuccessfulEntry, sources: sourceQueries ? sources : undefined, graphs: !merkleEvidence, upfrontSources: !merkleEvidence });
    return { exact, correlated, sources };
  }

  /** Genuine exact analysis of canonical entrypoints, in Program entry order.
   * One invocation preserves the shared value allowance and entry-local steps.
   * This API never accepts representative paths or modifies Program.entries.
   */
  analyzeSubset(entries: readonly string[]): AnalysisFacts {
    if (this.counterSelection) throw new Error("Exact subset analysis cannot run during Counter selection");
    if (!Array.isArray(entries) || Object.getPrototypeOf(entries) !== Array.prototype || entries.length > this.program.entries.length
      || Reflect.ownKeys(entries).length !== entries.length + 1) throw new Error("Expected an entrypoint array");
    const allowed = new Set(this.program.entries);
    const selected = new Set<string>();
    for (let index = 0; index < entries.length; index++) {
      const field = Object.getOwnPropertyDescriptor(entries, index);
      if (!field || !("value" in field) || !field.enumerable || typeof field.value !== "string"
        || !allowed.has(field.value) || selected.has(field.value)) throw new Error("Expected distinct canonical entrypoints");
      selected.add(field.value);
    }
    return this.analyzeEntries(this.program.entries.filter(entry => selected.has(entry)));
  }

  /** Replay a selected source CFG through the full ordinary state transfers.
   * Construction is lazy: it cannot publish eager assertion/call observations.
   * This is not used by scanners or successful-history consumers until their
   * queries can cover the retained alternatives without flattening them. */
  selectConditionalSource(entry: string, decisions: ReadonlyMap<number, boolean>): ConditionalSourceSelection {
    if (!this.program.entries.includes(entry) || this.counterSelection || this.conditionalSelection) throw new Error("Expected an idle canonical entrypoint");
    const graph = this.engine === "instructions" ? this.program.instructionCFG(entry) : this.program.functions.get(entry)!.cfg;
    for (const [node, value] of decisions) if (graph.nodes[node]?.kind !== "branch" || typeof value !== "boolean") throw new Error("Expected source branch decisions");
    this.conditionalSelection = { entry, decisions: new Map(decisions) };
    try {
      const facts = this.analyzeEntries([entry]);
      if (facts.diagnostics.length) return { status: "incomplete", diagnostics: structuredClone(facts.diagnostics), metrics: { ...facts.metrics } };
      const evidence = { assertions: structuredClone(facts.assertionReaches), calls: structuredClone(facts.callReaches ?? []), metrics: { ...facts.metrics } };
      if (!facts.paths.length) return { status: "rejected", ...evidence };
      if (facts.paths.length !== 1) throw new Error("Conditional source replay returned multiple histories");
      return { status: "selected", path: structuredClone(facts.paths[0]), ...evidence };
    } finally { this.conditionalSelection = undefined; }
  }

  /**
   * Select one eligible Boolean history using ordinary condition, control and
   * mutation transfers. Entry parameters remain private unknown values: selecting
   * an edge must not erase their provenance by substituting Boolean constants.
   * No AnalysisFacts/completedEntries result escapes this deliberately scoped API.
   */
  selectCounterWitness(entry: string, decisions: readonly boolean[], limits: CounterWitnessLimits = {}): CounterWitnessResult {
    if (!limits || typeof limits !== "object" || Array.isArray(limits)
      || Object.keys(limits).some(key => !["region", "maxGraphNodes", "maxProjectionWork"].includes(key))) throw new Error("Invalid Counter witness limits");
    if (this.counterSelection) throw new Error("Counter witness selection is already active");
    const extracted = extractTerminalCounterRegion(this.program, entry, limits.region);
    if (extracted.status !== "eligible") return extracted.status === "ineligible"
      ? { status: "ineligible", reason: extracted.reason, location: { ...extracted.location } }
      : { status: "incomplete", diagnostics: extracted.diagnostics };
    const graph = buildCounterHistoryGraph(extracted.region, limits.maxGraphNodes);
    if (graph.status === "incomplete") return graph;
    const projected = projectCounterHistory(graph.value, decisions, limits.maxProjectionWork);
    if (projected.status === "incomplete") return projected;
    const sites = this.engine === "instructions" ? extracted.region.graphs.instructions : extracted.region.graphs.statements;
    const selection = { entry, branches: new Map(sites.diamonds.map((site, index) => [site.branch, projected.value.decisions[index]])), visited: new Set<number>() };
    this.counterSelection = selection;
    try {
      const facts = this.analyzeEntries([entry]);
      if (facts.diagnostics.length) return { status: "incomplete", diagnostics: structuredClone(facts.diagnostics) };
      if (!facts.paths.length) return { status: "no-surviving-path", decisions: projected.value.decisions, metrics: { ...facts.metrics } };
      if (facts.paths.length !== 1 || selection.visited.size !== selection.branches.size) return {
        status: "incomplete", diagnostics: [{ code: "counter-witness-coverage", message: "Selected Counter history did not traverse exactly its qualified branches; results are incomplete", location: { ...extracted.region.location } }],
      };
      return { status: "selected", decisions: projected.value.decisions, projection: projected.value, path: structuredClone(facts.paths[0]), metrics: { ...facts.metrics } };
    } finally {
      this.counterSelection = undefined;
    }
  }

  /** Issues of the current exhaustive entry attempt, when a source fallback may follow it. */
  private attemptIssues?: { code: string; message: string }[];
  /** Retained-history limits whose exhaustion alone admits a source fallback. */
  private static readonly pathBudgetMessages: ReadonlySet<string> = new Set(["Abstract path budget exhausted; results are incomplete", "Higher-order call path budget exceeded"]);

  /** Source query in an isolated instance limited to this entry's remaining
   * steps and the remaining shared values; its work is charged here. */
  private remainingSourceQuery(entry: string): SourceQueryResult {
    const remaining = new Dataflow(this.program, Math.max(0, this.maxSteps - this.steps), this.maxPaths, this.maxValues - this.abstractValues,
      this.engine, this.useSummaries, this.useStatefulSummaries, this.pathSemantics, this.observeCalls, this.useFoldPartitions, this.predicateScope,
      this.observeMerkle, this.observeCollections, this.observeInitialization, this.useHashChoices, this.observeSignatures, this.observeEither, this.observeDigestInputs, this.observeArithmetic, this.observeMints, this.observeMintQuantities, this.observeInvocations, this.observeTransientOrigins, this.observeCommitInputs, this.observeSignatureKeyIdentity, this.observeSecpSignatures);
    const query = querySourceEntry(remaining, entry);
    this.steps += query.steps; this.abstractValues += query.values; this.sourceCount += query.sources;
    return query;
  }

  private analyzeEntries(entries: readonly string[], correlated?: { predicates: readonly CorrelatedPredicate[]; results: CorrelatedAnalysis["correlated"]; requireSuccessfulEntry: boolean; sources?: SourceQueryEvidence[]; graphs?: boolean; upfrontSources?: boolean }): AnalysisFacts {
    this.valueFingerprints = new ValueFingerprints();
    this.summaryFingerprints = new ValueFingerprints(true);
    this.controlDependencies = new ControlDependencies();
    this.liveValueIdentities = new WeakMap();
    this.hashRecipes = this.newHashRecipes();
    this.eitherBranches.clear();
    this.sourceCount = 0;
    this.abstractValues = 0;
    this.totalSteps = 0;
    const scalarSelected = this.observeInvocations.has(PUBLIC_SCALAR_CAST);
    const bindingSteps = this.secretBindingObservation ? new Map<string, number>() : undefined;
    if (bindingSteps) this.abstractValues += 24 + entries.length * 12;
    const bindingRefused = !!bindingSteps && this.abstractValues > this.maxValues;
    // Reserve the selected-only carrier, fixed matcher/failure frame and every
    // entry slot before allocating. Ordinary/default callers keep their counters.
    if (scalarSelected) this.abstractValues += 24 + entries.length * 12;
    const scalarCarrierRefused = scalarSelected && this.abstractValues > this.maxValues;
    // Even refusal retains the precharged failure carrier, without executing
    // source transfers. Its original limits/spent counters forbid a retry.
    const scalarSteps = scalarSelected ? new Map<string, number>() : undefined;
    const finishEntry = () => {
      if (scalarSelected) {
        this.steps++;
        if (scalarCarrierRefused) this.issue("public-scalar-retention-budget", "Selected scalar budget carrier exhausted the value allowance", this.program.functions.get(this.currentEntry)!.declaration.span);
        if (scalarSteps) {
          if (this.steps > this.maxSteps) this.issue("public-scalar-retention-budget", "Selected scalar budget carrier exhausted entry work", this.program.functions.get(this.currentEntry)!.declaration.span);
          scalarSteps.set(this.currentEntry, this.steps);
        }
      }
      if (bindingSteps) {
        this.secretBindingCharge(1, 0, this.program.functions.get(this.currentEntry)!.declaration.span);
        bindingSteps.set(this.currentEntry, this.steps);
      }
      this.totalSteps += this.steps;
    };
    this.writeCount = 0;
    this.snapshotCount = 0;
    this.nativeCount = 0;
    this.summaryHits = 0;
    this.statefulSummaryHits = 0;
    this.readSummaryHits = 0;
    this.summaryEffects = 0;
    this.guardSubsumptions = 0;
    this.summaries.clear();
    this.mutationSummaries.clear();
    this.readSummaries.clear();
    this.branchSummaries.clear();
    this.incompleteEntries.clear();
    this.diagnostics.length = 0;
    this.failedAssertions.length = 0;
    this.callReaches.clear();
    this.assertionReaches.clear();
    const paths: SuccessfulPath[] = [], exactEntries: string[] = [];
    const initialization: InitializationEvidence[] = [];
    const initializers = new Set(this.observeInitialization ? initializerEntries(this.program) : []);
    const sourceCandidates = new Set<string>(), preparation = new Map<string, number>();
    if (correlated?.sources && correlated.upfrontSources !== false && this.engine === "instructions") for (const entry of entries) {
      let work = 0;
      if (!initializers.has(entry) && sourceQueryCandidate(this.program, entry, Math.floor(Math.log2(this.maxPaths)) + 1, () => ++work <= this.maxSteps)) sourceCandidates.add(entry);
      else if (!initializers.has(entry)) {
        // Read-only joined expressions can expand histories too. This bounded
        // structural scan is charged only when it changes admission, so cheap
        // exact entries keep their existing preparation cost.
        let extra = 0;
        if (sourceQueryCandidate(this.program, entry, Math.floor(Math.log2(this.maxPaths)) + 1, () => ++extra + work <= this.maxSteps, true)) { sourceCandidates.add(entry); work += extra; }
        else {
          // Repeated invocations of branching helpers (call sites, fold/map
          // elements) also expand exact histories; likewise charged only if admitted.
          let repeated = 0;
          if (repeatedCallCandidate(this.program, entry, Math.floor(Math.log2(this.maxPaths)) + 1, () => ++repeated + work <= this.maxSteps, true)) { sourceCandidates.add(entry); work += repeated; }
        }
      }
      preparation.set(entry, work);
    }
    // Finish the ordinarily merging entries before spending the shared value
    // allowance on expanded update histories. Exact public APIs keep Program
    // order; scanner result coverage is restored to Program order by its caller.
    const planned = sourceCandidates.size ? [...entries.filter(entry => !sourceCandidates.has(entry)), ...entries.filter(entry => sourceCandidates.has(entry))] : entries;
    for (const entry of planned) {
      this.currentEntry = entry;
      this.compressionTokens = new Set();
      this.compressionTouchCache = new WeakMap();
      this.steps = preparation.get(entry) ?? 0;
      // Entrypoints begin with independent abstract storage. Do not traverse an
      // unrelated entry's recipes or let its selector identities affect costs.
      this.hashRecipes = this.newHashRecipes();
      const fn = this.program.functions.get(entry)!;
      if (bindingRefused) {
        this.issue("secret-binding-retention-budget", "Selected binding carrier exhausted its value allowance", fn.declaration.span);
        finishEntry(); continue;
      }
      if (scalarCarrierRefused) { finishEntry(); continue; }
      if (correlated?.sources && sourceCandidates.has(entry) && this.steps < this.maxSteps && this.abstractValues < this.maxValues) {
        const query = this.remainingSourceQuery(entry);
        if (query.status === "covered") {
          correlated.sources.push(query.evidence); finishEntry(); continue;
        }
        if (this.steps >= this.maxSteps || this.abstractValues >= this.maxValues) {
          this.issue("analysis-budget", `${query.reason}; shared source-query allowance exhausted`, fn.declaration.span);
          finishEntry(); continue;
        }
      }
      if (correlated?.sources && this.steps >= this.maxSteps) {
        this.issue("analysis-budget", "Source-query preparation exhausted the shared entry work allowance; results are incomplete", fn.declaration.span);
        finishEntry(); continue;
      }
      // Select before exhausting exact paths. A syntactic upper bound can
      // overselect, so unsupported graph attempts fall back using what remains.
      // Read-only void entries often lose dead branch values and merge cheaply
      // in the exact engine; keep that conservative optimization preference.
      const candidate = correlated && correlated.graphs !== false && !initializers.has(entry) && this.engine === "instructions" && this.pathSemantics === "equivalent-states"
        && (fn.writesState.size > 0 || this.program.representationOf(fn.declaration.type) !== "[]")
        && correlatedBranchCount(this.program, entry, Math.floor(Math.log2(this.maxPaths)) + 1) > Math.log2(this.maxPaths);
      if (candidate && this.abstractValues < this.maxValues) {
        const built = analyzeCorrelatedEntry(this.program, entry, { maxSteps: Math.max(1, Math.min(this.maxSteps - this.steps, 1000000)), maxFrontier: Math.min(this.maxPaths, 1000000), maxValues: Math.min(this.maxValues - this.abstractValues, 1000000) }, this.sourceCount);
        const used = built.status === "complete" ? built.graph.work : built.work;
        this.steps += used.steps; this.abstractValues += used.values;
        if (built.status === "complete" && this.steps < this.maxSteps && this.abstractValues < this.maxValues) {
          const query = queryCorrelatedGraph(built.graph, correlated!.predicates, {
            maxWork: Math.min(this.maxSteps - this.steps, 1000000), maxProjectionWork: Math.min(this.maxSteps - this.steps, 1000000),
            maxWitnesses: Math.min(this.maxPaths, 1000000), maxValues: Math.min(this.maxValues - this.abstractValues, 1000000),
          });
          this.steps += query.work.query + query.work.projections; this.abstractValues += query.work.values;
          // Assertion-free graphs can still have no surviving invocation (e.g.
          // checked casts). A full successful observation disproves that claim;
          // rejected probes prove nothing and must fall back to exact analysis.
          let successCovered = !correlated!.requireSuccessfulEntry || query.status === "complete" && query.witnesses.length > 0;
          // Rejected query observations consume this allowance too.
          const remainingObservations = Math.max(0, Math.min(this.maxPaths, 1000000) - query.work.witnesses);
          if (query.status === "complete" && !successCovered) for (const choice of [false, true].slice(0, remainingObservations)) {
            const remainingSteps = Math.min(this.maxSteps - this.steps, 1000000);
            const remainingValues = Math.min(this.maxValues - this.abstractValues, 1000000);
            if (remainingSteps <= 0 || remainingValues <= 0) break;
            const observation = selectCorrelatedObservation(built.graph, built.graph.choices.map(() => choice), remainingSteps, remainingValues);
            this.steps += observation.work; this.abstractValues += observation.values;
            if (observation.status === "selected") { successCovered = true; break; }
            if (observation.status === "incomplete") {
              for (const diagnostic of observation.diagnostics) this.issue(diagnostic.code, diagnostic.message, diagnostic.location);
              break;
            }
          }
          if (query.status === "complete" && successCovered) {
            correlated!.results.push({ graph: built.graph, query });
            this.sourceCount += fn.declaration.parameters.length;
            finishEntry(); continue;
          }
          if (query.status === "incomplete" && (this.steps >= this.maxSteps || this.abstractValues >= this.maxValues)) for (const diagnostic of query.diagnostics) this.issue(diagnostic.code, diagnostic.message, diagnostic.location);
        }
        if (this.steps >= this.maxSteps || this.abstractValues >= this.maxValues) {
          this.issue("analysis-budget", "Correlated construction/query exhausted the shared analysis allowance; results are incomplete", fn.declaration.span);
          finishEntry(); continue;
        }
      }
      exactEntries.push(entry);
      // A Merkle-reviewing entry (no up-front source admission) whose exhaustive attempt
      // exhausts only its path allowance may still be covered by a source query
      // with the entry's remaining step and the shared value allowance. The
      // attempt's work stays charged; its partial evidence is discarded only
      // when the query covers the entry.
      // Only scans that review Merkle membership use this fallback: they have no
      // up-front source admission and no correlated graphs. Other scans keep
      // their existing admission order and exhaustion results unchanged.
      const fallback = !!correlated?.sources && correlated.upfrontSources === false && !sourceCandidates.has(entry) && !initializers.has(entry) && this.engine === "instructions"
        && this.pathSemantics === "equivalent-states" && !this.incompleteEntries.has(entry);
      const attempt = fallback ? { diagnostics: this.diagnostics.length, failures: this.failedAssertions.length,
        assertions: new Set(this.assertionReaches.keys()), calls: new Set(this.callReaches.keys()) } : undefined;
      if (attempt) this.attemptIssues = [];
      this.observePreimageInputs = this.predicateScope !== "witness" || this.entryNeedsPreimagePredicates(entry);
      const state = this.entryState(fn.symbol.kind === "constructor");
      this.checkCollectionBudget(state, fn.declaration.span);
      const args = fn.declaration.parameters.map(parameter => {
        let leaf = 0;
        const argument = this.typedValue(parameter.type, (_type, digest) => {
          const value = this.source("entry-parameter", parameter.name, parameter.span, parameter.symbol, undefined, digest);
          if (this.observeDigestInputs) value.flows[0].source.declarationLeaf = leaf++;
          return value;
        });
        if (this.contractRecipientObservation?.parameter === parameter.symbol) {
          const tag = argument.fields?.is_left;
          this.steps += 3; this.abstractValues += 3;
          if (!tag || this.steps > this.maxSteps || this.abstractValues > this.maxValues)
            this.issue("contract-recipient-input-budget", "Recipient tag layout or shared allowance is unavailable", parameter.span);
          else return { ...argument, fields: { ...argument.fields, is_left: { ...tag, constant: "false", constantKind: "boolean" as const } } };
        }
        return this.zeroInput?.parameter === parameter.symbol ? { ...argument, constant: "0", constantKind: "integer" as const } : argument;
      });
      const results = this.invoke(fn, args, state, [], fn.declaration.span);
      for (const result of results) if (result.state.checkpoints) result.state.checkpoints = result.state.checkpoints.map(checkpoint => ({
        ...checkpoint, state: this.committedProofState(checkpoint.state, result.state),
      }));
      this.checkHashChoiceConstraints(results, fn.declaration.span);
      // Rule evidence whose exact value could depend on an elided fold partition
      // (constants, equalities or refined tags) makes the observation incomplete.
      // Checkpoint prefixes are committed histories too; check their own refinement.
      if (this.compressionTokens.size) for (const state of results.flatMap(result => [result.state, ...(result.state.checkpoints ?? []).map(checkpoint => checkpoint.state)])) {
        const evidence: unknown[] = [];
        if (this.observeDigestInputs) evidence.push(state.sinks);
        if (this.observeEither) evidence.push(state.eitherReads, (state.eitherReads ?? []).map(read => this.refine(read.tag, state)));
        if (this.observeInvocations.size) evidence.push((state.operations ?? []).filter(operation => operation.kind === "circuit-invocation" || operation.kind === "merkle-insert"));
        if (this.observeMints) evidence.push((state.operations ?? []).filter(operation => operation.kind === "shielded-mint"));
        if (this.compressionTouches(evidence)) {
          this.issue("observation-compression-dependency", "This rule cannot track all dependencies through an aggregated numeric value within its analysis limits; review this entry manually", fn.declaration.span);
          break;
        }
      }
      const issues = this.attemptIssues; this.attemptIssues = undefined;
      if (attempt && issues?.length && issues.every(issue => issue.code === "analysis-budget" && Dataflow.pathBudgetMessages.has(issue.message))
        && this.steps < this.maxSteps && this.abstractValues < this.maxValues) {
        const query = this.remainingSourceQuery(entry);
        if (query.status === "covered" && this.steps <= this.maxSteps && this.abstractValues <= this.maxValues) {
          this.diagnostics.length = attempt.diagnostics; this.failedAssertions.length = attempt.failures;
          for (const key of [...this.assertionReaches.keys()]) if (!attempt.assertions.has(key)) this.assertionReaches.delete(key);
          for (const key of [...this.callReaches.keys()]) if (!attempt.calls.has(key)) this.callReaches.delete(key);
          this.incompleteEntries.delete(entry); exactEntries.pop();
          correlated!.sources!.push(query.evidence); finishEntry(); continue;
        }
      }
      if (initializers.has(entry) && !this.incompleteEntries.has(entry)) initialization.push(this.initializationEvidence(fn));
      const history = (state: State): SuccessfulPath => (this.secretBindingCharge(1, 8, fn.declaration.span), ({ ...this.complementaryHistory(state), ...this.enrollmentHistory(state), ...(this.contractRecipientObservation && this.recipientCharge(3, 3, fn.declaration.span) ? { contractRecipientHistory: { operations: state.operations?.length ?? 0, predicates: state.predicates?.length ?? 0 } } : {}), ...(this.observeEither ? { eitherReads: (state.eitherReads ?? []).map(read => ({ ...read, tag: this.refine(read.tag, state) })) } : {}), ...(state.witnessCalls?.size ? { checkCoverage: state.otherChecks ? "unclassified" as const : "raw-witness-only" as const } : {}), ...(state.witnessCalls ? { witnessCalls: state.witnessCalls } : {}), ...(state.integerDomains ? { integerDomains: state.integerDomains } : {}), predicates: state.predicates ?? [], ...(this.mapDebitObservation ? { operations: state.operations ?? [] } : state.operations?.length ? { operations: state.operations } : {}), entry, bindings: state.bindings, sinks: state.sinks, path: state.path, writes: this.enrollmentWrites(state) }));
      // A successful history is provable; after proof, a failure of its fallible
      // segment commits only the guaranteed prefix at a reached checkpoint.
      const outcomes = new Set<string>();
      // Committed outcome, excluding explanatory trace steps.
      const outcome = (path: SuccessfulPath): string => this.valueFingerprints.key({ writes: path.writes, sinks: path.sinks, operations: path.operations, predicates: path.predicates,
        bindings: path.bindings, eitherReads: path.eitherReads, checkCoverage: path.checkCoverage, witnessCalls: path.witnessCalls && [...path.witnessCalls], integerDomains: path.integerDomains && [...path.integerDomains] });
      const histories: SuccessfulPath[] = [];
      for (const result of results) {
        const full = history(result.state);
        if (this.checkpointObservation) {
          this.checkpointFullHistories++;
          full.checkpointCount = result.state.checkpoints?.length ?? 0;
          full.checkpointOutcomes = [];
          for (const [ordinal, checkpoint] of (result.state.checkpoints ?? []).entries()) {
            if (++this.steps > this.maxSteps || ++this.abstractValues > this.maxValues) {
              this.issue("analysis-budget", "Checkpoint linkage exceeded the shared entry allowance; results are incomplete", fn.declaration.span);
              break;
            }
            if (!checkpoint.site) {
              this.issue("unsupported-checkpoint-linkage", "Checkpoint invocation identity is unavailable; results are incomplete", fn.declaration.span);
              break;
            }
            full.checkpointOutcomes.push({ ordinal, ...checkpoint.site, history: history(checkpoint.state) });
          }
        }
        histories.push(full);
        if (!result.state.checkpoints?.length) continue;
        outcomes.add(outcome(full));
        for (const checkpoint of result.state.checkpoints) {
          const prefix = history(checkpoint.state), key = outcome(prefix);
          if (outcomes.has(key)) continue;
          outcomes.add(key);
          histories.push(prefix);
        }
      }
      if (histories.length > this.maxPaths) {
        this.issue("analysis-budget", "Committed checkpoint histories exceeded the entry path allowance; results are incomplete", fn.declaration.span);
      } else paths.push(...histories);
      finishEntry();
    }
    return { program: this.program, ...(bindingSteps ? { secretBindingEvidence: { maxSteps: this.maxSteps, maxValues: this.maxValues, maxPaths: this.maxPaths, entrySteps: bindingSteps } } : {}), ...(scalarSteps ? { publicScalarEvidence: { maxSteps: this.maxSteps, maxValues: this.maxValues, maxPaths: this.maxPaths, entrySteps: scalarSteps } } : {}), ...(this.zeroInput ? { zeroEntry: { ...this.zeroInput, maxSteps: this.maxSteps, maxValues: this.maxValues } } : {}), ...(this.observeInvocations.size ? { invocationEvidence: [...this.observeInvocations] } : {}), ...(this.observeDigestInputs ? { digestEvidence: true } : {}), ...(this.observeCommitInputs ? { commitEvidence: true } : {}), ...(this.observeTransientOrigins ? { transientEvidence: true as const } : {}), ...(this.observeArithmetic ? { arithmeticEvidence: true } : {}), ...(this.observeEither ? { eitherEvidence: true, eitherBranches: [...this.eitherBranches.values()] } : {}), ...(this.observeSignatures ? { signatureEvidence: true } : {}), ...(this.observeMints ? { mintEvidence: true } : {}), ...(this.observeMintQuantities ? { mintQuantityEvidence: true as const } : {}), ...(this.observeInitialization ? { initialization } : {}), pathSemantics: this.pathSemantics, predicateScope: this.predicateScope, ...(this.observeMerkle ? { merkleEvidence: true } : {}), ...(this.observeCollections ? { collectionEvidence: true } : {}), paths, diagnostics: this.diagnostics, failedAssertions: this.failedAssertions, assertionReaches: [...this.assertionReaches.values()], ...(this.observeCalls ? { callReaches: [...this.callReaches.values()] } : {}), metrics: { steps: this.totalSteps, sources: this.sourceCount, paths: paths.length, abstractValues: this.abstractValues, summaryHits: this.summaryHits, summaryEntries: this.summaries.size + this.mutationSummaries.size + this.readSummaries.size + this.branchSummaries.size, statefulSummaryHits: this.statefulSummaryHits, readSummaryHits: this.readSummaryHits, summaryEffects: this.summaryEffects, guardSubsumptions: this.guardSubsumptions }, completedEntries: exactEntries.filter(entry => !this.incompleteEntries.has(entry)) };
  }

  private entryState(defaults: boolean): State {
    const state: State = { identityText: this.program.meteringIdentity, hashRecipes: this.useHashChoices ? this.hashRecipes : undefined, env: new Map(), ledger: new Map(), ledgerVersions: new Map(), collections: new CollectionFacts(256, this.observeCapacity), lists: new ListFacts<AbstractValue>(), bindings: [], sinks: [], path: [], control: [], truths: new Map(), known: new Map(), excluded: new Map(), aggregateExclusions: new Map(), aggregateExclusionLeaves: 0, aggregateExclusionsExhausted: false, guards: new Set(), writes: [] };
    if (this.complementarySendObservation) state.scalarMeter = withIdentityMeter(this.program.meteringIdentity, (work: number, values: number) => {
      if (!this.complementaryCharge(work, values, this.program.functions.get(this.currentEntry)!.declaration.span))
        throw new Error("Complementary scalar transfer allocation refused");
    });
    if (defaults) for (const symbol of this.program.activeSymbols().filter(symbol => symbol.kind === "ledger")) {
      const region = { root: symbol.id, path: [], type: symbol.type };
      const value = this.defaultValue(symbol.type);
      state.ledger.set(regionKey(region), value);
      if (value.emptyCollection) state.collections.reset(region);
      if (value.emptyList) state.lists.reset(region, value);
      if (value.emptyMerkle) this.merkleFacts(state).reset(region, value);
    }
    return state;
  }

  private checkHashChoiceConstraints(results: Evaluation[], location: Span): void {
    if (results.some(result => [result.state, ...(result.state.checkpoints ?? []).map(checkpoint => checkpoint.state)]
      .some(state => this.hashRecipes.pendingConstraints(state))))
      this.issue("unsupported-hash-choice-constraint", "Surviving hash-choice constraints require disjunctive reasoning; results are incomplete", location);
  }

  /** Exact immediate constructor-to-entry evidence; isolated from ordinary
   * failed assertions and unknown entry storage. Constructor defaults are used
   * only at this explicit invocation boundary. */
  analyzeConfiguredCapacityEntry(entry: string): AnalysisFacts {
    const facts = this.analyzeSubset([]);
    const fn = this.program.functions.get(entry), constructor = this.program.entries.map(id => this.program.functions.get(id)!).find(item => item.symbol.kind === "constructor");
    if (!fn || !this.program.entries.includes(entry) || fn.symbol.kind === "constructor") throw new Error("Expected exported gate entry");
    this.currentEntry = entry; this.steps = 0; this.observeCapacity = true; this.capacityPrefixes = [];
    const evidence: NonNullable<AnalysisFacts["configuredCapacity"]> = { entry, constructor: constructor?.symbol.id ?? "", prefixes: [], constructions: 0, successfulInvocations: 0, maxSteps: this.maxSteps, maxValues: this.maxValues };
    const boundary = (state: State): State => ({ ...this.cloneState(state), env: new Map(), guards: new Set(), bindings: [], sinks: [], writes: [], path: [], control: [], predicates: [], operations: [], witnessCalls: new Map(), integerDomains: undefined, branchJournal: undefined, otherChecks: undefined });
    const path = (id: string, state: State): SuccessfulPath => ({ entry: id, bindings: state.bindings.slice(), sinks: state.sinks.slice(), writes: state.writes.slice(), path: state.path.slice(), operations: state.operations?.slice(), predicates: state.predicates?.slice() });
    const run = (target: FunctionInfo, state: State, step: 0 | 1) => {
      this.sequenceStep = step;
      this.summaries.clear(); this.mutationSummaries.clear(); this.readSummaries.clear(); this.branchSummaries.clear();
      const args = target.declaration.parameters.map(parameter => this.typedValue(parameter.type, (_type, digest) => this.source("entry-parameter", parameter.name, parameter.span, parameter.symbol, undefined, digest)));
      return this.invoke(target, args, boundary(state), [], target.declaration.span);
    };
    try {
      if (!constructor || this.pathSemantics !== "equivalent-states" || this.predicateScope !== "all" || !this.observeCollections || this.useFoldPartitions || this.useHashChoices) {
        this.issue("capacity-evidence-unavailable", "Capacity review needs a represented constructor and exact uncompressed collection/predicate observations", fn.declaration.span);
      } else {
        const defaults = this.entryState(true); this.checkCollectionBudget(defaults, fn.declaration.span);
        for (const initial of run(constructor, defaults, 0)) {
          if (this.incompleteEntries.has(entry)) break;
          if (++evidence.constructions > this.maxPaths) { this.issue("capacity-observation-budget", "Constructor histories exhausted the path allowance", fn.declaration.span); break; }
          const constructionRetained = 1 + initial.state.bindings.length + initial.state.sinks.length + initial.state.writes.length + initial.state.path.length + (initial.state.predicates?.length ?? 0) + (initial.state.operations?.length ?? 0);
          this.steps += constructionRetained; this.abstractValues += constructionRetained;
          if (this.steps > this.maxSteps || this.abstractValues > this.maxValues) { this.issue("capacity-observation-budget", "Retained constructor evidence exhausted the shared allowance", fn.declaration.span); break; }
          this.capacityConstruction = path(constructor.symbol.id, initial.state);
          const results = run(fn, initial.state, 1);
          evidence.successfulInvocations += results.length;
          for (const result of results) {
            const retained = 1 + result.state.bindings.length + result.state.sinks.length + result.state.writes.length + result.state.path.length + (result.state.predicates?.length ?? 0) + (result.state.operations?.length ?? 0);
            this.steps += retained; this.abstractValues += retained;
            if (this.steps > this.maxSteps || this.abstractValues > this.maxValues) { this.issue("capacity-observation-budget", "Complete gate evidence exhausted the shared allowance", fn.declaration.span); break; }
            this.capacityPrefixes.push({ construction: this.capacityConstruction, location: fn.declaration.span, gate: path(entry, result.state) });
          }
          if (evidence.successfulInvocations > this.maxPaths) { this.issue("capacity-observation-budget", "Gate histories exhausted the path allowance", fn.declaration.span); break; }
        }
        if (!evidence.constructions && !this.incompleteEntries.has(entry)) this.issue("capacity-construction-unavailable", "No modeled successful constructor history; no initialized-state result is available", fn.declaration.span);
      }
      if (!this.incompleteEntries.has(entry)) { evidence.prefixes = this.capacityPrefixes; facts.completedEntries = [entry]; }
      facts.configuredCapacity = evidence;
      facts.metrics.steps = this.steps; facts.metrics.abstractValues = this.abstractValues; facts.metrics.sources = this.sourceCount; facts.metrics.paths = evidence.successfulInvocations;
      facts.metrics.summaryHits = this.summaryHits; facts.metrics.statefulSummaryHits = this.statefulSummaryHits; facts.metrics.readSummaryHits = this.readSummaryHits;
      facts.metrics.summaryEntries = this.summaries.size + this.mutationSummaries.size + this.readSummaries.size; facts.metrics.summaryEffects = this.summaryEffects;
      return facts;
    } finally {
      this.observeCapacity = false; this.sequenceStep = undefined; this.capacityConstruction = undefined; this.capacityPrefixes = [];
      // No sequence failure or assertion reach is ordinary entry evidence.
      this.failedAssertions.length = 0; this.assertionReaches.clear(); this.callReaches.clear();
    }
  }

  private initializationEvidence(fn: FunctionInfo): InitializationEvidence {
    const evidence: InitializationEvidence = { entry: fn.symbol.id, firstSuccesses: 0, secondSuccesses: 0, pairs: [] };
    // Assertions in a rejected second invocation must not become single-entry
    // impossible-assertion findings. Keep original observation objects untouched.
    const failures = this.failedAssertions.splice(0);
    const assertions = new Map(this.assertionReaches), calls = new Map(this.callReaches), eitherBranches = new Map(this.eitherBranches);
    this.assertionReaches.clear(); this.callReaches.clear();
    const path = (entry: string, state: State): SuccessfulPath => ({ entry,
      ...(state.witnessCalls?.size ? { checkCoverage: state.otherChecks ? "unclassified" as const : "raw-witness-only" as const } : {}), witnessCalls: state.witnessCalls, ...(state.integerDomains ? { integerDomains: state.integerDomains } : {}), predicates: state.predicates ?? [], operations: state.operations ?? [],
      bindings: state.bindings, sinks: state.sinks, path: state.path, writes: state.writes });
    const boundary = (state: State): State => ({ ...this.cloneState(state), env: new Map(), guards: new Set(),
      bindings: [], sinks: [], writes: [], path: [], control: [], predicates: [], operations: [],
      witnessCalls: new Map(), integerDomains: undefined, branchJournal: undefined, otherChecks: undefined });
    const run = (target: FunctionInfo, state: State, step: 0 | 1 | 2): Evaluation[] => {
      this.sequenceStep = step;
      // Caches remain useful within one invocation; no completed helper or cached
      // observation from another invocation may establish its guards or trust.
      this.summaries.clear(); this.mutationSummaries.clear(); this.readSummaries.clear(); this.branchSummaries.clear();
      const args = target.declaration.parameters.map(parameter => this.typedValue(parameter.type,
        (_type, digest) => this.source("entry-parameter", parameter.name, parameter.span, parameter.symbol, undefined, digest)));
      const results = this.invoke(target, args, boundary(state), [], target.declaration.span);
      this.checkHashChoiceConstraints(results, target.declaration.span);
      return results;
    };
    try {
      if (this.pathSemantics !== "equivalent-states") {
        this.issue("initialization-evidence-unavailable", "Consecutive invocation evidence requires exact histories; results are incomplete", fn.declaration.span);
        return evidence;
      }
      const constructor = this.program.entries.map(id => this.program.functions.get(id)!).find(item => item.symbol.kind === "constructor");
      const defaults = this.entryState(true);
      this.checkCollectionBudget(defaults, fn.declaration.span);
      const constructed = constructor ? run(constructor, defaults, 0) : [{ state: defaults, value: empty() }];
      for (const initial of constructed) {
        if (this.incompleteEntries.has(this.currentEntry)) break;
        for (const first of run(fn, initial.state, 1)) {
          if (this.incompleteEntries.has(this.currentEntry)) break;
          if (++evidence.firstSuccesses > this.maxPaths) {
            this.issue("analysis-budget", "Consecutive first-invocation histories exceed the path allowance; results are incomplete", fn.declaration.span); break;
          }
          for (const second of run(fn, first.state, 2)) {
            if (this.incompleteEntries.has(this.currentEntry)) break;
            if (++evidence.secondSuccesses > this.maxPaths) {
              this.issue("analysis-budget", "Consecutive invocation pairs exceed the path allowance; results are incomplete", fn.declaration.span); break;
            }
            const changes: InitializationEvidence["pairs"][number]["changes"] = [];
            for (const ledger of new Set(second.state.writes.map(write => write.ledger))) {
              if (++this.steps > this.maxSteps) { this.issue("analysis-budget", "Consecutive storage comparison exhausted the shared step allowance; results are incomplete", fn.declaration.span); break; }
              const symbol = this.program.symbols.get(ledger)!;
              const region = { root: ledger, path: [], type: symbol.type };
              const before = this.readRegion(first.state, region), after = this.readRegion(second.state, region);
              const differs = this.storageMayDiffer(before, after, second.state, fn.declaration.span,
                [...initial.state.predicates ?? [], ...first.state.predicates ?? [], ...second.state.predicates ?? []]);
              if (differs) changes.push({ ledger, before, after });
            }
            evidence.pairs.push({ ...(constructor ? { construction: path(constructor.symbol.id, initial.state) } : {}),
              first: path(fn.symbol.id, first.state), second: path(fn.symbol.id, second.state), changes });
          }
        }
      }
      if (this.incompleteEntries.has(this.currentEntry)) evidence.pairs.length = 0;
      return evidence;
    } finally {
      this.sequenceStep = undefined;
      this.failedAssertions.length = 0; this.failedAssertions.push(...failures);
      this.assertionReaches.clear(); for (const [key, value] of assertions) this.assertionReaches.set(key, value);
      this.callReaches.clear(); for (const [key, value] of calls) this.callReaches.set(key, value);
      this.eitherBranches.clear(); for (const [key, value] of eitherBranches) this.eitherBranches.set(key, value);
      this.summaries.clear(); this.mutationSummaries.clear(); this.readSummaries.clear(); this.branchSummaries.clear();
    }
  }

  private storageMayDiffer(before: AbstractValue, after: AbstractValue, state: State, location: Span, predicates: SuccessfulPredicate[]): boolean {
    if (++this.steps > this.maxSteps) { this.issue("analysis-budget", "Consecutive storage comparison exhausted the shared step allowance; results are incomplete", location); return false; }
    const type = this.program.representationOf(after.type ?? "unknown");
    // Counter payloads are already scalar values from the shared checked
    // mutation transfers. Compare their contents, not storage revision IDs.
    // Collection/transaction ADTs still need a separate contents comparison.
    if (["Map", "Set", "List", "MerkleTree", "HistoricMerkleTree", "Kernel"].includes(parseType(type).name)) {
      this.issue("initialization-state-unsupported", "Surviving ADT contents cannot yet be compared across invocations; initialization review is incomplete", location); return false;
    }
    if (parseType(type).name === "Counter" && before.counterOffset && after.counterOffset
      && before.counterOffset.identity === after.counterOffset.identity
      && before.counterOffset.offset === after.counterOffset.offset) return false;
    if (before.items && after.items && before.items.length === after.items.length)
      return before.items.map((value, index) => this.storageMayDiffer(value, after.items![index], state, location, predicates)).some(Boolean);
    if (before.fields && after.fields && Object.keys(before.fields).every(key => key in after.fields!))
      return Object.entries(before.fields).map(([key, value]) => this.storageMayDiffer(value, after.fields![key], state, location, predicates)).some(Boolean);
    const comparison = binaryValue([before, after], "==", location, type);
    if (!comparison) { this.issue("initialization-state-unsupported", "Storage difference has no supported comparison; initialization review is incomplete", location); return false; }
    // A different allocation identity/revision is not a different stored value.
    // Retained equalities/constants can disprove the potential difference.
    if (!this.assume(comparison, false, this.cloneState(state))) return false;
    // Immutable required equalities can relate different allocation IDs, including
    // aggregate leaves and a transitive alias. This is bounded equality closure,
    // not an assertion that all remaining abstract histories are concretely feasible.
    const parents = new Map<string, string>();
    const find = (key: string): string => {
      while (parents.has(key) && this.steps <= this.maxSteps) { this.steps++; key = parents.get(key)!; }
      return key;
    };
    const key = (value: AbstractValue): string | undefined => {
      const result = immutableOperandKey(value, Math.min(4096, Math.max(0, this.maxSteps - this.steps)), undefined, undefined, this.program.meteringIdentity);
      this.steps += result.work;
      if (!result.complete) this.issue(this.steps >= this.maxSteps ? "analysis-budget" : "predicate-budget", "Initialization equality identity exceeds its allowance; results are incomplete", location);
      return result.key;
    };
    for (const predicate of predicates) {
      const decoded = enforcedEqualities(predicate.value, predicate.truth);
      this.steps += decoded.work;
      if (!decoded.complete) this.issue("predicate-budget", "Initialization equality decoding exceeds its allowance; results are incomplete", location);
      for (const { left, right, equals } of decoded.equalities) {
        if (++this.steps > this.maxSteps) break;
        if (!equals) continue;
        const a = key(left), b = key(right);
        if (a && b) { const x = find(a), y = find(b); if (x !== y) parents.set(y, x); }
      }
      if (this.steps > this.maxSteps || this.incompleteEntries.has(this.currentEntry)) break;
    }
    const a = key(before), b = key(after);
    const same = a && b && find(a) === find(b);
    if (this.steps > this.maxSteps) this.issue("analysis-budget", "Initialization equality closure exhausted the shared allowance; results are incomplete", location);
    return !same;
  }

  private issue(code: string, message: string, location: Span): void {
    this.incompleteEntries.add(this.currentEntry);
    this.attemptIssues?.push({ code, message });
    if (!this.diagnostics.some(item => item.code === code && this.program.spanIdentity(item.location) === this.program.spanIdentity(location))) this.diagnostics.push({ code, message, location });
  }

  private source(kind: PrivateSource["kind"], name: string, location: Span, symbol?: string, invocation?: PrivateSource["invocation"], digest = false): AbstractValue {
    const source: PrivateSource = { ...(this.sequenceStep === undefined ? {} : { sequenceStep: this.sequenceStep }), id: `${this.program.spanIdentity(location)}:${this.sourceCount++}`, kind, name, location, symbol, ...(invocation ? { invocation } : {}), ...(this.observeMerkle && digest ? { merkleDigest: true as const } : {}) };
    return { flows: [{ source, form: "raw", trace: [{ kind: "source", label: name, location }] }], ledger: new Set(), identity: source.id };
  }

  private invoke(fn: FunctionInfo, args: AbstractValue[], input: State, stack: string[], location: Span, totalFoldReturn?: AbstractValue): Evaluation[] {
    this.callSites.push(location);
    try {
      const observe = this.observeCalls && stack.length > 0;
      const reach = observe ? this.observeCall(fn, stack, location) : undefined;
      if (observe && !reach) return [];
      const before = this.failedAssertions.length;
      // Capture the caller's refined key before the verifier can add constraints.
      // Retain each observation on its own successful history, never merge keys
      // from separate calls or branches into an identity-key certificate.
      if (this.contractRecipientObservation && this.observeInvocations.has(fn.symbol.id)
        && !this.recipientCharge(2 + args.length, 2 + args.length, location)) return [];
      if (this.complementarySendObservation && this.observeInvocations.has(fn.symbol.id)
        && !this.complementaryCharge(2 + args.length, 2 + args.length, location)) return [];
      const invocationArgs = this.observeInvocations.has(fn.symbol.id) ? args.slice() : undefined;
      const invocationOperationsBefore = invocationArgs ? (input.operations?.length ?? 0) : undefined;
      if (this.enrollmentReviewObservation && this.observeSignatures && (schnorrVerifier(fn.symbol.id) || this.observeSecpSignatures && !!signatureVerifierCurve(fn.symbol.id))
        && !this.enrollmentCharge(args.length * 2 + 2, args.length * 2 + 2, location)) return [];
      const signatureArgs = this.observeSignatures && (schnorrVerifier(fn.symbol.id) || this.observeSecpSignatures && !!signatureVerifierCurve(fn.symbol.id))
        ? args.map(value => refineScalar(value, input)) : undefined;
      const mintArgs = this.observeMints && fn.symbol.id === SHIELDED_MINT ? args.slice() : undefined;
      const nonceArgs = this.observeMints && fn.symbol.id === EVOLVE_NONCE ? args.slice() : undefined;
      let completed = this.invokeBody(fn, args, input, stack, location, totalFoldReturn);
      if (invocationArgs) completed = completed.filter(result => this.recordRuntimeOperation(result.state,
        { kind: "circuit-invocation", name: fn.symbol.id, location, args: invocationArgs, result: result.value, operationsBefore: invocationOperationsBefore }, [...stack, fn.symbol.id]));
      if (nonceArgs) completed = completed.map(result => ({ ...result, value: { ...result.value,
        nonceEvolution: { index: nonceArgs[0], nonce: nonceArgs[1] } } }));
      if (mintArgs) completed = completed.filter(result => this.recordRuntimeOperation(result.state,
        { kind: "shielded-mint", name: fn.symbol.id, location, args: mintArgs, result: result.value }, [...stack, fn.symbol.id]));
      if (signatureArgs) completed = completed.filter(result => {
        if (this.enrollmentReviewObservation) {
          // Outcome identity, input/output operation rows, argument/guard/control
          // copies and both invocation trace arrays are reserved before retention.
          const units = 14 + signatureArgs.length + result.state.guards.size + result.state.control.length
            + stack.length * 2 + this.callSites.length + Math.ceil(this.program.meteringIdentity(this.currentEntry).length / 64);
          if (!this.enrollmentCharge(units, units, location)) return false;
          result.value = { ...result.value, enrollmentSignatureOutcome: `${this.currentEntry}:${this.enrollmentSignatureOccurrence++}` };
        }
        // Enrollment proves exclusion from the metered complete predicate history;
        // its observer does not rebuild an eager scalar closure here.
        const equality = this.observeSignatureKeyIdentity && !this.enrollmentReviewObservation && binaryValue([signatureArgs[2], pointIdentity("JubjubPoint")], "==", location, "Boolean");
        const checked = equality && refineScalar(equality, result.state);
        return this.recordRuntimeOperation(result.state,
          { kind: "signature-verification", name: fn.symbol.id, location, args: signatureArgs, result: result.value,
            ...(this.observeSecpSignatures ? { signatureCurve: signatureVerifierCurve(fn.symbol.id) } : {}),
            ...(this.observeSignatureKeyIdentity ? { signatureKeyExcludesIdentity: !!checked && checked.constantKind === "boolean" && checked.constant === "false" } : {}) }, [...stack, fn.symbol.id]);
      });
      if (reach) {
        reach.maySucceed ||= completed.length > 0;
        if (!completed.length) {
          reach.failedWithoutAssertion ||= before === this.failedAssertions.length;
          reach.failure ??= this.failedAssertions[before];
        }
      }
      if (!this.observeMerkle || !merkleRootCircuit(fn.symbol.id) || !completed.length) return completed;
      const operand = immutableOperandKey(args[0], Math.min(4096, this.maxSteps - this.steps), undefined, undefined, this.program.meteringIdentity);
      this.steps += operand.work;
      if (!operand.complete) { this.issue("predicate-budget", "Merkle proof identity exceeds its bounded operand traversal; results are incomplete", location); return []; }
      const identity = operand.key ? this.derivedIdentity("merkle-digest", [fn.symbol.id, operand.key]) : `merkle-digest-fresh:${this.snapshotCount++}`;
      return completed.filter(result => {
        const field = result.value.fields?.field;
        if (!field) { this.issue("predicate-evidence-unavailable", "Canonical Merkle root has no modeled digest field; results are incomplete", location); return false; }
        result.value = { ...result.value, fields: { ...result.value.fields, field: { ...field, identity } } };
        return this.recordRuntimeOperation(result.state, { kind: "merkle-root", name: fn.symbol.id, location, args, result: result.value }, [...stack, fn.symbol.id]);
      });
    } finally { this.callSites.pop(); }
  }

  private observeCall(fn: FunctionInfo, stack: string[], location: Span): CallReach | undefined {
    const key = JSON.stringify([this.currentEntry, stack.at(-1), this.program.spanIdentity(location), fn.symbol.id]);
    let reach = this.callReaches.get(key);
    if (!reach) {
      if (++this.abstractValues > this.maxValues) {
        this.issue("value-budget", "Call observation capacity exhausted; results are incomplete", location);
        return undefined;
      }
      reach = { location, entry: this.currentEntry, owner: stack.at(-1)!, callee: fn.symbol.id, callPath: [...stack, fn.symbol.id],
        maySucceed: false, failedWithoutAssertion: false };
      this.callReaches.set(key, reach);
    }
    return reach;
  }

  private invokeBody(fn: FunctionInfo, args: AbstractValue[], input: State, stack: string[], location: Span, totalFoldReturn?: AbstractValue): Evaluation[] {
    if (this.counterSelection && (fn.symbol.id !== this.counterSelection.entry || stack.length)) {
      this.issue("counter-witness-coverage", "Unexpected call in selected Counter history; results are incomplete", location);
      return [];
    }
    if (args.length !== fn.declaration.parameters.length) {
      this.issue("call-arity", `Expected ${fn.declaration.parameters.length} arguments for ${fn.symbol.name}`, location);
      return [];
    }
    if (stack.includes(fn.symbol.id) || stack.length >= 32) {
      this.issue("call-depth", "Recursive or excessively deep call graph; path analysis stopped", location);
      return [];
    }
    if (++this.steps > this.maxSteps) {
      this.issue("analysis-budget", "Call budget exhausted; results are incomplete", location);
      return [];
    }
    // Only the proven total scalar-fold transfer supplies this opaque internal
    // accumulator. Its exact composed result is computed by that transfer. Reuse
    // ordinary invocation limits, observations and completion for every callback.
    if (totalFoldReturn) {
      const state = this.cloneState(input);
      this.completeCircuit(state, [...stack, fn.symbol.id]);
      return [{ state, value: totalFoldReturn }];
    }
    // Canonical Merkle roots are total over every path direction. Summarize
    // them for all Merkle-observing rules (except current-root/checkpoint
    // observations, which intentionally inspect the ordinary root transfer),
    // otherwise a 100-level proof creates an exponential fold frontier before
    // the detector can inspect its digest.
    const merkleTarget = merklePureRootSummaryTarget(this.program, fn.symbol.id);
    const longLegacyMerkle = (this.program.compilerVersion === "0.30.0" || this.program.compilerVersion === "0.31.1")
      && (merkleTarget?.depth ?? 0) > 32;
    const digestOnlyMerkle = this.observeDigestInputs && !this.observeMerkle && !!merkleTarget
      && (this.program.compilerVersion === "0.30.0" || this.program.compilerVersion === "0.31.1");
    if ((this.observeMerkle || this.observeDigestInputs) && (this.pureMerkleRootSummary || digestOnlyMerkle || longLegacyMerkle && !this.currentRootObservation && !this.checkpointObservation)) {
      const target = merklePureRootSummaryTarget(this.program, fn.symbol.id);
      if (target) return this.summarizePureMerkleRoot(fn, args, input, stack, location, target);
    }
    const diagnosticsBefore = this.diagnostics.length;
    // Existing summaries do not replay nested call/proof observations. Keep leaf
    // summaries, but interpret callers while this optional evidence is requested.
    // Receiver observations are current-state evidence. Until summaries replay
    // these operands, bypass caching rather than retain caller-refined tags.
    const summaries = this.useSummaries && !this.compressionTokens.size && !this.observeEither && !(this.checkpointProofTracking && (fn.readsState.size || fn.writesState.size)) && (!(this.observeCalls || this.observeMerkle || this.observeCollections || this.observeSignatures || this.observeInvocations.size) || !fn.calls.size);
    const summaryKey = summaries && stack.length && this.summaryEligibility.allows(fn.symbol.id) ? this.summaryKey(fn.symbol.id, args, input) : undefined;
    const summary = summaryKey ? this.summaries.get(summaryKey) : undefined;
    if (summary && stack.length + this.summaryEligibility.maximumDepth(fn.symbol.id) <= 32) {
      this.summaryHits++;
      const state = this.cloneState(input);
      for (const completion of summary.completions) this.completeCircuit(state, [...stack, ...completion]);
      return [{ state, value: summary.value }];
    }
    const readKey = !this.zeroInput && summaries && stack.length && fn.readsState.size && !fn.writesState.size && this.readEligibility.allows(fn.symbol.id) ? this.readSummaryKey(fn, args, input) : undefined;
    const read = readKey ? this.readSummaries.get(readKey) : undefined;
    if (read && stack.length + this.readEligibility.maximumDepth(fn.symbol.id) <= 32) return this.replayReadonlySummary(read, input, stack, location);
    const mutationKey = !this.zeroInput && summaries && this.useStatefulSummaries && stack.length && fn.writesState.size && this.mutationEligibility.allows(fn.symbol.id) ? this.summaryKey(fn.symbol.id, args, input) : undefined;
    const mutation = mutationKey ? this.mutationSummaries.get(mutationKey) : undefined;
    if (mutation && stack.length + this.mutationEligibility.maximumDepth(fn.symbol.id) <= 32) return this.replaySummary(mutation, input, stack, location);
    const branchPlan = !this.complementarySendObservation && !this.zeroInput && summaries && this.useStatefulSummaries && stack.length && this.pathSemantics === "equivalent-states" && !input.branchJournal ? this.branchEligibility.plan(fn.symbol.id) : undefined;
    const branchKey = branchPlan && this.branchArguments(args) && this.branchScopeSafe(fn) ? this.summaryKey(fn.symbol.id, args, input) : undefined;
    const branch = branchKey ? this.branchSummaries.get(branchKey) : undefined;
    if (branch) return this.replayBranchSummary(fn, args, branch, input, stack, location);
    const branchRecording = branchKey ? new BranchRecording(fn.symbol.id, branchPlan![this.engine].branch) : undefined;
    const recordedInput = branchRecording ? this.cloneState(input) : input;
    if (branchRecording) { this.effectRecorder.invalidateActive(); recordedInput.branchJournal = branchRecording.begin(); }
    const recording = mutationKey && !mutation ? this.effectRecorder.begin(stack.length) : readKey && !read ? this.effectRecorder.begin(stack.length, "readonly") : undefined;
    // Summaries do not replay the compressed-fold observation boundary.
    const compressionsBefore = this.observationCompressions;
    const checkpointsBefore = this.checkpointCount;
    let completed: Evaluation[];
    try { completed = this.interpret(fn, args, recordedInput, stack); }
    finally { if (recording) this.effectRecorder.end(recording); }
    if (branchRecording) {
      const cursors = completed.map(result => result.state.branchJournal);
      for (const result of completed) delete result.state.branchJournal;
      if (branchKey && branchRecording.complete && compressionsBefore === this.observationCompressions && checkpointsBefore === this.checkpointCount && completed.length > 0 && completed.length === branchRecording.observedChoices && completed.length <= 2 && cursors.every(cursor => cursor?.recording === branchRecording && cursor.tail) && this.diagnostics.length === diagnosticsBefore && !this.incompleteEntries.has(this.currentEntry) && this.summaries.size + this.mutationSummaries.size + this.readSummaries.size + this.branchSummaries.size < 256 && this.summaryEffects + branchRecording.effects <= 4096) {
        this.branchSummaries.set(branchKey, Object.freeze({ effects: branchRecording.effects, alternatives: Object.freeze(completed.map((result, index) => Object.freeze({ tail: cursors[index]!.tail!, value: result.value }))) }));
        this.summaryEffects += branchRecording.effects;
      }
    }
    const cacheable = completed.length === 1 && compressionsBefore === this.observationCompressions && checkpointsBefore === this.checkpointCount && this.diagnostics.length === diagnosticsBefore && !this.incompleteEntries.has(this.currentEntry) && this.summaries.size + this.mutationSummaries.size + this.readSummaries.size + this.branchSummaries.size < 256;
    let exactCache = !this.complementarySendObservation || !cacheable || !(summaryKey || mutationKey || readKey)
      || completed.length === 1 && this.complementaryCacheValue(completed[0].value, location);
    if (cacheable && exactCache && this.complementarySendObservation && recording) for (const record of recording.effects) {
      if (!this.complementaryCharge(1, 0, location)) { exactCache = false; break; }
      const effect = record.effect;
      if (effect.kind === "assignment") exactCache &&= this.complementaryCacheValue(effect.value, location);
      else if (effect.kind === "public-sink") exactCache &&= this.complementaryCacheValue(effect.sink.value, location);
      else if (effect.kind === "ledger-operation") for (const argument of effect.args) exactCache &&= this.complementaryCacheValue(argument, location);
      if (!exactCache) break;
    }
    if (summaryKey && cacheable && exactCache) this.summaries.set(summaryKey, { value: completed[0].value, completions: this.summaryEligibility.completions(fn.symbol.id) });
    if (mutationKey && recording?.complete && cacheable && exactCache && this.summaryEffects + recording.effects.length <= 4096) {
      this.mutationSummaries.set(mutationKey, { value: completed[0].value, effects: recording.effects as MutationSummary["effects"] });
      this.summaryEffects += recording.effects.length;
    }
    if (readKey && recording?.complete && cacheable && exactCache && this.summaryEffects + recording.effects.length <= 4096) {
      this.readSummaries.set(readKey, { value: completed[0].value, effects: recording.effects as ReadonlySummary["effects"] });
      this.summaryEffects += recording.effects.length;
    }
    return completed;
  }

  /** Pinned stdlib helper body only: a total, deterministic root value whose
   * dependence includes the leaf, every sibling and every direction. Argument
   * evaluation has already completed; no root trust or equality is inferred. */
  private summarizePureMerkleRoot(fn: FunctionInfo, args: AbstractValue[], input: State, stack: string[], location: Span,
    target: { depth: number; leaf: "Field" | "Bytes<32>"; noLeafHash: boolean }): Evaluation[] {
    // A nonempty fold invokes the pinned entry helper one frame inside this
    // root. Summarizing its pure body must retain the ordinary call-depth limit.
    if (target.depth > 0 && stack.length + 1 >= 32) {
      this.issue("call-depth", "Pure Merkle root helper closure exceeds the call-depth allowance; leaf-binding observation is incomplete", location);
      return [];
    }
    const proof = args[0];
    const fail = (message: string): Evaluation[] => {
      this.issue("merkle-summary-shape", `${message}; leaf-binding observation is incomplete`, location);
      return [];
    };
    if (proof.type !== fn.declaration.parameters[0].type || !proof.fields
      || Object.keys(proof.fields).length !== 2 || !proof.fields.leaf || !proof.fields.path
      || proof.fields.leaf.type !== target.leaf || proof.fields.leaf.fields || proof.fields.leaf.items
      || !proof.fields.path.items || proof.fields.path.items.length !== target.depth
      || !["Vector", TUPLE_TYPE].includes(parseType(this.program.representationOf(proof.fields.path.type ?? "unknown")).name)
      || sequenceLength(this.program.representationOf(proof.fields.path.type ?? "unknown")) !== target.depth)
      return fail("Canonical Merkle path operand lacks its exact represented shape");
    const parts = [proof.fields.leaf];
    let work = 3 + proof.flows.length;
    for (const entry of proof.fields.path.items) {
      work += 5 + entry.flows.length;
      if (this.program.representationOf(entry.type ?? "unknown") !== "MerkleTreePathEntry"
        || !entry.fields || Object.keys(entry.fields).length !== 2
        || entry.fields.goes_left?.type !== "Boolean" || entry.fields.goes_left.fields || entry.fields.goes_left.items
        || this.program.representationOf(entry.fields.sibling?.type ?? "unknown") !== "MerkleTreeDigest"
        || !entry.fields.sibling?.fields || Object.keys(entry.fields.sibling.fields).length !== 1
        || entry.fields.sibling.fields.field?.type !== "Field"
        || entry.fields.sibling.fields.field.fields || entry.fields.sibling.fields.field.items)
        return fail("Canonical Merkle path entry lacks its exact represented shape");
      parts.push(entry.fields.goes_left, entry.fields.sibling.fields.field);
    }
    for (const part of parts) work += part.flows.length;
    this.steps += work;
    this.abstractValues += 2;
    if (this.steps > this.maxSteps || this.abstractValues > this.maxValues) {
      this.issue(this.steps > this.maxSteps ? "analysis-budget" : "value-budget", "Pure Merkle root observation exhausted the shared allowance; results are incomplete", location);
      return [];
    }
    const form = target.noLeafHash && target.depth === 0 ? "derived" : "hash";
    const field = { ...step(combine(parts), "transform", fn.symbol.name, location, form), type: "Field",
      ...(target.depth > 0 ? { summarizedMerkleHash: true as const } : {}) };
    const value = { ...combine([field]), fields: { field }, type: fn.symbol.type };
    const state = this.cloneState(input);
    this.completeCircuit(state, [...stack, fn.symbol.id]);
    return [{ state, value }];
  }

  private branchArguments(args: AbstractValue[]): boolean {
    return args.every(value => !value.region && !value.ledger.size && !value.merklePredicate && !value.emptyMerkle && !value.collectionPredicate && !value.listPredicate && !value.negated && !value.comparison && !(value.ordering && value.identity) && !value.equalities?.length && !value.commitments?.length && !value.items && !value.fields && !value.emptyCollection && !value.emptyList);
  }

  private liveVariablesFor(fn: FunctionInfo, cfg: CFG): LiveVariables {
    const cached = this.liveness.get(fn.symbol.id);
    if (cached) return cached;
    const retained = [...this.liveness.values()].reduce((bytes, live) => bytes + live.storageBytes, 0);
    const live = liveVariables(this.program, { ...fn, cfg }, MAX_LIVENESS_STORAGE_BYTES - retained);
    this.liveness.set(fn.symbol.id, live);
    return live;
  }

  private branchScopeSafe(fn: FunctionInfo): boolean {
    const saved = this.branchScopeSafety.get(fn.symbol.id);
    if (saved !== undefined) return saved;
    const graph = this.engine === "instructions" ? this.program.instructionCFG(fn.symbol.id) : fn.cfg;
    const live = this.liveVariablesFor(fn, graph);
    const parameters = new Set(fn.declaration.parameters.map(parameter => parameter.symbol!));
    // Address temporaries are state snapshots. This first journal may omit them
    // only where none can survive into a join's current-state constraint cleanup.
    const safe = [...live.joins].every(node => [...live.liveIn.get(node)!].every(symbol => !live.owned.has(symbol) || parameters.has(symbol)));
    this.branchScopeSafety.set(fn.symbol.id, safe);
    return safe;
  }

  private bindParameters(fn: FunctionInfo, args: AbstractValue[], state: State, stack: string[]): void {
    fn.declaration.parameters.forEach((parameter, index) => {
      // Freeze numeric domains before the declared parameter type widens the
      // argument. Aggregate leaves are snapshots too: later projections use
      // the callee's type, but must retain the caller's narrower domain.
      const argument = this.observeMintQuantities ? this.mintNumericDomains(args[index], parameter.span) : args[index];
      const value = { ...step(argument, "argument", parameter.name, parameter.span), type: parameter.type };
      state.env.set(parameter.symbol!, value);
      if (parameter.pattern) this.bindPattern(parameter.pattern, value, state, stack);
    });
  }

  private mintNumericDomains(value: AbstractValue, location: Span, depth = 0): AbstractValue {
    if (++this.abstractValues > this.maxValues || depth > 12) {
      this.issue("value-budget", "Mint numeric argument snapshots exhausted the shared value/depth allowance; results are incomplete", location);
      return value;
    }
    const bound = numericBound(this.program.representationOf(value.type ?? "unknown"));
    const previous = value.integerRange;
    if (this.complementarySendObservation) {
      let fields = 0;
      for (const name in value.fields) if (Object.hasOwn(value.fields, name)) { this.steps++; fields++; }
      if (!this.complementaryCharge(1, (bound !== undefined && value.constant === undefined ? 2 : 0)
        + fields * 4 + (value.items?.length ?? 0), location)) return value;
    }
    return { ...value,
      ...(value.constant === undefined && bound !== undefined ? { integerRange: {
        minimum: previous?.minimum ?? "0",
        maximum: String(previous && BigInt(previous.maximum) < bound - 1n ? BigInt(previous.maximum) : bound - 1n),
      } } : {}),
      ...(value.fields ? { fields: Object.fromEntries(Object.entries(value.fields).map(([name, field]) => [name, this.mintNumericDomains(field, location, depth + 1)])) } : {}),
      ...(value.items ? { items: value.items.map(item => this.mintNumericDomains(item, location, depth + 1)) } : {}),
    };
  }

  private cleanNodeScope(fn: FunctionInfo, state: State, live: LiveVariables, node: number): void {
    state.control = state.control.filter(control => control.owner !== fn.symbol.id || control.until !== node);
    for (const symbol of state.env.keys()) if (live.owned.has(symbol) && !live.liveIn.get(node)!.has(symbol)) state.env.delete(symbol);
    if (live.joins.has(node)) this.forgetDeadLocals(state, live, node);
  }

  private appendBranch(state: State, effect: BranchMutationEffect): void {
    if (state.branchJournal) state.branchJournal = state.branchJournal.recording.append(state.branchJournal, effect);
  }

  private replayBranchSummary(fn: FunctionInfo, args: AbstractValue[], summary: BranchMutationSummary, input: State, stack: string[], location: Span): Evaluation[] {
    const journals = summary.alternatives.map(alternative => branchJournalNodes(alternative.tail));
    if (journals.some(events => !events)) return this.interpret(fn, args, input, stack);
    this.effectRecorder.invalidateActive();
    this.summaryHits++; this.statefulSummaryHits++;
    const callPath = [...stack, fn.symbol.id], live = this.liveness.get(fn.symbol.id)!;
    const seen = new Set<string>(), completed: Evaluation[] = [];
    const execute = (state: State, nodes: readonly BranchJournalNode[], start: number, end: number): boolean => {
      for (let position = start; position < end; position++) {
        const effect = nodes[position].effect;
        if (++this.steps > this.maxSteps) { this.issue("analysis-budget", "Branch summary replay budget exhausted; results are incomplete", location); return false; }
        if (effect.kind === "node") {
          this.cleanNodeScope(fn, state, live, effect.node);
          if (live.joins.has(effect.node)) {
            const identity = `${effect.node}:${this.stateIdentity(state)}`;
            if (seen.has(identity)) return false;
            seen.add(identity);
          }
        } else if (effect.kind === "choice") {
          if (!this.assume(effect.value, effect.selected, state) || !this.recordPredicate(effect.value, effect.selected, state, effect.location, callPath)) return false;
          state.path.push({ kind: "branch", label: `condition may be ${effect.selected}`, location: effect.location });
          state.control.push({ value: effect.value, until: effect.until, owner: effect.owner });
        } else if (effect.kind === "assignment") this.assignRegion(state, effect.region, effect.value, effect.location, callPath);
        else {
          state.control = state.control.filter(control => control.owner !== fn.symbol.id);
          this.completeCircuit(state, callPath);
          for (const symbol of live.owned) state.env.delete(symbol);
        }
        if (this.incompleteEntries.has(this.currentEntry)) return false;
      }
      return true;
    };
    // Execute the actual shared journal prefix once, as interpretation does
    // before forking. Repeating it can allocate different write identities and
    // duplicate resource charges even when the final scalar values agree.
    let shared = 0;
    if (journals.length > 1) while (journals[0]![shared] && journals.every(nodes => nodes![shared] === journals[0]![shared])) shared++;
    const initial = this.cloneState(input); this.bindParameters(fn, args, initial, [...stack, fn.symbol.id]);
    if (!execute(initial, journals[0]!, 0, shared)) return [];
    for (let index = 0; index < summary.alternatives.length; index++) {
      const state = journals.length === 1 ? initial : this.cloneState(initial);
      const surviving = execute(state, journals[index]!, shared, journals[index]!.length);
      if (this.incompleteEntries.has(this.currentEntry)) return [];
      if (surviving) completed.push({ state, value: summary.alternatives[index].value });
    }
    return completed;
  }

  private commonValue(left: AbstractValue, right: AbstractValue, location: Span, depth = 0): AbstractValue {
    if (++this.steps > this.maxSteps || ++this.abstractValues > this.maxValues || depth > 12) {
      this.issue("analysis-budget", "Common current value exhausted its allowance; results are incomplete", location);
      return empty();
    }
    // These primitive fields are included verbatim in the fingerprint. Unequal
    // identities/types/constants cannot have equal serialized values; avoid
    // serializing their often-large provenance when joining distinct snapshots.
    if (left === right || left.identity === right.identity && left.type === right.type
      && left.constant === right.constant && left.constantKind === right.constantKind
      && this.valueFingerprints.key(left) === this.valueFingerprints.key(right)) return left;
    const predicateAlternatives = left.type === "Boolean" && right.type === "Boolean" ? [left, right] as const : undefined;
    if (!predicateAlternatives && (left.comparison || right.comparison || left.negated || right.negated
      || left.predicateAlternatives || right.predicateAlternatives)) this.predicateStructureComplete = false;
    const constant = this.constant(left), other = this.constant(right);
    const same = constant && other && constant.kind === other.kind && constant.value === other.value;
    const fields = left.fields && right.fields && Object.keys(left.fields).every(name => name in right.fields!)
      ? Object.fromEntries(Object.keys(left.fields).map(name => [name, this.commonValue(left.fields![name], right.fields![name], location, depth + 1)])) : undefined;
    const items = left.items && right.items && left.items.length === right.items.length
      ? left.items.map((value, index) => this.commonValue(value, right.items![index], location, depth + 1)) : undefined;
    if ((left.fields || right.fields) && !fields || (left.items || right.items) && !items) this.predicateStructureComplete = false;
    // A may-value union cannot establish exact origins, predicate identities or
    // live regions. Its fresh immutable identity permits repeated local reads,
    // without equating this value with either incoming storage snapshot.
    const digestJoinedLeafType = this.ruleCertificate?.kind === "digest" && left.type && left.type === right.type
      && !left.fields && !left.items && !right.fields && !right.items
      && (!left.identity?.startsWith("common:") || left.digestJoinedLeafType === left.type)
      && (!right.identity?.startsWith("common:") || right.digestJoinedLeafType === right.type)
      ? left.type : undefined;
    return { ...combine([left, right]), ...uncertainTransientDependencies([left, right]), type: left.type, identity: `common:${this.snapshotCount++}`,
      digestJoinedLeafType,
      constant: same ? constant.value : undefined, constantKind: same ? constant.kind : undefined, fields, items,
      ...(predicateAlternatives ? { predicateAlternatives, predicateHasAlternatives: true as const, predicateStructureLost: undefined } : {}) };
  }

  private flushSourceHistory(state: State): boolean {
    if (!this.sourceHistories) return true;
    const history = this.sourceHistories.append(state.sourceHistory ?? 0, {
      bindings: state.bindings, predicates: state.predicates ?? [], sinks: state.sinks,
      writes: state.writes, operations: state.operations ?? [], path: state.path,
    });
    if (history === undefined) return false;
    state.sourceHistory = history;
    // The graph owns these immutable chunks. Later transfers start new arrays.
    state.bindings = []; state.predicates = []; state.sinks = [];
    state.writes = []; state.operations = []; state.path = [];
    return true;
  }

  private commonCurrent(left: State, right: State, location: Span): State | undefined {
    this.conservativeJoins++;
    const constraints = commonScalarConstraints(left, right, (work, values) => {
      this.steps += work; this.abstractValues += values;
      return this.steps <= this.maxSteps && this.abstractValues <= this.maxValues;
    });
    if (constraints.status === "incomplete") {
      this.issue("common-state-incomplete", `${constraints.reason}; current-state view is incomplete`, location); return;
    }
    // List/tree structural epochs cannot be reset or copied from an arbitrary
    // arm. Their differing current stores need a conditional domain of their own.
    if (this.valueFingerprints.key(left.lists.snapshot()) !== this.valueFingerprints.key(right.lists.snapshot())
      || this.valueFingerprints.key({ merkle: left.merkle?.snapshot() }) !== this.valueFingerprints.key({ merkle: right.merkle?.snapshot() })) {
      this.issue("common-state-domain", "Different List/Merkle structures have no common current-state transfer; view is incomplete", location); return;
    }
    if (!this.flushSourceHistory(left) || !this.flushSourceHistory(right)) return;
    const history = this.sourceHistories?.alternatives(left.sourceHistory!, right.sourceHistory!, location);
    if (this.sourceHistories && history === undefined) return;
    const result: State = { ...this.cloneState(left), ...constraints.constraints,
      ...(history === undefined ? {} : { sourceHistory: history }),
      env: new Map(), ledger: new Map(), ledgerVersions: new Map(), collections: left.collections.common(right.collections),
      guards: new Set([...left.guards].filter(guard => right.guards.has(guard))),
      otherChecks: left.otherChecks || right.otherChecks,
      // Histories remain in exact source replay, never unioned into this view.
      bindings: [], sinks: [], writes: [], operations: [], predicates: [], path: [], branchJournal: undefined,
      foldIdentities: new Set([...left.foldIdentities ?? [], ...right.foldIdentities ?? []]),
      witnessCalls: new Map(left.witnessCalls), control: [] };
    for (const [site, count] of right.witnessCalls ?? []) result.witnessCalls!.set(site, Math.max(count, result.witnessCalls!.get(site) ?? 0));
    const controls = new Map<string, State["control"][number]>();
    for (const control of [...left.control, ...right.control]) controls.set(this.valueFingerprints.key(control), control);
    result.control = [...controls.values()];
    for (const [symbol, first] of left.env) {
      const second = right.env.get(symbol);
      if (second) result.env.set(symbol, this.commonValue(first, second, location));
    }
    for (const root of new Set([...left.ledgerVersions.keys(), ...right.ledgerVersions.keys()])) {
      const first = left.ledgerVersions.get(root) ?? 0, second = right.ledgerVersions.get(root) ?? 0;
      result.ledgerVersions.set(root, first === second ? first : Math.max(first, second) + 1);
    }
    for (const key of new Set([...left.ledger.keys(), ...right.ledger.keys()])) {
      const stored = left.ledger.get(key) ?? right.ledger.get(key)!;
      const region = regionFromKey(key, stored.type ?? "unknown");
      const first = this.readRegion(left, region), second = this.readRegion(right, region);
      result.ledger.set(key, this.commonValue(first, second, location));
    }
    this.checkCollectionBudget(result, location);
    return this.incompleteEntries.has(this.currentEntry) ? undefined : result;
  }

  private commonEvaluations(results: Evaluation[], location: Span): Evaluation[] {
    if (!this.conservative || results.length < 2) return results;
    let result = results[0];
    for (const other of results.slice(1)) {
      const state = this.commonCurrent(result.state, other.state, location);
      if (!state) return [];
      result = { state, value: this.commonValue(result.value, other.value, location) };
    }
    return this.incompleteEntries.has(this.currentEntry) ? [] : [result];
  }

  /** Topological may-interpretation in the isolated conservative interpreter.
   * Incoming IR merge operands are read under their real predecessors before
   * states are combined. Returns and ordinary exit edges are not run twice. */
  private interpretCommon(fn: FunctionInfo, args: AbstractValue[], input: State, stack: string[]): Evaluation[] {
    if (this.maxPaths < 1) { this.issue("analysis-budget", "Current-state view has no frontier allowance; results are incomplete", fn.declaration.span); return []; }
    const cfg = this.engine === "instructions" ? this.program.instructionCFG(fn.symbol.id) : fn.cfg;
    const live = this.liveVariablesFor(fn, cfg);
    const callPath = [...stack, fn.symbol.id], state = this.cloneState(input);
    this.bindParameters(fn, args, state, callPath);
    const reachable = new Set<number>(), discover = [cfg.entry];
    while (discover.length) {
      const id = discover.pop()!;
      if (id === cfg.abort || reachable.has(id)) continue;
      if (++this.steps > this.maxSteps) { this.issue("analysis-budget", "Common source construction exhausted work; view is incomplete", fn.declaration.span); return []; }
      reachable.add(id);
      if (cfg.nodes[id].kind !== "return") discover.push(...cfg.nodes[id].edges.map(edge => edge.target));
    }
    const remaining = new Map([...reachable].map(id => [id, 0]));
    for (const id of reachable) if (cfg.nodes[id].kind !== "return") for (const edge of cfg.nodes[id].edges)
      if (remaining.has(edge.target)) remaining.set(edge.target, remaining.get(edge.target)! + 1);
    const incoming = new Map<number, { previous: number; state: State }[]>();
    incoming.set(cfg.entry, [{ previous: -1, state }]);
    const pending = [cfg.entry], completed: Evaluation[] = [];
    let visited = 0, frontier = 1;
    while (pending.length) {
      const node = cfg.nodes[pending.pop()!]; visited++;
      const inputs = incoming.get(node.id) ?? []; incoming.delete(node.id);
      if (frontier + completed.length > this.maxPaths) { this.issue("analysis-budget", "Common source frontier exhausted; view is incomplete", node.span); return []; }
      frontier -= inputs.length;
      for (const input of inputs) this.cleanNodeScope(fn, input.state, live, node.id);
      let before: Evaluation[];
      if (node.instruction?.kind === "merge") before = this.commonEvaluations(inputs.flatMap(input =>
        this.evaluateInstruction(node.instruction!, input.previous, input.state, callPath, node.span)), node.span);
      else before = this.commonEvaluations(inputs.map(input => ({ state: input.state, value: empty() })), node.span);
      const after: Evaluation[] = [];
      for (const current of before) {
        if (++this.steps > this.maxSteps) { this.issue("analysis-budget", "Common source transfer exhausted work; view is incomplete", node.span); return []; }
        if (node.kind === "exit") {
          current.state.control = current.state.control.filter(control => control.owner !== fn.symbol.id);
          this.completeCircuit(current.state, callPath);
          for (const symbol of live.owned) current.state.env.delete(symbol);
          const merged = this.commonEvaluations([...completed, { state: current.state, value: { ...empty(), items: [], type: "[]" } }], node.span);
          completed.splice(0, completed.length, ...merged); continue;
        }
        const evaluated = node.instruction?.kind === "merge" ? [current] : node.instruction
          ? this.evaluateInstruction(node.instruction, inputs[0].previous, current.state, callPath, node.span)
          : node.expr ? this.evaluate(node.expr, current.state, callPath) : [current];
        for (const result of this.commonEvaluations(evaluated, node.span)) {
          this.bindNodeEvaluation(fn, node, result, callPath, live);
          if (node.kind === "return") {
            const merged = this.commonEvaluations([...completed, result], node.span);
            completed.splice(0, completed.length, ...merged);
          } else after.push(result);
        }
      }
      if (this.incompleteEntries.has(this.currentEntry)) return [];
      if (node.kind === "return") continue;
      if (node.kind === "branch") for (const result of after) if (!this.flushSourceHistory(result.state)) return [];
      for (const edge of node.edges) {
        if (!remaining.has(edge.target)) continue;
        const targets = incoming.get(edge.target) ?? [];
        for (const result of after) {
          const next = this.cloneState(result.state);
          if (node.kind === "branch") {
            if (!this.assume(result.value, edge.condition!, next) || !this.recordPredicate(result.value, edge.condition!, next, node.span, callPath)) continue;
            next.path.push({ kind: "branch", label: `condition may be ${edge.condition}`, location: node.span });
            next.control.push({ value: this.eitherControl(result.value, node.span, node.sameValueArms ? "same-value" : "control"), until: node.join!, owner: fn.symbol.id });
          }
          targets.push({ previous: node.id, state: next });
          frontier++;
        }
        incoming.set(edge.target, targets);
        const count = remaining.get(edge.target)! - 1; remaining.set(edge.target, count);
        if (!count) pending.push(edge.target);
      }
    }
    if (visited !== reachable.size) this.issue("common-state-cfg", "Common source view requires an acyclic CFG; view is incomplete", fn.declaration.span);
    return this.commonEvaluations(completed, fn.declaration.span);
  }

  private interpret(fn: FunctionInfo, args: AbstractValue[], input: State, stack: string[]): Evaluation[] {
    if (this.conservative) return this.interpretCommon(fn, args, input, stack);
    if (this.conditionalSelection?.entry === fn.symbol.id && !stack.length) return this.interpretConditionalSource(fn, args, input, stack);
    const callPath = [...stack, fn.symbol.id];
    const graph = this.engine === "instructions" ? this.program.instructionCFG(fn.symbol.id) : fn.cfg;
    const state = this.cloneState(input);
    this.bindParameters(fn, args, state, callPath);
    const pending = [{ node: graph.entry, previous: -1, state }];
    const completed: Evaluation[] = [];
    const live = this.liveVariablesFor(fn, graph);
    const seen = new Set<string>();
    const guardCover = this.pathSemantics === "guard-cover" ? new GuardCover() : undefined;
    // A completed history equivalent (state identity and returned value) to an
    // earlier one is the same equivalent state a join would discard.
    let finished: Set<string> | undefined;
    const completionKey = (evaluation: Evaluation): string => `${this.stateIdentity(evaluation.state)}:${this.valueFingerprints.key(evaluation.value)}`;
    const finish = (evaluation: Evaluation): void => {
      if (completed.length && !evaluation.state.branchJournal && this.pathSemantics === "equivalent-states") {
        // A single completion needs no deduplication. Hash the retained states
        // only when an actual second completion can duplicate one of them.
        finished ??= new Set(completed.filter(item => !item.state.branchJournal).map(completionKey));
        const key = completionKey(evaluation);
        if (finished.has(key)) return;
        finished.add(key);
      }
      completed.push(evaluation);
    };
    while (pending.length) {
      const current = pending.pop()!;
      const node = graph.nodes[current.node];
      if (current.state.branchJournal) this.appendBranch(current.state, { kind: "node", node: node.id, previous: current.previous });
      this.cleanNodeScope(fn, current.state, live, node.id);
      if (live.joins.has(node.id)) {
        const identity = `${node.id}:${node.instruction?.kind === "merge" ? current.previous : ""}:${this.stateIdentity(current.state)}`;
        if (seen.has(identity)) continue;
        seen.add(identity);
        if (guardCover) {
          const continuation = `${node.id}:${node.instruction?.kind === "merge" ? current.previous : ""}:${this.stateIdentity(current.state, true)}`;
          if (guardCover.covered(continuation, [current.state.guards, ...current.state.writes.map(write => new Set(write.guards))])) {
            this.guardSubsumptions++;
            continue;
          }
        }
      }
      // The popped current state still consumes one path slot. Omitting it
      // permits maxPaths + 1 successful histories, including two under a limit
      // of one. Equivalent/subsumed states above do not consume a new slot.
      if (++this.steps > this.maxSteps) {
        this.issue("analysis-budget", "Analysis step budget exhausted; results are incomplete", fn.declaration.span);
        return completed;
      }
      if (pending.length + completed.length + 1 > this.maxPaths) {
        this.issue("analysis-budget", "Abstract path budget exhausted; results are incomplete", fn.declaration.span);
        return completed;
      }
      if (node.kind === "abort") continue;
      if (node.kind === "exit") { current.state.control = current.state.control.filter(control => control.owner !== fn.symbol.id); this.completeCircuit(current.state, callPath); for (const symbol of live.owned) current.state.env.delete(symbol); finish({ state: current.state, value: { ...empty(), items: [], type: "[]" } }); continue; }
      let selectedBranch: boolean | undefined;
      if (node.kind === "branch" && this.counterSelection) {
        const selection = this.counterSelection;
        if (!selection.branches.has(node.id) || selection.visited.has(node.id)) {
          this.issue("counter-witness-coverage", "Unexpected or repeated branch in selected Counter history; results are incomplete", node.span);
          return [];
        }
        selection.visited.add(node.id);
        selectedBranch = selection.branches.get(node.id)!;
      }
      const evaluations = node.instruction ? this.evaluateInstruction(node.instruction, current.previous, current.state, callPath, node.span) : node.expr ? this.evaluate(node.expr, current.state, callPath) : [{ state: current.state, value: empty() }];
      // An expression or nested call can replace the current state with several
      // alternatives, including at the final return where no next iteration
      // would check the count. Preserve completed evidence but mark the entry
      // incomplete before adding over-budget alternatives.
      if (pending.length + completed.length + evaluations.length > this.maxPaths) {
        this.issue("analysis-budget", "Abstract path budget exhausted; results are incomplete", fn.declaration.span);
        return completed;
      }
      for (const evaluation of evaluations) {
        this.bindNodeEvaluation(fn, node, evaluation, callPath, live);
        if (node.kind === "return") {
          finish(evaluation);
          continue;
        }
        const chosen = node.kind === "branch" && this.sourcePreference !== undefined ? this.selectedSourceBranch(evaluation.value, evaluation.state, node.booleanRhsTruth) : undefined;
        for (const edge of node.edges) {
          if (edge.target === graph.abort) continue;
          if (node.kind === "branch" && this.sourcePreference !== undefined && edge.condition !== chosen?.truth) continue;
          if (node.kind === "branch" && selectedBranch !== undefined && edge.condition !== selectedBranch) continue;
          if (node.kind === "branch" && evaluation.value.constantKind === "boolean" && evaluation.value.constant !== undefined && evaluation.value.constant !== String(edge.condition)) continue;
          const next = chosen?.state ?? this.cloneState(evaluation.state);
          if (node.kind === "branch") {
            if ((!chosen && !this.assume(evaluation.value, edge.condition!, next)) || !this.recordPredicate(evaluation.value, edge.condition!, next, node.span, callPath)) continue;
            if (next.branchJournal) this.appendBranch(next, { kind: "choice", node: node.id, value: evaluation.value, selected: edge.condition!, location: node.span, until: node.join!, owner: fn.symbol.id });
            next.path.push({ kind: "branch", label: `condition may be ${edge.condition}`, location: node.span });
            next.control.push({ value: this.eitherControl(evaluation.value, node.span, node.sameValueArms ? "same-value" : "control"), until: node.join!, owner: fn.symbol.id });
          }
          pending.push({ node: edge.target, previous: node.id, state: next });
        }
      }
    }
    return completed;
  }

  private bindNodeEvaluation(fn: FunctionInfo, node: CFGNode, evaluation: Evaluation, callPath: string[], live: LiveVariables): void {
    const boundValue = this.withControl(evaluation.value, evaluation.state, node.span);
    if (node.instruction?.result) evaluation.state.env.set(node.instruction.result, node.instruction.kind === "copy" ? boundValue : evaluation.value);
    if (node.binding) evaluation.state.env.set(node.binding, step(boundValue, "binding", this.program.symbols.get(node.binding)!.name, node.span));
    if (node.pattern) this.bindPattern(node.pattern, boundValue, evaluation.state, callPath);
    if (node.kind !== "return") return;
    evaluation.value = { ...this.withControl(step(evaluation.value, "return", fn.symbol.name, node.span), evaluation.state, node.span), type: fn.declaration.type };
    if (callPath.length === 1 && fn.symbol.kind !== "constructor") this.appendSink(evaluation.state,
      { kind: "exported-return", name: fn.symbol.name, location: node.span, value: evaluation.value, callPath });
    evaluation.state.control = evaluation.state.control.filter(control => control.owner !== fn.symbol.id);
    this.completeCircuit(evaluation.state, callPath);
    for (const symbol of live.owned) evaluation.state.env.delete(symbol);
  }

  /** Lift the real acyclic CFG, including predecessor-sensitive IR merges.
   * A rejected arm stays rejected. Each stored state is immutable; all ordinary
   * mutating transfers receive a clone. Call context stays live through selection
   * because no recipe escapes this synchronous invocation. */
  private interpretConditionalSource(fn: FunctionInfo, args: AbstractValue[], input: State, stack: string[]): Evaluation[] {
    if (this.maxPaths < 1) {
      this.issue("analysis-budget", "Selected source replay has no path allowance; results are incomplete", fn.declaration.span);
      return [];
    }
    type Cursor = { state: State; value: AbstractValue; previous: number; branch?: boolean } | undefined;
    const cfg = this.engine === "instructions" ? this.program.instructionCFG(fn.symbol.id) : fn.cfg;
    const callPath = [...stack, fn.symbol.id];
    const live = this.liveVariablesFor(fn, cfg);
    const graph = new ConditionalStateGraph((work, values) => {
      this.steps += work; this.abstractValues += values;
      return this.steps <= this.maxSteps && this.abstractValues <= this.maxValues;
    });
    const required = <T>(term: ConditionalTerm<T> | undefined): ConditionalTerm<T> => {
      if (!term) throw new Refused();
      return term;
    };
    class Refused extends Error {}
    try {
      const initial = this.cloneState(input);
      this.bindParameters(fn, args, initial, [...stack, fn.symbol.id]);
      const incoming = new Map<number, ConditionalTerm<Cursor>[]>();
      incoming.set(cfg.entry, [required(graph.atom<Cursor>({ state: initial, value: empty(), previous: -1 }))]);
      // CFG return edges describe structural flow to exit; the ordinary
      // interpreter completes at return and must not execute that exit again.
      const reachable = new Set<number>(), discover = [cfg.entry];
      while (discover.length) {
        const id = discover.pop()!;
        if (id === cfg.abort || reachable.has(id)) continue;
        if (++this.steps > this.maxSteps) {
          graph.refuse("Source construction exhausted the shared step allowance"); throw new Refused();
        }
        reachable.add(id);
        if (cfg.nodes[id].kind !== "return") discover.push(...cfg.nodes[id].edges.map(edge => edge.target));
      }
      const remaining = new Map([...reachable].map(node => [node, 0]));
      for (const id of reachable) if (cfg.nodes[id].kind !== "return") for (const edge of cfg.nodes[id].edges) {
        if (++this.steps > this.maxSteps) {
          graph.refuse("Source construction exhausted the shared step allowance"); throw new Refused();
        }
        if (remaining.has(edge.target)) remaining.set(edge.target, remaining.get(edge.target)! + 1);
      }
      const parentCounts = new Map(remaining);
      const pending = [cfg.entry], completed: ConditionalTerm<Cursor>[] = [];
      let visited = 0;
      const merge = (terms: ConditionalTerm<Cursor>[]): ConditionalTerm<Cursor> => required(graph.defer(terms, (...cursors) => {
        const surviving = cursors.filter(cursor => cursor !== undefined);
        if (surviving.length > 1) graph.refuse("Source join has multiple selected predecessors");
        return surviving.length === 1 ? surviving[0] : undefined;
      }));
      while (pending.length) {
        let node = cfg.nodes[pending.pop()!];
        visited++;
        const inputs = incoming.get(node.id) ?? [];
        const before = inputs.length === 1 ? inputs[0] : merge(inputs);
        // Keep straight-line source work in one recipe. Every instruction still
        // runs and pays its ordinary work; it need not add graph depth/value
        // capacity solely because IR split one expression into many nodes.
        const segment = [node];
        while (!["branch", "exit", "return"].includes(node.kind)) {
          const edges = node.edges.filter(edge => edge.target !== cfg.abort);
          if (edges.length !== 1 || parentCounts.get(edges[0].target) !== 1) break;
          remaining.set(edges[0].target, 0);
          node = cfg.nodes[edges[0].target];
          segment.push(node); visited++;
        }
        let after = required(graph.defer([before], (cursor): Cursor => {
          for (const node of segment) {
            if (!cursor) return;
            const state = this.cloneState(cursor.state);
            this.cleanNodeScope(fn, state, live, node.id);
            if (++this.steps > this.maxSteps) { graph.refuse("Source transfer exhausted the shared step allowance"); return; }
            if (node.kind === "exit") {
              state.control = state.control.filter(control => control.owner !== fn.symbol.id);
              this.completeCircuit(state, callPath);
              for (const symbol of live.owned) state.env.delete(symbol);
              return { state, value: { ...empty(), items: [], type: "[]" }, previous: node.id };
            }
            const evaluations = node.instruction ? this.evaluateInstruction(node.instruction, cursor.previous, state, callPath, node.span)
              : node.expr ? this.evaluate(node.expr, state, callPath) : [{ state, value: empty() }];
            if (this.incompleteEntries.has(this.currentEntry)) { graph.refuse("Source transfer is incomplete"); return; }
            if (evaluations.length > 1) { graph.refuse("Nested expression/call alternatives are not lifted into the source graph"); return; }
            const evaluation = evaluations[0];
            if (!evaluation) return;
            this.bindNodeEvaluation(fn, node, evaluation, callPath, live);
            cursor = { ...evaluation, previous: node.id };
          }
          return cursor;
        }));
        if (node.kind === "branch") after = required(graph.decision(String(node.id), after,
          cursor => !cursor ? false : cursor.value.constantKind === "boolean" && cursor.value.constant !== undefined ? cursor.value.constant === "true" : undefined,
          (cursor, selected): Cursor => {
            if (!cursor || cursor.value.constantKind === "boolean" && cursor.value.constant !== undefined && cursor.value.constant !== String(selected)) return;
            const state = this.cloneState(cursor.state);
            if (!this.assume(cursor.value, selected, state) || !this.recordPredicate(cursor.value, selected, state, node.span, callPath)) return;
            state.path.push({ kind: "branch", label: `condition may be ${selected}`, location: node.span });
            state.control.push({ value: this.eitherControl(cursor.value, node.span, node.sameValueArms ? "same-value" : "control"), until: node.join!, owner: fn.symbol.id });
            return { ...cursor, state, branch: selected };
          }));
        if (node.kind === "exit" || node.kind === "return") completed.push(after);
        if (node.kind === "return") continue;
        for (const edge of node.edges) {
          if (edge.target === cfg.abort) continue;
          const selected = node.kind === "branch" ? required(graph.defer([after], cursor => cursor?.branch === edge.condition ? cursor : undefined)) : after;
          const terms = incoming.get(edge.target) ?? [];
          terms.push(selected); incoming.set(edge.target, terms);
          const count = remaining.get(edge.target)! - 1;
          remaining.set(edge.target, count);
          if (!count) pending.push(edge.target);
        }
      }
      if (visited !== reachable.size) graph.refuse("Conditional source graph requires an acyclic CFG");
      const result = graph.select(merge(completed), new Map([...this.conditionalSelection!.decisions].map(([node, selected]) => [String(node), selected])), Math.max(1, this.maxSteps - this.steps), value => value);
      if (result.status === "incomplete") {
        this.issue("conditional-source-incomplete", `${result.reason}; selected source replay is incomplete`, fn.declaration.span);
        return [];
      }
      return result.value ? [{ state: result.value.state, value: result.value.value }] : [];
    } catch (error) {
      if (!(error instanceof Refused)) throw error;
      this.issue("conditional-source-incomplete", `${graph.incompleteReason ?? "Conditional source construction failed"}; selected source replay is incomplete`, fn.declaration.span);
      return [];
    }
  }

  private completeCircuit(state: State, stack: string[]): void {
    const circuit = stack.at(-1)!;
    state.guards.add(circuit);
    if (state.branchJournal) this.appendBranch(state, { kind: "completion", circuit });
    this.effectRecorder.record({ kind: "completion", circuit }, stack, this.callSites);
  }

  private appendSink(state: State, sink: PublicSink): void {
    if (this.ruleCertificate?.kind === "digest") this.ruleCertificate.sinks.push({ value: sink.value, location: sink.location });
    if (sink.kind !== "ledger-write") state.branchJournal?.recording.invalidate();
    state.sinks.push(sink);
    const { callPath, ...recorded } = sink;
    this.effectRecorder.record({ kind: "public-sink", sink: recorded }, callPath, this.callSites);
  }

  private replaySummary(summary: MutationSummary, input: State, stack: string[], location: Span): Evaluation[] {
    this.summaryHits++;
    this.statefulSummaryHits++;
    const state = this.cloneState(input);
    for (const recorded of summary.effects) {
      if (++this.steps > this.maxSteps) { this.issue("analysis-budget", "Summary effect budget exhausted; results are incomplete", location); return []; }
      const callPath = [...stack, ...recorded.callSuffix];
      const effect = recorded.effect;
      const callerSites = this.callSites;
      this.callSites = [...callerSites, ...recorded.locationSuffix ?? []];
      try {
        if (effect.kind === "completion") this.completeCircuit(state, callPath);
        else if (effect.kind === "assignment") this.assignRegion(state, effect.region, effect.value, effect.location, callPath);
        else if (!this.ledgerOperation(effect.expression, [this.readRegion(state, effect.region), ...effect.args], state, callPath)) return [];
      } finally { this.callSites = callerSites; }
      if (this.incompleteEntries.has(this.currentEntry)) return [];
    }
    return [{ state, value: summary.value }];
  }

  private replayReadonlySummary(summary: ReadonlySummary, input: State, stack: string[], location: Span): Evaluation[] {
    this.summaryHits++;
    this.readSummaryHits++;
    const state = this.cloneState(input);
    for (const recorded of summary.effects) {
      if (++this.steps > this.maxSteps) { this.issue("analysis-budget", "Summary effect budget exhausted; results are incomplete", location); return []; }
      const callPath = [...stack, ...recorded.callSuffix];
      if (recorded.effect.kind === "completion") this.completeCircuit(state, callPath);
      else this.appendSink(state, { ...recorded.effect.sink, callPath });
    }
    return [{ state, value: summary.value }];
  }

  private summaryKey(circuit: string, args: AbstractValue[], state: State): string | undefined {
    // Recipe-bearing calls use ordinary transfers until summary inputs retain
    // all selector constraints. No cache entry can freeze a selected arm.
    if (args.some(value => this.hashRecipes.contains(value))) return;
    const hasRegion = (value: AbstractValue): boolean => Boolean(value.region || value.merklePredicate || value.listPredicate || value.ledger.size || value.items?.some(hasRegion) || value.fields && Object.values(value.fields).some(hasRegion) || value.negated && hasRegion(value.negated) || value.byteEncoding && hasRegion(value.byteEncoding.scalar) || value.comparison && [value.comparison.left, value.comparison.right].some(hasRegion) || value.ordering && [value.ordering.left, value.ordering.right, ...value.ordering.leftBytes ?? []].some(hasRegion) || value.commitments?.some(commitment => hasRegion(commitment.input) || hasRegion(commitment.randomness)));
    if (args.some(hasRegion)) return undefined;
    const entries = <Value>(mapping: Map<string, Value>): [string, Value][] => [...mapping].sort(([first], [second]) => first.localeCompare(second));
    return this.summaryFingerprints.key({ circuit, args, control: state.control, known: entries(state.known), truths: entries(state.truths), excluded: entries(state.excluded), aggregateExclusions: entries(state.aggregateExclusions), aggregateExclusionsExhausted: state.aggregateExclusionsExhausted,
      scalarEqualities: state.scalarEqualities ? entries(state.scalarEqualities) : undefined, scalarEqualitiesExhausted: state.scalarEqualitiesExhausted,
      integerDomains: state.integerDomains ? entries(state.integerDomains) : undefined, orderings: state.orderings ? entries(state.orderings) : undefined, orderingsExhausted: state.orderingsExhausted });
  }

  private readSummaryKey(fn: FunctionInfo, args: AbstractValue[], state: State): string | undefined {
    const base = this.summaryKey(fn.symbol.id, args, state);
    if (!base) return undefined;
    const roots = [...fn.readsState].sort();
    if (roots.length > 64) return undefined;
    const selected = new Set(roots);
    const ledger = [...state.ledger]
      .filter(([key, value]) => selected.has(regionFromKey(key, value.type ?? "unknown").root))
      .sort(([left], [right]) => left.localeCompare(right));
    if (ledger.some(([, value]) => this.hashRecipes.contains(value))) return;
    if (ledger.length > 256) return undefined;
    const revisions = roots.map(root => [root, state.ledgerVersions.get(root) ?? 0] as const);
    const collections = state.collections.snapshot().collections.filter(collection => selected.has(collection.region.root));
    const lists = state.lists.snapshot().lists.filter(list => selected.has(list.region.root));
    return this.summaryFingerprints.key({ base, ledger, revisions, collections, lists });
  }

  private evaluateInstruction(instruction: Instruction, predecessor: number, state: State, stack: string[], location: Span): Evaluation[] {
    const inputs = instruction.kind === "merge" ? [instruction.inputs[instruction.predecessors.indexOf(predecessor)]] : instruction.inputs;
    const values: AbstractValue[] = [];
    for (const input of inputs) {
      const value = state.env.get(input);
      if (!value) { this.issue("invalid-ir-value", "Instruction operand has no abstract value", location); return []; }
      values.push(this.refine(value, state));
    }
    if (instruction.kind === "evaluate") return this.evaluate(instruction.expression, state, stack, instruction.deferred ? undefined : values);
    if (instruction.kind === "copy" || instruction.kind === "merge") return [{ state, value: values[0] }];
    const expr = instruction.expression;
    if (this.enrollmentReviewObservation && !this.enrollmentCharge(inputs.length, inputs.length + 1, location)) return [];
    const originals = this.observeEither || this.enrollmentReviewObservation ? inputs.map(input => state.env.get(input)!) : undefined;
    return [{ state, value: this.eitherLogicalValue(values, originals ?? values, expr, instruction.selected) }];
  }

  private evaluateArgs(args: Expr[], state: State, stack: string[]): { state: State; values: AbstractValue[] }[] {
    let results = [{ state, values: [] as AbstractValue[] }];
    for (const arg of args) {
      results = results.flatMap(result => this.evaluate(arg, result.state, stack).map(evaluation => ({ state: evaluation.state, values: [...result.values, evaluation.value] })));
      if (results.length > this.maxPaths) {
        this.issue("analysis-budget", "Expression path budget exhausted; results are incomplete", arg.span);
        return [];
      }
    }
    return results;
  }

  private hashChoice(expr: Expr, condition: Evaluation, stack: string[]): Evaluation | undefined {
    const selector = condition.value;
    if (selector.constant !== undefined || !selector.identity || selector.comparison || selector.negated || selector.ordering) return;
    if (!selector.flows.some(flow => flow.form === "raw" && flow.source.id === selector.identity)) return;
    // Admission excludes calls, mutations and short-circuiting in the operands.
    // Read both total arms without assuming the selector. Runtime dependency
    // checks below decline when that assumption could change preimage evidence.
    const yes = this.evaluate(expr.args[1], condition.state, stack);
    const no = this.evaluate(expr.args[2], condition.state, stack);
    if (yes.length !== 1 || no.length !== 1 || !yes[0].value.identity || !no[0].value.identity) return;
    const values = [yes[0].value, no[0].value];
    // Ambient caller control can occur in both operands without determining the
    // selector's raw Boolean value. Test its immutable leaf, not those controls.
    if (values.some(value => value.flows.some(flow => flow.source.id === selector.identity))) return;
    // Ledger origins disappear at the hash transfer, but remain in the input
    // expressions. Restrict ledger selectors until that independence is proved.
    if (selector.ledger.size) return;
    const canonical = (value: AbstractValue): AbstractValue => ({ ...value, identity: undefined,
      flows: [...value.flows].sort((a, b) => `${a.source.id}:${a.form}`.localeCompare(`${b.source.id}:${b.form}`)) });
    const [first, second] = values.map(canonical);
    // Exact digest observation compares typed input leaves, never their order.
    // Admit only permuted inputs, and only while the selector's elided Boolean
    // value cannot refine rule evidence (see compressionTouches).
    const comparable = (value: AbstractValue): AbstractValue => this.observeDigestInputs ? { ...value, directDigest: undefined } : value;
    if (this.valueFingerprints.key(comparable(first)) !== this.valueFingerprints.key(comparable(second))) return;
    const tokens = new Set([selector.identity]);
    if (this.observeDigestInputs && (!this.permutedDigests(values[0].directDigest, values[1].directDigest)
      || !this.existingCompressedValues(condition.state, tokens, new Set([selector.identity]))
      || this.compressionTouches([condition.state.scalarEqualities, condition.state.orderings, condition.state.aggregateExclusions, condition.state.bindings,
        condition.state.predicates, condition.state.operations, condition.state.collections.snapshot(), condition.state.lists.snapshot(), condition.state.merkle?.snapshot()], tokens))) return;
    const identity = this.hashRecipes.choose(selector.identity, values[0].identity!, values[1].identity!);
    if (!identity) return;
    if (this.observeDigestInputs) { for (const token of tokens) this.compressionTokens.add(token); this.observationCompressions++; }
    const flows = first.flows.map((flow, index) => {
      const other = second.flows[index];
      let prefix = 0;
      while (flow.trace[prefix] && other.trace[prefix]) {
        if (++this.steps > this.maxSteps || this.valueFingerprints.key(flow.trace[prefix]) !== this.valueFingerprints.key(other.trace[prefix])) break;
        prefix++;
      }
      return { ...flow, trace: [...flow.trace.slice(0, prefix), { kind: "hash-choice", label: "total hash-order alternatives", location: expr.span }] };
    });
    const value = controlled({ ...first, identity, flows }, [selector], expr.span, true);
    if (this.sourceHistories) {
      // Ordinary (selected) histories branch on this selector; exact histories
      // compress it. Retain both polarities as choice-only observations: never
      // required and outside effect guard masks (see querySourceEntry).
      // Exact histories record no selector check here, so gate classification
      // (otherChecks) is left to the compressed history itself.
      for (const truth of [true, false]) {
        const probe: State = { ...condition.state, predicates: [], writes: [], operations: [] };
        if (!this.recordPredicate(selector, truth, probe, expr.span, stack)) return;
        this.choicePredicates.push(...probe.predicates ?? []);
      }
    }
    condition.state.path.push({ kind: "summary", label: "total hash-order alternatives", location: expr.span });
    return { state: condition.state, value: this.refine(value, condition.state) };
  }

  private evaluate(expr: Expr, state: State, stack: string[], operands?: AbstractValue[]): Evaluation[] {
    return this.commonEvaluations(this.evaluateAlternatives(expr, state, stack, operands), expr.span);
  }

  private evaluateAlternatives(expr: Expr, state: State, stack: string[], operands?: AbstractValue[]): Evaluation[] {
    if (state.branchJournal && !["literal", "ref", "disclose", "assign", "default", "tuple"].includes(expr.kind)) state.branchJournal.recording.invalidate();
    if (++this.steps > this.maxSteps) {
      this.issue("analysis-budget", "Expression budget exhausted; results are incomplete", expr.span);
      return [];
    }
    if (expr.kind === "literal") {
      const constant = literalConstant(expr);
      if (!constant && expr.literalString !== undefined) {
        this.issue("literal-budget", `Decoded/padded literal exceeds the ${MAX_LITERAL_BYTES}-byte analysis limit`, expr.span);
        return [];
      }
      return [{ state, value: { ...empty(), type: expr.inferredType, constant: constant?.value, constantKind: constant?.kind } }];
    }
    if (expr.kind === "default") return [{ state, value: this.defaultValue(expr.type!) }];
    if (expr.kind === "lambda") return [{ state, value: empty() }];
    if (expr.kind === "ref") {
      const symbol = this.program.symbols.get(expr.symbol!)!;
      if (symbol.kind === "ledger") return [{ state, value: this.readRegion(state, { root: symbol.id, path: [], type: symbol.type }) }];
      if (symbol.kind === "type") return [{ state, value: empty() }];
      const value = state.env.get(symbol.id);
      if (!value) {
        this.issue("unknown-value", `No abstract value for ${symbol.name}`, expr.span);
        return [];
      }
      return [{ state, value: this.refine(value, state) }];
    }
    if (expr.kind === "conditional") {
      const results: Evaluation[] = [];
      for (const condition of this.evaluate(expr.args[0], state, stack)) {
        const compact = this.useHashChoices && !this.observeArithmetic && !this.counterSelection && hashChoiceCandidate(expr, this.program.symbols)
          ? this.hashChoice(expr, condition, stack) : undefined;
        if (compact) { results.push(compact); continue; }
        if (!this.flushSourceHistory(condition.state)) continue;
        const chosen = this.sourcePreference !== undefined ? this.selectedSourceBranch(condition.value, condition.state) : undefined;
        if (this.sourcePreference !== undefined && !chosen) continue;
        for (const selected of chosen ? [chosen.truth] : [true, false]) {
          if (condition.value.constantKind === "boolean" && condition.value.constant !== undefined && condition.value.constant !== String(selected)) continue;
          const branch = chosen?.state ?? this.cloneState(condition.state);
          if ((!chosen && !this.assume(condition.value, selected, branch)) || !this.recordPredicate(condition.value, selected, branch, expr.span, stack)) continue;
          branch.path.push({ kind: "branch", label: `conditional may be ${selected}`, location: expr.span });
          const controlDepth = branch.control.length;
          branch.control.push({ value: this.eitherControl(condition.value, expr.span, sameTotalValueArms(expr, this.program.symbols, type => this.program.representationOf(type)) ? "same-value" : "control"), until: -1, owner: stack.at(-1)! });
          for (const result of this.evaluate(expr.args[selected ? 1 : 2], branch, stack)) {
            result.value = this.withControl(result.value, result.state, expr.span);
            if (!expr.args.slice(1).some(this.program.mayAbortExpression)) result.state.control = result.state.control.slice(0, controlDepth);
            results.push(result);
          }
        }
      }
      return results;
    }
    if (expr.kind === "binary" && ["&&", "||"].includes(expr.name!)) return this.shortCircuit(expr, state, stack);
    if (expr.kind === "assign") {
      const addresses = operands ? [{ state, value: operands[0] }] : this.evaluate(expr.args[0], state, stack);
      return addresses.flatMap(address => (operands ? [{ state: address.state, value: operands[1] }] : this.evaluate(expr.args[1], address.state, stack)).flatMap(evaluation => {
        const region = address.value.region;
        if (!region) { this.issue("unknown-region", "Assignment target has no resolved ledger region", expr.span); return []; }
        const previous = expr.name === "=" || region.revision === (evaluation.state.ledgerVersions.get(region.root) ?? 0) ? address.value : this.readRegion(evaluation.state, region);
        if (expr.name !== "=") evaluation.state.otherChecks = true;
        const assigned = expr.name === "=" ? evaluation.value : this.counterMutation(previous, evaluation.value, expr.name === "+=" ? "+" : "-", expr.span);
        if (!assigned) return [];
        this.assignRegion(evaluation.state, region, assigned, expr.span, stack);
        return [{ state: evaluation.state, value: empty() }];
      }));
    }
    if (expr.kind === "map" || expr.kind === "fold") return this.iterate(expr, state, stack, operands);
    const results: Evaluation[] = [];
    for (const evaluation of operands ? [{ state, values: operands }] : this.evaluateArgs(expr.args, state, stack)) {
      const { values } = evaluation;
      const next = evaluation.state;
      let value: AbstractValue;
      if (expr.kind === "call") {
        const symbol = this.program.symbols.get(expr.symbol!)!;
        if (this.useHashChoices && symbol.kind === "intrinsic" && !["hash", "constructor", "witness"].includes(intrinsicModel(symbol).kind)
          && values.some(value => this.hashRecipes.contains(value))) {
          this.issue("unsupported-hash-choice", "Native transfer uses an unmodeled conditional identity; results are incomplete", expr.span);
          continue;
        }
        if (symbol.kind === "intrinsic" && intrinsicModel(symbol).nativeEffect) {
          next.otherChecks = true; // Native transaction checks are not sole-gate evidence.
          const result = { ...empty(), items: [], type: "[]" };
          if (!this.recordRuntimeOperation(next, { kind: "native-witness", name: symbol.name, location: expr.span, args: values, result }, stack)) continue;
          results.push({ state: next, value: result });
          continue;
        }
        if (symbol.kind === "witness" || symbol.kind === "intrinsic" && intrinsicModel(symbol).kind === "witness") {
          const dependencies = step(combine(values), "witness-argument", symbol.name, expr.span, "derived");
          const site = JSON.stringify([stack, this.callSites.map(site => this.program.spanIdentity(site)), this.program.spanIdentity(expr.span)]);
          const calls = next.witnessCalls ??= new Map(), occurrence = calls.get(site) ?? 0;
          calls.set(site, occurrence + 1);
          let leaf = 0;
          value = this.typedValue(expr.inferredType ?? symbol.type, (_type, digest) => {
            const source = this.source("witness", symbol.name, expr.span, symbol.id, { site, occurrence, leaf: leaf++ }, digest);
            return { ...source, flows: combine([source, dependencies]).flows, commitments: dependencies.commitments };
          });
          // Selected invocation observers retain a witness's exact input and
          // returned snapshots too. Argument dependencies alone never bind a
          // witness result to its input. This adds evidence, not a constraint.
          if (this.observeInvocations.has(symbol.id) && !this.recordRuntimeOperation(next,
            { kind: "circuit-invocation", name: symbol.id, location: expr.span, args: values, result: value }, [...stack, symbol.id])) continue;
        } else if (symbol.kind === "intrinsic") {
          if (intrinsicModel(symbol).kind === "derived") next.otherChecks = true;
          if (intrinsicModel(symbol).kind === "derived" && !["degradeToTransient", "upgradeFromTransient"].includes(symbol.name)) {
            const representation = this.program.representationOf(expr.inferredType!);
            // Historical/RC2 points retain nominal opaque source identity, but
            // native operations still obey their selected curve signatures.
            const nativeType = representation === 'Opaque<"JubjubPoint">' ? "JubjubPoint" : representation;
            if (this.observeSecpSignatures && !this.enrollmentCharge(3 + values.length, 3 + values.length, expr.span)) continue;
            const result = nativeValue(symbol.id.slice("intrinsic::".length), nativeType, values, expr.span, next, () => `native-fresh:${this.nativeCount++}`, this.observeSignatureKeyIdentity, this.observeSecpSignatures, this.program.meteringIdentity);
            if (result) {
              this.trackCompressedValue(result, values, expr.span);
              const observedResult = this.enrollmentDependencies({ ...result, type: expr.inferredType }, values, expr.span);
              if (this.observeInvocations.has(PUBLIC_SCALAR_CAST) && this.observeInvocations.has(symbol.id) && !this.recordRuntimeOperation(next,
                { kind: "circuit-invocation", name: symbol.id, location: expr.span, args: values, result: observedResult }, stack)) continue;
              results.push({ state: next, value: observedResult });
            }
            continue;
          }
          if (intrinsicModel(symbol).kind === "constructor") {
            const types = typeArguments(expr.generics);
            let fields: Record<string, AbstractValue>;
            if (["some", "none"].includes(symbol.name)) fields = { is_some: this.boolean(symbol.name === "some"), value: symbol.name === "some" ? values[0] : this.defaultValue(types[0] ?? "unknown") };
            else fields = { is_left: this.boolean(symbol.name === "left"), left: symbol.name === "left" ? values[0] : this.defaultValue(types[0] ?? "unknown"), right: symbol.name === "right" ? values[0] : this.defaultValue(types[1] ?? "unknown") };
            if (this.observeEither && this.eitherType(expr.inferredType)) for (const arm of ["left", "right"]) fields[arm] = reconstructedPayload(fields[arm], () => this.chargeEither(expr.span));
            value = { ...combine(Object.values(fields)), fields, type: expr.inferredType };
            results.push({ state: next, value });
            continue;
          }
          const input = combine(values);
          value = step(input, "transform", symbol.name, expr.span, symbol.type as Flow["form"]);
          if ((this.leafBindingObservation || this.observeInvocations.has(PUBLIC_SCALAR_CAST)) && ["degradeToTransient", "upgradeFromTransient"].includes(symbol.name)) {
            // These change representation. Keep dependencies, but give the
            // result its own deterministic value identity: Bytes -> Field ->
            // Bytes is not an equality proof about the original bytes.
            value.identity = nativeIdentity(symbol.id, values, () => `native-fresh:${this.nativeCount++}`, this.program.meteringIdentity);
          }
          if (this.observeInvocations.has(PUBLIC_SCALAR_CAST) && this.observeInvocations.has(symbol.id) && !this.recordRuntimeOperation(next,
            { kind: "circuit-invocation", name: symbol.id, location: expr.span, args: values, result: { ...value, type: expr.inferredType } }, stack)) continue;
          if (this.currentRootObservation) {
            const dependency = containsObservedMerkleCheck({ ...empty(), items: values }, next.operations ?? [], () => ++this.steps <= this.maxSteps);
            if (dependency === undefined) this.issue("predicate-budget", "Opaque Merkle-check transformation exceeds its bounded allowance; policy observation is incomplete", expr.span);
            if (dependency !== false) value.predicateStructureLost = true;
          }
          if (symbol.type === "commitment") {
            value.commitments = [{ primitive: symbol.name, location: expr.span, input: values[0], randomness: values[1] }];
            if (this.observeCommitInputs) value.directCommit = { primitive: symbol.name, input: values[0], randomness: values[1] };
          }
          if (symbol.type === "hash") {
            if (!this.secretBindingCharge(2, 3, expr.span)) continue;
            if (this.observeDigestInputs) value.directDigest = { primitive: symbol.name, input: values[0], inputType: typeArguments(expr.generics)[0] };
            if (this.ruleCertificate?.kind === "digest") {
              if (++this.abstractValues > this.maxValues) this.issue("value-budget", "Digest certificate observations exhausted the shared value allowance; results are incomplete", expr.span);
              this.ruleCertificate.digests.push({ input: values[0], location: expr.span });
            }
            const origin = directPreimageSource(values[0], this.maxSteps - this.steps);
            this.steps += origin.work;
            if (!origin.complete) {
              this.issue("predicate-budget", "Private preimage origin traversal exceeded its bounded allowance; results are incomplete", expr.span);
              continue;
            }
            value.flows = value.flows.map((flow, index) => ({ ...flow, form: input.flows[index].form === "raw" ? "hash" : "derived",
              directPreimage: input.flows.length === 1 && input.flows[index].form === "raw" && origin.source?.id === flow.source.id }));
            if (origin.source) value.directHash = { source: origin.source, primitive: symbol.name };
          }
          if (this.observeTransientOrigins && ["transientHash", "transientCommit"].includes(symbol.name))
            value = { ...value, ...transientDependencies([value, { ...empty(), transientOrigins: [{ primitive: symbol.name as TransientOrigin["primitive"], location: expr.span }] }]) };
          // Caller-convention and collection analyses need a stable identity
          // for a repeated pure hash expression even when no collection
          // detector is selected. Keep this bounded and only retain it when
          // every operand has an immutable key; unknown operands stay fresh.
          if (!value.identity && symbol.type === "hash" && (this.predicateScope !== "witness" || this.useHashChoices)) {
            const operand = immutableOperandKey({ ...empty(), items: values }, Math.min(1024, Math.max(0, this.maxSteps - this.steps)), undefined, undefined, this.program.meteringIdentity);
            this.steps += operand.work;
            if (operand.complete && operand.key) value.identity = this.derivedIdentity("hash-derived", [symbol.id, expr.generics, expr.inferredType, operand.key]);
          }
          if (this.observeCollections && ["hash", "commitment"].includes(symbol.type)) {
            const operand = immutableOperandKey({ ...empty(), items: values }, Math.min(4096, this.maxSteps - this.steps), undefined, undefined, this.program.meteringIdentity);
            this.steps += operand.work;
            if (!operand.complete) {
              this.issue(this.steps > this.maxSteps ? "analysis-budget" : "predicate-budget",
                this.steps > this.maxSteps ? "Analysis step budget exhausted during collection key derivation; results are incomplete"
                  : "Collection key derivation exceeds its bounded operand traversal; results are incomplete", expr.span);
              continue;
            }
            value.identity = operand.key ? this.derivedIdentity("collection-derived", [symbol.id, expr.generics, expr.inferredType, operand.key]) : `collection-derived-fresh:${this.snapshotCount++}`;
          }
          if (symbol.type === "hash" && this.useHashChoices && values.some(value => this.hashRecipes.contains(value))) {
            const identity = this.hashRecipes.hash(values, [symbol.id, expr.generics, expr.inferredType], this.observeCollections ? "collection-derived" : "hash-derived");
            if (identity) value.identity = identity;
            else { this.issue("unsupported-hash-choice", "Hash input uses an unmodeled conditional identity; results are incomplete", expr.span); continue; }
          }
          value.ledger = new Set();
        } else {
          const callee = this.program.functions.get(symbol.id)!;
          results.push(...this.invoke(callee, values, next, stack, expr.span).map(result => ({ state: result.state, value: step(result.value, "call", symbol.name, expr.span) })));
          continue;
        }
      } else if (expr.kind === "emit") {
        value = { ...empty(), items: [], type: "[]" };
        if (!this.recordRuntimeOperation(next, { kind: "event", name: expr.event!.name, event: expr.event, location: expr.span, args: values, result: value }, stack)) continue;
        const payload = this.withControl(step(values[0], "event", expr.event!.name, expr.span), next, expr.span, true);
        this.appendSink(next, { kind: "event", name: expr.event!.name, location: expr.span, value: payload, callPath: [...stack] });
      } else if (expr.kind === "disclose") {
        value = step(values[0], "disclose", "explicit disclosure permission", expr.span);
      } else if (expr.kind === "assert") {
        if (this.observeCapacity && this.sequenceStep === 1 && this.capacityConstruction) {
          const retained = 1 + (next.predicates?.length ?? 0) + (next.operations?.length ?? 0) + next.writes.length + next.bindings.length + next.sinks.length + next.path.length;
          this.abstractValues += retained; this.steps += retained;
          if (this.abstractValues > this.maxValues || this.steps > this.maxSteps) { this.issue("capacity-observation-budget", "Constructor/gate prefix evidence exhausted its shared allowance", expr.span); continue; }
          this.capacityPrefixes.push({ construction: this.capacityConstruction, location: expr.span, gate: { entry: this.currentEntry, bindings: next.bindings.slice(), sinks: next.sinks.slice(), path: next.path.slice(), writes: next.writes.slice(), operations: next.operations?.slice(),
            predicates: [...next.predicates ?? [], { value: values[0], truth: true, location: expr.span, callPath: [...stack], callSites: this.callSites.slice(), writesBefore: next.writes.length, operationsBefore: next.operations?.length ?? 0 }] } });
        }
        const mayFail = values[0].constantKind !== "boolean" || values[0].constant !== "true";
        const possible = this.assume(values[0], true, next);
        const site = JSON.stringify([this.currentEntry, this.program.spanIdentity(expr.span)]);
        const previous = this.assertionReaches.get(site);
        if (previous) { previous.maySucceed ||= possible; previous.mayFail ||= mayFail; }
        else this.assertionReaches.set(site, { location: expr.span, entry: this.currentEntry, owner: stack.at(-1)!,
          literalFalse: expr.args[0].kind === "literal" && expr.args[0].value === "false", maySucceed: possible, mayFail });
        if (!possible) {
          this.failedAssertions.push({ location: expr.span, condition: values[0], message: expr.value ?? "Assertion fails", callPath: [...stack], path: [...next.path] });
          continue;
        }
        if (!this.recordPredicate(values[0], true, next, expr.span, stack, this.enrollmentReviewObservation || this.observeEither && (mayFail || !!values[0].eitherLogicalGate))) continue;
        next.bindings.push(...(values[0].equalities ?? []).map(binding => ({ ...binding, location: expr.span })));
        next.path.push({ kind: "constraint", label: "assertion must succeed", location: expr.span });
        value = empty();
      } else if (expr.kind === "tuple" || expr.kind === "bytes") {
        if ((sequenceLength(this.program.representationOf(expr.inferredType!)) ?? 0) > 256) { this.issue("sequence-budget", "Constructed sequence layout exceeds 256 elements", expr.span); continue; }
        const expanded = values.flatMap((value, index) => {
          if (expr.args[index].kind !== "spread") return [value];
          const items = this.sequenceItems(value, expr.span);
          if (items) return items;
          this.issue("unknown-spread", "Spread requires a known sequence layout of at most 256 elements", expr.span);
          return [value];
        });
        value = { ...combine(expanded), items: expanded, type: expr.inferredType };
        if (expr.kind === "bytes") value = this.withByteConstant(value);
      } else if (expr.kind === "spread") value = values[0];
      else if (expr.kind === "sequence") value = values.at(-1) ?? empty();
      else if (expr.kind === "struct") {
        const fields: Record<string, AbstractValue> = {};
        for (let index = 0; index < values.length; index++) {
          if (expr.fields![index] === "...") {
            if (!values[index].fields) { this.issue("unknown-struct-spread", "Struct spread requires a known field layout", expr.span); continue; }
            Object.assign(fields, values[index].fields);
          } else fields[expr.fields![index]] = values[index];
        }
        if (this.observeEither && this.eitherType(expr.type)) for (const arm of ["left", "right"]) fields[arm] = reconstructedPayload(fields[arm], () => this.chargeEither(expr.span));
        value = { ...combine(Object.values(fields)), fields, type: expr.type };
      } else if (expr.kind === "index") {
        if (values[1].constant === undefined) next.otherChecks = true;
        const index = values[1].constantKind === "integer" && values[1].constant !== undefined ? Number(values[1].constant) : undefined;
        const projected = index === undefined ? undefined : this.sequenceElement(values[0], index, expr.span);
        if (!projected) { this.issue("unsupported-projection", "Sequence projection requires a known layout and in-bounds constant index", expr.span); continue; }
        value = this.withSelection(projected, step(values[1], "selection", "sequence index", expr.span, "derived"));
      } else if (expr.kind === "slice") {
        if (values[1].constant === undefined) next.otherChecks = true;
        const start = values[1].constantKind === "integer" ? Number(values[1].constant) : undefined;
        const length = Number(expr.value);
        const inputLength = sequenceLength(this.program.representationOf(values[0].type ?? "unknown"));
        if (start === undefined || !Number.isSafeInteger(start) || start < 0 || !Number.isSafeInteger(length) || length < 0 || inputLength === undefined || start + length > inputLength) { this.issue("unsupported-slice", "Slice requires known in-bounds dimensions", expr.span); continue; }
        if (length > 256) { this.issue("sequence-budget", "Slice result layout exceeds 256 elements", expr.span); continue; }
        const items = Array.from({ length }, (_, index) => this.sequenceElement(values[0], start + index, expr.span));
        if (items.some(item => !item)) { this.issue("unsupported-slice", "Slice requires a modeled element layout", expr.span); continue; }
        value = { ...combine(items as AbstractValue[]), items: items as AbstractValue[], type: expr.inferredType };
        if (parseType(this.program.representationOf(expr.inferredType!)).name === "Bytes") value = length === inputLength ? step(values[0], "projection", "full Bytes slice", expr.span) : this.withByteConstant(value);
        if (length) value = this.withSelection(value, step(values[1], "selection", "sequence index", expr.span, "derived"));
      } else if (expr.kind === "member") {
        const symbol = this.program.symbols.get(expr.symbol ?? expr.args[0].symbol ?? "");
        if (expr.contractCall) {
          // 0.35 resolves the implementation at runtime. Preserve the caller's
          // ledger writes, but make reads after the boundary unknown because a
          // callee can re-enter this contract. The call remains an explicit
          // incomplete boundary; it is no longer represented as whole-ledger
          // havoc that destroys writes and hides the call operation.
          if (this.program.compilerVersion === "0.35.0" || this.program.compilerVersion === "0.35.0-rc.1") {
            this.modelDynamicContractCall(next, expr, values, expr.span, stack);
            value = { ...empty(), type: expr.inferredType ?? "unknown", predicateStructureLost: true };
          } else {
            // Older profiles retain the historical hard boundary.
            this.issue("unsupported-contract-call", `Cross-contract call ${this.program.symbols.get(expr.contractCall.contract)?.name ?? "unknown"}.${expr.contractCall.circuit} has no effect model; this entry is incomplete`, expr.span);
            continue;
          }
        }
        else if (symbol?.declaration?.typeKind === "enum" && expr.value === "field") value = { ...empty(), constantKind: "enum", constant: `${symbol.name}.${expr.name}`, type: symbol.name };
        else if (expr.value === "call" && values[0].region) {
          const result = this.ledgerOperation(expr, values, next, stack);
          if (!result) continue;
          value = result;
        }
        else if (values[0].fields && expr.name! in values[0].fields) {
          value = step(values[0].fields[expr.name!], "projection", expr.name!, expr.span);
          if (expr.ledgerRoot && values[0].region) value = this.readRegion(next, { ...values[0].region, path: [...values[0].region.path, `field:${expr.name}`], type: expr.inferredType ?? "unknown" });
          value = this.selectEitherPayload(values[0], expr.name!, value, next, expr.span, stack, !!expr.ledgerRoot);
        } else { this.issue("unsupported-projection", `Unknown field ${expr.name} of ${values[0].type ?? "unknown"}`, expr.span); continue; }
      } else if (expr.kind === "binary") {
        if ((expr.checkedArithmetic || expr.name === "-" && (expr.numericType ?? expr.inferredType) !== "Field") && values.some(value => value.constant === undefined)) next.otherChecks = true;
        const computed = binaryValue(values, expr.name!, expr.span, expr.numericType ?? expr.inferredType ?? "unknown", expr.checkedArithmetic);
        if (!computed) continue;
        value = computed;
        if ((this.observeMintQuantities || this.mapDebitObservation || this.operationIntentObservation || this.complementarySendObservation) && ["+", "-", "*"].includes(expr.name!)) {
          if (this.operationIntentObservation) {
            this.steps++; this.abstractValues += 2 + values.length;
            if (this.steps > this.maxSteps || this.abstractValues > this.maxValues) {
              this.issue("operation-intent-operand-budget", "Exact numeric operands exhausted the shared allowance", expr.span); continue;
            }
          }
          if (this.complementarySendObservation && !this.complementaryCharge(1, 3 + values.length, expr.span)) continue;
          value = { ...value, numericExpression: { operator: expr.name! as "+" | "-" | "*", operands: values, ...(this.complementarySendObservation ? { numericType: expr.numericType ?? expr.inferredType } : {}) } };
        }
        if (this.observeArithmetic && expr.numericType === "Field" && ["+", "-", "*"].includes(expr.name!))
          value = { ...value, identity: value.identity ?? (value.constant === undefined ? nativeIdentity(`arithmetic:Field:${expr.name}`,values,() => `arithmetic-result:${this.snapshotCount++}`, this.program.meteringIdentity) : undefined), fieldArithmetic: { operator: expr.name! as "+" | "-" | "*", operands: values.map(input => ({
            flows: input.flows, ledger: input.ledger, type: input.type, identity: input.identity,
            constant: input.constant, constantKind: input.constantKind, integerRange: input.integerRange, uintOrigin: input.uintOrigin || numericBound(this.program.representationOf(input.type ?? "unknown")) !== undefined ? true : undefined,
          })), location: expr.span } };
        if (this.observeEither && ["==", "!="].includes(expr.name!) && valueIdentity(values[0]) !== undefined && valueIdentity(values[0]) === valueIdentity(values[1]))
          value = { ...value, eitherPayloads: undefined, eitherLogicalGate: undefined, eitherControls: undefined };
      } else if (expr.kind === "unary") {
        value = negateValue(values[0], expr.span);
      } else if (expr.kind === "cast") {
        if (!expr.castKind) { this.issue("unknown-cast", "Cast has no resolved conversion model", expr.span); continue; }
        if (expr.castKind !== "identity" && !["bytes-to-sequence", "sequence-to-bytes"].includes(expr.castKind) && values[0].constant === undefined) next.otherChecks = true;
        const sourceType = this.program.representationOf(expr.args[0].inferredType ?? values[0].type ?? "unknown");
        const targetType = this.program.representationOf(expr.type!);
        // A successful numeric narrowing preserves the immutable scalar, so
        // its target domain must intersect existing unsigned constraints.
        // Empty intersection is a definite abort, in both engines and without
        // enabling optional arithmetic observation.
        // A checked narrowing constrains its (identity-preserving) operand's domain.
        if (this.ruleCertificate?.kind === "digest" && expr.castKind === "numeric" && this.program.mayAbortExpression(expr))
          this.ruleCertificate.constraints.push({ value: values[0], location: expr.span });
        if (expr.castKind === "numeric" && this.program.mayAbortExpression(expr)
          && (next.orderings?.size || values[0].integerRange)
          && integerEnvelope(targetType, values[0], next) === null) continue;
        if (expr.castKind === "identity") value = step(values[0], "cast", expr.type!, expr.span);
        else if (expr.castKind === "bytes-to-sequence" || expr.castKind === "sequence-to-bytes") {
          const sequence = this.sequenceItems(values[0], expr.span);
          if (!sequence || sequence.length !== sequenceLength(targetType)) { this.issue("unsupported-sequence-cast", "Sequence conversion requires a known equally sized layout of at most 256 elements", expr.span); continue; }
          const items = sequence.map((item, index) => ({ ...item, type: elementType(targetType, index) }));
          value = step({ ...combine(items), items }, "cast", expr.type!, expr.span, "derived");
          if (values[0].byteEncoding && sequence.length === 32) value.byteEncoding = values[0].byteEncoding;
          if (expr.castKind === "sequence-to-bytes") value = this.withByteConstant(value);
        }
        else {
          value = step(values[0], "cast", expr.type!, expr.span, expr.castKind === "numeric" ? undefined : "derived");
          const constant = this.castScalarConstant(this.constant(values[0]), sourceType, targetType);
          if (constant === null) continue;
          // Scalar conversion discards the source representation. In particular,
          // modular Bytes -> field casts must not retain unreduced byte items.
          if (expr.castKind === "scalar") value = { ...value, fields: undefined, items: undefined, region: undefined, byteEncoding: undefined };
          value = { ...value, ledger: expr.castKind === "numeric" ? value.ledger : new Set(), equalities: undefined, constant: constant?.value, constantKind: constant?.kind, identity: expr.castKind === "numeric" ? value.identity : undefined, comparison: undefined, ordering: undefined, negated: undefined,
            ...(value.predicateHasAlternatives || value.predicateAlternatives || this.currentRootObservation && sourceType === "Boolean" ? { predicateStructureLost: true as const } : {}), collectionPredicate: undefined, listPredicate: undefined, ...(value.merklePredicate ? { merklePredicate: undefined } : {}) };
          if (value.predicateAlternatives) delete value.predicateAlternatives;
          rememberReportIdentity(`cast:${sourceType}:${targetType}`,
            `cast:${this.program.reportIdentity(sourceType)}:${this.program.reportIdentity(targetType)}`, this.program.meteringIdentity);
          if (expr.castKind === "scalar" && (foreignField(sourceType) || foreignField(targetType) || this.program.zkirVersion === 3 && targetType === "JubjubScalar")) value.identity = nativeIdentity(`cast:${sourceType}:${targetType}`, values, () => `native-fresh:${this.nativeCount++}`, this.program.meteringIdentity);
          if (expr.castKind === "scalar" && value.identity && values[0].constant === undefined && this.hashRecipes.contains(values[0])) {
            if (!this.hashRecipes.has(values[0].identity)) {
              this.issue("unsupported-hash-choice", "Scalar cast of an aggregate conditional identity is not modeled; results are incomplete", expr.span);
              continue;
            }
            value.identity = this.hashRecipes.cast(values[0].identity!, `cast:${sourceType}:${targetType}`);
          }
          if (this.observeArithmetic && expr.castKind === "numeric" && values[0].constant === undefined && values[0].identity
            && numericBound(targetType) !== undefined && (sourceType === "Field" || (numericBound(sourceType) ?? 0n) > numericBound(targetType)!)) {
            const domains = next.integerDomains ??= new Map();
            if (!domains.has(values[0].identity) && (domains.size >= 256 || ++this.abstractValues > this.maxValues)) {
              this.issue("arithmetic-domain-budget", "Checked numeric result domains exceeded their shared value/capacity allowance; results are incomplete", expr.span);
              continue;
            }
            const range = integerEnvelope(targetType,values[0],next);
            if (!range) continue;
            domains.set(values[0].identity,{ minimum: String(range.minimum), maximum: String(range.maximum) });
          }
          if (this.observeArithmetic && expr.castKind === "numeric" && numericBound(sourceType) !== undefined) value = { ...value, uintOrigin: true };
          if (this.observeMints && targetType === "Bytes<32>" && (sourceType === "Field" || /^Uint</.test(sourceType)) && values[0].listLengthSnapshot) value.listLengthEncoding = values[0];
          if (sourceType === "Secp256k1Scalar" && targetType === "Bytes<32>" && value.identity)
            value.byteEncoding = { scalar: values[0], identity: value.identity };
        }
      } else {
        this.issue("unsupported-expression", `No transfer function for ${expr.kind}`, expr.span);
        continue;
      }
      if (this.observeInvocations.has(PUBLIC_SCALAR_CAST) && expr.kind === "cast"
        && this.program.compilerVersion === "0.34.0"
        && (this.program.zkirVersion === 2 && expr.castKind === "numeric" || this.program.zkirVersion === 3 && expr.castKind === "scalar")
        && values[0].type === "Field" && expr.inferredType === standardType("JubjubScalar")) {
        value = { ...value, identity: value.identity ?? nativeIdentity(PUBLIC_SCALAR_CAST, values, () => `native-fresh:${this.nativeCount++}`, this.program.meteringIdentity), type: expr.inferredType };
        if (!this.recordRuntimeOperation(next, { kind: "circuit-invocation", name: PUBLIC_SCALAR_CAST,
          location: expr.span, args: values, result: value }, stack)) continue;
      }
      if (expr.kind === "cast" && value.eitherSelection) value = { ...value, eitherSelection: undefined };
      // Retain an opaque computed key once, without claiming that independently
      // recomputing an unmodeled expression produces the same value.
      if (this.observeCollections && !value.identity && value.constant === undefined && !value.fields && !value.items
        && !["assert", "emit", "sequence"].includes(expr.kind)) value = { ...value, identity: `collection-value:${this.snapshotCount++}` };
      if ((this.observeMints || this.complementarySendObservation) && !value.identity && !value.mintSnapshot && value.constant === undefined && !value.fields && !value.items
        && !value.region?.path.some(part => part === "*" || part === "key:*")
        && !["assert", "emit", "sequence"].includes(expr.kind)) {
        if (this.complementarySendObservation && !this.complementaryCharge(1, 2, expr.span)) continue;
        value = { ...value, mintSnapshot: `mint-snapshot:${this.snapshotCount++}` };
      }
      if (value.eitherEvidenceLost) this.issue("either-evidence-budget", "Native Either selection evidence exhausted its bounded allowance; results are incomplete", expr.span);
      // Digest/native identities hide their operands. Name any identity computed
      // from compressed-fold values so later relations and evidence still see it.
      if (expr.kind !== "assert" && expr.inferredType !== "[]") this.trackCompressedValue(value, values, expr.span);
      results.push({ state: next, value: this.refine(this.enrollmentDependencies({ ...value, type: expr.inferredType ?? value.type }, values, expr.span), next) });
    }
    return results;
  }

  private modelDynamicContractCall(state: State, expr: Expr, values: AbstractValue[], location: Span, stack: string[]): void {
    this.issue("dynamic-contract-call", "0.35 dynamic contract call resolves its implementation at runtime; post-call reads are incomplete because the callee may re-enter", location);
    state.otherChecks = true;
    state.externalCallWriteIndex = state.writes.length;
    state.predicates = [];
    state.known.clear(); state.truths.clear(); state.excluded.clear(); state.guards.clear();
    for (const symbol of this.program.activeSymbols().filter(item => item.kind === "ledger")) {
      const region = { root: symbol.id, path: [], type: symbol.type };
      state.collections.invalidateWrite(region);
      state.lists.invalidateWrite(region);
      state.merkle?.invalidateWrite(region);
    }
    state.path.push({ kind: "summary", label: `dynamic contract call ${expr.contractCall?.circuit ?? expr.name} may re-enter or abort`, location });
    this.recordRuntimeOperation(state, {
      kind: "circuit-invocation",
      name: `contract.${expr.contractCall?.circuit ?? expr.name}`,
      location,
      args: values.slice(1),
      result: { ...empty(), type: expr.inferredType ?? "unknown", predicateStructureLost: true },
    }, stack);
  }

  private constant(value: AbstractValue): Constant | undefined {
    return value.constant !== undefined && value.constantKind ? { kind: value.constantKind, value: value.constant } : undefined;
  }

  private withByteConstant(value: AbstractValue): AbstractValue {
    if (!value.items?.every(item => item.constantKind === "integer" && item.constant !== undefined && BigInt(item.constant) >= 0n && BigInt(item.constant) < 256n)) return value;
    return { ...value, constant: value.items.map(item => BigInt(item.constant!).toString(16).padStart(2, "0")).join(""), constantKind: "bytes" };
  }

  private sequenceElement(value: AbstractValue, index: number, location: Span): AbstractValue | undefined {
    const representation = this.program.representationOf(value.type ?? "unknown");
    const length = sequenceLength(representation);
    if (!Number.isSafeInteger(index) || index < 0 || length === undefined || index >= length) return undefined;
    if (value.items?.[index]) return step(value.items[index], "projection", `[${index}]`, location);
    if (parseType(representation).name !== "Bytes") return undefined;
    const constant = value.constantKind === "bytes" ? String(parseInt(value.constant!.slice(2 * index, 2 * index + 2), 16)) : undefined;
    return { ...step(value, "projection", `[${index}]`, location, "derived"), type: "Uint<8>", constant, constantKind: constant === undefined ? undefined : "integer", identity: value.identity ? this.hashRecipes.has(value.identity) ? this.hashRecipes.byte(value.identity, index) : `${value.identity}::byte:${index}` : undefined };
  }

  private sequenceItems(value: AbstractValue, location: Span): AbstractValue[] | undefined {
    if (value.items) return value.items;
    const representation = this.program.representationOf(value.type ?? "unknown");
    const length = sequenceLength(representation);
    if (parseType(representation).name !== "Bytes" || length === undefined || length > 256) return undefined;
    return Array.from({ length }, (_, index) => ({ ...step(value, "projection", `[${index}]`, location, "derived"), type: "Uint<8>", constant: value.constantKind === "bytes" ? String(parseInt(value.constant!.slice(2 * index, 2 * index + 2), 16)) : undefined, constantKind: value.constantKind === "bytes" ? "integer" : undefined, identity: value.identity ? this.hashRecipes.has(value.identity) ? this.hashRecipes.byte(value.identity, index) : `${value.identity}::byte:${index}` : undefined }));
  }

  private castScalarConstant(value: Constant | undefined, sourceType: string, targetType: string): Constant | undefined | null {
    if (!value) return undefined;
    if (targetType === "JubjubScalar" && this.program.zkirVersion === 2) targetType = "Field";
    const source = this.program.symbols.get(sourceType)?.declaration;
    if (value.kind === "enum" && source?.typeKind === "enum") {
      const index = source.variants!.findIndex(variant => value.value === `${source.name}.${variant}`);
      return index < 0 ? undefined : castConstant({ kind: "integer", value: String(index) }, targetType);
    }
    const target = this.program.symbols.get(targetType)?.declaration;
    if (value.kind === "integer" && target?.typeKind === "enum") {
      const index = BigInt(value.value);
      return index < 0n || index >= BigInt(target.variants!.length) ? null : { kind: "enum", value: `${target.name}.${target.variants![Number(index)]}` };
    }
    return castConstant(value, targetType);
  }

  private forgetDeadLocals(state: State, live: LiveVariables, node: number): void {
    for (const symbol of state.env.keys()) if (live.owned.has(symbol) && !live.liveIn.get(node)!.has(symbol)) state.env.delete(symbol);
    const identities = new Set<string>();
    const visited = new Set<AbstractValue>();
    const visit = (value: AbstractValue): void => {
      if (visited.has(value)) return;
      visited.add(value);
      let identity = this.liveValueIdentities.get(value);
      if (identity === undefined) {
        identity = valueIdentity(value) ?? null;
        this.liveValueIdentities.set(value, identity);
      }
      if (identity) identities.add(identity);
      value.items?.forEach(visit);
      if (value.fields) Object.values(value.fields).forEach(visit);
      if (value.negated) visit(value.negated);
      if (value.listPredicate) visit(value.listPredicate.structure);
      if (value.merklePredicate) visit(value.merklePredicate.structure);
      if (value.comparison) { visit(value.comparison.left); visit(value.comparison.right); }
      if (value.ordering) { visit(value.ordering.left); visit(value.ordering.right); value.ordering.leftBytes?.forEach(visit); }
      if (value.byteEncoding) visit(value.byteEncoding.scalar);
    };
    for (const value of state.env.values()) visit(value);
    for (const value of state.ledger.values()) visit(value);
    state.lists.visitValues(visit);
    state.merkle?.visitValues(visit);
    for (const read of state.eitherReads ?? []) visit(read.tag);
    if (this.pathSemantics === "equivalent-states") for (const control of state.control) visit(control.value);
    for (const identity of state.foldIdentities ?? []) identities.add(identity);
    for (const [identity, { left, right }] of state.scalarEqualities ?? []) { identities.add(identity); visit(left); visit(right); }
    for (const [identity, { predicate }] of state.orderings ?? []) {
      identities.add(identity); visit(predicate.left); visit(predicate.right); predicate.leftBytes?.forEach(visit);
    }
    // Earlier constraints on a choice remain live even if only a selected arm
    // or a downstream hash is still referenced. Their aliases can conflict later.
    for (const mapping of [state.known, state.excluded]) for (const identity of mapping.keys()) if (this.hashRecipes.has(identity)) identities.add(identity);
    const candidates = new Set<string>();
    for (const mapping of [state.known, state.truths, state.excluded]) for (const identity of mapping.keys())
      if (!identities.has(identity)) candidates.add(identity);
    for (const leaves of state.aggregateExclusions.values()) for (const [identity] of leaves)
      if (!identities.has(identity)) candidates.add(identity);
    if (candidates.size) this.hashRecipes.retainDependencies(identities, candidates, dependency => identities.add(dependency));
    // An aggregate can be dead while one of its saved projections is live.
    // Keep its finite exclusion and the other scalar facts needed to check it.
    const pending = new Map(state.aggregateExclusions);
    let changed = true;
    while (changed) {
      changed = false;
      for (const [key, leaves] of pending) if (leaves.some(([identity]) => identities.has(identity) || identity.startsWith("ledger:"))) {
        for (const [identity] of leaves) identities.add(identity);
        pending.delete(key);
        changed = true;
      }
    }
    for (const [key, leaves] of pending) { state.aggregateExclusions.delete(key); state.aggregateExclusionLeaves -= leaves.length; }
    // A repeated storage query can be recomputed after its local result dies.
    // Its exact receiver/key/revision identity is still a valid observation.
    for (const mapping of [state.truths, state.known, state.excluded]) for (const identity of mapping.keys())
      if (!identities.has(identity) && !identity.startsWith("ledger:") && !identity.startsWith("collection-query:")) {
        mapping.delete(identity); state.hashRecipes?.invalidate(state, identity);
      }
  }

  private stateIdentity(state: State, withoutGuards = false): string {
    const entries = <Value>(mapping: Map<string, Value>): [string, Value][] => [...mapping].sort(([left], [right]) => left.localeCompare(right));
    const records = (history: readonly object[] | undefined) => history?.map(record => this.valueFingerprints.record(record));
    const writes = state.writes.map(write => this.valueFingerprints.record(write, withoutGuards));
    return this.valueFingerprints.key({ otherChecks: state.otherChecks, witnessCalls: state.witnessCalls ? entries(state.witnessCalls) : undefined, predicates: records(state.predicates), integerDomains: state.integerDomains ? entries(state.integerDomains) : undefined, scalarEqualities: state.scalarEqualities ? entries(state.scalarEqualities) : undefined, scalarEqualitiesExhausted: state.scalarEqualitiesExhausted, orderings: state.orderings ? entries(state.orderings) : undefined, orderingsExhausted: state.orderingsExhausted, foldIdentities: state.foldIdentities, merkle: state.merkle?.snapshot(), eitherReads: records(state.eitherReads), operations: records(state.operations), checkpoints: state.checkpoints?.map(item => item.key), env: entries(state.env), ledger: entries(state.ledger), ledgerVersions: entries(state.ledgerVersions), collections: state.collections.snapshot(), lists: state.lists.snapshot(), known: entries(state.known), truths: entries(state.truths), excluded: entries(state.excluded).map(([key, values]) => [key, [...values].sort()]), aggregateExclusions: entries(state.aggregateExclusions), aggregateExclusionsExhausted: state.aggregateExclusionsExhausted, guards: withoutGuards ? undefined : [...state.guards].sort(), bindings: records(state.bindings), sinks: state.sinks.map(sink => this.valueFingerprints.record(sink)), writes, control: records(state.control) });
  }

  private refine(value: AbstractValue, state: State): AbstractValue {
    // Reserve the envelope carrier before either helper. The selected scalar
    // meter charges every recursive refinement/closure/constraint round itself.
    if (this.complementarySendObservation && !this.complementaryCharge(1, 2,
      this.program.functions.get(this.currentEntry)!.declaration.span)) return value;
    let refined = refineScalar(value, state);
    if (this.observeArithmetic || this.observeMintQuantities) {
      const range = integerEnvelope(this.program.representationOf(refined.type ?? "unknown"), refined, state);
      if (range) refined = { ...refined, integerRange: { minimum: String(range.minimum), maximum: String(range.maximum) } };
      else if (range === null) {
        this.issue("numeric-range-incomplete", "Retained numeric evidence has an empty domain intersection; results are incomplete", this.program.functions.get(this.currentEntry)!.declaration.span);
        refined = { ...refined, integerRange: undefined };
      }
    }
    const predicate = value.merklePredicate;
    const tree = predicate && state.merkle?.view(predicate.region);
    const known = predicate?.full ? state.merkle?.fullAt(predicate.region, predicate.revision)
      : predicate && (predicate.revision === tree?.rootEpoch || predicate.historyEpoch !== undefined && predicate.historyEpoch === tree?.historyEpoch)
        ? state.merkle?.root(predicate.region, predicate.key, predicate.exclusive, predicate.revision) : undefined;
    return known === undefined ? refined : { ...refined, constant: String(known), constantKind: "boolean" };
  }

  private assume(value: AbstractValue, truth: boolean, state: State): boolean {
    // A represented leaf is refined only through a constraint operand carrying its
    // identity, and identity-preserving transfers keep its raw dependency form.
    if (this.ruleCertificate?.kind === "digest") this.ruleCertificate.constraints.push({ value, location: this.program.functions.get(this.currentEntry)!.declaration.span });
    if (this.compressionTokens.size && !this.compressionSafeAssumption(value))
      this.issue("observation-compression-dependency", "This rule cannot track all dependencies through an aggregated numeric value within its analysis limits; review this entry manually", this.program.functions.get(this.currentEntry)!.declaration.span);
    const possible = assumeScalar(value, truth, state, (value, truth) => {
      const predicate = value.collectionPredicate;
      if (predicate && predicate.revision === (state.ledgerVersions.get(predicate.region.root) ?? 0)) {
        const possible = predicate.empty ? state.collections.assumeEmpty(predicate.region, truth) : state.collections.assumeMember(predicate.region, predicate.key, truth);
        if (!possible) return false;
        this.checkCollectionBudget(state, this.program.symbols.get(predicate.region.root)!.span);
      }
      const merkle = value.merklePredicate;
      const tree = merkle && state.merkle?.view(merkle.region);
      if (merkle?.full) {
        if (!this.merkleFacts(state).assumeFullAt(merkle.region, merkle.revision, truth)) return false;
      } else if (merkle && (merkle.revision === tree?.rootEpoch
        || merkle.historyEpoch !== undefined && merkle.historyEpoch === tree?.historyEpoch)) {
        if (!this.merkleFacts(state).assumeRoot(merkle.region, merkle.key, truth, merkle.structure, merkle.exclusive, merkle.revision)) return false;
        this.checkCollectionBudget(state, this.program.symbols.get(merkle.region.root)!.span);
      }
      const list = value.listPredicate;
      if (list && list.revision === (state.ledgerVersions.get(list.region.root) ?? 0)) {
        if (!state.lists.assumeEmpty(list.region, truth, list.structure)) return false;
        this.checkCollectionBudget(state, this.program.symbols.get(list.region.root)!.span);
      }
      return true;
    });
    if (state.aggregateExclusionsExhausted) this.issue("constraint-budget", `Aggregate exclusions exceed ${MAX_AGGREGATE_EXCLUSION_LEAVES} retained compared leaves; results are incomplete`, this.program.functions.get(this.currentEntry)!.declaration.span);
    if (state.scalarEqualitiesExhausted) this.issue("constraint-budget", `Scalar relation capacity, operand traversal or propagation allowance exhausted; results are incomplete`, this.program.functions.get(this.currentEntry)!.declaration.span);
    if (state.orderingsExhausted) this.issue("constraint-budget", `Ordered predicates exceed ${MAX_ORDERED_PREDICATES} retained comparisons; results are incomplete`, this.program.functions.get(this.currentEntry)!.declaration.span);
    return possible;
  }

  private recordWrite(state: State, region: NonNullable<AbstractValue["region"]>, value: AbstractValue, location: Span, stack: string[]): void {
    if (!this.secretBindingCharge(4 + stack.length + this.callSites.length + region.path.length,
      12 + stack.length + this.callSites.length + region.path.length, location)) return;
    if ((this.listGrowthObservation || this.sourceClaimObservation) && !this.complementaryCharge(4 + stack.length + this.callSites.length + region.path.length,
      12 + stack.length + this.callSites.length + region.path.length + (region.collectionSelectors?.length ?? 0) * 2, location)) return;
    recordStorageWrite(state, region, value, location, stack, this.callSites, this.storageServices);
  }

  /** Reserve observer work and abstract allocations before constructing metadata.
   * Exhaustion suppresses all further observer retention on this entry. */
  private enrollmentCharge(steps: number, values: number, location: Span): boolean {
    if (this.enrollmentRetentionExhausted) return false;
    this.steps += steps; this.abstractValues += values;
    if (this.steps > this.maxSteps || this.abstractValues > this.maxValues) {
      this.enrollmentRetentionExhausted = true;
      this.issue(this.observeSecpSignatures ? "signature-identity-retention-budget" : "enrollment-review-budget", this.observeSecpSignatures ? "Signature identity observer retention exhausted the shared allowance" : "Enrollment observer retention exhausted the shared allowance", location);
      return false;
    }
    return true;
  }

  private enrollmentWrites(state: State): StateWrite[] {
    if (!this.enrollmentReviewObservation) return state.writes;
    if (!this.enrollmentCharge(1, 1, this.program.functions.get(this.currentEntry)!.declaration.span)) return state.writes;
    const writes: StateWrite[] = [];
    for (const write of state.writes) {
      if (!this.enrollmentCharge(2, 1, write.location)) return state.writes;
      const type = this.program.representationOf(write.after.type ?? "");
      if (write.region.length || type !== "JubjubPoint" && type !== 'Opaque<"JubjubPoint">') { writes.push(write); continue; }
      if (!this.enrollmentCharge(1, 1, write.location)) return state.writes;
      writes.push({ ...write, enrollmentWriteObserved: true });
    }
    return writes;
  }

  private enrollmentHistory(state: State): Pick<SuccessfulPath, "enrollmentHistory"> {
    if (!this.enrollmentReviewObservation || !this.enrollmentCharge(4, 4, this.program.functions.get(this.currentEntry)!.declaration.span)) return {};
    return { enrollmentHistory: { writes: state.writes.length, operations: state.operations?.length ?? 0, predicates: state.predicates?.length ?? 0 } };
  }

  private enrollmentDependencies(value: AbstractValue, inputs: AbstractValue[], location: Span): AbstractValue {
    if (!this.enrollmentReviewObservation || value.enrollmentPointInputs || value.enrollmentSignatureOutcome) return value;
    if (!this.enrollmentCharge(inputs.length * 2, 0, location)) return value;
    const relevant = inputs.some(input => input.enrollmentPointInputs || ["JubjubPoint", 'Opaque<"JubjubPoint">', ...(this.observeSecpSignatures ? ["Secp256k1Point"] : [])].includes(this.program.representationOf(input.type ?? "")));
    if (!relevant || inputs.includes(value) || !this.enrollmentCharge(0, inputs.length + 2, location)) return value;
    return { ...value, enrollmentPointInputs: inputs.slice() };
  }

  private recordPredicate(value: AbstractValue, truth: boolean, state: State, location: Span, stack: string[], assertionGate = false): boolean {
    if (this.compressionTokens.size && this.observeEither && (value.eitherPayloads?.length || value.eitherControls?.length || value.eitherLogicalGate) && this.compressionTouches(value))
      this.issue("observation-compression-dependency", "This rule cannot track all dependencies through an aggregated numeric value within its analysis limits; review this entry manually", location);
    if (!state.otherChecks) {
      const coverage = rawPublicPredicate(value, truth);
      this.steps += coverage.work;
      if (!coverage.complete || this.steps > this.maxSteps) {
        this.issue("predicate-budget", "Gate classification exceeds its bounded allowance; results are incomplete", location);
        return false;
      }
      if (!coverage.allowed) state.otherChecks = true;
    }
    // First consumer: actual witness constraints and alternate private-preimage
    // authentication. Keep source provenance; an entry parameter alone is not
    // an actual witness call. Operand recursion retains negated/Boolean helpers.
    const relevant = (part: AbstractValue): boolean => this.checkpointProofTracking || this.sequenceStep !== undefined || this.predicateScope === "all" || this.observeEither && !!part.eitherPayloads?.length || part.flows.some(flow => this.observePreimageInputs || flow.source.kind === "witness" || flow.form === "hash" && !!flow.directPreimage)
      || !!part.negated && relevant(part.negated)
      || !!part.comparison && (relevant(part.comparison.left) || relevant(part.comparison.right));
    // Full observation must retain the immutable condition behind a path-refined
    // constant. A later application check can reuse an earlier library decision;
    // consumers that exclude library mechanics still need that application use.
    // Literal/tautological conditions are simplified by the coverage query.
    if ((!this.checkpointProofTracking && this.sequenceStep === undefined && this.predicateScope !== "all" && !this.observeEither && value.constantKind === "boolean" && value.constant !== undefined) || !relevant(value)) return true;
    if (++this.abstractValues > this.maxValues) {
      this.issue("predicate-budget", "Successful predicate evidence exceeds the shared abstract value budget; results are incomplete", location);
      return false;
    }
    if (this.enrollmentReviewObservation && !this.enrollmentCharge(4 + stack.length + this.callSites.length,
      4 + stack.length + this.callSites.length, location)) return false;
    if (this.complementarySendObservation && !this.complementaryCharge(4 + stack.length + this.callSites.length,
      5 + stack.length + this.callSites.length, location)) return false;
    if (!this.secretBindingCharge(4 + stack.length + this.callSites.length, 5 + stack.length + this.callSites.length, location)) return false;
    (state.predicates ??= []).push({ ...(assertionGate ? { assertionGate: true as const } : {}), value, truth, location, callPath: [...stack], callSites: this.callSites.slice(), writesBefore: state.writes.length, operationsBefore: state.operations?.length ?? 0 });
    return true;
  }

  private entryNeedsPreimagePredicates(entry: string): boolean {
    if (!this.program.functions.get(entry)!.calls.size) return false;
    const seen = new Set<string>(), pending = [entry];
    let hash = false, witness = false;
    while (pending.length) {
      const id = pending.pop()!;
      if (seen.has(id)) continue;
      seen.add(id);
      if (seen.size > 4096 || ++this.steps > this.maxSteps) {
        this.issue("predicate-budget", "Preimage evidence call-graph allowance exhausted; results are incomplete", this.program.functions.get(entry)!.declaration.span);
        return true;
      }
      const symbol = this.program.symbols.get(id);
      hash ||= symbol?.kind === "intrinsic" && symbol.type === "hash";
      witness ||= symbol?.kind === "witness" || symbol?.kind === "intrinsic" && intrinsicModel(symbol).kind === "witness";
      // Only a raw witness guard can trigger this consumer. Retaining arbitrary
      // parameter conditions in witness-free entries would needlessly distinguish
      // histories in the existing guard-cover optimization.
      if (hash && witness) return true;
      for (const callee of this.program.functions.get(id)?.calls ?? []) if (!seen.has(callee)) pending.push(callee);
    }
    return false;
  }

  private assignRegion(state: State, region: NonNullable<AbstractValue["region"]>, assigned: AbstractValue, location: Span, stack: string[]): void {
    if (this.compressionTokens.size && this.compressionTouches(region))
      this.issue("observation-compression-dependency", "This rule cannot track all dependencies through an aggregated numeric value within its analysis limits; review this entry manually", location);
    if (state.branchJournal) this.appendBranch(state, { kind: "assignment", region: { root: region.root, path: [...region.path], type: region.type }, value: assigned, location });
    this.effectRecorder.record({ kind: "assignment", region: { root: region.root, path: [...region.path], type: region.type }, value: assigned, location }, stack, this.callSites);
    const value = this.withControl(assigned, state, location, true);
    this.recordWrite(state, region, value, location, stack);
    this.writeRegion(state, region, value);
    this.checkCollectionBudget(state, location);
    this.appendSink(state, { kind: "ledger-write", name: this.program.symbols.get(region.root)!.name, location, value, callPath: stack });
  }

  private counterMutation(previous: AbstractValue, amount: AbstractValue, operator: string, location: Span): AbstractValue | undefined {
    return counterMutation(previous, amount, operator, location);
  }

  private boolean(value: boolean): AbstractValue {
    return { ...empty(), constantKind: "boolean", constant: String(value), type: "Boolean" };
  }

  private typedValue(type: string, leaf: (type: string, digest?: boolean) => AbstractValue, depth = 0, digest = false, proof = false): AbstractValue {
    if (++this.abstractValues > this.maxValues || depth > 12) {
      this.issue("value-budget", "Abstract aggregate expansion budget exhausted; results are incomplete", this.program.rootSource.ast.span);
      return { ...leaf(type), type };
    }
    const representation = this.program.representationOf(type);
    proof ||= this.observeMerkle && representation.startsWith("MerkleTreePath<");
    digest = !proof && (digest || this.observeMerkle && representation === "MerkleTreeDigest");
    const fields = this.program.fieldsOf(type);
    if (fields) {
      const values = Object.fromEntries(Object.entries(fields).map(([name, field]) => [name, this.typedValue(field, leaf, depth + 1, digest, proof)]));
      return { ...combine(Object.values(values)), fields: values, type };
    }
    const term = parseType(representation);
    const length = sequenceLength(representation);
    if (["Vector", TUPLE_TYPE].includes(term.name) && length !== undefined && length <= 256) {
      const items = Array.from({ length }, (_, index) => this.typedValue(elementType(representation, index), leaf, depth + 1, digest, proof));
      return { ...combine(items), items, type };
    }
    return { ...leaf(type, digest), type };
  }

  private defaultValue(type: string): AbstractValue {
    return this.typedValue(type, fieldType => {
      const term = parseType(this.program.representationOf(fieldType));
      if (term.name === "Boolean") return this.boolean(false);
      // Both supported opaque defaults have empty byte contents (including
      // inactive Maybe/Either fields); fresh storage revisions do not change them.
      if (term.name === "Opaque" && ['"string"', '"Uint8Array"'].includes(term.args[0]?.name))
        return { ...empty(), constantKind: "bytes", constant: "" };
      if (term.name === "Opaque" && term.args[0]?.name === '"JubjubPoint"') return pointIdentity("JubjubPoint");
      if (["MerkleTree", "HistoricMerkleTree"].includes(term.name)) return { ...empty(), emptyMerkle: true };
      if (["Map", "Set"].includes(term.name)) return { ...empty(), emptyCollection: true };
      if (term.name === "List") return { ...empty(), emptyList: true };
      if (["Uint", "Field", "JubjubScalar", "Counter", "Secp256k1Base", "Secp256k1Scalar"].includes(term.name)) return { ...empty(), constantKind: "integer", constant: "0" };
      if (["JubjubPoint", "Secp256k1Point"].includes(term.name)) return pointIdentity(term.name);
      const length = sequenceLength(this.program.representationOf(fieldType));
      if (term.name === "Bytes" && length !== undefined && length <= 1048576) return { ...empty(), constantKind: "bytes", constant: "00".repeat(length) };
      const enumeration = [...this.program.symbols.values()].find(symbol => symbol.kind === "type" && (symbol.name === term.name || symbol.id === term.name) && symbol.declaration?.typeKind === "enum");
      if (enumeration) return { ...empty(), constantKind: "enum", constant: `${enumeration.name}.${enumeration.declaration!.variants![0]}` };
      return empty();
    });
  }

  private valueSnapshot(value: AbstractValue, location: Span, depth = 0): AbstractValue | undefined {
    if (++this.abstractValues > this.maxValues || depth > 12) {
      this.issue("value-budget", "Stored List element snapshot exceeds the abstract value budget", location);
      return undefined;
    }
    const result: AbstractValue = { ...value, region: undefined };
    if (value.fields) {
      const fields: [string, AbstractValue][] = [];
      for (const [name, field] of Object.entries(value.fields)) {
        const saved = this.valueSnapshot(field, location, depth + 1);
        if (!saved) return undefined;
        fields.push([name, saved]);
      }
      result.fields = Object.fromEntries(fields);
    }
    if (value.items) {
      result.items = [];
      for (const item of value.items) {
        const saved = this.valueSnapshot(item, location, depth + 1);
        if (!saved) return undefined;
        result.items.push(saved);
      }
    }
    return result;
  }

  private eitherType(type: string | undefined): boolean {
    return !!type && this.program.nativeTypeOf(type) === "Either";
  }

  private chargeEither(location: Span): boolean {
    if (++this.steps <= this.maxSteps && ++this.abstractValues <= this.maxValues) return true;
    this.issue("either-evidence-budget", "Native Either selection evidence exhausted the shared work/value allowance; results are incomplete", location);
    return false;
  }

  private selectEitherPayload(receiver: AbstractValue, name: string, value: AbstractValue, state: State, location: Span, stack: string[], liveStorage = false): AbstractValue {
    if (this.ruleCertificate?.kind === "either" && this.eitherType(receiver.type) && (name === "left" || name === "right")) {
      // Same receiver tag snapshot as the exact observer, refined by the joined
      // current constraints (a constant here is that constant on every history).
      const tag = liveStorage && receiver.region
        ? this.readRegion(state, { ...receiver.region, path: [...receiver.region.path, "field:is_left"], type: "Boolean" })
        : receiver.fields?.is_left;
      if (++this.steps > this.maxSteps) this.issue("analysis-budget", "Either certificate exhausted its allowance; results are incomplete", location);
      else if (eitherReadCandidate(name, tag && this.refine(tag, state))) this.ruleCertificate.candidates.push(`${location.file.replace(/.*\//, "")}:${location.line}`);
    }
    if (!this.observeEither || !this.eitherType(receiver.type) || name !== "left" && name !== "right") return value;
    const reads = state.eitherReads ??= [];
    if (reads.length >= MAX_EITHER_READS || !this.chargeEither(location)) {
      this.issue("either-evidence-budget", `Native Either selections exceed ${MAX_EITHER_READS} retained reads or the shared allowance; results are incomplete`, location);
      return { ...value, eitherEvidenceLost: true };
    }
    const tag = liveStorage && receiver.region
      ? this.readRegion(state, { ...receiver.region, path: [...receiver.region.path, "field:is_left"], type: "Boolean" })
      : receiver.fields?.is_left;
    if (!tag) {
      this.issue("either-evidence-unavailable", "Native Either receiver has no modeled tag snapshot; results are incomplete", location);
      return value;
    }
    const id = JSON.stringify([this.program.spanIdentity(location), this.callSites.map(site => this.program.spanIdentity(site)), reads.length]);
    reads.push({ id, arm: name, tag, location, callPath: [...stack], callSites: this.callSites.slice() });
    return markPayload(value, id, () => this.chargeEither(location));
  }

  private bindPattern(pattern: Pattern, value: AbstractValue, state: State, stack: string[]): void {
    if (pattern.kind === "name") state.env.set(pattern.symbol!, value);
    for (let index = 0; index < pattern.children.length; index++) {
      const child = pattern.children[index];
      if (child.kind === "skip") continue;
      let item = pattern.kind === "struct" ? value.fields?.[pattern.fields![index]] : this.sequenceElement(value, index, child.span);
      if (!item) { this.issue("unknown-destructuring", "Cannot project a destructured value", pattern.span); continue; }
      if (pattern.kind === "struct") item = this.selectEitherPayload(value, pattern.fields![index], item, state, child.span, stack);
      this.bindPattern(child, item, state, stack);
    }
  }

  private withControl(value: AbstractValue, state: State, location: Span, force = false): AbstractValue {
    return controlled(value, state.control.map(control => control.value), location, force, this.controlDependencies);
  }

  private readonly storageServices: StorageServices<State> = {
    typedValue: (type, leaf) => this.typedValue(type, leaf),
    refine: (state, value) => this.refine(value, state),
    nextSnapshot: () => this.snapshotCount++,
    nextWrite: () => this.writeCount++,
    rootType: root => this.program.symbols.get(root)!.type,
    representationOf: type => this.program.representationOf(type),
    fieldsOf: type => this.program.fieldsOf(type),
    guardReads: (guard, root) => this.program.functions.get(guard)?.readsState.has(root) ?? false,
  };

  private readRegion(state: State, region: NonNullable<AbstractValue["region"]>): AbstractValue {
    if (this.externalCallReadUnknown(state, region)) {
      const unknown = this.typedValue(region.type, type => ({ ...empty(), type, ledger: new Set([region.root]), region, predicateStructureLost: true }));
      return this.checkpointLedgerValue(unknown, state);
    }
    const value = readStorageRegion(state, region, this.storageServices);
    return this.checkpointLedgerValue(value, state);
  }

  private externalCallReadUnknown(state: State, region: NonNullable<AbstractValue["region"]>): boolean {
    const start = state.externalCallWriteIndex;
    if (start === undefined) return false;
    const overlaps = (left: string[], right: string[]) => {
      const prefix = (short: string[], long: string[]) => short.every((part, index) => part === long[index] || part === "key:*" || long[index] === "key:*");
      return prefix(left, right) || prefix(right, left);
    };
    return !state.writes.slice(start).some(write => write.ledger === region.root && overlaps(write.region, region.path));
  }

  private checkpointLedgerValue(value: AbstractValue, state: State): AbstractValue {
    if (!this.checkpointProofTracking) return value;
    const epoch = state.checkpoints?.length ?? 0;
    const mark = (part: AbstractValue): AbstractValue => {
      if (++this.steps > this.maxSteps) { this.issue("analysis-budget", "Checkpoint ledger dependency tracking exhausted the entry allowance; results are incomplete", this.program.functions.get(this.currentEntry)!.declaration.span); return part; }
      return { ...part, proofLedgerEpoch: Math.max(part.proofLedgerEpoch ?? 0, epoch),
        ...(part.items ? { items: part.items.map(mark) } : {}),
        ...(part.fields ? { fields: Object.fromEntries(Object.entries(part.fields).map(([key, field]) => [key, mark(field)])) } : {}),
      };
    };
    return mark(value);
  }

  /** Ledger effects stop at the prefix, but proof constraints on immutable
   * inputs (or already guaranteed reads) still hold for the entire proof. */
  private committedProofState(prefix: State, full: State): State {
    const result = this.cloneState(prefix), epoch = prefix.checkpoints?.length ?? 0;
    // These calls supplied the invocation's private proof inputs, not committed effects.
    if (full.witnessCalls) result.witnessCalls = new Map(full.witnessCalls);
    const existing = new Set(prefix.predicates ?? []);
    const assertions = new Set(full.path.filter(step => step.kind === "constraint").map(step => this.program.spanIdentity(step.location)));
    for (const predicate of full.predicates ?? []) {
      if (existing.has(predicate) || (predicate.value.proofLedgerEpoch ?? 0) > epoch) continue;
      if (++this.abstractValues > this.maxValues || ++this.steps > this.maxSteps) {
        this.issue("analysis-budget", "Checkpoint proof constraint projection exhausted the shared allowance; results are incomplete", predicate.location);
        break;
      }
      if (!this.assume(predicate.value, predicate.truth, result)) {
        this.issue("unsupported-checkpoint-proof-constraint", "A successful proof constraint disagrees with its committed prefix; results are incomplete", predicate.location);
        break;
      }
      (result.predicates ??= []).push(predicate);
      if (assertions.has(this.program.spanIdentity(predicate.location))) result.path.push({ kind: "constraint", label: "assertion required by the full proof across kernel checkpoint", location: predicate.location });
      const coverage = rawPublicPredicate(predicate.value, predicate.truth);
      this.steps += coverage.work;
      if (!coverage.complete || this.steps > this.maxSteps) {
        this.issue("predicate-budget", "Checkpoint proof gate classification exhausted the shared allowance; results are incomplete", predicate.location);
        break;
      }
      if (!coverage.allowed) result.otherChecks = true;
    }
    return result;
  }

  private withSelection(value: AbstractValue, selection: AbstractValue): AbstractValue {
    return selectStorageValue(value, selection);
  }

  private writeRegion(state: State, region: NonNullable<AbstractValue["region"]>, value: AbstractValue): void {
    state.collections.invalidateWrite(region);
    state.lists.invalidateWrite(region);
    state.merkle?.invalidateWrite(region);
    if (value.emptyCollection) state.collections.reset(region);
    if (value.emptyList) state.lists.reset(region, value);
    if (value.emptyMerkle) this.merkleFacts(state).reset(region, value);
    writeStorageRegion(state, region, value, this.storageServices);
  }

  private checkCollectionBudget(state: State, location: Span): void {
    if (state.merkle?.exhausted) this.issue("merkle-budget", "Tracked Merkle tree/query facts exceed the bounded domain", location);
    if (state.collections.exhausted) this.issue("collection-budget", "Tracked collection facts exceed the bounded domain", location);
    if (state.lists.exhausted) this.issue("list-budget", "Tracked List prefixes exceed the bounded domain", location);
  }

  private recordRuntimeOperation(state: State, operation: Omit<RuntimeOperation, "guards" | "control" | "callPath">, stack: string[]): boolean {
    if (this.membershipIdentityObservation && !this.secretBindingCharge(
      4 + operation.args.length + state.guards.size + state.control.length + stack.length + this.callSites.length,
      5 + operation.args.length + state.guards.size + state.control.length + stack.length + this.callSites.length, operation.location)) return false;
    if (this.complementarySendObservation && !this.complementaryCharge(
      4 + operation.args.length + state.guards.size + state.control.length + stack.length + this.callSites.length,
      5 + operation.args.length + state.guards.size + state.control.length + stack.length + this.callSites.length, operation.location)) return false;
    if (this.observeSecpSignatures && !this.enrollmentCharge(
      4 + operation.args.length + state.guards.size + state.control.length + stack.length + this.callSites.length,
      4 + operation.args.length + state.guards.size + state.control.length + stack.length + this.callSites.length, operation.location)) return false;
    if (this.contractRecipientObservation && !this.recipientCharge(
      4 + operation.args.length + state.guards.size + state.control.length + stack.length + this.callSites.length,
      4 + operation.args.length + state.guards.size + state.control.length + stack.length + this.callSites.length, operation.location)) return false;
    if (this.sequenceStep !== undefined && ["kernel-read", "kernel-write", "coin-qualification"].includes(operation.kind)) {
      this.issue("initialization-effect-unsupported", "Consecutive invocation analysis does not carry transaction/context effects; initialization review is incomplete", operation.location);
      return false;
    }
    this.effectRecorder.invalidateActive();
    state.branchJournal?.recording.invalidate();
    if (++this.abstractValues > this.maxValues) {
      this.issue("effect-budget", "Retained runtime operation budget exhausted; results are incomplete", operation.location);
      return false;
    }
    (state.operations ??= []).push({ ...operation, args: operation.args.slice(), guards: [...state.guards], control: state.control.map(control => control.value), callPath: [...stack], callSites: this.callSites.slice() });
    return true;
  }

  private recipientCharge(work: number, retained: number, location: Span): boolean {
    this.steps += work; this.abstractValues += retained;
    if (this.steps > this.maxSteps || this.abstractValues > this.maxValues) {
      this.issue("contract-recipient-retention-budget", "Recipient observation exhausted its shared work/value allowance", location);
      return false;
    }
    return true;
  }

  private contextValueIdentity(value: AbstractValue): string | undefined {
    const scalar = valueIdentity(value);
    if (scalar) return scalar;
    const constant = this.constant(value);
    if (constant) return `${constant.kind}:${constant.value}`;
    const children = value.fields ? Object.entries(value.fields) : value.items?.map((item, index) => [String(index), item] as const);
    if (!children) return undefined;
    const parts = children.map(([key, child]) => [key, this.contextValueIdentity(child)]);
    return parts.every(([, child]) => child !== undefined) ? JSON.stringify(parts) : undefined;
  }

  private qualifyCoin(coin: AbstractValue, recipient: AbstractValue, state: State, location: Span, stack: string[]): AbstractValue | undefined {
    if (!coin.fields) {
      this.issue("unsupported-coin-layout", "Coin qualification requires the resolved ShieldedCoinInfo fields", location);
      return undefined;
    }
    const keys = [coin, recipient].map(value => this.contextValueIdentity(value));
    const key = keys.every(value => value !== undefined) ? JSON.stringify(keys) : undefined;
    // This is the successful outcome of a checked lookup in the transaction
    // context. It does not invent an index or prove the allocation exists.
    const index = { ...step(combine([coin, recipient]), "coin-qualification", "transaction Merkle index", location, "derived"), type: "Uint<64>",
      ...(key ? { identity: `ledger:coin-index:${this.currentEntry}:${key}` } : {}) };
    const fields = { nonce: coin.fields.nonce, color: coin.fields.color, value: coin.fields.value, mt_index: this.checkpointLedgerValue(index, state) };
    const result = { ...combine(Object.values(fields)), fields, type: standardType("QualifiedShieldedCoinInfo") };
    return this.recordRuntimeOperation(state, { kind: "coin-qualification", name: "allocatedCoinIndex", location, args: [coin, recipient], result }, stack) ? result : undefined;
  }

  private kernelOperation(expr: Expr, values: AbstractValue[], state: State, stack: string[]): AbstractValue | undefined {
    const region = values[0].region!;
    const operation = this.program.ledgerEffect(region.type, expr.name!)!;
    if (expr.name === "checkpoint") {
      if (this.zeroInput) {
        this.issue("zero-entry-checkpoint-unavailable", this.mapDebitObservation
          ? "Entry-zero Map debit review requires full successful invocations; checkpoint committed prefixes are outside this observation"
          : "Entry-zero membership review requires full successful invocations; checkpoint committed prefixes are outside this observation", expr.span);
        return undefined;
      }
      // The exact engine keeps each guaranteed prefix as its own committed
      // history. Joined/selected/replayed histories have no such prefix view.
      if (this.conservative || this.sourcePreference !== undefined || this.counterSelection || this.conditionalSelection || this.sequenceStep !== undefined) {
        this.issue("unsupported-kernel-checkpoint", "Kernel checkpoint permits partial transaction failure; rollback boundaries are modeled only by exact histories", expr.span);
        return undefined;
      }
      if (++this.steps > this.maxSteps || ++this.abstractValues > this.maxValues || (state.checkpoints?.length ?? 0) >= 64) {
        this.issue("analysis-budget", "Kernel checkpoint prefix histories exhausted the analysis allowance; results are incomplete", expr.span);
        return undefined;
      }
      // Branch summaries do not replay checkpoint prefixes; keep ordinary histories.
      state.branchJournal?.recording.invalidate();
      this.checkpointCount++;
      const prefix = this.cloneState(state);
      prefix.path.push({ kind: "constraint", label: "fallible segment after kernel checkpoint failed; guaranteed prefix committed", location: expr.span });
      if (this.checkpointObservation && (this.steps + stack.length + this.callSites.length > this.maxSteps
        || this.abstractValues + stack.length + this.callSites.length > this.maxValues)) {
        this.issue("analysis-budget", "Checkpoint invocation metadata exceeded the shared allowance; results are incomplete", expr.span);
        return undefined;
      }
      if (this.checkpointObservation) {
        this.steps += stack.length + this.callSites.length;
        this.abstractValues += stack.length + this.callSites.length;
      }
      const site = this.checkpointObservation ? { location: expr.span, callPath: [...stack], callSites: this.callSites.slice() } : undefined;
      const key = site ? this.valueFingerprints.key({ state: this.stateIdentity(prefix), site }) : this.stateIdentity(prefix);
      (state.checkpoints ??= []).push({ state: prefix, key, ...(site ? { site } : {}) });
      state.path.push({ kind: "summary", label: "kernel checkpoint: later effects are fallible", location: expr.span });
      return { ...empty(), items: [], type: "[]" };
    }
    const args = values.slice(1);
    const disclosed = operation.publicArguments ? operation.publicArguments.map(index => args[index]) : args;
    const publicValue = this.withControl(combine(disclosed), state, expr.span, true);
    if (publicValue.flows.length) this.appendSink(state, { kind: "ledger-operation", name: `kernel.${expr.name}`, location: expr.span, value: publicValue, callPath: stack });
    let result: AbstractValue = { ...empty(), items: [], type: "[]" };
    if (operation.reads) {
      const comparison = ["balanceLessThan", "balanceGreaterThan", "blockTimeLessThan", "blockTimeGreaterThan"].includes(expr.name!);
      const contextName = expr.name!.startsWith("balance") ? "balance" : expr.name!.startsWith("blockTime") ? "blockTime" : expr.name!;
      const contextArgs = contextName === "balance" ? args.slice(0, 1) : [];
      const contextType = contextName === "blockTime" ? "Uint<64>" : contextName === "balance" ? "Uint<128>" : operation.result;
      const keys = contextArgs.map(value => this.contextValueIdentity(value));
      const key = keys.every(value => value !== undefined) ? JSON.stringify([contextName, ...keys]) : undefined;
      const dependencies = step(combine(contextArgs), "kernel-query", contextName, expr.span, "derived");
      let leaf = 0;
      // Context is fixed for this invocation, including the initial balance.
      // Sending, receiving or minting must not mutate these values. Unknown
      // arguments have no must-equality identity (in particular wildcard reads).
      result = this.typedValue(contextType, () => ({ ...dependencies, ledger: new Set([region.root]),
        ...(key ? { identity: `ledger:kernel-context:${this.currentEntry}:${key}:${leaf++}` } : {}) }));
      result = this.refine(result, state);
      if (comparison) {
        const bound = args.at(-1)!;
        const predicate = binaryValue([result, bound], expr.name!.endsWith("LessThan") ? "<" : ">", expr.span, contextType)!;
        const boundIdentity = this.contextValueIdentity(bound);
        result = this.refine({ ...predicate, type: "Boolean",
          ...(key && boundIdentity ? { identity: `ledger:kernel-predicate:${this.currentEntry}:${JSON.stringify([expr.name, key, boundIdentity])}` } : {}) }, state);
      }
    }
    if ((this.domainReviewObservation || this.operationIntentObservation || this.contractRecipientObservation) && canonicalSelfRead(region, expr.name!)) {
      this.steps += 3; this.abstractValues += 3;
      if (this.steps > this.maxSteps || this.abstractValues > this.maxValues) {
        this.issue(this.operationIntentObservation ? "operation-intent-self-budget" : this.contractRecipientObservation ? "contract-recipient-self-budget" : "domain-review-self-budget", "Exact self provenance exhausted its shared allowance", expr.span);
        return undefined;
      }
      result = { ...result, kernelSelf: true, ...(result.fields?.bytes
        ? { fields: { ...result.fields, bytes: { ...result.fields.bytes, kernelSelf: true } } } : {}) };
    }
    if (expr.name === "caller") result = { ...result, kernelCaller: true };
    return this.recordRuntimeOperation(state, { kind: operation.reads ? "kernel-read" : "kernel-write", name: expr.name!, location: expr.span, args, result }, stack) ? result : undefined;
  }

  private merkleFacts(state: State): MerkleFacts<AbstractValue> {
    return state.merkle ??= new MerkleFacts<AbstractValue>();
  }

  private merkleOperation(expr: Expr, values: AbstractValue[], receiver: AbstractValue, state: State, stack: string[]): AbstractValue | undefined {
    this.effectRecorder.invalidateActive();
    const merkle = this.merkleFacts(state);
    const region = values[0].region!;
    const type = parseType(this.program.representationOf(region.type));
    const structure = merkle.view(region)?.structure ?? receiver;
    if (["checkRoot", "isFull"].includes(expr.name!)) {
      const full = expr.name === "isFull";
      const revision = merkle.queryEpoch(region, structure, full);
      const exclusive = type.name === "MerkleTree" || merkle.currentOnly(region);
      const digest = full ? undefined : values[1].fields?.field;
      const key = digest && (this.constant(digest) ? `integer:${digest.constant}` : this.contextValueIdentity(digest));
      const dependencies = step(combine(full ? [structure] : [receiver, values[1]]), "ledger-query", expr.name!, expr.span, "derived");
      const constant = full ? merkle.full(region) : merkle.root(region, key, exclusive);
      let result: AbstractValue = { ...dependencies, type: "Boolean", constant: constant === undefined ? undefined : String(constant), constantKind: constant === undefined ? undefined : "boolean" };
      if (revision !== undefined) {
        if (!full && exclusive && digest) {
          const root: AbstractValue = { ...step(receiver, "merkle-root", "current Merkle root", expr.span, "hash"), type: "Field", identity: `merkle-root:${regionKey(region)}:${revision}` };
          const compared = binaryValue([this.refine(root, state), digest], "==", expr.span, "Field")!;
          result = { ...result, ...compared, type: "Boolean", ...(constant === undefined ? {} : { constant: String(constant), constantKind: "boolean" as const }) };
        }
        if (full || key !== undefined) result.identity = `merkle-query:${regionKey(region)}:${revision}:${full ? "full" : key}`;
        result.merklePredicate = { region: { root: region.root, path: [...region.path], type: region.type }, revision, key, full, structure, exclusive,
          ...(!full && type.name === "HistoricMerkleTree" ? { historyEpoch: merkle.view(region)!.historyEpoch } : {}) };
      }
      // Wildcard paths are may-alias sets, but each observed Boolean is still
      // immutable. Separate unknown observations must never share an identity.
      result.identity ??= `snapshot:${this.snapshotCount++}`;
      this.checkCollectionBudget(state, expr.span);
      const refined = this.refine(result, state);
      if (this.observeMerkle && !full && !this.recordRuntimeOperation(state, { kind: "merkle-check", name: expr.name!, location: expr.span, args: values, result: refined, writesBefore: state.writes.length }, stack)) return undefined;
      return refined;
    }
    if (["insert", "insertHash"].includes(expr.name!) && !region.path.includes("key:*")) {
      // A successful append requires space in the pre-mutation tree. Retained
      // isFull results must not later admit a contradictory full-tree history.
      const revision = merkle.queryEpoch(region, structure, true);
      if (revision !== undefined) {
        const prior: AbstractValue = { ...empty(), type: "Boolean", identity: `merkle-query:${regionKey(region)}:${revision}:full`,
          merklePredicate: { region, revision, full: true, structure } };
        if (!this.assume(prior, false, state)) return undefined;
      }
    }
    const trees = merkle.clone();
    const selected = (value: AbstractValue): AbstractValue => region.selection ? this.withSelection(value, region.selection) : value;
    const controlledStructure = this.withControl(selected(expr.name!.includes("Index") ? combine([structure, values.at(-1)!]) : structure), state, expr.span, true);
    if (expr.name === "resetToDefault") trees.reset(region, this.withControl(selected(empty()), state, expr.span, true));
    else if (expr.name === "resetHistory") trees.resetHistory(region, controlledStructure);
    else {
      const index = expr.name!.includes("Index") ? this.constant(values.at(-1)!) : undefined;
      if (!trees.insert(region, 2 ** Number(type.args[0].name), type.name === "HistoricMerkleTree", expr.name!.includes("Index"), index?.kind === "integer" ? BigInt(index.value) : undefined, controlledStructure)) return undefined;
    }
    const contents = expr.name === "resetToDefault" ? this.defaultValue(region.type) : { ...combine([receiver, ...values.slice(1)]), type: region.type };
    const stored = this.withControl(step(selected(contents), "ledger-mutation", expr.name!, expr.span, "derived"), state, expr.span);
    this.recordWrite(state, region, stored, expr.span, stack);
    this.writeRegion(state, region, stored);
    state.merkle = trees;
    this.checkCollectionBudget(state, expr.span);
    return { ...empty(), items: [], type: "[]" };
  }

  private ledgerOperation(expr: Expr, values: AbstractValue[], state: State, stack: string[]): AbstractValue | undefined {
    const result = this.ledgerOperationTransferred(expr, values, state, stack);
    return result && this.program.ledgerEffect(values[0].region!.type, expr.name!)?.reads ? this.checkpointLedgerValue(result, state) : result;
  }

  private ledgerOperationTransferred(expr: Expr, values: AbstractValue[], state: State, stack: string[]): AbstractValue | undefined {
    if (this.compressionTokens.size && this.compressionTouches([values[0].region, values.slice(1)]))
      this.issue("observation-compression-dependency", "This rule cannot track all dependencies through an aggregated numeric value within its analysis limits; review this entry manually", expr.span);
    const receiverType = parseType(this.program.representationOf(values[0].region!.type)).name;
    if (["Map", "Set"].includes(receiverType) && values[1] && this.hashRecipes.contains(values[1])) {
      this.issue("unsupported-hash-choice", "Collection keys with unresolved hash choices require distinct storage histories; results are incomplete", expr.span);
      return;
    }
    if (!["Map", "Set", "List"].includes(receiverType) && values.slice(1).some(value => this.hashRecipes.contains(value))) {
      this.issue("unsupported-hash-choice", "Ledger operation uses an unmodeled conditional identity; results are incomplete", expr.span);
      return;
    }
    // Queries/inserts/removals below are total. Lookups, counter arithmetic,
    // Merkle mutations and transaction effects may reject implicitly; their
    // constraints are not represented by successful predicates.
    const total = ["member", "isEmpty", "size", "length", "head", "read", "lessThan", "resetToDefault"].includes(expr.name!)
      || ["Map", "Set"].includes(receiverType) && ["insert", "insertDefault", "remove"].includes(expr.name!)
      || receiverType === "List" && expr.name === "pushFront";
    if (receiverType === "Kernel" || !total) state.otherChecks = true;
    const merkleInsert = this.observeInvocations.has(MERKLE_INSERT_OBSERVER)
      && ["MerkleTree", "HistoricMerkleTree"].includes(receiverType)
      && ["insert", "insertHash", "insertIndex", "insertHashIndex"].includes(expr.name!);
    const memoAppend = (this.observeInvocations.has(MEMO_NONCE_APPEND) || this.observeInvocations.has(LIST_GROWTH_APPEND))
      && receiverType === "List" && expr.name === "pushFront";
    const listLength = this.observeInvocations.has(LIST_GROWTH_APPEND) && receiverType === "List" && expr.name === "length";
    if (!this.observeCollections && !merkleInsert && !memoAppend && !listLength) return this.ledgerOperationBody(expr, values, state, stack);
    const region = values[0].region!;
    const type = parseType(this.program.representationOf(region.type));
    const observe = this.observeCollections && ["Map", "Set"].includes(type.name)
      && ["member", "insert", "insertDefault", "insertCoin", "remove", "resetToDefault"].includes(expr.name!)
      || this.membershipIdentityObservation && membershipIdentityList(this.program, region.type, (work, values) => this.secretBindingCharge(work, values, expr.span))
      && ["pushFront", "popFront", "resetToDefault"].includes(expr.name!);
    const writesBefore = state.writes.length;
    const operationsBefore = state.operations?.length ?? 0;
    let result = this.ledgerOperationBody(expr, values, state, stack);
    if (observe && result) {
      if (expr.name === "member") result = { ...result, identity: result.identity ?? `collection-query-fresh:${this.snapshotCount++}` };
      if (!this.recordRuntimeOperation(state, { kind: expr.name === "member" ? "collection-query" : "collection-write", name: expr.name!, location: expr.span, args: values, result, writesBefore }, stack)) return undefined;
    }
    if (merkleInsert && result && !this.recordRuntimeOperation(state, { kind: "merkle-insert", name: expr.name!,
      location: expr.span, args: values, result, writesBefore, operationsBefore }, stack)) return undefined;
    if (listLength && result && !this.recordRuntimeOperation(state, { kind: "collection-query", name: "length",
      location: expr.span, args: values, result, writesBefore, operationsBefore }, stack)) return undefined;
    if (memoAppend && result && !this.recordRuntimeOperation(state, { kind: "list-append", name: expr.name!,
      location: expr.span, args: values, result, writesBefore, operationsBefore }, stack)) return undefined;
    return result;
  }

  private ledgerOperationBody(expr: Expr, values: AbstractValue[], state: State, stack: string[]): AbstractValue | undefined {
    state.branchJournal?.recording.invalidate();
    const region = values[0].region!;
    const receiver = region.revision === (state.ledgerVersions.get(region.root) ?? 0) ? values[0] : this.readRegion(state, region);
    const operation = this.program.ledgerEffect(region.type, expr.name!);
    if (!operation) { this.issue("unknown-ledger-effect", `No effect model for ${region.type}.${expr.name}`, expr.span); return empty(); }
    if (this.program.representationOf(region.type) === "Kernel") return this.kernelOperation(expr, values, state, stack);
    // Readonly queries record their public sinks below. Writes and refining
    // lookups are transfer effects and must invalidate any readonly recording.
    if (operation.writes || operation.region) this.effectRecorder.record({ kind: "ledger-operation", region: { root: region.root, path: [...region.path], type: region.type }, expression: expr, args: values.slice(1) }, stack, this.callSites);
    const argumentsValue = this.withControl(combine(values.slice(1)), state, expr.span, true);
    if (argumentsValue.flows.length) this.appendSink(state, { kind: "ledger-operation", name: `${this.program.symbols.get(region.root)!.name}.${expr.name}`, location: expr.span, value: argumentsValue, callPath: stack });
    let operationName = expr.name!;
    if (operation.coinArgument !== undefined) {
      const index = operation.coinArgument + 1;
      const qualified = this.qualifyCoin(values[index], values[index + 1], state, expr.span, stack);
      if (!qualified) return undefined;
      values = [...values.slice(0, index), qualified];
      operationName = expr.name!.slice(0, -"Coin".length);
    }
    const type = parseType(this.program.representationOf(region.type));
    if (values[1]?.constant !== undefined && !this.secretBindingCharge(0,
      2 + Math.ceil(values[1].constant.length / 64), expr.span)) return undefined;
    const literalKey = values[1]?.constant !== undefined ? `${values[1].constantKind}:${values[1].constant}` : undefined;
    let knownKey = literalKey;
    // Collection facts can retain a bounded immutable identity for dynamic
    // operands (derived hashes, arithmetic over identified values, and
    // aggregates). Unknown or exhausted identities remain wildcard entries.
    if (knownKey === undefined && ["Map", "Set"].includes(type.name) && values[1]) {
      const operand = immutableOperandKey(values[1], Math.min(4096, Math.max(0, this.maxSteps - this.steps)), undefined,
        this.secretBindingObservation ? withIdentityMeter(this.program.meteringIdentity, (_work: number, retained: number) => this.secretBindingCharge(0, retained, expr.span)) : undefined, this.program.meteringIdentity);
      this.steps += operand.work;
      if (!operand.complete) {
        this.issue(this.steps > this.maxSteps ? "analysis-budget" : "predicate-budget",
          this.steps > this.maxSteps ? "Analysis step budget exhausted during collection key derivation; results are incomplete"
            : "Collection key identity exceeds its bounded operand traversal; results are incomplete", expr.span);
        return undefined;
      }
      if (operand.key) knownKey = `identity:${operand.key}`;
    }
    // Stable identities correlate repeated operands; mayOverlap still treats
    // distinct identities and concrete keys as possible aliases. Unidentified
    // keys stay wildcard regions and never establish must-equality.
    if (knownKey && !this.secretBindingCharge(0, 3 + Math.ceil(this.program.meteringIdentity(knownKey).length / 64), expr.span)) return undefined;
    const key = knownKey ?? "*";
    if (["MerkleTree", "HistoricMerkleTree"].includes(type.name)) return this.merkleOperation(expr, values, receiver, state, stack);
    if (type.name === "Map" && operationName === "lookup") {
      const before = this.zeroInput || this.mapDebitObservation ? state.collections.member(region, knownKey) : undefined;
      if (!state.collections.assumeMember(region, knownKey, true)) return undefined;
      this.checkCollectionBudget(state, expr.span);
      const selection = combine([...(region.selection ? [region.selection] : []), step(values[1], "ledger-selection", "lookup key", expr.span, "derived")]);
      const result = this.readRegion(state, { root: region.root, path: [...region.path, `key:${key}`], type: operation.result, selection,
        collectionSelectors: [...region.collectionSelectors ?? [], { index: region.path.length, value: values[1] }] });
      const observed = this.mapDebitObservation && /^(Field|Uint<\d+>)$/.test(this.program.representationOf(operation.result))
        ? { ...result, mapDebitLookupOrigin: `map-debit-lookup:${this.snapshotCount++}` } : result;
      if ((this.zeroInput || this.mapDebitObservation) && !this.recordRuntimeOperation(state, { kind: "map-lookup", name: "lookup", location: expr.span,
        args: values, result: observed, writesBefore: state.writes.length,
        membership: { region: { root: region.root, path: [...region.path], type: region.type }, key: knownKey,
          revision: state.ledgerVersions.get(region.root) ?? 0, before } }, stack)) return undefined;
      return observed;
    }
    if (operationName === "read") return receiver;
    if (operation.writes) {
      const collections = state.collections.clone();
      let lists: ListFacts<AbstractValue> | undefined;
      let target = region;
      let stored: AbstractValue;
      if (type.name === "Map" && ["insert", "insertDefault"].includes(operationName)) {
        target = { ...region, path: [...region.path, `key:${key}`], type: type.args[1] ? printType(type.args[1]) : "unknown" };
        stored = operationName === "insert" ? values[2] : this.defaultValue(target.type);
        stored = this.withSelection(stored, step(values[1], "ledger-selection", "insertion key", expr.span, "derived"));
      } else if (type.name === "Map" && operationName === "remove") {
        target = { ...region, path: [...region.path, `key:${key}`], type: type.args[1] ? printType(type.args[1]) : "unknown" };
        const dependencies = step(combine([receiver, values[1]]), "ledger-mutation", "remove", expr.span, "derived");
        stored = this.typedValue(target.type, () => this.observeTransientOrigins ? { ...dependencies, transientOrigins: undefined, transientOriginsUnavailable: undefined } : dependencies);
      } else if (operationName === "write") stored = values[1];
      else if (operationName === "resetToDefault") stored = this.defaultValue(region.type);
      else if (type.name === "Counter") {
        const updated = this.counterMutation(receiver, values[1], operationName === "increment" ? "+" : "-", expr.span);
        if (!updated) return undefined;
        stored = updated;
      }
      else if (type.name === "List" && ["pushFront", "popFront"].includes(operationName)) {
        lists = state.lists.clone();
        const structure = lists.view(region)?.structure ?? receiver;
        const controlled = (value: AbstractValue): AbstractValue => {
          const selected = region.selection ? this.withSelection(value, region.selection) : value;
          return this.withControl(selected, state, expr.span, true);
        };
        if (operationName === "pushFront") {
          const saved = this.valueSnapshot(controlled(values[1]), expr.span);
          if (!saved) return undefined;
          lists.push(region, saved, controlled(structure), structure);
        } else if (!lists.pop(region, previous => controlled(combine([previous, structure])))) {
          this.issue("list-pop-outcome-unqualified", "Cannot qualify popFront without a known prefix or revision-matched nonempty List proof; empty pop evaluation and later query rejection are distinct outcomes", expr.span);
          return undefined;
        }
        stored = { ...step(combine([receiver, ...values.slice(1)]), "ledger-mutation", operationName, expr.span, "derived"), type: region.type };
      }
      else stored = { ...step(combine([receiver, ...values.slice(1)]), "ledger-mutation", operationName, expr.span, "derived"), type: region.type };
      if (this.observeTransientOrigins && type.name === "Set" && operationName === "remove")
        stored = { ...stored, transientOrigins: undefined, transientOriginsUnavailable: undefined, ...uncertainTransientDependencies([receiver]) };
      if (region.selection) stored = this.withSelection(stored, region.selection);
      this.recordWrite(state, target, this.withControl(stored, state, expr.span), expr.span, stack);
      this.writeRegion(state, target, this.withControl(stored, state, expr.span));
      if (["Map", "Set"].includes(type.name) && ["insert", "insertDefault", "remove"].includes(operationName)) {
        if (operationName === "remove") collections.remove(region, knownKey);
        else collections.insert(region, knownKey);
        if (stored.emptyCollection) collections.reset(target);
        state.collections = collections;
      }
      if (lists) state.lists = lists;
      this.checkCollectionBudget(state, expr.span);
      if (state.lists.exhausted) return undefined;
      return operation.result === "[]" ? { ...empty(), items: [], type: "[]" } : this.typedValue(operation.result, () => ({ ...empty(), ledger: new Set([region.root]) }));
    }
    if (type.name === "List") {
      const list = state.lists.view(region);
      const structure = list?.structure ?? receiver;
      const dependencies = step(combine([structure, ...(region.selection ? [region.selection] : [])]), "ledger-query", operationName, expr.span, "derived");
      const query = (type: string, constant?: string, kind?: Constant["kind"]): AbstractValue => ({ ...this.typedValue(type, () => ({ ...dependencies, ledger: new Set(structure.ledger) })), constant, constantKind: kind });
      const revision = state.ledgerVersions.get(region.root) ?? 0;
      const identify = (value: AbstractValue, suffix: string): AbstractValue => {
        const identity = listQueryIdentity(region, revision, suffix);
        return identity ? { ...value, identity } : value;
      };
      if (operationName === "head") {
        const elementType = this.program.fieldsOf(operation.result)!.value;
        const present = identify(query("Boolean", list?.empty === undefined ? undefined : String(!list.empty), list?.empty === undefined ? undefined : "boolean"), "head-present");
        const value = list?.empty === true ? this.withSelection(this.defaultValue(elementType), dependencies) : list?.head ? this.withSelection(step(list.head, "ledger-query", "head value", expr.span), dependencies) : this.typedValue(elementType, () => ({ ...dependencies, ledger: new Set(structure.ledger) }));
        const fields = { is_some: present, value };
        return { ...combine(Object.values(fields)), fields, type: operation.result };
      }
      const constant = operationName === "length" ? list?.length : list?.empty;
      const result = identify(query(operation.result, constant === undefined ? undefined : String(constant), constant === undefined ? undefined : operationName === "length" ? "integer" : "boolean"), operationName);
      if (operationName === "length" && this.observeMints) result.listLengthSnapshot = { root: region.root, path: [...region.path], revision,
        ...((this.observeInvocations.has(MEMO_NONCE_APPEND) || this.observeInvocations.has(LIST_GROWTH_APPEND)) ? { receiver: values[0] } : {}) };
      if (operationName === "isEmpty" && !region.path.includes("key:*")) result.listPredicate = { region: { root: region.root, path: [...region.path], type: region.type }, revision, structure: dependencies };
      return result;
    }
    const dependencies = step(combine([receiver, ...values.slice(1)]), "ledger-query", operationName, expr.span, "derived");
    const result = this.typedValue(operation.result, () => ({ ...dependencies, ledger: new Set(receiver.ledger) }));
    if (["Map", "Set"].includes(type.name) && ["member", "isEmpty", "size"].includes(operationName)) {
      const constant = operationName === "member" ? state.collections.member(region, knownKey) : operationName === "isEmpty" ? state.collections.isEmpty(region) : state.collections.size(region);
      result.constant = constant === undefined ? undefined : String(constant);
      result.constantKind = constant === undefined ? undefined : operationName === "size" ? "integer" : "boolean";
      const revision = state.ledgerVersions.get(region.root) ?? 0;
      if (!region.path.includes("key:*") && (expr.name !== "member" || knownKey !== undefined)) result.identity = `collection:${regionKey(region)}:${revision}:${expr.name}:${knownKey ?? ""}`;
      if (operationName === "member") {
        const address = immutableCollectionAddress(values[0], Math.min(4096, this.maxSteps - this.steps), undefined, undefined, this.program.meteringIdentity);
        this.steps += address.work;
        const member = immutableOperandKey(values[1], Math.min(4096, this.maxSteps - this.steps), undefined, undefined, this.program.meteringIdentity);
        this.steps += member.work;
        if (!address.complete || !member.complete) {
          this.issue(this.steps > this.maxSteps ? "analysis-budget" : "predicate-budget",
            this.steps > this.maxSteps ? "Analysis step budget exhausted during collection query identity; results are incomplete"
              : "Collection query identity exceeds its bounded operand traversal; results are incomplete", expr.span);
          return undefined;
        }
        if (address.key && member.key) result.identity = this.derivedIdentity("collection-query", [address.key, revision, member.key]);
      }
      if (expr.name !== "size") result.collectionPredicate = { region: { root: region.root, path: [...region.path], type: region.type }, key: knownKey, empty: operationName === "isEmpty", revision,
        ...(this.observeCapacity ? { upperBound: state.collections.upperBound(region) } : {}),
        ...(this.zeroInput ? { writesBefore: state.writes.length } : {}) };
    }
    return result;
  }

  private iterate(expr: Expr, state: State, stack: string[], operands?: AbstractValue[]): Evaluation[] {
    const callable: Expr = { ...expr.args[0], kind: "call", args: [] };
    const results: Evaluation[] = [];
    for (const evaluated of operands ? [{ state, values: operands }] : this.evaluateArgs(expr.args.slice(1), state, stack)) {
      const sequenceValues = expr.kind === "fold" ? evaluated.values.slice(1) : evaluated.values;
      const sequences = sequenceValues.map(value => this.sequenceItems(value, expr.span));
      const length = sequences[0]?.length;
      if (length === undefined || sequences.some(items => !items || items.length !== length)) { this.issue("unknown-higher-order-size", "Map/fold requires known equally sized sequences", expr.span); continue; }
      const fn = this.program.functions.get(callable.symbol!);
      // Exact observations keep ordinary callback histories, except for the
      // total scalar comparison below when its partitions stay unobserved.
      const exactObservation = this.observeEither || this.observeDigestInputs || this.observeCommitInputs || this.observeArithmetic || this.observeMints || this.observeMintQuantities || !!this.observeInvocations.size;
      const plan = !this.observeInvocations.size && (!exactObservation || !this.observeArithmetic) && this.useFoldPartitions && expr.kind === "fold" && fn ? overwriteFoldPlan(fn) : undefined;
      const encoded = plan && this.scalarComparisonFold(expr, callable, plan, fn!, evaluated.state, evaluated.values[0], sequenceValues, sequences as AbstractValue[][], stack);
      if (encoded) { results.push(...encoded); continue; }
      // A total fold callback can discard branch choices only when all its
      // alternatives have equivalent value evidence. Purity alone does not
      // preserve correlations with later caller checks. The
      // admission check is intentionally stricter than ordinary pure-summary
      // eligibility: assertions, witnesses, ledger access, user calls and
      // aborting expressions keep exact path semantics and their budgets.
      // Exact suffix/scalar transfers have priority. Disabling fold transfers
      // also disables this join so the ordinary interpreter remains an oracle.
      // Digest observation alone may join alternatives whose values differ at
      // most in direct-digest input order, behind the compressed-choice boundary.
      if (!this.observeInvocations.size && (!exactObservation || this.digestOrderJoin()) && this.useFoldPartitions && !plan && expr.kind === "fold" && fn && this.pureFoldJoinable(fn)) {
        const joined = this.joinPureFold(expr, callable, evaluated.state, evaluated.values[0], sequences as AbstractValue[][], stack);
        if (joined) { results.push(joined); continue; }
      }
      if (plan && !exactObservation && sequences.every(sequence => sequence!.every(value => valueIdentity(value) !== undefined || this.constant(value) !== undefined))) {
        results.push(...this.partitionFold(expr, callable, plan, evaluated.state, evaluated.values[0], sequences as AbstractValue[][], stack));
        if (results.length > this.maxPaths) { this.issue("analysis-budget", "Higher-order call path budget exceeded", expr.span); return []; }
        continue;
      }
      let pending = [{ state: evaluated.state, accumulator: expr.kind === "fold" ? evaluated.values[0] : empty(), items: [] as AbstractValue[] }];
      for (let index = 0; index < length; index++) {
        pending = pending.flatMap(current => this.evaluate(callable, current.state, stack, [...(expr.kind === "fold" ? [current.accumulator] : []), ...sequences.map(sequence => sequence![index])]).map(result => ({ state: result.state, accumulator: result.value, items: [...current.items, result.value] })));
        if (pending.length > this.maxPaths) { this.issue("analysis-budget", "Higher-order call path budget exceeded", expr.span); pending = []; break; }
      }
      results.push(...pending.map(current => ({ state: current.state, value: expr.kind === "fold" ? { ...current.accumulator, type: expr.inferredType } : { ...combine(current.items), items: current.items, type: expr.inferredType } })));
    }
    return results;
  }

  /** Conservative admission for the bounded pure-fold join. */
  private pureFoldJoinable(fn: FunctionInfo): boolean {
    if (fn.symbol.kind !== "circuit" || fn.emitsEvent || fn.readsState.size || fn.writesState.size) return false;
    // Boolean recurrences carry predicates that callers can constrain later.
    // Keep their exact transfer (or ordinary interpretation when ineligible).
    if (this.program.representationOf(fn.symbol.type) === "Boolean") return false;
    const expression = (expr: Expr): boolean => {
      if (["assert", "assign", "index", "slice", "map", "fold"].includes(expr.kind)) return false;
      if (expr.kind === "cast" && expr.castKind !== "identity") return false;
      // This join discards callback histories, so admission must prove totality.
      // In particular Uint subtraction can reject even without checkedArithmetic.
      if (expr.kind === "binary" && (expr.checkedArithmetic || expr.name === "-" && (expr.numericType ?? expr.inferredType) !== "Field")) return false;
      // Keep branch-dependent arithmetic recurrences exact: later checked
      // casts/equalities rely on their relation to the branch operands.
      if (expr.kind === "binary" && expr.args.some(argument => this.containsConditional(argument))) return false;
      if (expr.kind === "member" && expr.value === "call") return false;
      if (expr.kind === "call") {
        const symbol = this.program.symbols.get(expr.symbol!);
        if (!symbol || symbol.kind === "witness" || symbol.kind === "intrinsic" && ["witness", "derived"].includes(intrinsicModel(symbol).kind)) return false;
        // User circuits are deliberately excluded here.  Their effects and
        // control contracts require the ordinary invoke path; only modeled
        // hash/commitment/constructor intrinsics are admitted.
        if (symbol.kind !== "intrinsic") return false;
      }
      return expr.args.every(expression);
    };
    const reachable = fn.cfg.reachableFrom(fn.cfg.entry);
    return fn.cfg.nodes.filter(node => reachable.has(node.id)).every(node => !node.expr || expression(node.expr));
  }

  private containsConditional(expr: Expr): boolean {
    return expr.kind === "conditional" || expr.args.some(argument => this.containsConditional(argument));
  }

  /** Fold only equivalent abstract evidence. Different constants,
   * identities or preimage/dependency evidence must retain ordinary paths. */
  private joinPureFold(expr: Expr, callable: Expr, input: State, seed: AbstractValue, sequences: AbstractValue[][], stack: string[]): Evaluation | undefined {
    const length = sequences[0]?.length;
    if (length === undefined || sequences.some(sequence => sequence.length !== length)) return undefined;
    let state = input;
    let accumulator = seed;
    // Digest observation: identities constrained only inside joined callback
    // alternatives (their selectors). Committed when the whole fold joins.
    const elided = this.digestOrderJoin() ? new Set<string>() : undefined;
    // Choice markers created by this join, with the trace position each was
    // placed at. Traces are only ever extended by copying (or truncated after a
    // longer prefix), so a trace that holds one of these marker objects at its
    // recorded position shares every earlier step object with the trace the
    // marker was created in. See the provenance prefix below.
    const markers = new Map<TraceStep, number>(), positions = new Set<number>();
    for (let index = 0; index < length; index++) {
      const args = [accumulator, ...sequences.map(sequence => sequence[index])];
      const alternatives = this.evaluate(callable, state, stack, args);
      if (!alternatives.length) return undefined;
      if (alternatives.length === 1) {
        state = alternatives[0].state;
        accumulator = { ...alternatives[0].value, type: expr.inferredType };
        continue;
      }
      let value = alternatives[0].value;
      if (alternatives.length > 1) {
        // Branch traversal order is not dependency order. Keep all other
        // metadata, especially immutable hash identities and direct preimages.
        const canonical = (value: AbstractValue): AbstractValue => ++this.steps > this.maxSteps ? value : ({ ...value,
          flows: [...value.flows].sort((a, b) => a.source.id.localeCompare(b.source.id) || a.form.localeCompare(b.form)),
          ...(value.items ? { items: value.items.map(canonical) } : {}),
          ...(value.fields ? { fields: Object.fromEntries(Object.entries(value.fields).map(([key, child]) => [key, canonical(child)])) } : {}) });
        const values = alternatives.map(item => canonical(item.value));
        if (this.steps > this.maxSteps) { this.issue("analysis-budget", "Pure-fold equivalence budget exhausted; results are incomplete", expr.span); return undefined; }
        // Exact digest observation reads typed input leaves, never their order.
        const comparable = (value: AbstractValue): AbstractValue => elided ? this.digestOrderFree(value) : value;
        const key = this.valueFingerprints.key(comparable(values[0]));
        if (values.slice(1).some(item => this.valueFingerprints.key(comparable(item)) !== key)) return undefined;
        if (this.steps > this.maxSteps) { this.issue("analysis-budget", "Pure-fold equivalence budget exhausted; results are incomplete", expr.span); return undefined; }
        if (elided) {
          const identities = this.elidedChoiceIdentities(state, alternatives.map(item => item.state));
          if (!identities) return undefined;
          for (const identity of identities) elided.add(identity);
        }
        // A summary must not claim that one arbitrary arm ran. Keep only the
        // common provenance prefix and identify the compressed choice itself.
        const provenance = (parts: AbstractValue[]): AbstractValue => ({ ...parts[0],
          flows: parts[0].flows.map((flow, index) => {
            let prefix = 0;
            // An earlier iteration of this join already reduced this flow to its
            // common prefix plus a marker. When every alternative still holds that
            // same marker object at its recorded position, all steps before it are
            // the same objects: the comparison below would accept each of them and
            // then stop at the marker. Take that prefix directly, with one
            // reference check per alternative instead of one serialized comparison
            // per step and alternative. Otherwise compare exactly as before.
            let shared: number | undefined;
            if (foldProvenance.shareMarkers) for (const position of positions) {
              // Marker discovery is work too, including unsuccessful probes of
              // positions contributed by other flows or aggregate leaves.
              if (++this.steps > this.maxSteps) break;
              if (markers.get(flow.trace[position]) === position) { shared = position; break; }
            }
            if (shared !== undefined && parts.every(part => ++this.steps <= this.maxSteps && part.flows[index].trace[shared] === flow.trace[shared])) prefix = shared;
            else while (flow.trace[prefix]) {
              // The existing marker already summarizes this fold's preceding
              // iterations. Repeating its suffix grows explanation work at
              // every level without adding origin or value evidence.
              if (flow.trace[prefix].kind === "fold-choice" && this.program.spanIdentity(flow.trace[prefix].location) === this.program.spanIdentity(expr.span)) break;
              if (!parts.every(part => ++this.steps <= this.maxSteps && JSON.stringify(part.flows[index].trace[prefix]) === JSON.stringify(flow.trace[prefix]))) break;
              prefix++;
            }
            const marker: TraceStep = { kind: "fold-choice", label: "equivalent pure fold alternatives", location: expr.span };
            markers.set(marker, prefix); positions.add(prefix);
            return { ...flow, trace: [...flow.trace.slice(0, prefix), marker] };
          }),
          ...(parts[0].items ? { items: parts[0].items.map((_, index) => provenance(parts.map(part => part.items![index]))) } : {}),
          ...(parts[0].fields ? { fields: Object.fromEntries(Object.keys(parts[0].fields).map(key => [key, provenance(parts.map(part => part.fields![key]))])) } : {}) });
        value = provenance(values);
        if (this.steps > this.maxSteps) { this.issue("analysis-budget", "Pure-fold provenance budget exhausted; results are incomplete", expr.span); return undefined; }
      }
      accumulator = { ...value, type: expr.inferredType };
      // The callback was admitted without writes, operations or aborts.  Keep
      // the input state rather than retaining one arbitrary branch's guards.
      // Callback completion is common to every alternative and really occurred.
      state = this.cloneState(state);
      for (const guard of alternatives[0].state.guards) if (alternatives.every(item => item.state.guards.has(guard))) state.guards.add(guard);
    }
    if (elided?.size) {
      // As for hash-order choices: no existing relation, predicate, binding,
      // collection or tree fact may already mention an elided selector.
      if (this.compressionTouches([state.scalarEqualities, state.orderings, state.aggregateExclusions, state.bindings, state.predicates, state.operations,
        state.collections.snapshot(), state.lists.snapshot(), state.merkle?.snapshot()], elided)) return undefined;
      for (const identity of elided) this.compressionTokens.add(identity);
      this.observationCompressions++;
      state.path.push({ kind: "summary", label: "digest-order-equivalent pure fold alternatives", location: expr.span });
    }
    return { state, value: accumulator };
  }

  /** Only the exact digest observer (no other observer) may join pure-fold
   * alternatives that differ in direct-digest input order. */
  private digestOrderJoin(): boolean {
    return this.observeDigestInputs && !this.observeCommitInputs && !this.observeEither && !this.observeArithmetic && !this.observeMints && !this.observeMintQuantities
      && !this.observeSignatures && !this.operationIntentObservation && !this.conservative && this.sourcePreference === undefined && !this.counterSelection && !this.conditionalSelection;
  }

  /** A comparison key that ignores the order of a direct digest's input items
   * (the multiset of typed leaves, constancy and provenance is kept). */
  private digestOrderFree(value: AbstractValue, depth = 0): AbstractValue {
    if (++this.steps > this.maxSteps || depth > 64) return value;
    const flows = [...value.flows].sort((a, b) => `${a.source.id}:${a.form}`.localeCompare(`${b.source.id}:${b.form}`));
    let directDigest = value.directDigest;
    if (directDigest) {
      const input = this.digestOrderFree(directDigest.input, depth + 1);
      const items = input.items && !input.fields && input.constant === undefined
        ? input.items.map(item => [this.valueFingerprints.key(item), item] as const).sort(([a], [b]) => a.localeCompare(b)).map(([, item]) => item) : input.items;
      directDigest = { ...directDigest, input: { ...input, items } };
    }
    return { ...value, flows, ...(directDigest ? { directDigest } : {}),
      ...(value.items ? { items: value.items.map(item => this.digestOrderFree(item, depth + 1)) } : {}),
      ...(value.fields ? { fields: Object.fromEntries(Object.entries(value.fields).map(([name, field]) => [name, this.digestOrderFree(field, depth + 1)])) } : {}) };
  }

  /** Identities constrained by joined callback alternatives beyond their common
   * input: branch truths/constants/exclusions, relations and new predicates.
   * Undefined when a new relation or predicate has no immutable operand name. */
  private elidedChoiceIdentities(input: State, alternatives: State[]): Set<string> | undefined {
    const result = new Set<string>();
    const name = (value: AbstractValue): boolean => {
      const identity = valueIdentity(value);
      if (identity) result.add(identity);
      return !!identity || this.constant(value) !== undefined;
    };
    for (const state of alternatives) {
      if (++this.steps > this.maxSteps) return undefined;
      for (const [key, truth] of state.truths) if (input.truths.get(key) !== truth) result.add(key);
      for (const [key, value] of state.known) { const before = input.known.get(key); if (!before || before.kind !== value.kind || before.value !== value.value) result.add(key); }
      for (const [key, values] of state.excluded) { const before = input.excluded.get(key); if (!before || before.size !== values.size || [...values].some(item => !before.has(item))) result.add(key); }
      for (const key of state.aggregateExclusions.keys()) if (!input.aggregateExclusions.has(key)) result.add(key);
      for (const [key, domain] of state.integerDomains ?? []) { const before = input.integerDomains?.get(key); if (!before || before.minimum !== domain.minimum || before.maximum !== domain.maximum) result.add(key); }
      for (const [key, { predicate }] of state.orderings ?? []) if (!input.orderings?.has(key) && !(name(predicate.left) && name(predicate.right))) return undefined;
      for (const [key, { left, right }] of state.scalarEqualities ?? []) if (!input.scalarEqualities?.has(key) && !(name(left) && name(right))) return undefined;
      for (const predicate of (state.predicates ?? []).slice(input.predicates?.length ?? 0)) if (!name(predicate.value)) return undefined;
      if (this.steps > this.maxSteps) return undefined;
    }
    return result;
  }

  /** An exact numeric predicate for a full native scalar byte view compared
   * with constant bytes. This avoids multiplying suffix cases across signatures;
   * arbitrary vector folds retain the disjoint partition transfer below. */
  private scalarComparisonFold(expr: Expr, callable: Expr, plan: OverwriteFoldPlan, fn: FunctionInfo, state: State, seed: AbstractValue, values: AbstractValue[], sequences: AbstractValue[][], stack: string[]): Evaluation[] | undefined {
    const encoding = values[0].byteEncoding;
    if (!encoding || (!valueIdentity(encoding.scalar) && !this.constant(encoding.scalar)) || this.counterSelection || sequences.length !== 2 || sequences[0].length !== 32
      || seed.constantKind !== "boolean" || seed.constant === undefined || seed.flows.length || seed.ledger.size
      || plan.left === plan.right || plan.replacement.name !== "<"
      || plan.replacement.args[0].symbol !== fn.declaration.parameters[1].symbol
      || plan.replacement.args[1].symbol !== fn.declaration.parameters[2].symbol
      || !sequences[0].every((value, index) => value.identity === `${encoding.identity}::byte:${index}`)
      || values[1].flows.length || !sequences[1].every(value => value.constantKind === "integer" && value.constant !== undefined
        && BigInt(value.constant) >= 0n && BigInt(value.constant) < 256n && !value.flows.length)) return;
    const exactObservation = this.observeEither || this.observeDigestInputs || this.observeCommitInputs || this.observeArithmetic || this.observeMints || this.observeMintQuantities || !!this.observeInvocations.size;
    let tokens: Set<string> | undefined;
    if (exactObservation) {
      // The composed predicate omits per-byte partition constants. Admit it only
      // for an unknown scalar without observer metadata and without prior
      // relations; later dependent evidence is rejected by compressionTouches.
      const scalarIdentity = valueIdentity(encoding.scalar);
      if (this.observeArithmetic || this.observeMintQuantities || !scalarIdentity || !encoding.scalar.flows.some(flow => flow.form === "raw" && flow.source.id === scalarIdentity) || this.constant(encoding.scalar) || this.counterSelection || this.sourcePreference !== undefined || this.conservative
        || [seed, ...values, ...sequences.flat(), encoding.scalar].some(value => this.observationMetadata(value))) return;
      tokens = new Set([scalarIdentity, encoding.identity, ...sequences[0].map(value => valueIdentity(value)!)]);
      if (!this.existingCompressedValues(state, tokens, new Set([scalarIdentity])) || this.compressionTouches([state.scalarEqualities, state.orderings, state.aggregateExclusions, state.bindings, state.predicates, state.eitherReads,
        state.operations, state.collections.snapshot(), state.lists.snapshot(), state.merkle?.snapshot()], tokens)) return;
    }
    // Charge the byte decoding and predicate, then use ordinary invocation
    // bookkeeping for each total callback represented by the composed transfer.
    this.steps += 32;
    this.abstractValues += 2;
    if (this.steps > this.maxSteps || this.abstractValues > this.maxValues) {
      this.issue("analysis-budget", "Pure-fold scalar predicate budget exhausted; results are incomplete", expr.span); return [];
    }
    const internal: AbstractValue = { ...empty(), type: "Boolean" };
    let accumulator = seed;
    for (let index = 0; index < 32; index++) {
      const completed = this.invoke(fn, [accumulator, sequences[0][index], sequences[1][index]], state, stack, callable.span, internal);
      if (!completed.length) return [];
      ({ state, value: accumulator } = completed[0]);
    }
    let bound = 0n;
    for (let index = 31; index >= 0; index--) bound = bound * 256n + BigInt(sequences[1][index].constant!);
    const maximum: AbstractValue = { ...empty(), type: "Secp256k1Scalar", constantKind: "integer", constant: String(bound) };
    const value = binaryValue([encoding.scalar, maximum], seed.constant === "true" ? "<=" : "<", expr.span, "Secp256k1Scalar")!;
    value.ordering = { ...value.ordering!, leftBytes: sequences[0] };
    // The exact alternate representation exists even if the caller never asserts
    // the result. Retain its tautological native range in the bounded constraint
    // store so later scalar/byte guards cannot silently disagree with one another.
    const range = binaryValue([encoding.scalar, { ...maximum, constant: String(SECP256K1_SCALAR_MODULUS - 1n) }], "<=", expr.span, "Secp256k1Scalar")!;
    range.ordering = { ...range.ordering!, leftBytes: sequences[0] };
    if (!this.assume(range, true, state) || this.incompleteEntries.has(this.currentEntry)) return [];
    // Include selection provenance from the actual snapshot, not just its source
    // scalar. The callback is total; its completion cannot authorize earlier effects.
    const dependencies = step(combine([value, seed, ...values]), "expression", "little-endian comparison", expr.span, "derived");
    value.flows = dependencies.flows;
    value.ledger = dependencies.ledger;
    state.path.push({ kind: "summary", label: "total little-endian comparison fold", location: expr.span });
    if (tokens) {
      if (value.identity) tokens.add(value.identity);
      for (const token of tokens) this.compressionTokens.add(token);
      this.observationCompressions++;
    }
    return [{ state, value: this.refine({ ...value, type: "Boolean" }, state) }];
  }

  /** Exact disjoint suffixes for a total overwrite recurrence. Prefix callbacks
   * have no observable effects and their accumulator is overwritten. Replay the
   * relevant suffix in source order through ordinary call transfers. */
  private partitionFold(expr: Expr, callable: Expr, plan: OverwriteFoldPlan, input: State, seed: AbstractValue, sequences: AbstractValue[][], stack: string[]): Evaluation[] {
    const length = sequences[0].length, results: Evaluation[] = [];
    if (!length) return [{ state: input, value: { ...seed, type: expr.inferredType } }];
    const argsAt = (index: number, accumulator = seed) => [accumulator, ...sequences.map(sequence => sequence[index])];
    let suffix = this.cloneState(input);
    for (let differing = length - 1; differing >= -1; differing--) {
      let condition: AbstractValue | undefined;
      if (differing >= 0) {
        if (++this.steps > this.maxSteps || ++this.abstractValues > this.maxValues) {
          this.issue("analysis-budget", "Pure-fold partition budget exhausted; results are incomplete", expr.span); return [];
        }
        const args = argsAt(differing), operands = [args[plan.left], args[plan.right]];
        condition = binaryValue(operands, "==", plan.condition.span, plan.condition.numericType ?? "Boolean")!;
        const identities = suffix.foldIdentities ??= new Set();
        for (const value of [condition, ...operands]) { const identity = valueIdentity(value); if (identity) identities.add(identity); }
        if (identities.size > MAX_AGGREGATE_EXCLUSION_LEAVES) {
          this.issue("constraint-budget", "Pure-fold snapshot identity capacity exhausted; results are incomplete", expr.span); return [];
        }
      }
      const state = this.cloneState(suffix);
      if (!condition || this.assume(condition, false, state)) {
        // Each elided invocation still consumes work. The nonempty suffix always
        // invokes the same total callback, preserving depth checks, completed-call
        // guards and optional call-site observations without fabricated branches.
        this.steps += Math.max(0, differing);
        let pending: Evaluation[] = [{ state, value: seed }];
        for (let index = Math.max(0, differing); index < length; index++) {
          pending = pending.flatMap(current => this.evaluate(callable, current.state, stack, argsAt(index, current.value)));
          if (pending.length + results.length > this.maxPaths) { this.issue("analysis-budget", "Higher-order call path budget exceeded", expr.span); return []; }
          if (this.incompleteEntries.has(this.currentEntry)) return [];
        }
        results.push(...pending.map(current => ({ state: current.state, value: { ...current.value, type: expr.inferredType } })));
      }
      if (condition && !this.assume(condition, true, suffix)) break;
    }
    return results;
  }

  /** Opaque pre-existing values may depend on a subsequently compressed source.
   * Provenance is used only to decline admission or mark a MAY-dependency;
   * it never certifies equality or a must-relation. */
  private existingCompressedValues(state: State, tokens: Set<string>, sources: ReadonlySet<string>): boolean {
    const pending: unknown[] = [state.env, state.ledger, state.predicates, state.sinks, state.operations, state.scalarEqualities, state.orderings];
    const seen = new Set<object>();
    while (pending.length) {
      const item = pending.pop();
      if (!item || typeof item !== "object" || seen.has(item)) continue;
      seen.add(item);
      if (++this.steps > this.maxSteps) return false;
      if (item instanceof Map) { for (const child of item.values()) pending.push(child); continue; }
      if (item instanceof Set || Array.isArray(item)) { pending.push(...item); continue; }
      const value = item as AbstractValue;
      if (Array.isArray(value.flows) && value.flows.some(flow => sources.has(flow.source.id)) && value.constant === undefined) {
        if (value.identity) tokens.add(value.identity);
        else if (value.mintSnapshot) tokens.add(value.mintSnapshot);
        else if (!value.items && !value.fields) return false;
      }
      for (const [key, child] of Object.entries(item)) {
        // User field names are data, even when they match metadata labels.
        if (key === "fields" && child && typeof child === "object") pending.push(...Object.values(child));
        else if (!COMPRESSION_PROVENANCE_KEYS.has(key)) pending.push(child);
      }
    }
    return true;
  }

  /** Refuse an identity-erasing transfer rather than treating source labels as
   * immutable value identities. Snapshot/aggregate outputs retain boundaries. */
  private trackCompressedValue(value: AbstractValue, inputs: AbstractValue[], location: Span): void {
    if (!this.compressionTokens.size || !this.compressionTouches(inputs)) return;
    const pending = [value], seen = new Set<AbstractValue>();
    while (pending.length) {
      const part = pending.pop()!;
      if (seen.has(part)) continue;
      seen.add(part);
      if (++this.steps > this.maxSteps) { this.issue("analysis-budget", "Compressed value tracking exhausted the entry step allowance", location); return; }
      if (part.constant !== undefined) continue;
      if (part.fields) { pending.push(...Object.values(part.fields)); continue; }
      if (part.items) { pending.push(...part.items); continue; }
      const identity = part.identity ?? part.mintSnapshot;
      // The admitted hash recipe already preserves its selector relation; its
      // direct digest observer deliberately ignores the permutation's order.
      if (identity && this.observeDigestInputs && part.directDigest && this.hashRecipes.has(identity)) continue;
      if (identity) this.compressionTokens.add(identity);
      else this.issue("observation-compression-dependency", "This rule cannot track all dependencies through an aggregated numeric value within its analysis limits; review this entry manually", location);
    }
  }

  /** Digest inputs with the same typed leaves in another order. */
  private permutedDigests(left: AbstractValue["directDigest"], right: AbstractValue["directDigest"]): boolean {
    if (!left || !right) return !left && !right;
    if (left.primitive !== right.primitive || left.inputType !== right.inputType) return false;
    const [a, b] = [left.input, right.input];
    if (!a.items || !b.items || a.items.length !== b.items.length || a.fields || b.fields || a.constant !== undefined || b.constant !== undefined)
      return this.valueFingerprints.key(a) === this.valueFingerprints.key(b);
    const keys = (items: AbstractValue[]) => items.map(item => this.valueFingerprints.key(item)).sort();
    this.steps += a.items.length + b.items.length;
    return JSON.stringify(keys(a.items)) === JSON.stringify(keys(b.items));
  }

  /** Observer-only metadata that the composed scalar fold does not reproduce. */
  private observationMetadata(root: AbstractValue): boolean {
    const keys = ["eitherPayloads", "eitherControls", "eitherSelection", "eitherLogicalGate", "eitherEvidenceLost", "directDigest", "mintSnapshot", "nonceEvolution", "fieldArithmetic", "integerRange", "uintOrigin"];
    const pending: unknown[] = [root], seen = new Set<object>();
    while (pending.length) {
      const item = pending.pop();
      if (!item || typeof item !== "object" || seen.has(item)) continue;
      seen.add(item);
      if (++this.steps > this.maxSteps) return true;
      if (item instanceof Map) { for (const entry of item) pending.push(...entry); continue; }
      if (item instanceof Set || Array.isArray(item)) { pending.push(...item); continue; }
      const abstract = this.enrollmentReviewObservation && "flows" in item && Array.isArray(item.flows)
        && "ledger" in item && item.ledger instanceof Set;
      for (const [key, child] of Object.entries(item)) {
        if ((keys.includes(key) || this.complementarySendObservation && ["numericExpression", "complementaryLineageLost"].includes(key) || abstract && ["enrollmentSignatureOutcome", "enrollmentConjunctionInputs", "enrollmentPointInputs"].includes(key)) && child !== undefined) return true;
        pending.push(child);
      }
    }
    return false;
  }

  /** Conservative dependency test on compressed-fold immutable identities: any
   * identity, relation, region or composed key string naming one. Provenance
   * (flows, traces, spans, call paths) is dependency labelling, not a value relation. */
  private compressionTouches(root: unknown, tokens: ReadonlySet<string> = this.compressionTokens): boolean {
    if (!tokens.size) return false;
    const names = [...tokens];
    const matches = (text: string): boolean => names.some(name => {
      for (let index = text.indexOf(name); index >= 0; index = text.indexOf(name, index + 1)) {
        const next = text.charCodeAt(index + name.length);
        if (!(next >= 48 && next <= 57)) return true;
      }
      return false;
    });
    // Immutable values are shared by many checks. The entry token set only grows,
    // so a positive answer stays valid; a negative one is valid for its version.
    const shared = tokens === this.compressionTokens;
    const version = tokens.size;
    let exhausted = false, cyclic = false;
    const active = new Set<object>();
    const visit = (item: unknown, depth: number): boolean => {
      if (typeof item === "string") return matches(item);
      if (!item || typeof item !== "object") return false;
      // A revisited ancestor contributes its own answer at the top; negative
      // answers of this walk are then not cached for its descendants.
      if (active.has(item)) { cyclic = true; return false; }
      const cached = shared ? this.compressionTouchCache.get(item) : undefined;
      if (cached !== undefined && (cached === true || cached === version)) return cached === true;
      // Exhausting the entry allowance is itself incomplete; answer conservatively.
      if (exhausted || depth > 256 || ++this.steps > this.maxSteps) { exhausted = true; return true; }
      active.add(item);
      let found = false;
      if (item instanceof Map) { for (const [key, child] of item) if (visit(key, depth + 1) || visit(child, depth + 1)) { found = true; break; } }
      else if (item instanceof Set || Array.isArray(item)) { for (const child of item) if (visit(child, depth + 1)) { found = true; break; } }
      else for (const [key, child] of Object.entries(item)) {
        if (key === "fields" && child && typeof child === "object") {
          for (const field of Object.values(child)) if (visit(field, depth + 1)) { found = true; break; }
          if (found) break;
        } else if (!COMPRESSION_PROVENANCE_KEYS.has(key) && visit(child, depth + 1)) { found = true; break; }
      }
      active.delete(item);
      if (shared && (found || !cyclic)) this.compressionTouchCache.set(item, found || version);
      return found;
    };
    const found = visit(root, 0);
    if (exhausted) this.issue("analysis-budget", "Compressed-fold dependency check exhausted the entry step budget; results are incomplete", this.program.functions.get(this.currentEntry)!.declaration.span);
    return found || exhausted;
  }

  /** A constraint may mention compressed-fold values only if it relates them to
   * constants or to other values derived solely from the same compressed origins.
   * A unary truth of an identity outside the fold does not relate the two. */
  private compressionSafeAssumption(value: AbstractValue): boolean {
    if (!this.compressionTouches(value)) return true;
    // Pure: a constant, a value named by the fold, or an aggregate of such parts.
    const pure = (part: AbstractValue): boolean => this.constant(part) !== undefined
      || (part.items || part.fields ? (part.items ?? []).every(pure) && Object.values(part.fields ?? {}).every(pure)
        : !!part.identity && this.compressionTouches(part.identity) && !part.region);
    if (value.collectionPredicate || value.merklePredicate || value.listPredicate || value.predicateAlternatives || value.predicateHasAlternatives || value.equalities?.length) return false;
    if (value.negated) return !value.comparison && !value.ordering && this.compressionSafeAssumption(value.negated);
    if (value.comparison) return !value.ordering && pure(value.comparison.left) && pure(value.comparison.right);
    if (value.ordering) return pure(value.ordering.left) && pure(value.ordering.right) && (value.ordering.leftBytes ?? []).every(pure);
    // Only the Boolean's own truth is retained; operand provenance is not a relation.
    return !value.items && !value.fields && !value.region;
  }

  private eitherControl(value: AbstractValue, location: Span, kind = "control"): AbstractValue {
    if (!this.observeEither || !value.eitherPayloads?.length && !value.eitherControls?.length) return value;
    if (this.compressionTokens.size && this.compressionTouches(value))
      this.issue("observation-compression-dependency", "This rule cannot track all dependencies through an aggregated numeric value within its analysis limits; review this entry manually", location);
    if (kind === "same-value") return { ...value, eitherPayloads: undefined, eitherControls: undefined, eitherLogicalGate: undefined };
    const payloads = [...new Set([...(value.eitherPayloads ?? []), ...(value.eitherControls ?? []).flatMap(control => control.payloads)])].sort();
    const id = JSON.stringify([this.currentEntry, kind, this.program.spanIdentity(location), this.callSites.map(site => this.program.spanIdentity(site)), payloads]);
    if (!this.chargeEither(location) || this.eitherBranches.size >= 4096 && !this.eitherBranches.has(id)) {
      this.issue("either-evidence-budget", "Either Boolean/control evidence exhausted its bounded allowance; results are incomplete", location);
      return { ...value, eitherEvidenceLost: true };
    }
    const previous = this.eitherBranches.get(id);
    this.eitherBranches.set(id, { id, mayTrue: !!previous?.mayTrue || value.constant !== "false", mayFalse: !!previous?.mayFalse || value.constant !== "true" });
    const controls = [...value.eitherControls ?? []].map(control => ({ ...control, branches: [...control.branches, id] }));
    if (value.eitherPayloads?.length) controls.push({ branches: [id], payloads: value.eitherPayloads });
    if (controls.length > MAX_EITHER_READS || controls.some(control => control.branches.length > 64)) {
      this.issue("either-evidence-budget", "Either conditional dependency capacity exhausted; results are incomplete", location);
      return { ...value, eitherEvidenceLost: true };
    }
    return { ...value, eitherPayloads: undefined, eitherControls: controls };
  }

  private eitherLogicalValue(values: AbstractValue[], originals: AbstractValue[], expr: Expr, selected: boolean): AbstractValue {
    let value = logicalValue(values, expr.name!, selected, expr.span);
    if (this.enrollmentReviewObservation && expr.name === "&&"
      && this.enrollmentCharge(originals.length, originals.length + 2, expr.span))
      value = { ...value, enrollmentConjunctionInputs: originals.slice() };
    if (!this.observeEither) return value;
    // Neutral constants contribute no Boolean decision. Original operands are
    // captured before short-circuit assumptions refine them in the IR engine.
    const relevant = originals.filter(part => part.constantKind !== "boolean" || part.constant === undefined || part.eitherLogicalGate);
    const dependencies = payloadDependencies(relevant);
    const decision = originals[0];
    const observed = { ...value, eitherPayloads: undefined, eitherControls: undefined, ...dependencies,
      ...(decision.eitherLogicalGate || decision.constant === undefined && (decision.eitherPayloads?.length || decision.eitherControls?.length) || originals[1]?.eitherLogicalGate ? { eitherLogicalGate: true as const } : {}) };
    // The identity denotes this immutable result, not the condition selected
    // earlier. Aliases of a computed Boolean still support exact self-equality.
    if (!observed.identity && (observed.eitherPayloads?.length || observed.eitherControls?.length)) observed.identity = `either-boolean:${this.snapshotCount++}`;
    return this.eitherControl(observed, expr.span, "value");
  }

  private shortCircuit(expr: Expr, state: State, stack: string[]): Evaluation[] {
    const results: Evaluation[] = [];
    for (const left of this.evaluate(expr.args[0], state, stack)) {
      if (!this.flushSourceHistory(left.state)) continue;
      const chosen = this.sourcePreference !== undefined ? this.selectedSourceBranch(left.value, left.state, expr.name === "&&") : undefined;
      if (this.sourcePreference !== undefined && !chosen) continue;
      for (const truth of chosen ? [chosen.truth] : [true, false]) {
        if (left.value.constantKind === "boolean" && left.value.constant !== undefined && left.value.constant !== String(truth)) continue;
        const next = chosen?.state ?? this.cloneState(left.state);
        if ((!chosen && !this.assume(left.value, truth, next)) || !this.recordPredicate(left.value, truth, next, expr.span, stack)) continue;
        next.path.push({ kind: "branch", label: `left operand may be ${truth}`, location: expr.span });
        const skip = expr.name === "&&" ? !truth : truth;
        if (skip) {
          if (this.program.mayAbortExpression(expr.args[1])) next.control.push({ value: this.eitherControl(left.value, expr.span), until: -1, owner: stack.at(-1)! });
          results.push({ state: next, value: this.eitherLogicalValue([left.value], [left.value], expr, truth) });
        }
        else {
          const controlDepth = next.control.length;
          next.control.push({ value: this.eitherControl(left.value, expr.span), until: -1, owner: stack.at(-1)! });
          for (const right of this.evaluate(expr.args[1], next, stack)) {
            const value = this.eitherLogicalValue([left.value, right.value], [left.value, right.value], expr, truth);
            if (!this.program.mayAbortExpression(expr.args[1])) right.state.control = right.state.control.slice(0, controlDepth);
            results.push({ state: right.state, value });
          }
        }
      }
    }
    return results;
  }
}
