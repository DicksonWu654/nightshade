import { MEMO_NONCE_APPEND, MEMO_NONCE_RULE } from "./semantic/memo-nonce-targets.js";
import { KEYED_STATE_INVARIANT } from "./dataflow/keyed-state-invariant.js";
import { PUBLIC_SCALAR_RULE, PUBLIC_SCALAR_TARGETS } from "./semantic/public-scalar-targets.js";
import { QUORUM_RULE, quorumTargets } from "./semantic/quorum-targets.js";
import { NATIVE_KEY_RULE } from "./semantic/native-key-targets.js";
import { FIELD_RECOMPOSITION_RULE } from "./semantic/field-recomposition.js";
import { REDUNDANT_RECEIVE_RULE, SELF_COIN_TARGETS } from "./semantic/redundant-receive-targets.js";
import { ZERO_SEND_RULE, ZERO_SEND_TARGET } from "./semantic/zero-send-targets.js";
import { encryptionTargets } from "./semantic/encryption-targets.js";
import { OBSERVATION_RULES, observeRules, type RuleCoverage, type RuleObservationWork } from "./analysis/rule-observations.js";
import { digestTargets } from "./semantic/digest-targets.js";
import { existsSync, readdirSync, realpathSync, statSync } from "node:fs";
import { delimiter, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { Dataflow } from "./dataflow/index.js";
import { arithmeticTargets } from "./semantic/arithmetic-targets.js";
import { eitherTargets } from "./semantic/either-targets.js";
import { signedInputTargets } from "./semantic/signed-input-targets.js";
import { hasSchnorrVerifier } from "./semantic/signature-targets.js";
import { Finding, detectors } from "./detectors/index.js";
import { AnalysisError, Diagnostic, Span, isNoEntrypointsNotice } from "./model.js";
import { GRAMMAR_BUILD, GRAMMAR_REVISION } from "./parser/index.js";
import { Program } from "./semantic/index.js";
import { Policies, resolvePolicies, validatePolicies } from "./policies.js";
import { CompilerValidation, compilerIdentity, validateWithCompiler } from "./compiler/index.js";
import { Sources } from "./semantic/sources.js";
import { SEMANTIC_PROFILE, selectCompilerVersion, semanticProfile, validCompilerVersion, validZkirVersion, type CompilerVersion, type SemanticProfile, type ZkirVersion } from "./semantic/profile.js";
import { analyzeCounterPredicates, type CounterDetectorCoverage } from "./analysis/counter-scan.js";
import type { CorrelatedPredicate } from "./dataflow/correlated-queries.js";
import { secretPublicationOnPath, unguardedWriteOnPath, forbiddenTransitionOnPath } from "./detectors/path-observations.js";
import { unique, withFindingContract } from "./detectors/types.js";
import { accessTargets } from "./semantic/access-targets.js";
import { mayReceiveShielded, mayTransferValue } from "./semantic/value-transfers.js";
import { MERKLE_INSERT_OBSERVER, MERKLE_INSERT_RULE, merkleTargets, merklePathWitnessTargets } from "./semantic/merkle-targets.js";
import { collectionTargets } from "./semantic/collection-targets.js";
import { applyInlineSuppressions } from "./reporting/suppressions.js";
import { loadDetectorModules } from "./runtime/detector-modules.js";
import type { CustomDetectorDefinition } from "./detector-api.js";
import { informationalDetectors } from "./detectors/informational.js";

/** High-volume source hygiene observations remain available through the
 * compatibility `hygiene` profile but are omitted from the default audit. */
const HYGIENE_PROFILE_DETECTORS = new Set([
  "unnecessary-disclose",
  "time-dependence",
  "unused-declaration",
  "always-true-assertion",
  "dead-code",
  "constant-condition",
  "shadowing",
]);

export { Program, Dataflow, detectors, SEMANTIC_PROFILE };
export { ZKIR3_PROFILE } from "./semantic/profile.js";
export type { CompilerVersion, SemanticProfile, ZkirVersion } from "./semantic/profile.js";
export { buildAnalysisInventory } from "./analysis/inventory.js";
export { ledgerUsage, cachedLedgerUsage } from "./analysis/ledger-usage.js";
export { atomicUpdateObservations } from "./analysis/atomic-updates.js";
export type { AtomicUpdateObservation } from "./analysis/atomic-updates.js";
export { balanceThresholds } from "./semantic/balance-thresholds.js";
export type { BalanceThresholdObservation } from "./semantic/balance-thresholds.js";
export type { LedgerUsageResult, WriteOnlyLedgerObservation } from "./analysis/ledger-usage.js";
export type { AnalysisInventory, InventoryOptions, InventoryType, InventoryFunction, InventoryIdentity, InventoryGap, InventoryGapCode } from "./analysis/inventory.js";
export { scanFileIsolated } from "./runtime/index.js";
export type { ExecutionLimits } from "./runtime/index.js";
export { dependsOn } from "./dataflow/index.js";
export { parseSource } from "./parser/index.js";
export { resolvePolicies } from "./policies.js";
export { lowerInstructions, verifyInstructions } from "./ir/index.js";
export type { Instruction, Effect } from "./ir/index.js";
export type { Policies } from "./policies.js";
export type { Detector, Finding, Severity, Confidence } from "./detectors/types.js";
export type { AnalysisFacts, AbstractValue, PrivateSource, StateWrite } from "./dataflow/index.js";

export interface ScanOptions {
  /** Explicit trusted local CommonJS files; never read from automatic project configuration. */
  detectorModules?: string[];
  compilerVersion?: CompilerVersion;
  zkirVersion?: ZkirVersion;
  searchPaths?: string[];
  sourceRoot?: string;
  policies?: Policies;
  detectors?: string[];
  maxSteps?: number;
  maxPaths?: number;
  maxValues?: number;
  compiler?: string;
  experimentalCounterQueries?: boolean;
  /** Default audit profile omits high-volume hygiene observations. The
   * compatibility hygiene profile restores the historical default selection. */
  profile?: "audit" | "hygiene";
}

interface ScanResultBase {
  customDetectors?: CustomDetectorDefinition[];
  ruleObservationWork?: Omit<RuleObservationWork, "analysisMs" | "detectorMs">[];
  selection?: { minimumSeverity?: import("./detectors/types.js").Severity; findingsBeforeFilter: number; excludedRoots?: string[]; discovery?: { omittedLibraries: string[]; inferredSearchPaths: Record<string, string[]> } };
  semanticProfile: SemanticProfile | "mixed";
  toolVersion: "0.1.1";
  grammarRevision: string;
  grammarBuild: string;
  status: "complete" | "incomplete";
  compilerValidated: boolean;
  compiler?: CompilerValidation;
  entrypoints: string[];
  scanned: string[];
  findings: Finding[];
  diagnostics: Diagnostic[];
  coverage: { noEntrypointRoots: string[]; attempted: string[]; parsed: string[]; resolved: string[]; completedEntries: string[]; detectors: string[]; baselineStatus?: "complete" | "incomplete"; rules?: RuleCoverage[] };
  metrics: { frontendMs: number; analysisMs: number; detectorMs: number; totalMs: number; workerMs: number; cfgNodes: number; instructionNodes: number; calls: number; steps: number; sources: number; paths: number; abstractValues: number; summaryHits: number; summaryEntries: number; statefulSummaryHits: number; readSummaryHits: number; summaryEffects: number; guardSubsumptions: number };
}

/** Schema compatibility name: default coverage may use bounded correlated facts. */
export interface ExactScanResult extends ScanResultBase {
  schemaVersion: "1.6.0";
  scope: "experimental-subset";
}

export interface CounterScanAnalysis {
  mode: "experimental-counter-queries";
  scope: "selected-detector-predicates";
  contract: "experimental-counter-scan-1";
  coverage: CounterDetectorCoverage[];
  workPolicies: { root: string; circuit: string; status: "covered" | "incomplete" }[];
  /** Known subtotals only when expenditureKnown is false. */
  queryWork: { preparation: number; query: number; witnesses: number; transferSteps: number; transferValues: number; findingChecks: number; expenditureKnown: boolean };
}

export interface ExperimentalCounterScanResult extends ScanResultBase {
  schemaVersion: "1.7.0";
  scope: "selected-detector-predicates";
  analysis: CounterScanAnalysis;
}

export type ScanResult = ExactScanResult | ExperimentalCounterScanResult;

export function scanFile(path: string, optionsOrPaths: ScanOptions | string[] = {}, sourceRoot?: string): ScanResult {
  const options: ScanOptions = Array.isArray(optionsOrPaths) ? { searchPaths: optionsOrPaths, sourceRoot } : { sourceRoot, ...optionsOrPaths };
  const location: Span = { file: resolve(path), start: 0, end: 0, line: 1, column: 1, endLine: 1, endColumn: 1 };
  const result = emptyResult(options.experimentalCounterQueries === true, options.zkirVersion, options.compilerVersion);
  const started = performance.now();
  const sources = new Sources(options.searchPaths ?? (process.env.COMPACT_PATH ?? "").split(delimiter).filter(Boolean));
  result.coverage.attempted = [resolve(path)];
  let registry = detectors;
  const customIssues: Diagnostic[] = [];
  try {
    if (options.zkirVersion !== undefined && !validZkirVersion(options.zkirVersion)) throw new AnalysisError({ code: "invalid-config", message: "zkirVersion must be 2 or 3", location });
    if (options.experimentalCounterQueries !== undefined && typeof options.experimentalCounterQueries !== "boolean") throw new AnalysisError({ code: "invalid-config", message: "experimentalCounterQueries must be a boolean", location });
    if (!existsSync(path)) throw new AnalysisError({ code: "input-error", message: "Input file does not exist", location });
    let requestedCompiler = options.compilerVersion;
    if (options.compiler) {
      const identity = compilerIdentity(options.compiler);
      if (!identity.valid || !validCompilerVersion(identity.version)) throw new AnalysisError({ code: "compiler-validation", message: identity.error!, location });
      if (requestedCompiler && requestedCompiler !== identity.version) throw new AnalysisError({ code: "compiler-profile-mismatch", message: `Configured compiler ${requestedCompiler} differs from executable ${identity.version}`, location });
      requestedCompiler = identity.version;
      result.semanticProfile = semanticProfile(options.zkirVersion, requestedCompiler);
    }
    const input = sources.read(realpathSync(path));
    const compilerVersion = selectCompilerVersion(input.ast.pragmas, input.ast.span, requestedCompiler, options.zkirVersion);
    result.semanticProfile = semanticProfile(options.zkirVersion, compilerVersion);
    const program = new Program(realpathSync(path), sources.searchPaths, options.sourceRoot, sources, options.zkirVersion, compilerVersion);
    result.coverage.resolved = [program.root];
    result.metrics.frontendMs = performance.now() - started;
    result.metrics.cfgNodes = [...program.functions.values()].reduce((sum, fn) => sum + fn.cfg.nodes.length, 0);
    result.metrics.calls = [...program.functions.values()].reduce((sum, fn) => sum + fn.calls.size, 0);
    if (options.compiler) {
      result.compiler = validateWithCompiler(options.compiler, program.root, program.searchPaths, 30000, program.zkirVersion, program.compilerVersion);
      result.compilerValidated = result.compiler.valid;
      if (!result.compiler.valid) throw new AnalysisError({ code: "compiler-validation", message: result.compiler.error!, location });
    }
    const extensions = loadDetectorModules(options.detectorModules, location, customIssues);
    registry = [...detectors, ...extensions.detectors];
    if (options.detectors?.some(id => !registry.some(detector => detector.id === id))) throw new AnalysisError({ code: "invalid-config", message: "Unknown detector selection", location });
    if (result.schemaVersion === "1.7.0" && options.detectors?.length === 0) throw new AnalysisError({ code: "invalid-config", message: "Experimental Counter queries require at least one selected detector", location });
    for (const budget of [options.maxSteps, options.maxPaths, options.maxValues]) if (budget !== undefined && (!Number.isSafeInteger(budget) || budget < 1)) throw new AnalysisError({ code: "invalid-config", message: "Analysis budgets must be positive safe integers", location });
    const policies = resolvePolicies(program, options.policies ? validatePolicies(options.policies, location) : undefined);
    const selected = registry.filter(detector => {
      if (options.detectors) return options.detectors.includes(detector.id);
      if (detector.defaultEnabled === false) return false;
      if ((options.profile ?? "audit") === "audit" && HYGIENE_PROFILE_DETECTORS.has(detector.id)) return false;
      return detector.id !== "openzeppelin-preconditions" || !!policies.builtins?.length;
    });
    const custom = extensions.definitions.filter(definition => selected.some(detector => detector.id === definition.id));
    if (custom.length) result.customDetectors = custom;
    if (custom.length && result.schemaVersion === "1.7.0") throw new AnalysisError({ code: "custom-detector-mode", message: "Custom facts version 1 requires exact analysis, not experimental Counter queries", location });
    const observationRules = result.schemaVersion === "1.6.0" ? selected.filter(detector => OBSERVATION_RULES.has(detector.id)) : [];
    const baselineSelected = selected.filter(detector => !observationRules.includes(detector));
    const separateObservations = result.schemaVersion === "1.6.0";
    const keyedStateScope = !separateObservations && selected.some(detector => detector.id === KEYED_STATE_INVARIANT) ? collectionTargets(program) : undefined;
    const keyedStateAbsent = !!keyedStateScope?.complete && !keyedStateScope.applicable;
    const keyedStateEvidence = !!keyedStateScope && !keyedStateAbsent;
    const customRequirements = new Set(custom.flatMap(definition => definition.requires));
    const analysisStarted = performance.now();
    const observeCalls = customRequirements.has("calls") || selected.some(detector => detector.id === "openzeppelin-preconditions") && !!policies.builtins?.length;
    const callerScope = selected.some(detector => detector.id === "inconsistent-access-control") ? accessTargets(program) : undefined;
    const callerEvidence = !!callerScope && (!callerScope.complete || callerScope.applicable);
    const transferScope = selected.some(detector => detector.id === "unprotected-value-transfer") ? mayTransferValue(program) : undefined;
    const transferEvidence = !!transferScope && (!transferScope.complete || transferScope.applicable);
    const receiveScope = selected.some(detector => detector.id === "received-coin-not-validated") ? mayReceiveShielded(program) : undefined;
    const receiveEvidence = !!receiveScope && (!receiveScope.complete || receiveScope.applicable);
    const leafBindingEvidence = !separateObservations && selected.some(detector => detector.id === "merkle-leaf-binding-review");
    const nativeKeyEvidence = !separateObservations && selected.some(detector => detector.id === NATIVE_KEY_RULE);
    const recompositionEvidence = !separateObservations && selected.some(detector => detector.id === FIELD_RECOMPOSITION_RULE);
    const zeroSendEvidence = !separateObservations && selected.some(detector => detector.id === ZERO_SEND_RULE);
    const merkleInsertEvidence = !separateObservations && selected.some(detector => detector.id === MERKLE_INSERT_RULE);
    const splitIdentityEvidence = !separateObservations && selected.some(detector => detector.id === "split-witness-identity");
    const memoNonceEvidence = !separateObservations && selected.some(detector => detector.id === MEMO_NONCE_RULE);
    const quorumEvidence = !separateObservations && selected.some(detector => detector.id === QUORUM_RULE);
    const signatureReviewEvidence = !separateObservations && selected.some(detector => detector.id === "enrolled-signature-key-review");
    const signedInputEvidence = !separateObservations && selected.some(detector => detector.id === "signed-effect-input");
    const leafWitnessTargets = leafBindingEvidence ? merklePathWitnessTargets(program) : undefined;
    if (leafWitnessTargets && !leafWitnessTargets.complete) throw new AnalysisError({ code: "merkle-witness-target-budget", message: "Path-witness invocation targets exceeded their allowance; leaf-binding review is incomplete", location });
    const merkleScope = selected.some(detector => detector.id === "merkle-membership-not-enforced" || leafBindingEvidence && detector.id === "merkle-leaf-binding-review") ? merkleTargets(program) : undefined;
    const merkleEvidence = !!merkleScope && (!merkleScope.complete || merkleScope.applicable);
    const collectionScope = selected.some(detector => detector.id === "nullifier-check-without-insert" || !separateObservations && detector.id === "public-key-membership-authorization") ? collectionTargets(program) : undefined;
    const collectionEvidence = keyedStateEvidence || quorumEvidence || splitIdentityEvidence || merkleInsertEvidence || !!collectionScope && (!collectionScope.complete || collectionScope.applicable);
    // Informational source rules are independent of path correlation. Keep
    // them selected and default-on, but do not let their exact-path
    // requirements disable the bounded correlated engine used by the
    // security detectors.
    const sourceOnlyIds = new Set([...informationalDetectors.map(detector => detector.id), "ignored-validation-result", "discarded-comparison", "discarded-shielded-send-result", "exported-shielded-descriptor", "missing-role-bootstrap", "generic-witness-maybe-abi", "conditional-hash-range", "exact-balance-threshold", "checked-digest-narrowing", "shielded-burn-amount-width", "shared-module-once-gate", "caller-supplied-deadline", "freshness-bound-caller-time", "caller-supplied-time-review", "unasserted-security-result", "witness-derived-value-review", "context-binding-review", "field-arithmetic-domain-review", "terminal-state-exclusivity-review"]);
    const correlatedSelected = baselineSelected.filter(detector => !sourceOnlyIds.has(detector.id));
    const eitherScope = !separateObservations && selected.some(detector => detector.id === "either-payload-mismatch") ? eitherTargets(program) : undefined;
    const eitherEvidence = !!eitherScope && (!eitherScope.complete || eitherScope.applicable);
    const digestScope = !separateObservations && selected.some(detector => detector.id === "low-entropy-hash-disclosure") ? digestTargets(program) : undefined;
    const digestEvidence = !!digestScope && (!digestScope.complete || digestScope.applicable);
    const arithmeticScope = !separateObservations && selected.some(detector => detector.id === "field-arithmetic-wraparound") ? arithmeticTargets(program) : undefined;
    const arithmeticEvidence = !!arithmeticScope && (!arithmeticScope.complete || arithmeticScope.applicable);
    const signatureEvidence = !separateObservations && selected.some(detector => detector.id === "identity-signature-key" || detector.id === "signed-effect-input" || detector.id === "enrolled-signature-key-review") && hasSchnorrVerifier(program);
    const invocationTargets = new Set([
      ...(!separateObservations && selected.some(rule => rule.id === MEMO_NONCE_RULE) ? [MEMO_NONCE_APPEND] : []),
      ...leafWitnessTargets?.targets ?? [],
      ...(!separateObservations && selected.some(rule => rule.id === PUBLIC_SCALAR_RULE) ? PUBLIC_SCALAR_TARGETS : []),
      ...(signedInputEvidence ? signedInputTargets(program) : []),
      ...(quorumEvidence ? quorumTargets(program) : []),
      ...(zeroSendEvidence ? [ZERO_SEND_TARGET] : []),
      ...(!separateObservations && selected.some(rule => rule.id === REDUNDANT_RECEIVE_RULE) ? SELF_COIN_TARGETS : []),
      ...(merkleInsertEvidence ? [MERKLE_INSERT_OBSERVER] : []),
      ...(!separateObservations && selected.some(detector => detector.id === "publicly-derivable-encryption-secret") ? encryptionTargets(program).targets : []),
    ]);
    const flow = new Dataflow(program, options.maxSteps, options.maxPaths, options.maxValues, "instructions", true, true, "equivalent-states", observeCalls, !keyedStateEvidence && !nativeKeyEvidence && !splitIdentityEvidence && !merkleInsertEvidence && !signedInputEvidence && !quorumEvidence && !signatureReviewEvidence && !leafBindingEvidence,
      nativeKeyEvidence || splitIdentityEvidence || memoNonceEvidence || recompositionEvidence || zeroSendEvidence || signedInputEvidence || quorumEvidence || signatureReviewEvidence || leafBindingEvidence || arithmeticEvidence || eitherEvidence || transferEvidence || receiveEvidence || collectionEvidence || customRequirements.has("predicates") || customRequirements.has("collections") ? "all" : callerEvidence || merkleEvidence || customRequirements.has("merkle") ? "all-private" : "witness",
      merkleEvidence || customRequirements.has("merkle"), collectionEvidence || customRequirements.has("collections"), selected.some(detector => detector.id === "re-initialization") || customRequirements.has("initialization"), !keyedStateEvidence && !nativeKeyEvidence && !splitIdentityEvidence && !merkleInsertEvidence && !signedInputEvidence && !quorumEvidence && !signatureReviewEvidence && !leafBindingEvidence,
      signatureEvidence, eitherEvidence, nativeKeyEvidence || splitIdentityEvidence || signedInputEvidence || quorumEvidence || leafBindingEvidence || digestEvidence || !separateObservations && selected.some(detector => detector.id === PUBLIC_SCALAR_RULE || detector.id === "publicly-derivable-encryption-secret" || (detector.id === "resettable-list-nonce" || detector.id === MEMO_NONCE_RULE)), arithmeticEvidence, !separateObservations && selected.some(rule => rule.id === REDUNDANT_RECEIVE_RULE || (rule.id === "resettable-list-nonce" || rule.id === MEMO_NONCE_RULE)), recompositionEvidence || zeroSendEvidence || leafBindingEvidence, invocationTargets, false, nativeKeyEvidence, signatureReviewEvidence);
    if (result.schemaVersion === "1.7.0") {
      // The coordinator combines analysis and detection; no artificial timing split.
      result.entrypoints = program.entries;
      result.coverage.detectors = selected.map(detector => detector.id);
      result.analysis.queryWork.expenditureKnown = false;
      const predicates = analyzeCounterPredicates(flow, policies, selected.map(detector => detector.id));
      result.metrics.analysisMs = performance.now() - analysisStarted;
      if (predicates.exact) {
        Object.assign(result.metrics, predicates.exact.facts.metrics);
        result.coverage.completedEntries = predicates.exact.facts.completedEntries;
      }
      result.analysis.coverage = predicates.coverage;
      result.analysis.workPolicies = predicates.workPolicies.map(policy => ({ root: predicates.root, ...policy }));
      result.analysis.queryWork = { preparation: predicates.work.preparation, ...predicates.work.query, findingChecks: predicates.work.findingChecks, expenditureKnown: predicates.work.queryExpenditureKnown };
      result.findings = predicates.findings;
      result.diagnostics = predicates.diagnostics;
      result.status = predicates.status;
    } else {
      const consumers = { "declared-secret-publication": secretPublicationOnPath, "unguarded-sensitive-state-write": unguardedWriteOnPath, "forbidden-state-transition": forbiddenTransitionOnPath };
      const requested: { predicate: CorrelatedPredicate; detector: keyof typeof consumers; policies: typeof policies }[] = [];
      const wanted = new Set(selected.map(detector => detector.id));
      const secretSymbols = new Set<string>();
      if (wanted.has("declared-secret-publication")) for (const policy of policies.secrets) {
        // The ordinary consumer uses the first policy for each private source.
        if (secretSymbols.has(policy.symbol)) continue;
        secretSymbols.add(policy.symbol);
        requested.push({ predicate: { kind: "public-flow", source: policy.symbol, forms: (["raw", "derived", "hash", "commitment"] as const).filter(form => !policy.allowedForms.includes(form)) },
          detector: "declared-secret-publication", policies: { secrets: [policy], authorization: [], transitions: [], workBudgets: [] } });
      }
      if (wanted.has("unguarded-sensitive-state-write")) for (const policy of policies.authorization) requested.push({
        predicate: { kind: "missing-guard", ledger: policy.state, guard: policy.guard }, detector: "unguarded-sensitive-state-write",
        policies: { secrets: [], authorization: [policy], transitions: [], workBudgets: [] },
      });
      if (wanted.has("forbidden-state-transition")) for (const policy of policies.transitions) requested.push({
        predicate: { kind: "transition", ledger: policy.state, from: policy.from, to: policy.to }, detector: "forbidden-state-transition",
        policies: { secrets: [], authorization: [], transitions: [policy], workBudgets: [] },
      });
      // Correlated admission excludes all witness/intrinsic calls, including
      // nested helpers: the raw-witness rule is structurally absent in that domain.
      const supported = ["ledger-bound-preimage-publication", "predictable-commitment-randomness", "impossible-assertion", "circuit-work-budget", "spoofable-authorization", ...Object.keys(consumers)];
      // Cross-entry conventions have no per-entry no-witness certificate. Only
      // whole-program inapplicability permits existing correlated admission.
      if (!callerEvidence) supported.push("inconsistent-access-control");
      if (!transferEvidence) supported.push("unprotected-value-transfer");
      // Correlated graphs have no Merkle certificate. With Merkle evidence they
      // stay off and source queries, which certify Merkle findings, are only a
      // fallback after an exhausted exact path allowance (analyzeWithCorrelatedQueries).
      supported.push("merkle-membership-not-enforced");
      if (!collectionEvidence) supported.push("nullifier-check-without-insert");
      if (keyedStateAbsent) supported.push(KEYED_STATE_INVARIANT);
      if (!eitherEvidence) supported.push("either-payload-mismatch");
      if (!digestEvidence) supported.push("low-entropy-hash-disclosure");
      if (!arithmeticEvidence) supported.push("field-arithmetic-wraparound");
      if (!signatureEvidence) supported.push("identity-signature-key");
      const sourceSupported = ["ledger-bound-preimage-publication", "predictable-commitment-randomness", "impossible-assertion", "spoofable-authorization", "circuit-work-budget", ...Object.keys(consumers)];
      sourceSupported.push("merkle-membership-not-enforced");
      if (!eitherEvidence) sourceSupported.push("either-payload-mismatch");
      if (!digestEvidence) sourceSupported.push("low-entropy-hash-disclosure");
      if (!arithmeticEvidence) sourceSupported.push("field-arithmetic-wraparound");
      if (!signatureEvidence) sourceSupported.push("identity-signature-key");
      if (keyedStateAbsent) sourceSupported.push(KEYED_STATE_INVARIANT);
      const sourceQueries = !policies.secrets.length && !policies.authorization.length && !policies.transitions.length
        && correlatedSelected.every(detector => sourceSupported.includes(detector.id));
      const analysis = correlatedSelected.every(detector => supported.includes(detector.id)) ? flow.analyzeWithCorrelatedQueries(requested.map(item => item.predicate), wanted.has("impossible-assertion"), sourceQueries, merkleEvidence) : { exact: flow.analyze(), correlated: [], sources: [] };
      const facts = analysis.exact;
      if (analysis.sources.length) facts.sourceQueries = analysis.sources;
      result.metrics.analysisMs = performance.now() - analysisStarted;
      Object.assign(result.metrics, facts.metrics);
      result.metrics.paths += analysis.sources.reduce((sum, source) => sum + source.paths.length, 0);
      result.coverage.completedEntries = [...facts.completedEntries, ...analysis.sources.map(source => source.entry)];
      result.diagnostics = facts.diagnostics;
      result.metrics.instructionNodes = program.instructionNodeCount();
      result.scanned = [...program.files.keys()];
      result.entrypoints = program.entries;
      const baselineAnalysisDiagnostics = result.diagnostics.length;
      const detectorsStarted = performance.now();
      const graphFindings = new Map<string, Finding[]>();
      for (const { graph, query } of analysis.correlated) {
        const findings: Finding[] = []; graphFindings.set(graph.entry, findings);
        let used = graph.work.steps + query.work.query + query.work.projections, complete = true;
        for (const item of query.evidence) {
          const request = requested[item.predicate], path = query.witnesses[item.witness].path;
          const sink = request.predicate.kind === "public-flow" ? path.sinks[item.eventIndex] : undefined;
          const charge = 1 + (sink?.value.flows.length ?? 1);
          used += charge; result.metrics.steps += charge;
          if (used > flow.maxSteps || result.metrics.abstractValues >= flow.maxValues) {
            result.diagnostics.push({ code: "correlated-consumer-budget", message: "Shared correlated finding allowance exhausted; results are incomplete", location: graph.location });
            complete = false; break;
          }
          const observed = request.detector === "declared-secret-publication" ? secretPublicationOnPath(program, path, request.policies, [sink!])
            : request.detector === "unguarded-sensitive-state-write" ? unguardedWriteOnPath(program, path, request.policies, [path.writes[item.eventIndex]])
              : forbiddenTransitionOnPath(program, path, request.policies, [path.writes[item.eventIndex]]);
          result.metrics.abstractValues += observed.length;
          if (result.metrics.abstractValues > flow.maxValues) {
            result.diagnostics.push({ code: "correlated-consumer-value-budget", message: "Shared correlated finding capacity exhausted; results are incomplete", location: graph.location });
            complete = false; break;
          }
          findings.push(...observed);
        }
        if (complete) result.coverage.completedEntries.push(graph.entry);
      }
      result.coverage.completedEntries = program.entries.filter(entry => result.coverage.completedEntries.includes(entry));
      result.findings = !analysis.correlated.length ? baselineSelected.flatMap(detector => detector.run(facts, policies)) : baselineSelected.flatMap(detector => {
        const consumer = consumers[detector.id as keyof typeof consumers];
        return consumer ? unique(program.entries.flatMap(entry => graphFindings.has(entry) ? graphFindings.get(entry)!.filter(finding => finding.detectorId === detector.id)
          : facts.paths.filter(path => path.entry === entry).flatMap(path => consumer(program, path, policies)))) : detector.run(facts, policies);
      });
      result.metrics.detectorMs = performance.now() - detectorsStarted;
      const baselineIssues = result.diagnostics.filter(issue => issue.scope?.kind !== "rule");
      result.coverage.baselineStatus = baselineIssues.length || result.coverage.completedEntries.length !== program.entries.length ? "incomplete" : "complete";
      result.coverage.rules = baselineSelected.flatMap(detector => program.entries.map(entry => {
        if (detector.id === KEYED_STATE_INVARIANT && keyedStateAbsent) return { root: program.root, detectorId: detector.id, entry, status: "not-applicable" as const, evidence: "structural-absence" as const, diagnosticCodes: [] };
        const ownIssues = result.diagnostics.filter(issue => issue.scope?.kind === "rule" && issue.scope.detectorId === detector.id && issue.scope.entry === entry);
        const complete = result.coverage.completedEntries.includes(entry) && baselineIssues.length === baselineAnalysisDiagnostics && !ownIssues.length;
        return { root: program.root, detectorId: detector.id, entry, status: complete ? "complete" as const : "incomplete" as const,
          evidence: "baseline" as const, diagnosticCodes: complete ? [] : [...baselineIssues, ...ownIssues].map(issue => issue.code) };
      }));
      const observed = observeRules(program, observationRules, policies, options, new Set(result.coverage.completedEntries));
      result.findings.push(...observed.findings);
      result.diagnostics.push(...observed.diagnostics);
      result.coverage.rules.push(...observed.coverage);
      if (observed.work.length) result.ruleObservationWork = observed.work.map(({ analysisMs: _analysis, detectorMs: _detector, ...item }) => item);
      for (const item of observed.work) {
        result.metrics.analysisMs += item.analysisMs;
        result.metrics.detectorMs += item.detectorMs;
        for (const key of Object.keys(item.metrics) as (keyof typeof item.metrics)[]) result.metrics[key] += item.metrics[key];
      }
    }
    result.metrics.instructionNodes = program.instructionNodeCount();
    result.scanned = [...program.files.keys()];
    result.entrypoints = program.entries;
    if (!program.entries.length && !result.diagnostics.length) result.coverage.noEntrypointRoots = [program.root];
    result.coverage.detectors = selected.map(detector => detector.id);
  } catch (error) {
    result.diagnostics.push(error instanceof AnalysisError ? error.diagnostic : { code: "analysis-error", message: error instanceof Error ? error.message : String(error), location });
  }
  result.coverage.parsed = [...sources.files.keys()].sort();
  result.scanned = result.coverage.parsed;
  result.diagnostics.push(...customIssues);
  applyInlineSuppressions(result, sources.files.values(), registry.map(detector => detector.id));
  // A few legacy and custom detector paths construct Finding objects directly.
  // Normalize them here so every public audit-default finding has the same
  // one-line evidence and impact fields as findings made through finding().
  result.findings = result.findings.map(withFindingContract);
  result.metrics.totalMs = performance.now() - started;
  result.findings.sort((left, right) => left.location.file.localeCompare(right.location.file) || left.location.start - right.location.start || left.detectorId.localeCompare(right.detectorId) || left.fingerprint.localeCompare(right.fingerprint));
  if (result.diagnostics.length || result.coverage.baselineStatus === "incomplete" || result.coverage.rules?.some(row => row.status === "incomplete")) result.status = "incomplete";
  if (result.schemaVersion === "1.6.0" && result.diagnostics.some(issue => issue.scope?.kind !== "rule")) result.coverage.baselineStatus = "incomplete";
  if (result.coverage.baselineStatus !== undefined) result.coverage.rules ??= [];
  if (result.status !== "complete") result.coverage.noEntrypointRoots = [];
  for (const file of result.coverage.noEntrypointRoots) result.diagnostics.push({
    code: "no-entrypoints-analyzed", message: "No entrypoints analyzed; declaration checks completed.",
    location: { file, start: 0, end: 0, line: 1, column: 1, endLine: 1, endColumn: 1 },
  });
  return result;
}

export function emptyResult(experimentalCounterQueries: true, zkirVersion?: ZkirVersion, compilerVersion?: CompilerVersion): ExperimentalCounterScanResult;
export function emptyResult(experimentalCounterQueries?: false, zkirVersion?: ZkirVersion, compilerVersion?: CompilerVersion): ExactScanResult;
export function emptyResult(experimentalCounterQueries: boolean, zkirVersion?: ZkirVersion, compilerVersion?: CompilerVersion): ScanResult;
export function emptyResult(experimentalCounterQueries = false, zkirVersion: ZkirVersion = 2, compilerVersion?: CompilerVersion): ScanResult {
  const base: ScanResultBase = { semanticProfile: semanticProfile(zkirVersion, validCompilerVersion(compilerVersion) ? compilerVersion : undefined), toolVersion: "0.1.1", grammarRevision: GRAMMAR_REVISION, grammarBuild: GRAMMAR_BUILD, status: "complete", compilerValidated: false, entrypoints: [], scanned: [], findings: [], diagnostics: [], coverage: { noEntrypointRoots: [], attempted: [], parsed: [], resolved: [], completedEntries: [], detectors: [] }, metrics: { frontendMs: 0, analysisMs: 0, detectorMs: 0, totalMs: 0, workerMs: 0, cfgNodes: 0, instructionNodes: 0, calls: 0, steps: 0, sources: 0, paths: 0, abstractValues: 0, summaryHits: 0, summaryEntries: 0, statefulSummaryHits: 0, readSummaryHits: 0, summaryEffects: 0, guardSubsumptions: 0 } };
  return experimentalCounterQueries ? { ...base, schemaVersion: "1.7.0", scope: "selected-detector-predicates", analysis: {
    mode: "experimental-counter-queries", scope: "selected-detector-predicates", contract: "experimental-counter-scan-1", coverage: [], workPolicies: [],
    queryWork: { preparation: 0, query: 0, witnesses: 0, transferSteps: 0, transferValues: 0, findingChecks: 0, expenditureKnown: true },
  } } : { ...base, schemaVersion: "1.6.0", scope: "experimental-subset" };
}

export function mergeResults(results: ScanResult[]): ScanResult {
  const result = emptyResult(results.some(item => item.schemaVersion === "1.7.0"));
  result.status = results.some(item => item.status === "incomplete") ? "incomplete" : "complete";
  result.compilerValidated = results.length > 0 && results.every(item => item.compilerValidated);
  for (const key of ["scanned", "entrypoints"] as const) result[key] = [...new Set(results.flatMap(item => item[key]))].sort();
  for (const key of ["noEntrypointRoots", "attempted", "parsed", "resolved", "completedEntries", "detectors"] as const) result.coverage[key] = [...new Set(results.flatMap(item => item.coverage[key]))].sort();
  if (results.some(item => item.coverage.baselineStatus)) result.coverage.baselineStatus = results.every(item => (item.coverage.baselineStatus ?? item.status) === "complete") ? "complete" : "incomplete";
  const ruleRows = new Map<string, RuleCoverage>();
  for (const item of results) for (const row of item.coverage.rules ?? []) {
    const key = JSON.stringify([row.root, row.entry, row.detectorId]);
    const previous = ruleRows.get(key);
    if (previous && JSON.stringify(previous) !== JSON.stringify(row)) {
      ruleRows.set(key, { ...row, status: "incomplete", evidence: "unavailable", diagnosticCodes: [...new Set([...previous.diagnosticCodes, ...row.diagnosticCodes, "rule-coverage-conflict"])] });
      result.status = "incomplete";
      result.diagnostics.push({ code: "rule-coverage-conflict", message: `Conflicting coverage for ${row.detectorId} at ${row.entry}`, location: { file: row.root, start: 0, end: 0, line: 1, column: 1, endLine: 1, endColumn: 1 }, scope: { kind: "rule", detectorId: row.detectorId, entry: row.entry } });
    } else ruleRows.set(key, row);
  }
  if (ruleRows.size) result.coverage.rules = [...ruleRows.values()];
  const observationWork = results.flatMap(item => item.ruleObservationWork ?? []);
  if (observationWork.length) result.ruleObservationWork = observationWork;
  for (const key of Object.keys(result.metrics) as (keyof ScanResult["metrics"])[]) result.metrics[key] = results.reduce((sum, item) => sum + item.metrics[key], 0);
  result.findings = [...new Map(results.flatMap(item => item.findings).map(finding => [finding.fingerprint, withFindingContract(finding)])).values()].sort((left, right) => left.location.file.localeCompare(right.location.file) || left.location.start - right.location.start || left.detectorId.localeCompare(right.detectorId) || left.fingerprint.localeCompare(right.fingerprint));
  result.diagnostics.push(...results.flatMap(item => item.diagnostics));
  if (result.diagnostics.some(issue => !isNoEntrypointsNotice(issue, result.coverage.noEntrypointRoots))) result.status = "incomplete";
  for (const item of results) if (item.coverage.noEntrypointRoots.some(root =>
    !item.coverage.resolved.includes(root) || item.entrypoints.length !== 0 || item.status !== "complete"
    || item.diagnostics.filter(issue => isNoEntrypointsNotice(issue, [root])).length !== 1)) {
    result.status = "incomplete";
    result.coverage.baselineStatus = "incomplete";
    result.diagnostics.push({ code: "no-entrypoints-notice-mismatch", message: "Zero-entrypoint root lacks its exact completion notice",
      location: { file: item.coverage.noEntrypointRoots[0], start: 0, end: 0, line: 1, column: 1, endLine: 1, endColumn: 1 } });
  }
  const custom = new Map<string, CustomDetectorDefinition>();
  for (const item of results) for (const definition of item.customDetectors ?? []) {
    const previous = custom.get(definition.id);
    if (previous && JSON.stringify(previous) !== JSON.stringify(definition)) {
      result.status = "incomplete";
      result.diagnostics.push({ code: "custom-detector-conflict", message: `Different definitions for ${definition.id} across roots`, location: { file: item.coverage.attempted[0], start: 0, end: 0, line: 1, column: 1, endLine: 1, endColumn: 1 } });
    }
    custom.set(definition.id, definition);
  }
  if (custom.size) result.customDetectors = [...custom.values()];
  const profiles = new Set(results.map(item => item.semanticProfile));
  if (profiles.size === 1) result.semanticProfile = results[0].semanticProfile;
  if (profiles.size > 1 || profiles.has("mixed")) {
    result.semanticProfile = "mixed";
    result.status = "incomplete";
    result.compilerValidated = false;
    result.diagnostics.push({ code: "mixed-semantic-profiles", message: "Cannot merge results from different semantic profiles; scan roots separately", location: { file: result.coverage.attempted[0] ?? ".", start: 0, end: 0, line: 1, column: 1, endLine: 1, endColumn: 1 } });
  }
  if (result.schemaVersion === "1.7.0") {
    const issue = (code: string, message: string, root: string): void => {
      result.status = "incomplete";
      result.diagnostics.push({ code, message, location: { file: root, start: 0, end: 0, line: 1, column: 1, endLine: 1, endColumn: 1 } });
    };
    const coverage = new Map<string, CounterDetectorCoverage>();
    const workPolicies = new Map<string, CounterScanAnalysis["workPolicies"][number]>();
    const conflicts = new Set<string>();
    for (const item of results) {
      if (item.schemaVersion !== "1.7.0") continue;
      for (const row of item.analysis.coverage) {
        const key = JSON.stringify([row.root, row.entry, row.detector]);
        const previous = coverage.get(key);
        if (previous && (previous.status !== row.status || previous.method !== row.method || previous.contract !== row.contract)) {
          coverage.set(key, { root: row.root, entry: row.entry, detector: row.detector, status: "incomplete", method: "unavailable" });
          if (!conflicts.has(key)) issue("counter-coverage-conflict", `Conflicting predicate coverage for ${row.entry} / ${row.detector}`, row.root);
          conflicts.add(key);
        } else if (!previous) coverage.set(key, { ...row });
        if (row.status === "incomplete") result.status = "incomplete";
      }
      for (const row of item.analysis.workPolicies) {
        const key = JSON.stringify([row.root, row.circuit]);
        const previous = workPolicies.get(key);
        if (previous && previous.status !== row.status) {
          workPolicies.set(key, { ...row, status: "incomplete" });
          if (!conflicts.has(key)) issue("counter-work-policy-conflict", `Conflicting work-policy coverage for ${row.circuit}`, row.root);
          conflicts.add(key);
        } else if (!previous) workPolicies.set(key, { ...row });
        if (row.status === "incomplete") result.status = "incomplete";
      }
      for (const key of ["preparation", "query", "witnesses", "transferSteps", "transferValues", "findingChecks"] as const) result.analysis.queryWork[key] += item.analysis.queryWork[key];
      result.analysis.queryWork.expenditureKnown &&= item.analysis.queryWork.expenditureKnown;
    }
    result.analysis.coverage = [...coverage.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([, row]) => row);
    result.analysis.workPolicies = [...workPolicies.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([, row]) => row);
    if (results.some(item => item.schemaVersion === "1.6.0")) issue("mixed-analysis-modes", "Cannot establish combined completion from exact and experimental Counter-query reports; scan all roots with the same mode", result.coverage.attempted[0] ?? ".");
  }
  if (result.coverage.baselineStatus && result.diagnostics.some(issue => !issue.scope && !isNoEntrypointsNotice(issue, result.coverage.noEntrypointRoots))) result.coverage.baselineStatus = "incomplete";
  return result;
}

export function discover(path: string): string[] {
  const absolute = resolve(path);
  if (!statSync(absolute).isDirectory()) return [absolute];
  const files: string[] = [];
  const walk = (directory: string): void => {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name))) {
      if (entry.isSymbolicLink() || ["node_modules", "dist", "managed", ".git", ".cache"].includes(entry.name)) continue;
      const child = resolve(directory, entry.name);
      if (entry.isDirectory()) walk(child);
      else if (entry.isFile() && entry.name.endsWith(".compact")) files.push(child);
    }
  };
  walk(absolute);
  return files;
}
