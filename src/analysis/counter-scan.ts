import { REFUND_ENDPOINT_RULE } from "../semantic/refund-endpoint.js";
import { SOURCE_CLAIM_RULE } from "../semantic/source-claims.js";
import { SOURCE_MAP_GETTER_RULE } from "../semantic/source-map-getters.js";
import { Dataflow, type AnalysisFacts } from "../dataflow/index.js";
import type { CounterQueryWork } from "../dataflow/counter-queries.js";
import { counterPolicyFindings, type CounterConsumerLimits, type CounterPolicyDetector } from "../detectors/counter-consumers.js";
import { detectors, type Finding } from "../detectors/index.js";
import { workBudget } from "../detectors/rules.js";
import { secretPublicationOnPath, unguardedWriteOnPath } from "../detectors/path-observations.js";
import { unique } from "../detectors/types.js";
import type { Diagnostic } from "../model.js";
import type { ResolvedPolicies } from "../policies.js";
import { qualifyCounterDetectors, type CounterAbsenceCertificate, type CounterQualification } from "./counter-certificates.js";
import { accessTargets } from "../semantic/access-targets.js";
import { mayReceiveShielded, mayTransferValue } from "../semantic/value-transfers.js";
import { merkleTargets } from "../semantic/merkle-targets.js";
import { collectionTargets } from "../semantic/collection-targets.js";
import { informationalDetectors } from "../detectors/informational.js";

export interface CounterScanLimits {
  consumer?: CounterConsumerLimits;
  maxEntries?: number;
  maxCoverageRows?: number;
  maxPreparationWork?: number;
  maxFindings?: number;
}
export interface CounterDetectorCoverage {
  root: string;
  entry: string;
  detector: string;
  status: "covered" | "incomplete";
  method: "exact" | "counter-query" | "structural-absence" | "source-work" | "unavailable";
  contract?: string;
}
export interface CounterScanResult {
  contract: "experimental-counter-scan-1";
  scope: "selected-detector-predicates";
  status: "complete" | "incomplete";
  root: string;
  selectedDetectors: string[];
  /** Produced exclusively by the genuine exact subset API, never by queries. */
  exact?: { entries: string[]; facts: AnalysisFacts };
  coverage: CounterDetectorCoverage[];
  certificates: CounterAbsenceCertificate[];
  findings: Finding[];
  diagnostics: Diagnostic[];
  workPolicies: { circuit: string; status: "covered" | "incomplete" }[];
  work: { preparation: number; query: CounterQueryWork; queryExpenditureKnown: boolean; findingChecks: number };
}
const positive = (value: number | undefined, fallback: number): number => {
  const actual = value ?? fallback;
  if (!Number.isSafeInteger(actual) || actual < 1 || actual > 1000000) throw new Error("Invalid Counter scan budget");
  return actual;
};

/** Selected-predicate orchestration; the default scanner still uses exact analysis. */
export function analyzeCounterPredicates(flow: Dataflow, policies: ResolvedPolicies, selected: readonly string[] = detectors.filter(detector => detector.defaultEnabled !== false && (detector.id !== "openzeppelin-preconditions" || policies.builtins?.length)).map(detector => detector.id), limits: CounterScanLimits = {}): CounterScanResult {
  if (!Array.isArray(selected) || Object.getPrototypeOf(selected) !== Array.prototype || !selected.length || selected.length > detectors.length
    || Reflect.ownKeys(selected).length !== selected.length + 1) throw new Error("Expected distinct registered detector IDs");
  const requested: string[] = [];
  for (let index = 0; index < selected.length; index++) {
    const field = Object.getOwnPropertyDescriptor(selected, index);
    if (!field || !("value" in field) || !field.enumerable || typeof field.value !== "string" || requested.includes(field.value)
      || !detectors.some(detector => detector.id === field.value)) throw new Error("Expected distinct registered detector IDs");
    requested.push(field.value);
  }
  selected = requested;
  if (!limits || typeof limits !== "object" || Array.isArray(limits) || Object.keys(limits).some(key => !["consumer", "maxEntries", "maxCoverageRows", "maxPreparationWork", "maxFindings"].includes(key))) throw new Error("Invalid Counter scan limits");
  const maxEntries = positive(limits.maxEntries, 4096), maxCoverageRows = positive(limits.maxCoverageRows, 32768);
  const maxPreparationWork = positive(limits.maxPreparationWork, 20000), maxFindings = positive(limits.maxFindings, 4096);
  const maxPolicies = positive(limits.consumer?.maxPolicies, 256), maxFindingWork = positive(limits.consumer?.maxFindingWork, 20000);
  const queryLimits = limits.consumer?.query;
  const queryBounds = { query: positive(queryLimits?.maxQueryWork, 20000), witnesses: positive(queryLimits?.maxWitnesses, 256),
    transferSteps: positive(queryLimits?.maxTransferSteps, 20000), transferValues: positive(queryLimits?.maxTransferValues, 50000) };
  const program = flow.program;
  const selectedDetectors = detectors.filter(detector => selected.includes(detector.id));
  // Source observations must not consume the bounded Counter predicate allowance.
  // Role-bootstrap uses actual exact constructor histories and conservative
  // source routes; it makes no new Counter predicate or history claim.
  // Keep them in the public coverage/findings contract and evaluate them from
  // the exact facts available here; only security predicates participate in
  // qualification, query work and finding capacity.
  const sourceOnlyIds = new Set([...informationalDetectors.map(detector => detector.id), "ignored-validation-result", "discarded-comparison", "discarded-shielded-send-result", "missing-role-bootstrap", "generic-witness-maybe-abi", "conditional-hash-range", "checked-digest-narrowing", "shielded-burn-amount-width", "caller-supplied-deadline", "freshness-bound-caller-time", "caller-supplied-time-review", "unasserted-security-result", "witness-derived-value-review", "context-binding-review", "field-arithmetic-domain-review", "terminal-state-exclusivity-review"]);
  const predicateSelected = selected.filter(id => !sourceOnlyIds.has(id));
  const result: CounterScanResult = { contract: "experimental-counter-scan-1", scope: "selected-detector-predicates", status: "incomplete", root: program.root,
    selectedDetectors: selectedDetectors.map(detector => detector.id), coverage: [], certificates: [], findings: [], diagnostics: [], workPolicies: [],
    work: { preparation: 0, query: { query: 0, witnesses: 0, transferSteps: 0, transferValues: 0 }, queryExpenditureKnown: true, findingChecks: 0 } };
  const issue = (code: string, message: string, entry?: string): void => {
    result.diagnostics.push({ code, message, location: { ...(program.functions.get(entry ?? "")?.declaration.span ?? program.rootSource.ast.span) } });
  };
  if (program.entries.length > maxEntries || program.entries.length * selectedDetectors.length > maxCoverageRows) {
    issue("counter-scan-coverage-budget", "Counter scan entry/coverage capacity exhausted; results are incomplete");
    return result;
  }
  if (policies.secrets.length + policies.authorization.length + policies.transitions.length + policies.workBudgets.length > maxPolicies) {
    issue("counter-scan-policy-budget", "Counter scan policy capacity exhausted; results are incomplete");
    return result;
  }
  const rows = new Map<string, CounterDetectorCoverage[]>();
  for (const entry of program.entries) {
    const current = selectedDetectors.map(detector => ({ root: program.root, entry, detector: detector.id, status: "incomplete", method: "unavailable" } as CounterDetectorCoverage));
    rows.set(entry, current); result.coverage.push(...current);
  }
  const qualified = new Map<string, Extract<CounterQualification, { status: "eligible" }>>();
  const exactEntries: string[] = [];
  for (const entry of program.entries) {
    const qualification = qualifyCounterDetectors(program, entry, predicateSelected, policies, queryLimits?.region);
    result.work.preparation += qualification.work.syntaxNodes + qualification.work.cfgNodes + qualification.work.branches;
    if (result.work.preparation > maxPreparationWork) {
      issue("counter-scan-preparation-budget", "Counter scan qualification work exhausted; results are incomplete", entry);
      return result;
    }
    if (qualification.status === "ineligible") exactEntries.push(entry);
    else if (qualification.status === "incomplete") result.diagnostics.push(...qualification.diagnostics);
    else qualified.set(entry, qualification);
  }
  // All fallback entries share one original exact value allowance. Queries then
  // share its remainder; completed query entries never enter these exact facts.
  const callerScope = selected.includes("inconsistent-access-control") ? accessTargets(program) : undefined;
  const transferScope = selected.includes("unprotected-value-transfer") ? mayTransferValue(program) : undefined;
  const receiveScope = selected.includes("received-coin-not-validated") ? mayReceiveShielded(program) : undefined;
  const merkleScope = selected.includes("merkle-membership-not-enforced") ? merkleTargets(program) : undefined;
  const observeMerkle = flow.observeMerkle || !!merkleScope && (!merkleScope.complete || merkleScope.applicable);
  const collectionScope = selected.some(id => id === "nullifier-check-without-insert" || id === "public-key-membership-authorization") ? collectionTargets(program) : undefined;
  const observeCollections = flow.observeCollections || !!collectionScope && (!collectionScope.complete || collectionScope.applicable);
  const exact = new Dataflow(program, flow.maxSteps, flow.maxPaths, flow.maxValues, flow.engine, flow.useSummaries, flow.useStatefulSummaries, flow.pathSemantics, flow.observeCalls, flow.useFoldPartitions,
    flow.predicateScope === "all" || observeCollections || transferScope && (!transferScope.complete || transferScope.applicable) || receiveScope && (!receiveScope.complete || receiveScope.applicable) ? "all" : observeMerkle || callerScope && (!callerScope.complete || callerScope.applicable) ? "all-private" : flow.predicateScope, observeMerkle, observeCollections, flow.observeInitialization || selected.includes("re-initialization"), flow.useHashChoices, flow.observeSignatures, flow.observeEither, flow.observeDigestInputs, flow.observeArithmetic, flow.observeMints, flow.observeMintQuantities, flow.observeInvocations, flow.observeTransientOrigins, flow.observeCommitInputs, flow.observeSignatureKeyIdentity).analyzeSubset(exactEntries);
  result.exact = { entries: exactEntries, facts: exact };
  const policyFindings = new Map<string, Finding[]>();
  const otherFindings = new Map<string, Finding[]>();
  let retainedCandidates = 0;
  const retain = (findings: Finding[]): Finding[] => {
    if (findings.length > maxFindings - retainedCandidates) {
      if (!result.diagnostics.some(item => item.code === "counter-scan-finding-budget")) issue("counter-scan-finding-budget", "Counter scan finding capacity exhausted; results are incomplete");
      return [];
    }
    retainedCandidates += findings.length;
    return findings;
  };
  for (const path of exact.paths) {
    const findings = retain([
      ...(selected.includes("declared-secret-publication") ? secretPublicationOnPath(program, path, policies) : []),
      ...(selected.includes("unguarded-sensitive-state-write") ? unguardedWriteOnPath(program, path, policies) : []),
    ]);
    const previous = policyFindings.get(path.entry) ?? [];
    previous.push(...findings); policyFindings.set(path.entry, previous);
  }
  const informationalFindings = new Map<string, Finding[]>();
  for (const detector of selectedDetectors) {
    if (sourceOnlyIds.has(detector.id)) {
      informationalFindings.set(detector.id, detector.run(exact, policies));
      continue;
    }
    if (![workBudget.id, "declared-secret-publication", "unguarded-sensitive-state-write"].includes(detector.id)) otherFindings.set(detector.id, retain(detector.run(exact, policies)));
  }
  for (const entry of exactEntries) for (const row of rows.get(entry)!) {
    row.method = "exact";
    const missingClaimHistory = row.detector === SOURCE_CLAIM_RULE && !!policies.sourceClaims?.length
      || row.detector === SOURCE_MAP_GETTER_RULE && !!policies.sourceMapGetters?.length;
    row.status = exact.completedEntries.includes(entry) && !missingClaimHistory ? "covered" : "incomplete";
    if (row.detector === SOURCE_MAP_GETTER_RULE && policies.sourceMapGetters?.length) result.diagnostics.push({
      code: "source-map-getter-counter-unavailable",
      message: "Configured Map getter review requires selected original setter/getter histories unavailable in experimental Counter mode",
      location: program.functions.get(entry)!.declaration.span,
      scope: { kind: "rule", detectorId: SOURCE_MAP_GETTER_RULE, entry },
    });
  }
  // The work detector uses the original Program and all configured circuits,
  // including helper policies when no entry needed exact execution.
  if (selected.includes(workBudget.id)) {
    const before = exact.diagnostics.length;
    otherFindings.set(workBudget.id, retain(workBudget.run(exact, policies)));
    const gaps = exact.diagnostics.slice(before);
    for (const policy of policies.workBudgets) result.workPolicies.push({ circuit: policy.circuit,
      status: gaps.some(gap => gap.location === program.symbols.get(policy.circuit)?.span) ? "incomplete" : "covered" });
  }
  result.diagnostics.push(...structuredClone(exact.diagnostics));
  const policyDetectors = result.selectedDetectors.filter((id): id is CounterPolicyDetector => id === "declared-secret-publication" || id === "unguarded-sensitive-state-write");
  let stopQueries = false;
  for (const [entry, qualification] of qualified) {
    result.certificates.push(...qualification.certificates);
    for (const certificate of qualification.certificates) {
      const row = rows.get(entry)!.find(row => row.detector === certificate.detector)!;
      row.status = "covered"; row.method = "structural-absence"; row.contract = certificate.contract;
    }
    if (!policyDetectors.length || stopQueries) continue;
    const used = result.work.query;
    const remaining = { maxQueryWork: queryBounds.query - used.query, maxWitnesses: queryBounds.witnesses - used.witnesses,
      maxTransferSteps: queryBounds.transferSteps - used.transferSteps,
      maxTransferValues: Math.min(queryBounds.transferValues - used.transferValues, flow.maxValues - exact.metrics.abstractValues - used.transferValues) };
    if (Object.values(remaining).some(value => value < 1)) {
      issue("counter-scan-query-budget", "Aggregate Counter scan query/transfer allowance exhausted; results are incomplete", entry);
      stopQueries = true; continue;
    }
    const remainingFindingWork = maxFindingWork - result.work.findingChecks;
    if (remainingFindingWork < 1) {
      issue("counter-scan-finding-work-budget", "Aggregate Counter matching allowance exhausted; results are incomplete", entry);
      stopQueries = true; continue;
    }
    const consumer = counterPolicyFindings(flow, entry, policies, policyDetectors, { ...limits.consumer, maxFindingWork: remainingFindingWork, query: { ...queryLimits, ...remaining } });
    if (consumer.status !== "complete") {
      if (consumer.status === "incomplete") result.diagnostics.push(...structuredClone(consumer.diagnostics));
      else issue("counter-scan-contract", "Previously eligible entry lost its Counter consumer contract; results are incomplete", entry);
      // Incomplete consumers expose no partial work. Stop rather than treating
      // unknown expenditure as zero and refreshing budgets for another entry.
      result.work.queryExpenditureKnown = false; stopQueries = true; continue;
    }
    for (const key of Object.keys(used) as (keyof CounterQueryWork)[]) used[key] += consumer.work.query[key];
    result.work.findingChecks += consumer.work.findingChecks;
    policyFindings.set(entry, retain(consumer.findings));
    for (const row of rows.get(entry)!) if (policyDetectors.includes(row.detector as CounterPolicyDetector)) {
      row.status = "covered"; row.method = "counter-query"; row.contract = consumer.coverage.contract;
    }
  }
  if (selected.includes(workBudget.id)) for (const row of result.coverage) if (row.detector === workBudget.id) {
    row.method = "source-work"; row.contract = "expanded-syntax-upper-bound-v1";
    row.status = result.workPolicies.every(policy => policy.status === "covered") ? "covered" : "incomplete";
  }
  for (const row of result.coverage) if (sourceOnlyIds.has(row.detector)) {
    row.method = "source-work";
    row.contract = row.detector === "missing-role-bootstrap" ? "role-bootstrap-source-observation-v1"
      : row.detector === "generic-witness-maybe-abi" ? "generic-witness-source-schema-v1" : row.detector === "conditional-hash-range" ? "conditional-hash-source-range-v1"
      : row.detector === "shielded-burn-amount-width" ? "burn-amount-width-source-v1"
      : row.detector === "checked-digest-narrowing" ? "digest-source-checked-cast-v1" : "informational-source-observation-v1";
    row.status = result.diagnostics.some(issue => issue.scope?.kind === "rule" && issue.scope.detectorId === row.detector && issue.scope.entry === row.entry) ? "incomplete" : "covered";
  }
  for (const row of result.coverage) if (row.detector === REFUND_ENDPOINT_RULE) {
    row.status = "incomplete"; row.method = "unavailable";
    result.diagnostics.push({ code: "refund-endpoint-counter-unavailable", message: "Source-local refund endpoint certificates are unavailable in experimental Counter mode",
      location: program.functions.get(row.entry)!.declaration.span, scope: { kind: "rule", detectorId: REFUND_ENDPOINT_RULE, entry: row.entry } });
  }
  if (result.diagnostics.some(diagnostic => diagnostic.code === "counter-scan-finding-budget")) for (const row of result.coverage) row.status = "incomplete";
  // Match each detector's original deduplication contract. Policy evidence uses
  // Program entry order, including later fallback callers of an eligible entry.
  // Work-budget intentionally preserves one finding per exceeded policy row.
  result.findings = selectedDetectors.flatMap(detector => sourceOnlyIds.has(detector.id) ? informationalFindings.get(detector.id) ?? [] : policyDetectors.includes(detector.id as CounterPolicyDetector)
    ? unique(program.entries.flatMap(entry => (policyFindings.get(entry) ?? []).filter(finding => finding.detectorId === detector.id)))
    : otherFindings.get(detector.id) ?? []).sort((left, right) => left.location.file.localeCompare(right.location.file) || left.location.start - right.location.start || left.detectorId.localeCompare(right.detectorId) || left.fingerprint.localeCompare(right.fingerprint));
  result.status = result.diagnostics.length || result.coverage.some(row => row.status !== "covered") || result.workPolicies.some(policy => policy.status !== "covered") ? "incomplete" : "complete";
  return result;
}
