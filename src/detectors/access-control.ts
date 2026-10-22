import type { AnalysisFacts, PrivateSource, SuccessfulPath, SuccessfulPredicate } from "../dataflow/index.js";
import { predicateEvidence, predicateSourceKey, rawWitnessSources } from "../dataflow/predicates.js";
import type { Span } from "../model.js";
import { accessTargets } from "../semantic/access-targets.js";
import { finding, type Detector, type Finding } from "./types.js";

interface Authentication {
  key: string;
  kind: "secret-preimage" | "raw-witness";
  predicate: SuccessfulPredicate;
  source: PrivateSource;
  ledger: string[];
}
interface Reach {
  path: SuccessfulPath;
  kind: "ledger" | "operation";
  target: string;
  index: number;
  location: Span;
  callPath: string[];
  callSites?: Span[];
  guards: Map<string, Authentication>;
}
const MAX_WORK = 1_000_000;
// These are actual modeled transaction writes, not source-level helper names.
const VALUE_OPERATIONS = new Set(["mintShielded", "mintUnshielded", "claimZswapCoinSpend", "claimUnshieldedCoinSpend", "createZswapInput", "createZswapOutput"]);

export const inconsistentAccessControl: Detector = {
  id: "inconsistent-access-control",
  defaultEnabled: false,
  description: "An exported writer omits the caller-check convention required by a strict majority of its peers",
  requires: ["successful-predicates", "all-private-predicates", "state-writes", "runtime-operations", "completed-entries"],
  run(facts) {
    const scope = accessTargets(facts.program);
    const issue = (code: string, message: string) => facts.diagnostics.push({ code, message: `${message}; caller-convention results are incomplete`, location: facts.program.rootSource.ast.span });
    if (!scope.complete) { issue("predicate-analysis-budget", "Caller-convention applicability exceeded its bounded allowance"); return []; }
    if (!scope.applicable) return [];
    if (facts.predicateScope !== "all-private" && facts.predicateScope !== "all") { issue("predicate-evidence-unavailable", "Caller conventions require complete private-input predicates"); return []; }
    const completed = new Set(facts.completedEntries);
    const groups = new Map<string, Map<string, Reach[]>>();
    let work = scope.work;
    const charge = () => ++work <= MAX_WORK;
    for (const path of facts.paths) {
      if (!completed.has(path.entry) || !scope.entries.has(path.entry)) continue;
      const evidence = predicateEvidence(path, MAX_WORK - work);
      work += evidence.work;
      if (!evidence.complete) { issue("predicate-analysis-budget", "Caller-convention predicate decoding exceeded its allowance or evidence is missing"); return []; }
      const guards = new Map<string, Authentication>();
      for (const { predicate, equality } of evidence.equalities) {
        if (!charge()) { issue("predicate-analysis-budget", "Caller-convention matching exceeded its allowance"); return []; }
        if (!equality.equals) continue;
        for (const [input, trusted] of [[equality.left, equality.right], [equality.right, equality.left]]) {
          if (!trusted.preexistingLedger?.size) continue;
          const secret = input.directHash?.source;
          const source = secret && !evidence.publicValues.has(predicateSourceKey(secret, path)) ? secret : rawWitnessSources(input)[0];
          if (!source) continue;
          const kind = secret === source ? "secret-preimage" : "raw-witness";
          const ledger = [...trusted.preexistingLedger].sort();
          const key = JSON.stringify([kind, kind === "secret-preimage" ? input.directHash!.primitive : "", ledger]);
          if (!guards.has(key)) guards.set(key, { key, kind, predicate, source, ledger });
        }
      }
      const reaches: Reach[] = [
        ...path.writes.map((effect, index) => ({ path, kind: "ledger" as const, target: effect.ledger, index, location: effect.location, callPath: effect.callPath, callSites: effect.callSites, guards })),
        ...(path.operations ?? []).flatMap((effect, index) => VALUE_OPERATIONS.has(effect.name) && ["kernel-write", "native-witness"].includes(effect.kind)
          ? [{ path, kind: "operation" as const, target: effect.name, index, location: effect.location, callPath: effect.callPath, callSites: effect.callSites, guards }] : []),
      ];
      for (const reach of reaches) {
        if (!charge()) { issue("predicate-analysis-budget", "Caller-convention effects exceeded their allowance"); return []; }
        if (!reach.callSites) { issue("predicate-evidence-unavailable", "Caller-convention effect invocation evidence is missing"); return []; }
        const key = JSON.stringify([reach.kind, reach.target]);
        const writers = groups.get(key) ?? new Map<string, Reach[]>();
        const histories = writers.get(path.entry) ?? [];
        histories.push(reach); writers.set(path.entry, histories); groups.set(key, writers);
      }
    }
    const findings: Finding[] = [];
    for (const writers of groups.values()) {
      const first = writers.values().next().value![0];
      const missing = [...scope.entries].filter(([entry, target]) => !completed.has(entry) && (first.kind === "ledger" ? target.ledgers.has(first.target) : target.transaction));
      if (missing.length) {
        issue("caller-convention-incomplete", `Potential writers of ${first.target} have incomplete analysis`);
        continue;
      }
      if (writers.size < 3) continue;
      const conventions = new Map<string, Map<string, Authentication>>();
      for (const [entry, reaches] of writers) for (const [key, guard] of reaches[0].guards) {
        const required = reaches.every(reach => charge() && reach.guards.has(key));
        if (work > MAX_WORK) { issue("predicate-analysis-budget", "Caller-convention intersection exceeded its allowance"); return []; }
        if (!required) continue;
        const peers = conventions.get(key) ?? new Map<string, Authentication>();
        peers.set(entry, guard); conventions.set(key, peers);
      }
      for (const peers of conventions.values()) {
        if (peers.size < 2 || peers.size * 2 <= writers.size) continue;
        const convention = peers.values().next().value!;
        for (const [entry, reaches] of writers) {
          if (peers.has(entry)) continue;
          const omitted = reaches.find(reach => ![...reach.guards.values()].some(guard => {
            if (!charge()) return false;
            return guard.kind === "secret-preimage" || convention.kind === "raw-witness";
          }));
          if (work > MAX_WORK) { issue("predicate-analysis-budget", "Caller-convention alternatives exceeded their allowance"); return []; }
          if (omitted) findings.push(conventionFinding(facts, entry, omitted, convention, peers, writers.size));
        }
      }
    }
    return findings;
  },
};

function conventionFinding(facts: AnalysisFacts, entry: string, reach: Reach, convention: Authentication, peers: Map<string, Authentication>, writerCount: number): Finding {
  const name = (id: string) => facts.program.symbols.get(id)?.name ?? id;
  const target = name(reach.target);
  const before = (guard: Authentication, effect: Reach) => effect.kind === "ledger" ? guard.predicate.writesBefore <= effect.index : guard.predicate.operationsBefore <= effect.index;
  return finding(facts, {
    detectorId: inconsistentAccessControl.id, severity: "medium", confidence: "low", title: "Exported writer omits a sibling caller-check convention",
    message: `${name(entry)} has a modeled successful ${reach.kind === "ledger" ? "write to" : "call to"} ${target} without the ${convention.kind} convention required by ${peers.size} of ${writerCount} distinct exported writers, or a modeled alternative of the same strength. The convention checks ${convention.ledger.map(name).join(", ")}. Mixed public and restricted operations may be intentional; review the intended access policy.`,
    location: reach.location, constraint: convention.predicate.location, source: convention.source.location,
    trace: [...peers].map(([peer, guard]) => ({ kind: "constraint", label: `${name(peer)} requires ${guard.kind}`, location: guard.predicate.location })).concat([
      ...reach.callSites!.slice(1).map(location => ({ kind: "call", label: "writer invocation", location })),
      { kind: "effect", label: `writer without this convention: ${target}`, location: reach.location },
    ]),
    callPath: reach.callPath.map(name),
    remediation: "Check whether this writer is intentionally public or uses an unsupported authentication mechanism. If it should follow the sibling policy, enforce that check on every successful operation. Document intentional exceptions.",
    metadata: { reviewRequired: true, authenticationIntent: "unknown", pathFeasibility: "not-proven", entry: name(entry), target, targetKind: reach.kind,
      convention: convention.kind, trustedLedger: convention.ledger.map(name), guardedWriters: [...peers.keys()].map(name), writerCount,
      effectIndex: reach.index, effectCallSites: reach.callSites,
      peerGuards: [...peers].map(([peer, guard]) => ({ entry: name(peer), location: guard.predicate.location, callSites: guard.predicate.callSites,
        writesBefore: guard.predicate.writesBefore, operationsBefore: guard.predicate.operationsBefore })),
      omittedHistoryGuards: [...reach.guards.values()].map(guard => ({ kind: guard.kind, location: guard.predicate.location, position: before(guard, reach) ? "before-effect" : "after-effect" })) },
  }, `${entry}:${reach.kind}:${reach.target}:${convention.key}`);
}
