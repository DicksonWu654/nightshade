import type { AnalysisFacts, RuntimeOperation, SuccessfulPath } from "../dataflow/index.js";
import { collectionAbsenceConsumption } from "../dataflow/collection-consumption.js";
import { immutableCollectionAddress } from "../dataflow/immutable-key.js";
import { mayOverlap } from "../dataflow/regions.js";
import { ruleObservationIssue } from "../analysis/rule-diagnostics.js";
import { MERKLE_INSERT_OBSERVER, MERKLE_INSERT_RULE, merkleInsertScope } from "../semantic/merkle-targets.js";
import { finding, unique, type Detector, type Finding } from "./types.js";

/** Review repeated-value handling, not a capacity-exhaustion or replay proof. */
export function merkleInsertFindings(facts: AnalysisFacts, allowance = 1000000, entries: readonly string[] = facts.program.entries): Finding[] {
  const scope = merkleInsertScope(facts.program, entries);
  const incomplete = (reason: string): Finding[] => {
    ruleObservationIssue(facts, MERKLE_INSERT_RULE, "merkle-insert-evidence-incomplete", `${reason}; bounded insertion review is incomplete`);
    return [];
  };
  if (!scope.complete) return incomplete("Native tree write applicability exceeded its allowance");
  if (!scope.applicable) return [];
  if (!facts.invocationEvidence?.includes(MERKLE_INSERT_OBSERVER) || !facts.collectionEvidence
    || facts.predicateScope !== "all" || facts.pathSemantics !== "equivalent-states")
    return incomplete("Exact insertion and collection observations and original all-predicate histories are required");
  for (const entry of entries) if (!facts.completedEntries.includes(entry)) {
    const target = merkleInsertScope(facts.program, [entry]);
    if (!target.complete || target.applicable) return incomplete("Applicable entry lacks complete successful-history coverage");
  }
  let work = 0;
  const charge = (units = 1) => {
    work += units;
    if (!Number.isSafeInteger(allowance) || work > allowance) throw new Error("Insertion matching allowance exhausted");
  };
  const address = (operation: RuntimeOperation) => {
    const result = immutableCollectionAddress(operation.args[0], Math.min(4096, allowance - work));
    charge(result.work);
    if (!result.complete || !result.key) throw new Error("Exact collection receiver is unavailable");
    return result.key;
  };
  // A prior absence cannot be recycled after erasing its receiver or after
  // another possibly aliasing tree insert. Set/Map insertion before the tree
  // is permitted as the remembering write, but replacing/removing is not.
  const currentAt = (path: SuccessfulPath, query: RuntimeOperation, insert: RuntimeOperation, preservingInsertWrites: readonly number[]): boolean => {
    const operations = path.operations!;
    const queryIndex = operations.indexOf(query), tree = insert.args[0].region!, memory = query.args[0].region!;
    const permitted = new Set(preservingInsertWrites);
    for (let index = queryIndex + 1; index < insert.operationsBefore!; index++) {
      charge();
      const operation = operations[index];
      if (operation.kind === "merkle-insert" && operation.args[0].region
        && mayOverlap(tree, operation.args[0].region)) return false;
    }
    for (let index = query.writesBefore!; index < insert.writesBefore!; index++) {
      charge();
      const write = path.writes[index];
      if (write.region.length <= memory.path.length && mayOverlap(memory, { root: write.ledger, path: write.region, type: "unknown" })
        && !permitted.has(index)) return false;
    }
    return true;
  };
  const findings: Finding[] = [];
  try {
    for (const path of facts.paths) {
      charge();
      if (!entries.includes(path.entry) || facts.program.symbols.get(path.entry)?.kind === "constructor") continue;
      if (!facts.completedEntries.includes(path.entry)) return incomplete("Entry lacks complete successful-history coverage");
      for (const operation of path.operations ?? []) {
        charge();
        // Indexed replacement has a different capacity contract and is not
        // treated as sequential bounded growth by this rule.
        if (operation.kind !== "merkle-insert" || !["insert", "insertHash"].includes(operation.name)) continue;
        if (!operation.args[0]?.region || !operation.args[1] || operation.operationsBefore === undefined || operation.writesBefore === undefined)
          return incomplete("Insertion lacks original receiver, operand or ordering boundary");
        address(operation);
        const result = collectionAbsenceConsumption(path, allowance - work,
          { value: operation.args[1], beforeOperation: operation.operationsBefore });
        charge(result.work);
        if (!result.complete) return incomplete("Required-absence matching lacks exact operands or exhausted its allowance");
        if (result.absences.some(absence => { charge(); return absence.survives && currentAt(path, absence.query, operation, absence.preservingInsertWrites); })) continue;
        const entry = facts.program.symbols.get(path.entry)!.name, tree = facts.program.symbols.get(operation.args[0].region.root)!.name;
        findings.push(finding(facts, {
          detectorId: MERKLE_INSERT_RULE, severity: "info", confidence: "medium",
          title: "Bounded Merkle insertion lacks an exact surviving duplicate check",
          message: `${entry} sequentially inserts into ${tree} without a modeled preceding enforced absence check for that exact value and a surviving insertion into the checked persistent collection. Review whether repeated values should be rejected; intentional repeated leaves, external protocol invariants or indexed updates have different contracts.`,
          location: operation.location,
          trace: [{ kind: "state-write", label: "sequential bounded tree insertion", location: operation.location }],
          callPath: operation.callPath.map(id => facts.program.symbols.get(id)?.name ?? id),
          remediation: "If duplicate leaves are invalid, check the actual inserted value against a persistent dedupe collection and remember it on every successful history. Retain that record through completion and avoid reusing an earlier guard for a second insertion.",
          metadata: { reviewRequired: true, entry, tree, operation: operation.name, evidence: "bounded-insert-without-exact-surviving-dedupe",
            repeatedValueIntent: "unknown", scope: "original-successful-history", pathFeasibility: "not-proven", capacityExhaustion: "not-proven", deployedImpact: "not-proven" },
        }, path.entry));
      }
    }
  } catch (error) { return incomplete(error instanceof Error ? error.message : String(error)); }
  return unique(findings);
}

export const merkleInsertWithoutDedupe: Detector = {
  id: MERKLE_INSERT_RULE, defaultEnabled: false,
  description: "Review sequential bounded Merkle insertion without exact surviving duplicate prevention",
  requires: ["canonical-insertion-snapshots", "collection-observations", "all-predicates", "completed-entries"],
  run: facts => merkleInsertFindings(facts),
};
