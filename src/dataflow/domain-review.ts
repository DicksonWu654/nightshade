import { pathLength, identityLength } from "../semantic/metering.js";
import type { AbstractValue, AnalysisFacts, PrivateSource, StateWrite, SuccessfulPath } from "./index.js";
import { projectEnforcedEqualities } from "./predicates.js";
import { DOMAIN_REVIEW_RULE, entryParameter, scalarEntryBytes } from "../semantic/domain-review.js";
import type { Diagnostic, Span } from "../model.js";

type Charge = (work?: number, retained?: number) => boolean;
export interface DomainReviewObservation { entry: string; write: StateWrite; hash: Span; components: readonly PrivateSource[] }
const ZERO = "00".repeat(32);

/** Exact scalar provenance; aggregate parameter leaves, dependency unions and
 * transformed inputs cannot stand for independent supplied byte components. */
function supplied(value: AbstractValue, facts: AnalysisFacts, entry: string, charge: Charge): PrivateSource | undefined {
  charge(1 + value.flows.length);
  const flow = value.flows.length === 1 ? value.flows[0] : undefined;
  if (!flow || flow.form !== "raw" || value.identity !== flow.source.id || value.type !== "Bytes<32>"
    || value.ledger.size || value.fields || value.items || value.directDigest || value.directCommit
    || value.numericExpression || value.negated || value.comparison || value.ordering) return;
  charge(facts.program.functions.get(entry)!.declaration.parameters.length);
  return scalarEntryBytes(facts.program, entry, flow.source) ? flow.source : undefined;
}

/** Restricted component proof: both components' default assignment is compatible
 * with represented component-only scalar equalities. This does not establish a
 * globally feasible execution, roles, uniqueness or deployment separation. */
export function domainReviewObservations(facts: AnalysisFacts) {
  const observations: DomainReviewObservation[] = [], diagnostics: Diagnostic[] = [];
  const evidence = facts.domainReviewEvidence;
  if (!evidence) return { observations, diagnostics };
  const entry = evidence.entry;
  let work = 0, values = 0;
  const charge: Charge = (amount = 1, retained = 0) => {
    work += amount; values += retained;
    if (facts.metrics.steps + work > evidence.maxSteps || facts.metrics.abstractValues + values > evidence.maxValues)
      throw new Error("Domain review exhausted its shared work/value allowance");
    return true;
  };
  Object.assign(charge, { identityText: facts.program.meteringIdentity });
  const unavailable = (message: string): never => { throw new Error(message); };
  try {
    charge(facts.completedEntries.length);
    if (!facts.digestEvidence || facts.predicateScope !== "all" || facts.pathSemantics !== "equivalent-states"
      || !facts.completedEntries.includes(entry) || facts.diagnostics.length) unavailable("Complete exact public-preimage entry histories are unavailable");
    charge(0, 2);
    const selected: SuccessfulPath[] = [];
    for (const path of facts.paths) { charge(); if (path.entry === entry) { charge(0, 1); selected.push(path); } }
    for (const path of selected) {
      charge();
      if (!path.predicates) unavailable("Exact predicate histories are unavailable");
      for (const write of path.writes) {
        charge();
        const visitPublication = (value: AbstractValue, depth = 0): void => {
          charge();
          if (depth > 64) unavailable("Public-preimage traversal exceeds its depth allowance");
          if (value.directDigest?.primitive === "persistentHash") {
            const input = value.directDigest.input;
            charge(0, 3);
            const components: PrivateSource[] = [];
            let self = false, unsupported = false, leaves = 0;
            const visit = (part: AbstractValue, depth: number): void => {
              charge();
              if (depth > 64) unavailable("Preimage traversal exceeds its depth allowance");
              if (part.kernelSelf) { self = true; return; }
              if (part.fields) { for (const name in part.fields) { charge(); visit(part.fields[name], depth + 1); } return; }
              if (part.items) { for (const child of part.items) visit(child, depth + 1); return; }
              leaves++;
              const source = supplied(part, facts, entry, charge);
              if (source) { charge(0, 1); components.push(source); }
              else {
                // Fully represented raw leaves of one aggregate parameter are
                // outside the scalar-parameter scope, rather than opaque input.
                const flow = part.flows.length === 1 ? part.flows[0] : undefined;
                charge(facts.program.functions.get(entry)!.declaration.parameters.length);
                const aggregateInput = flow?.form === "raw" && part.identity === flow.source.id && !part.ledger.size
                  && !part.directDigest && !part.directCommit && !part.numericExpression && !part.comparison && !part.ordering && !part.negated
                  && entryParameter(facts.program, entry, flow.source);
                if (!aggregateInput && (part.constant === undefined || !part.constantKind || part.flows.length || part.ledger.size)) unsupported = true;
              }
            };
            visit(input, 0);
            // A self discriminator is sufficient for this restricted review
            // even if the remaining composition is outside its two-input scope.
            if (unsupported) unavailable("Published native hash preimage contains opaque, transformed or unavailable components");
            if (self) return;
            if (leaves !== 2 || components.length !== 2 || components[0].symbol === components[1].symbol) return;
            charge(0, 6);
            const ids = new Set(components.map(component => component.id));
            let excluded = false;
            for (const predicate of path.predicates!) {
              charge(1 + predicate.value.flows.length);
              // Unrelated controls cannot donate a component exclusion.
              if (!predicate.value.flows.some(flow => ids.has(flow.source.id))) continue;
              let classified = false;
              const projected = projectEnforcedEqualities(predicate.value, predicate.truth, equality => {
                charge();
                const left = supplied(equality.left, facts, entry, charge), right = supplied(equality.right, facts, entry, charge);
                const first = left && ids.has(left.id), second = right && ids.has(right.id);
                if (!first && !second) {
                  charge(equality.left.flows.length + equality.right.flows.length);
                  if ([equality.left, equality.right].some(part => part.flows.some(flow => ids.has(flow.source.id))))
                    unavailable("A component guard uses unsupported transformed operands");
                  return [];
                }
                classified = true;
                if (first && second) {
                  if (!equality.equals) { charge(0, 2); return [{ key: "default-excluded", value: true }]; }
                  return [];
                }
                const constant = first ? equality.right : equality.left;
                if (constant.constantKind !== "bytes" || constant.constant === undefined || constant.flows.length || constant.ledger.size)
                  unavailable("A component guard has an opaque or external operand");
                charge(1 + Math.ceil(constant.constant!.length / 64));
                const forbids = equality.equals ? constant.constant !== ZERO : constant.constant === ZERO;
                if (!forbids) return [];
                charge(0, 2); return [{ key: "default-excluded", value: true }];
              }, charge);
              if (!projected || !classified) unavailable("Component predicate structure or scalar guard is unavailable");
              if (projected!.required.has("default-excluded")) excluded = true;
            }
            if (excluded) return;
            // Find the actual native transform span, never the ledger write,
            // a sibling digest or a source-text/name search.
            let hash: Span | undefined;
            for (const flow of value.flows) {
              charge();
              if (!ids.has(flow.source.id)) continue;
              for (const trace of flow.trace) { charge(); if (trace.kind === "transform" && trace.label === "persistentHash") hash = trace.location; }
            }
            if (!hash) unavailable("Exact native hash source span is unavailable");
            let emission = 80 + write.callPath.length + write.callSites!.length;
            for (const component of components) { charge(); emission += 6 * Math.ceil((identityLength(component.id, charge) + identityLength(component.symbol!, charge) + pathLength(component.location.file, charge)) / 64); }
            for (const id of write.callPath) { charge(); emission += 6 * Math.ceil(identityLength(id, charge) / 64); }
            charge(emission, emission);
            observations.push({ entry, write, hash: hash!, components });
            return;
          }
          if (value.fields) for (const name in value.fields) visitPublication(value.fields[name], depth + 1);
          if (value.items) for (const item of value.items) visitPublication(item, depth + 1);
          if (!value.directDigest && !value.fields && !value.items && value.flows.some(flow => flow.form === "hash"))
            unavailable("Public hash value has no exact native preimage snapshot");
        };
        if (!write.callSites || write.callSites.length !== write.callPath.length) unavailable("Public write invocation identity is unavailable");
        visitPublication(write.after);
      }
    }
  } catch (error) {
    observations.length = 0;
    diagnostics.push({ code: "domain-review-evidence-unavailable", message: error instanceof Error ? error.message : String(error),
      location: facts.program.functions.get(entry)!.declaration.span, scope: { kind: "rule", detectorId: DOMAIN_REVIEW_RULE, entry } });
  } finally { facts.metrics.steps += work; facts.metrics.abstractValues += values; }
  return { observations, diagnostics };
}
