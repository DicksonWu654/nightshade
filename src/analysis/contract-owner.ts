import type { AnalysisFacts, StateWrite } from "../dataflow/index.js";
import { successfulConstants } from "../dataflow/successful-constants.js";
import { defaultAddressTargets } from "../semantic/default-address-targets.js";
import { hasContractOwnerEffects } from "../semantic/contract-owner-targets.js";
import type { ResolvedPolicies } from "../policies.js";
import type { Diagnostic, Span } from "../model.js";

export interface ContractOwnerObservation {
  owner: string; entry: string; instance: string; location: Span; effect: Span;
  guard: Span; callPath: string[]; callSites: Span[];
}

/** A final owner-tag write selects the arm explicitly rejected by the pinned
 * guard. Payload-only writes preserve it; unknown overlapping writes withhold it.
 * Provider and observation gaps belong to their selected relation; a supported
 * relation/history remains existential evidence when another is unavailable. */
export function contractOwnerObservations(facts: AnalysisFacts, policies?: ResolvedPolicies, allowance = 200000,
  selectedEntries: readonly string[] = facts.program.entries) {
  const { program } = facts;
  const observations: ContractOwnerObservation[] = [], diagnostics: Diagnostic[] = [];
  let work = 0;
  if (!policies?.callableOwnable?.length) return { complete: true, work, observations, diagnostics };
  const scope = defaultAddressTargets(program), issued = new Set<string>();
  // Direct consumers owe every applicable program entry. The observation
  // orchestrator explicitly scopes its entry-isolated passes, including entries
  // with no retained successful paths; engine facts need no new instrumentation.
  const entries = [...new Set(selectedEntries)].filter(entry => hasContractOwnerEffects(program, entry, policies));
  const issue = (owner: string, entry: string, code: string, message: string) => {
    const key = JSON.stringify([owner, entry, code]);
    if (issued.has(key)) return;
    issued.add(key);
    diagnostics.push({ code, message: `${message} (owner=${owner})`, location: program.functions.get(entry)!.declaration.span,
      scope: { kind: "rule", detectorId: "unsupported-contract-owner", entry } });
  };
  for (const { owner } of policies?.callableOwnable ?? []) for (const entry of entries) {
    if (!program.functions.get(entry)?.writesState.has(owner)) continue;
    if (++work > allowance) {
      issue(owner, entry, "contract-owner-observation-budget", "Callable Ownable relation observation exhausted its bounded allowance"); continue;
    }
    if (!scope.owners.has(owner)) {
      issue(owner, entry, "contract-owner-provider-unavailable", "Callable Ownable requires the pinned Ownable owner ledger and authenticated dependencies"); continue;
    }
    const instance = owner.slice(0, owner.lastIndexOf("::"));
    const guard = [...program.symbols.values()].find(symbol => symbol.name === "assertOnlyOwner"
      && symbol.id === `${instance}::assertOnlyOwner`);
    if (!guard) {
      issue(owner, entry, "contract-owner-provider-unavailable", "The authenticated owner guard declaration is unavailable"); continue;
    }
    if (program.semanticProfile !== "compact-0.34.0-zkir2") {
      issue(owner, entry, "contract-owner-profile-unavailable", "Callable Ownable evidence is qualified only for Compact 0.34.0/ZKIR2"); continue;
    }
    if (!facts.completedEntries.includes(entry) || facts.pathSemantics !== "equivalent-states" || facts.predicateScope !== "all") {
      issue(owner, entry, "contract-owner-observation-unavailable", "Callable Ownable requires complete exact successful histories and all successful predicates"); continue;
    }
    const supported: ContractOwnerObservation[] = [];
    let exhausted = false;
    for (const path of facts.paths) {
      if (++work > allowance) { exhausted = true; break; }
      if (path.entry !== entry) continue;
      let final: StateWrite | undefined;
      for (let index = path.writes.length - 1; index >= 0; index--) {
        if (++work > allowance) { exhausted = true; break; }
        const write = path.writes[index];
        if (write.ledger !== owner) continue;
        // A typed native Either payload mutation cannot alter its discriminator.
        // Other/unknown regions may overlap the tag and block earlier evidence.
        if (["field:left", "field:right"].includes(write.region[0])) continue;
        final = write; break;
      }
      if (exhausted) break;
      if (!final) continue;
      const tagWrite = final.region.length === 1 && final.region[0] === "field:is_left";
      if (final.region.length && !tagWrite) {
        issue(owner, entry, "contract-owner-final-write-unavailable", "A later partial or unknown owner-region write prevents an exact final-tag certificate"); continue;
      }
      if (!path.predicates) {
        issue(owner, entry, "contract-owner-observation-unavailable", "The owner history is missing successful predicates"); continue;
      }
      const value = tagWrite ? final.after : final.after.fields?.is_left;
      if (!value) {
        issue(owner, entry, "contract-owner-tag-unavailable", "The final owner write is missing its exact discriminator"); continue;
      }
      const constants = successfulConstants(path, Math.max(0, allowance - work), facts.program.meteringIdentity);
      const tag = constants.refine(value);
      work += constants.work;
      if (!constants.complete || work > allowance) { exhausted = true; break; }
      if (tag.constantKind !== "boolean" || !["true", "false"].includes(tag.constant!)) {
        issue(owner, entry, "contract-owner-tag-unavailable", "The final owner tag is unknown on this successful history"); continue;
      }
      if (tag.constant !== "false") continue;
      const index = final.callPath.findIndex(id => scope.functions.has(id));
      // Direct authenticated ledger assignments use their own source span.
      const location = index < 0 ? final.location : final.callSites?.[index];
      if (!location) {
        issue(owner, entry, "contract-owner-observation-unavailable", "The authenticated owner write is missing its application invocation location"); continue;
      }
      supported.push({ owner, entry, instance, location, effect: final.location, guard: guard.span,
        callPath: final.callPath, callSites: final.callSites ?? [] });
    }
    if (exhausted) issue(owner, entry, "contract-owner-observation-budget", "Successful owner constraints or relation observation exhausted its bounded allowance");
    else observations.push(...supported);
  }
  return { complete: diagnostics.length === 0, work, observations, diagnostics };
}
