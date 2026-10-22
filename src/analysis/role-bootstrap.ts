import type { AnalysisFacts } from "../dataflow/index.js";
import type { Span } from "../model.js";
import { shieldedAccessControlIdentities } from "../semantic/openzeppelin-identities.js";
import { sourceStorageReferences } from "../semantic/source-storage-references.js";

export interface RoleBootstrapObservation { location: Span; initializer: Span; instance: string; protectedCircuits: string[] }

/** Fail-closed absence of any role-seeding route in an authenticated composition.
 * Call/effect traversal overapproximates all entry-reachable source, including
 * dead branches. grantRole is a byte-authenticated guarded boundary; _grantRole
 * elsewhere, or any application reference to this instance's storage, withholds
 * the absence claim. Actual complete constructor histories must initialize it.
 * This does not reason about whether a supplied seed/admin policy is adequate. */
export function roleBootstrapObservations(facts: AnalysisFacts, allowance = 200000) {
  const { program } = facts, identity = shieldedAccessControlIdentities(program);
  let work = 0, complete = true, unresolvedCall = false;
  const charge = (depth = 0) => { if (!complete) return false; if (++work > allowance || depth > 128) complete = false; return complete; };
  const observations: RoleBootstrapObservation[] = [];
  let needsConstructor = false;
  const instances = new Map(identity.instances.map(edge => [edge.target, edge]));
  const unsupportedProfile = instances.size > 0 && program.semanticProfile !== "compact-0.34.0-zkir2";
  if (!instances.size || unsupportedProfile) return { complete: !unsupportedProfile, work, needsConstructor, unresolvedCall, unsupportedProfile, observations };
  const constructors = new Set<string>();
  for (const id of program.entries) { if (!charge()) break; if (program.symbols.get(id)?.kind === "constructor") constructors.add(id); }
  const constructorPaths = [];
  for (const path of facts.paths) { if (!charge()) break; if (constructors.has(path.entry)) constructorPaths.push(path); }
  for (const [instance, edge] of instances) {
    if (!charge()) break;
    const member = (id: string) => id.startsWith(`${instance}::`);
    const storage = new Set<string>();
    let initialized: string | undefined, initializer: string | undefined;
    for (const symbol of program.symbols.values()) {
      if (!charge()) break;
      if (symbol.kind === "ledger" && member(symbol.id) && identity.authenticated(symbol.span)) {
        storage.add(symbol.id);
        if (symbol.name === "_isInitialized") initialized = symbol.id;
      }
    }
    const protectedCircuits = new Set<string>(), seen = new Set<string>(), pending = [...program.entries];
    let alternate = false;
    while (pending.length && !alternate && charge()) {
      const id = pending.pop()!;
      if (seen.has(id)) continue;
      seen.add(id);
      const fn = program.functions.get(id);
      if (!fn) {
        if (!["witness", "intrinsic"].includes(program.symbols.get(id)?.kind ?? "")) { complete = false; unresolvedCall = true; }
        continue;
      }
      const canonical = member(id) && !!identity.authenticated(fn.declaration.span);
      if (canonical && fn.symbol.name === "_grantRole") { alternate = true; break; }
      if (canonical && fn.symbol.name === "grantRole") { protectedCircuits.add(id); continue; }
      if (canonical && fn.symbol.name === "initialize") initializer = id;
      if (!canonical) {
        if (!fn.declaration.body) { complete = false; unresolvedCall = true; break; }
        // CFGs omit empty-loop bodies; source references still withhold absence.
        const source = sourceStorageReferences(fn.declaration.body, storage, charge);
        if (!source.complete) { complete = false; unresolvedCall ||= source.unresolvedCall; break; }
        if (source.references.length) { alternate = true; break; }
      }
      for (const callee of fn.calls) { if (!charge()) break; pending.push(callee); }
    }
    if (!complete || alternate || !protectedCircuits.size || !initializer || !initialized) continue;
    if (!constructors.size || [...constructors].some(id => !facts.completedEntries.includes(id)) || !constructorPaths.length) {
      needsConstructor = true; continue;
    }
    let initializes = true;
    for (const path of constructorPaths) {
      let found = false;
      for (const write of path.writes) {
        if (!charge()) break;
        if (write.ledger !== initialized || write.after.constant !== "true") continue;
        for (const id of write.callPath) { if (!charge()) break; if (id === initializer) { found = true; break; } }
        if (found || !complete) break;
      }
      if (!found || !complete) { initializes = false; break; }
    }
    if (initializes) observations.push({ location: edge.location, initializer: program.functions.get(initializer)!.declaration.span,
      instance, protectedCircuits: [...protectedCircuits].sort() });
  }
  return { complete: complete && !needsConstructor, work, needsConstructor, unresolvedCall, unsupportedProfile, observations: complete && !needsConstructor ? observations : [] };
}
