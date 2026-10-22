import type { AnalysisFacts, FailedAssertion } from "../dataflow/index.js";
import { spanId } from "../model.js";

/** Physical-site universality includes all callers and instantiated declarations.
 * An uncovered entry that may call a site's declaration blocks its proof, even
 * when analysis stopped before observing that site. Other entries stay useful. */
export function uncoveredDeclarations(facts: AnalysisFacts): Set<string> {
  const complete = new Set([...facts.completedEntries, ...facts.sourceQueries?.map(query => query.entry) ?? []]);
  const uncovered = new Set<string>();
  const pending = facts.program.entries.filter(entry => !complete.has(entry));
  while (pending.length) {
    const id = pending.pop()!;
    if (uncovered.has(id)) continue;
    uncovered.add(id);
    for (const callee of facts.program.functions.get(id)?.calls ?? []) pending.push(callee);
  }
  // Specialized/generic instances share physical declaration spans; a single
  // successful or uncovered instance must veto a universal source-site claim.
  return new Set([...uncovered].flatMap(id => {
    const fn = facts.program.functions.get(id);
    return fn ? [spanId(fn.declaration.span)] : [];
  }));
}

export function universallyFailedAssertions(facts: AnalysisFacts): FailedAssertion[] {
  const complete = new Set([...facts.completedEntries, ...facts.sourceQueries?.map(query => query.entry) ?? []]);
  const uncovered = uncoveredDeclarations(facts);
  const reached = new Set<string>(), blocked = new Set<string>();
  for (const reach of [...facts.assertionReaches, ...facts.sourceQueries?.flatMap(query => query.assertionReaches) ?? []]) {
    const site = spanId(reach.location), owner = facts.program.functions.get(reach.owner);
    reached.add(site);
    if (reach.maySucceed || reach.literalFalse || !complete.has(reach.entry) || !owner
      || uncovered.has(spanId(owner.declaration.span))) blocked.add(site);
  }
  return facts.failedAssertions.filter(failure => reached.has(spanId(failure.location)) && !blocked.has(spanId(failure.location)));
}
