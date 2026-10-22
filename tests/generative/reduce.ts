import { GeneratedCase, shrinkCandidates, validateCase } from "./model.js";

export interface ReductionResult {
  case: GeneratedCase;
  checks: number;
  exhausted: boolean;
  interrupted: boolean;
  changed: boolean;
}

/** Bounded typed reduction; the caller must preserve failure identity. */
export async function reduceCase(input: GeneratedCase, preserves: (candidate: GeneratedCase) => Promise<boolean>, maxChecks = 64, cancelled: () => boolean = () => false): Promise<ReductionResult> {
  validateCase(input);
  if (!Number.isSafeInteger(maxChecks) || maxChecks < 1 || maxChecks > 1024) throw new Error("Reduction budget must be 1..1024");
  let current: GeneratedCase = structuredClone(input);
  let checks = 0;
  let exhausted = false;
  while (current.operations.length && checks < maxChecks && !cancelled()) {
    let reduced = false;
    const candidates = shrinkCandidates(current);
    for (const candidate of candidates) {
      if (cancelled()) break;
      if (checks >= maxChecks) { exhausted = true; break; }
      checks++;
      if (await preserves(candidate)) {
        current = candidate;
        reduced = true;
        break;
      }
    }
    if (!reduced) break;
    if (checks === maxChecks && current.operations.length) exhausted = true;
  }
  const interrupted = cancelled();
  return { case: current, checks, exhausted: !interrupted && exhausted, interrupted, changed: JSON.stringify(current) !== JSON.stringify(input) };
}
