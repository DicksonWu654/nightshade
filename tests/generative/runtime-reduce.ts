import { validateCase, type GeneratedCase } from "./model.js";
import { reduceCase, type ReductionResult } from "./reduce.js";
import { incompleteRuntimeResult, validateRuntimeResult, type RuntimeCheckResult } from "./runtime-artifacts.js";

export interface RuntimeReductionAttempt {
  model: GeneratedCase;
  result: RuntimeCheckResult;
  preserved: boolean;
}

export interface RuntimeReductionResult extends ReductionResult {
  result: RuntimeCheckResult;
  attempts: RuntimeReductionAttempt[];
}

function protocolFailure(error: unknown): RuntimeCheckResult {
  let message: string;
  try { message = error instanceof Error ? error.message : String(error); }
  catch { message = "Runtime evaluator threw an unreadable error"; }
  return incompleteRuntimeResult("runtime-protocol", typeof message === "string" && message ? message : "Runtime evaluator returned an invalid result or threw an empty error");
}

/**
 * Pure orchestration for the bounded owned model; evaluation is supplied by the
 * caller. Every attempted candidate retains its checked result. A different
 * failure, incomplete evaluation or invalid protocol never replaces the last
 * validated instance of the original disagreement.
 */
export async function reduceRuntimeCase(
  input: GeneratedCase,
  initial: RuntimeCheckResult,
  evaluate: (candidate: GeneratedCase) => Promise<unknown>,
  maxChecks = 32,
  cancelled: () => boolean = () => false,
): Promise<RuntimeReductionResult> {
  const model = validateCase(input);
  if (!Number.isSafeInteger(maxChecks) || maxChecks < 1 || maxChecks > 256) throw new Error("Runtime reduction budget must be 1..256");
  let accepted = validateRuntimeResult(model, initial);
  if (accepted.status !== "failed" || accepted.category !== "runtime-model-disagreement") throw new Error("Runtime reduction requires a checked runtime-model-disagreement failure");
  const signature = accepted.signature;
  const attempts: RuntimeReductionAttempt[] = [];
  let interrupted = false;
  const isCancelled = (): boolean => interrupted ||= cancelled();
  const reduced = await reduceCase(model, async candidate => {
    const attempted = validateCase(candidate);
    let result: RuntimeCheckResult;
    try { result = validateRuntimeResult(attempted, await evaluate(structuredClone(attempted))); }
    catch (error) { result = protocolFailure(error); }
    if (result.status === "incomplete" && result.category === "worker-interrupted") interrupted = true;
    const preserved = !isCancelled() && result.status === "failed" && result.category === "runtime-model-disagreement" && result.signature === signature;
    attempts.push({ model: attempted, result: structuredClone(result), preserved });
    if (preserved) accepted = result;
    return preserved;
  }, maxChecks, isCancelled);
  return { ...reduced, result: validateRuntimeResult(reduced.case, accepted), attempts };
}
