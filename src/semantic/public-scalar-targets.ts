import type { Program } from "./index.js";
import { intrinsicModel } from "./intrinsics.js";

export const PUBLIC_SCALAR_RULE = "published-digest-generator-scalar-review";
/** Selection token for exact Field -> JubjubScalar casts, never a user call. */
export const PUBLIC_SCALAR_CAST = "observer::public-scalar-cast";
export const PUBLIC_SCALAR_TARGETS = new Set([PUBLIC_SCALAR_CAST, "intrinsic::degradeToTransient", "intrinsic::ecMulGenerator"]);
export function publicScalarProfile(program: Program): boolean {
  return publicScalarRecipe(program) !== undefined;
}

/** Source-profile admission, using the resolved native overload. A legacy
 * Field operand is not a synthetic scalar cast. */
export function publicScalarRecipe(program: Program): "field" | "scalar-cast" | undefined {
  const generator = program.symbols.get("intrinsic::ecMulGenerator");
  if (generator?.kind !== "intrinsic") return;
  const model = intrinsicModel(generator);
  if (model.result !== "JubjubPoint" || model.parameters.length !== 1) return;
  if (program.compilerVersion === "0.31.1" && program.zkirVersion === 2
    && generator.intrinsicProfile === "legacy" && model.parameters[0] === "Field") return "field";
  if (program.compilerVersion === "0.34.0" && (program.zkirVersion === 2 || program.zkirVersion === 3)
    && generator.intrinsicProfile !== "legacy" && model.parameters[0] === "JubjubScalar") return "scalar-cast";
}

export const PUBLIC_SCALAR_PROFILE_MESSAGE = "Published digest scalar review supports only the canonical Field recipe on compiler 0.31.1/ZKIR 2 and canonical scalar-cast recipes on compiler 0.34.0/ZKIR 2 or 3";

/** Syntactic may-reachability only; a native target need not execute. Resolved
 * call edges include ordinary helpers and map/fold callbacks, even at size zero.
 * Missing callable models and exhausted walks can never certify absence. */
export function publicScalarScope(program: Program, entry: string, allowance = 20000, meter?: (work: number, values: number) => boolean): {
  complete: boolean; applicable: boolean; work: number; unavailable?: "budget" | "unresolved";
} {
  let work = 0;
  if (meter && !meter(0, 5)) return { complete: false, applicable: true, work, unavailable: "budget" };
  const spend = (values = 0) => {
    work++;
    if (meter && !meter(1, values)) return false;
    return Number.isSafeInteger(allowance) && allowance >= 1 && work <= allowance;
  };
  const seen = new Set<string>(), pending = [entry];
  while (pending.length) {
    if (!spend())
      return { complete: false, applicable: true, work, unavailable: "budget" };
    const id = pending.pop()!;
    if (seen.has(id)) continue;
    if (meter && !meter(0, 2)) return { complete: false, applicable: true, work, unavailable: "budget" };
    seen.add(id);
    const symbol = program.symbols.get(id);
    if (!symbol) return { complete: false, applicable: true, work, unavailable: "unresolved" };
    if (id === "intrinsic::ecMulGenerator" && symbol.kind === "intrinsic")
      return { complete: true, applicable: true, work };
    if (symbol.kind === "intrinsic" || symbol.kind === "witness") continue;
    const fn = program.functions.get(id);
    if (!fn) return { complete: false, applicable: true, work, unavailable: "unresolved" };
    for (const callee of fn.calls) {
      if (!spend(2)) return { complete: false, applicable: true, work, unavailable: "budget" };
      pending.push(callee);
    }
  }
  return { complete: true, applicable: false, work };
}
