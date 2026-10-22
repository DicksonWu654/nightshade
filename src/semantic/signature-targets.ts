import type { Program } from "./index.js";
import { ECDSA_VERIFIER } from "./signed-input-targets.js";

export const ENROLLED_SIGNATURE_KEY_RULE = "enrolled-signature-key-review";

/** Whole persistent native-point Cells only. Plain ledgers are implicit Cells.
 * Struct fields and collection projections need separate provenance. */
export function persistentSchnorrKeyCell(program: Program, root: string): boolean {
  const symbol = program.symbols.get(root);
  if (symbol?.kind !== "ledger") return false;
  const type = program.representationOf(symbol.type);
  return type === "JubjubPoint" || type === 'Opaque<"JubjubPoint">';
}

/** Canonical identity of the pinned stdlib verifier and its specializations.
 * An imported alias retains it; a same-named application circuit does not. */
export function schnorrVerifier(id: string): boolean {
  return id.startsWith("standard-library::jubjubSchnorrVerify<");
}

/** Functions are materialized only for resolved calls. No extra observations or
 * summary restrictions are needed in compilation units without this verifier. */
export function hasSchnorrVerifier(program: Program): boolean {
  for (const id of program.functions.keys()) if (schnorrVerifier(id)) return true;
  return false;
}

/** A transparent checker returns exactly the pinned verifier outcome. Helpers
 * with setup, assertions, branches or computed Boolean returns are excluded.
 * Resolution/depth work belongs to the caller's existing source allowance. */
export function returnedSchnorrVerifier(program: Program, expression: import("../model.js").Expr,
  charge: (depth: number) => boolean, depth = 0, seen = new Set<string>()): { target: string; forwarders: string[] } | undefined {
  if (!charge(depth)) return;
  if (expression.kind === "disclose" || expression.kind === "cast" && expression.castKind === "identity")
    return expression.args[0] && returnedSchnorrVerifier(program, expression.args[0], charge, depth + 1, seen);
  if (expression.kind !== "call" || !expression.symbol) return;
  if (schnorrVerifier(expression.symbol)) return { target: expression.symbol, forwarders: [] };
  if (seen.has(expression.symbol)) return;
  const fn = program.functions.get(expression.symbol), body = fn?.declaration.body;
  const returned = body?.kind === "block" && body.body.length === 1 ? body.body[0] : body;
  if (returned?.kind !== "return") return;
  const next = new Set(seen); next.add(expression.symbol);
  const result = returnedSchnorrVerifier(program, returned.expr, charge, depth + 1, next);
  return result && { ...result, forwarders: [expression.symbol, ...result.forwarders] };
}

export const SIGNATURE_IDENTITY_REVIEW = "signature-key-identity-exclusion-review";
export type SignatureCurve = "JubjubPoint" | "Secp256k1Point";
export type SignatureCharge = (work?: number, values?: number) => boolean;

export function signatureVerifierCurve(id: string): SignatureCurve | undefined {
  return schnorrVerifier(id) ? "JubjubPoint" : id === ECDSA_VERIFIER ? "Secp256k1Point" : undefined;
}

/** Native identity, including canonical nominal aliases. Intrinsic results use
 * normalized native names; user declarations retain their owned identities. */
export function signaturePointCurve(program: Program, type: string): SignatureCurve | undefined {
  const native = program.nativeTypeOf(type);
  return native === "JubjubPoint" || native === "Secp256k1Point" ? native
    : type === "JubjubPoint" || type === "Secp256k1Point" ? type : undefined;
}

/** Preparation is charged before every retained traversal row. Inspect callbacks
 * even when their sequence is empty: unsupported composition is not absence. */
export function signatureIdentityScope(program: Program, entry: string, charge: SignatureCharge): boolean {
  charge(0, 3);
  const pending = [entry], seen = new Set<string>();
  let applicable = false;
  while (pending.length) {
    charge(); const id = pending.pop()!;
    if (seen.has(id)) continue;
    charge(0, 1); seen.add(id);
    applicable ||= !!signatureVerifierCurve(id);
    const fn = program.functions.get(id);
    if (!fn) {
      const symbol = program.symbols.get(id);
      if (!symbol || symbol.kind !== "intrinsic" && symbol.kind !== "witness") throw new Error("Signature review callable closure is unresolved");
      continue;
    }
    for (const node of fn.cfg.nodes) {
      charge(1, 1); const expressions = node.expr ? [node.expr] : [];
      while (expressions.length) {
        charge(); const expr = expressions.pop()!;
        if (expr.contractCall || expr.kind === "call" && (!expr.symbol || !program.symbols.has(expr.symbol)))
          throw new Error("Signature review external composition or call identity is unavailable");
        if (expr.kind === "member" && expr.name === "checkpoint" && expr.ledgerRoot === "standard-library::kernel")
          throw new Error("Signature review checkpoint histories are unavailable");
        if (expr.kind === "lambda" && expr.symbol) { charge(0, 1); pending.push(expr.symbol); }
        for (const child of expr.args) { charge(1, 1); expressions.push(child); }
      }
    }
    for (const callee of fn.calls) { charge(1, 1); pending.push(callee); }
  }
  return applicable;
}
