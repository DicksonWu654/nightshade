import { fail, type Span } from "../model.js";
import type { Program, SymbolInfo } from "./index.js";
import { parseType, printType } from "./types.js";
import { SHIELDED_MINT } from "./mint-targets.js";

export const SOURCE_CLAIM_RULE = "source-claim-shielded-issuance-review";
export interface SourceClaimPolicy { kind: "non-transferable-shielded-issuance"; circuit: string; quote: string }
export interface ResolvedSourceClaim extends SourceClaimPolicy { source: Span }
export type SourceClaimCharge = (work?: number, values?: number) => boolean;

/** The policy supplies meaning. Neither comment text nor identifier spelling is interpreted. */
export function validateSourceClaims(value: unknown, location: Span, code: string): SourceClaimPolicy[] {
  const invalid = (): never => fail(code, "sourceClaims requires a dense array of at most 64 exact kind/circuit/quote records; selectors are limited to 1024 UTF-8 bytes and quotes to 2048", location);
  if (!Array.isArray(value) || value.length > 64 || Reflect.ownKeys(value).length !== value.length + 1) return invalid();
  const result: SourceClaimPolicy[] = [];
  for (let index = 0; index < value.length; index++) {
    const slot = Object.getOwnPropertyDescriptor(value, index);
    if (!slot || !("value" in slot) || !slot.enumerable) return invalid();
    const item = slot.value;
    if (!item || typeof item !== "object" || Array.isArray(item) || Reflect.ownKeys(item).length !== 3) return invalid();
    const fields: string[] = [];
    for (const name of ["kind", "circuit", "quote"]) {
      const property = Object.getOwnPropertyDescriptor(item, name);
      if (!property || !("value" in property) || !property.enumerable || typeof property.value !== "string" || !property.value.length) return invalid();
      fields.push(property.value);
    }
    if (fields[0] !== "non-transferable-shielded-issuance" || fields[1].length > 1024 || fields[2].length > 2048
      || Buffer.byteLength(fields[1], "utf8") > 1024 || Buffer.byteLength(fields[2], "utf8") > 2048) return invalid();
    result.push({ kind: "non-transferable-shielded-issuance", circuit: fields[1], quote: fields[2] });
  }
  return result;
}

/** Selection and comment inspection share the rule allowance. UTF-8 offsets remain
 * parser-owned; a cursor over the original string inspects the intervening bytes. */
export function prepareSourceClaims(program: Program, policies: readonly SourceClaimPolicy[], charge: SourceClaimCharge): Map<string, ResolvedSourceClaim[]> {
  charge(0, 2); const selected = new Map<string, ResolvedSourceClaim[]>(), identities = new Set<string>();
  for (const policy of policies) {
    const selectorLength = program.meteringSelector(policy.circuit).length;
    charge(1 + selectorLength + policy.quote.length, 4 + Math.ceil((selectorLength + policy.quote.length) / 32));
    let target: SymbolInfo | undefined;
    for (const symbol of program.symbols.values()) {
      charge(1 + Math.ceil((program.meteringIdentity(symbol.id).length + symbol.name.length) / 64));
      if (symbol.kind !== "circuit" || !program.isActiveSymbol(symbol) || symbol.id !== policy.circuit && symbol.name !== policy.circuit) continue;
      if (target) fail("invalid-policy", "Source claim selector is ambiguous; use a canonical exported circuit ID", symbol.span);
      target = symbol;
    }
    if (!target || !program.entries.includes(target.id)) fail("invalid-policy", "Source claim selector requires a unique canonical exported circuit", target?.span ?? program.rootSource.ast.span);
    charge(1 + program.meteringIdentity(target.id).length, 2 + Math.ceil(program.meteringIdentity(target.id).length / 32)); const identity = target.id + ":" + policy.kind;
    if (identities.has(identity)) fail("invalid-policy", "Duplicate resolved source claim for one entry and kind", target.span);
    identities.add(identity);
    const source = program.files.get(target.span.file);
    if (!source || !source.comments) throw new Error("Parser-owned source comments are unavailable");
    let preceding: { text: string; span: Span } | undefined;
    for (const comment of source.comments) {
      charge(1);
      if (comment.span.end > target.span.start) break;
      preceding = comment;
    }
    if (!preceding) continue;
    charge(1 + preceding.text.length);
    if (preceding.text !== policy.quote) continue;
    let bytes = 0, whitespace = true;
    for (let position = 0; position < source.text.length && bytes < target.span.start;) {
      charge(1); const point = source.text.codePointAt(position)!;
      const width = point > 0xffff ? 2 : 1, byteWidth = point <= 0x7f ? 1 : point <= 0x7ff ? 2 : point <= 0xffff ? 3 : 4;
      if (bytes >= preceding.span.end && point !== 0x85 && !/\s/u.test(String.fromCodePoint(point))) whitespace = false;
      bytes += byteWidth; position += width;
    }
    if (bytes !== target.span.start) throw new Error("Original UTF-8 declaration boundary is unavailable");
    if (!whitespace) continue;
    charge(1, 4); selected.set(target.id, [{ ...policy, circuit: target.id, source: preceding.span }]);
  }
  return selected;
}

/** Conservative closure admission never treats unresolved effects as absence. */
export function sourceClaimScope(program: Program, entry: string, charge: SourceClaimCharge): boolean {
  charge(0, 3); const seen = new Set<string>(), pending = [entry]; let present = false;
  while (pending.length) {
    charge(); const id = pending.pop()!;
    if (seen.has(id)) continue;
    charge(0, 1); seen.add(id);
    present ||= id === SHIELDED_MINT;
    const fn = program.functions.get(id);
    if (!fn) {
      const symbol = program.symbols.get(id);
      if (!symbol || symbol.kind !== "intrinsic" && symbol.kind !== "witness") throw new Error("Source claim callable closure is unresolved");
      continue;
    }
    for (const node of fn.cfg.nodes) {
      charge(1, 1); const expressions = node.expr ? [node.expr] : [];
      for (const edge of node.edges) charge();
      while (expressions.length) {
        charge(); const expr = expressions.pop()!;
        if (expr.contractCall || expr.kind === "call" && (!expr.symbol || !program.symbols.has(expr.symbol))) throw new Error("Source claim call identity is unavailable");
        if (expr.kind === "member" && expr.name === "checkpoint" && expr.ledgerRoot === "standard-library::kernel") throw new Error("Source claim checkpoint histories are unavailable");
        if (expr.kind === "lambda" && expr.symbol) { charge(0, 1); pending.push(expr.symbol); }
        for (const arg of expr.args) { charge(1, 1); expressions.push(arg); }
      }
    }
    for (const callee of fn.calls) { charge(1, 1); pending.push(callee); }
  }
  return present;
}

/** Account for nominal identity chains and represented type parsing before use. */
export function sourceClaimRecipientType(program: Program, type: string, charge: SourceClaimCharge): boolean {
  const account = (text: string): void => {
    let current = text, depth = 0;
    for (;;) {
      charge(4 + program.meteringIdentity(current).length * 4, 2 + Math.ceil(program.meteringIdentity(current).length / 8));
      if (++depth > 64) throw new Error("Source claim native identity depth is unavailable");
      const nominal = program.nominalTypes.get(current);
      if (!nominal) break;
      current = nominal.underlying;
    }
  };
  account(type);
  const representation = program.representationOf(type);
  charge(4 + program.meteringIdentity(representation).length * 4, 2 + Math.ceil(program.meteringIdentity(representation).length / 8));
  const term = parseType(representation);
  if (program.nativeTypeOf(type) !== "Either" || term.args.length !== 2) return false;
  charge(0, 2); const left = printType(term.args[0]), right = printType(term.args[1]);
  account(left); account(right);
  return program.nativeTypeOf(left) === "ZswapCoinPublicKey" && program.nativeTypeOf(right) === "ContractAddress";
}
