import { fail, type Span } from "../model.js";
import type { Program, SymbolInfo } from "./index.js";
import { parseType, printType } from "./types.js";

export const SOURCE_MAP_GETTER_RULE = "source-claim-map-getter-review";
export interface SourceMapGetterPolicy { setter: string; getter: string; map: string; setterKey: string; setterValue: string; getterKey: string; quote: string }
export interface ResolvedSourceMapGetter extends SourceMapGetterPolicy { source: Span; setterKeyIndex: number; setterValueIndex: number }
export type MapGetterCharge = (work?: number, values?: number) => boolean;
const fields = ["setter", "getter", "map", "setterKey", "setterValue", "getterKey", "quote"] as const;
export function validateSourceMapGetters(value: unknown, location: Span, code: string): SourceMapGetterPolicy[] {
  const invalid = (): never => fail(code, "sourceMapGetters requires a dense array of at most 64 exact setter/getter/map/setterKey/setterValue/getterKey/quote records; selectors are bounded to1024 UTF-8 bytes and quotes to2048", location);
  if (!Array.isArray(value) || value.length > 64 || Reflect.ownKeys(value).length !== value.length + 1) return invalid();
  const result: SourceMapGetterPolicy[] = [];
  for (let index = 0; index < value.length; index++) {
    const slot = Object.getOwnPropertyDescriptor(value, index);
    if (!slot || !("value" in slot) || !slot.enumerable) return invalid();
    const item = slot.value;
    if (!item || typeof item !== "object" || Array.isArray(item) || Reflect.ownKeys(item).length !== fields.length) return invalid();
    const selected = {} as SourceMapGetterPolicy;
    for (const field of fields) {
      const prop = Object.getOwnPropertyDescriptor(item, field), limit = field === "quote" ? 2048 : 1024;
      if (!prop || !("value" in prop) || !prop.enumerable || typeof prop.value !== "string" || !prop.value.length
        || prop.value.length > limit || Buffer.byteLength(prop.value, "utf8") > limit) return invalid();
      selected[field] = prop.value;
    }
    if (result.some(prior => fields.every(field => prior[field] === selected[field]))) return invalid();
    result.push(selected);
  }
  return result;
}

/** Activation examines owned comments before resolving removable configuration
 * symbols. Policy supplies all meaning; no prose or spelling is interpreted. */
export function prepareSourceMapGetters(program: Program, policies: readonly SourceMapGetterPolicy[], charge: MapGetterCharge): ResolvedSourceMapGetter[] {
  const account = (text: string) => {
    let current = text, depth = 0;
    for (;;) {
      charge(4 + current.length * 4, 2 + Math.ceil(current.length / 8));
      if (++depth > 64) throw new Error("Source Map canonical type identity depth is unavailable");
      const nominal = program.nominalTypes.get(current); if (!nominal) break;
      current = nominal.underlying;
    }
  };
  charge(0, 2); const result: ResolvedSourceMapGetter[] = [], seen = new Set<string>();
  const select = (selector: string, kind: SymbolInfo["kind"]): SymbolInfo => {
    let selected: SymbolInfo | undefined;
    for (const symbol of program.symbols.values()) {
      charge(1 + Math.ceil((symbol.id.length + symbol.name.length) / 64));
      if (symbol.kind !== kind || !program.isActiveSymbol(symbol) || symbol.id !== selector && symbol.name !== selector) continue;
      if (selected) fail("invalid-policy", "Source Map getter selector is ambiguous; use a canonical symbol ID", symbol.span);
      selected = symbol;
    }
    if (!selected) fail("invalid-policy", "Active source Map getter claim has an unresolved selector", program.rootSource.ast.span);
    return selected;
  };
  for (const policy of policies) {
    let quoted = false;
    charge(1 + fields.reduce((sum, field) => sum + policy[field].length, 0), 8);
    for (const source of program.files.values()) {
      if (!source.comments) throw new Error("Parser-owned source comments are unavailable");
      for (const comment of source.comments) { charge(1 + comment.text.length); quoted ||= comment.text === policy.quote; }
    }
    if (!quoted) continue;
    const setter = select(policy.setter, "circuit");
    if (!program.entries.includes(setter.id)) fail("invalid-policy", "Source Map setter must be an exported circuit", setter.span);
    const file = program.files.get(setter.span.file)!; let preceding: { text: string; span: Span } | undefined;
    for (const comment of file.comments!) { charge(); if (comment.span.end > setter.span.start) break; preceding = comment; }
    if (!preceding || preceding.text !== policy.quote) continue;
    let bytes = 0, whitespace = true;
    for (let position = 0; position < file.text.length && bytes < setter.span.start;) {
      charge(); const point = file.text.codePointAt(position)!, width = point > 0xffff ? 2 : 1;
      if (bytes >= preceding.span.end && point !== 0x85 && !/\s/u.test(String.fromCodePoint(point))) whitespace = false;
      bytes += point <= 0x7f ? 1 : point <= 0x7ff ? 2 : point <= 0xffff ? 3 : 4; position += width;
    }
    if (bytes !== setter.span.start) throw new Error("Original UTF-8 setter boundary is unavailable");
    if (!whitespace) continue;
    const getter = select(policy.getter, "circuit"), map = select(policy.map, "ledger");
    if (!program.entries.includes(getter.id) || setter.id === getter.id) fail("invalid-policy", "Source Map claim requires distinct exported setter/getter circuits", getter.span);
    account(map.type);
    const shape = parseType(program.representationOf(map.type));
    if (program.nativeTypeOf(map.type) !== "Map" || shape.args.length !== 2) fail("invalid-policy", "Source Map getter requires a canonical root native Map", map.span);
    const parameter = (fn: SymbolInfo, name: string) => {
      let selected: { symbol: string; type: string; index: number } | undefined;
      for (const [index, param] of program.functions.get(fn.id)!.declaration.parameters.entries()) {
        charge(); if (param.name !== name && param.symbol !== name) continue;
        if (selected || !param.symbol || param.pattern && param.pattern.kind !== "name") fail("invalid-policy", "Source Map selector requires an ordinary original parameter", param.span);
        selected = { symbol: param.symbol, type: param.type, index };
      }
      if (!selected) fail("invalid-policy", "Source Map parameter selector is unresolved", fn.span);
      return selected;
    };
    const key = parameter(setter, policy.setterKey), value = parameter(setter, policy.setterValue), getKey = parameter(getter, policy.getterKey);
    const keyType = printType(shape.args[0]), valueType = printType(shape.args[1]);
    for (const text of [key.type,value.type,getKey.type,getter.type,keyType,valueType]) account(text);
    // Exact canonical types retain nominal identity; arithmetic coercion is not compatibility.
    if (key.type !== keyType || getKey.type !== keyType || value.type !== valueType || getter.type !== valueType || key.symbol === value.symbol)
      fail("invalid-policy", "Source Map key/value/getter parameter and result types must agree exactly", map.span);
    charge(4, 8); const identity = JSON.stringify([setter.id,getter.id,map.id,key.symbol,value.symbol,getKey.symbol]);
    if (seen.has(identity)) fail("invalid-policy", "Duplicate canonical source Map getter contract", getter.span);
    seen.add(identity); result.push({ ...policy, setter: setter.id, getter: getter.id, map: map.id, setterKey: key.symbol, setterValue: value.symbol, getterKey: getKey.symbol,
      setterKeyIndex: key.index, setterValueIndex: value.index, source: preceding.span });
  }
  return result;
}

/** Syntax-wide closure includes nonexecuting callbacks. A read is refusal of this
 * precise observation; unresolved effects/checkpoints are never absence. */
export function mapGetterClosure(program: Program, entry: string, map: string, charge: MapGetterCharge): boolean {
  charge(0, 3); const pending = [entry], seen = new Set<string>(); let reads = false;
  while (pending.length) {
    charge(); const id = pending.pop()!;
    if (seen.has(id)) continue;
    charge(0, 1); seen.add(id);
    const fn = program.functions.get(id), symbol = program.symbols.get(id);
    if (!fn) { if (!symbol || symbol.kind !== "intrinsic" && symbol.kind !== "witness") throw new Error("Source Map callable closure is unresolved"); continue; }
    charge(); reads ||= fn.readsState.has(map);
    for (const node of fn.cfg.nodes) {
      charge(); if (!node.expr) continue;
      charge(0, 1); const expressions = [node.expr];
      while (expressions.length) {
        charge(); const expr = expressions.pop()!;
        if (expr.contractCall || expr.kind === "call" && (!expr.symbol || !program.symbols.has(expr.symbol))) throw new Error("Source Map callable identity is unavailable");
        if (expr.kind === "member" && expr.name === "checkpoint" && program.nativeTypeOf(expr.args[0]?.inferredType ?? "") === "Kernel") throw new Error("Source Map checkpoint history is unavailable");
        for (const arg of expr.args) { charge(1, 1); expressions.push(arg); }
        if (expr.kind === "lambda" && expr.symbol) { charge(0, 1); pending.push(expr.symbol); }
      }
    }
    for (const callee of fn.calls) { charge(1, 1); pending.push(callee); }
  }
  return reads;
}
