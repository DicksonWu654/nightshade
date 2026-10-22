export interface TypeTerm {
  name: string;
  args: TypeTerm[];
}

export const FIELD_MODULUS = 52435875175126190479447740508185965837690552500527637822603658699938581184513n;
export const UINT_BITS = 248;
export const UINT_BOUND = 1n << BigInt(UINT_BITS);
export const MAX_SEQUENCE_LENGTH = 1n << 24n;
export const EMPTY_ELEMENT_TYPE = "$empty-sequence-element";
export const TUPLE_TYPE = "$tuple";

export function naturalValue(text: string): bigint | undefined {
  return /^(?:\d+|0[xX][\da-fA-F]+|0[oO][0-7]+|0[bB][01]+)$/.test(text) ? BigInt(text) : undefined;
}

export function splitTypeList(text: string): string[] {
  const result: string[] = [];
  let depth = 0;
  let quoted = false;
  let escaped = false;
  let start = 0;
  for (let index = 0; index < text.length; index++) {
    const character = text[index];
    if (escaped) { escaped = false; continue; }
    if (character === "\\" && quoted) { escaped = true; continue; }
    if (character === '"') quoted = !quoted;
    if (quoted) continue;
    if ("<[({".includes(character)) depth++;
    else if (">])}".includes(character)) depth--;
    else if (character === "," && depth === 0) { result.push(text.slice(start, index).trim()); start = index + 1; }
  }
  const last = text.slice(start).trim();
  if (last) result.push(last);
  return result;
}

export function parseType(text: string): TypeTerm {
  const value = text.trim();
  if (value.startsWith("[") && value.endsWith("]")) return { name: TUPLE_TYPE, args: splitTypeList(value.slice(1, -1)).map(parseType) };
  const opening = value.indexOf("<");
  if (opening >= 0 && value.endsWith(">")) return { name: value.slice(0, opening).trim(), args: splitTypeList(value.slice(opening + 1, -1)).map(parseType) };
  const range = /^([^.]*)\.\.([^.]*)$/.exec(value)?.map(part => part.trim());
  const name = range ? `${naturalValue(range[1]) ?? range[1]}..${naturalValue(range[2]) ?? range[2]}` : naturalValue(value)?.toString() ?? value;
  return { name, args: [] };
}

export function printType(type: TypeTerm): string {
  if (type.name === TUPLE_TYPE) return `[${type.args.map(printType).join(",")}]`;
  return type.name + (type.args.length ? `<${type.args.map(printType).join(",")}>` : "");
}

export function typeArguments(text?: string): string[] {
  return text ? splitTypeList(text.trim().slice(1, -1)) : [];
}

export function substituteType(text: string, bindings: Map<string, string>): string {
  const term = parseType(text);
  if (!term.args.length && bindings.has(term.name)) return bindings.get(term.name)!;
  const range = /^([^.]*)\.\.([^.]*)$/.exec(term.name);
  if (range) term.name = `${bindings.get(range[1]) ?? range[1]}..${bindings.get(range[2]) ?? range[2]}`;
  term.args = term.args.map(arg => parseType(substituteType(printType(arg), bindings)));
  return printType(term);
}

export function numericBound(type: string): bigint | undefined {
  // Analysis repeatedly queries canonical scalar types. Avoid rebuilding the
  // generic type tree for this common spelling; other forms use the parser.
  const scalar = /^Uint<(0\.\.)?(\d+)>$/.exec(type);
  if (scalar) return scalar[1] ? BigInt(scalar[2]) : Number(scalar[2]) <= UINT_BITS ? 1n << BigInt(scalar[2]) : undefined;
  const term = parseType(type);
  if (term.name !== "Uint") return undefined;
  const size = term.args[0]?.name ?? "";
  const range = /^0\.\.(\d+)$/.exec(size);
  if (range) return BigInt(range[1]);
  if (/^\d+$/.test(size) && Number(size) <= UINT_BITS) return 1n << BigInt(size);
  return undefined;
}

export function numericTypeError(term: TypeTerm): string | undefined {
  if (!["Uint", "Bytes", "Vector", TUPLE_TYPE].includes(term.name)) return undefined;
  if (term.name === TUPLE_TYPE) return BigInt(term.args.length) > MAX_SEQUENCE_LENGTH ? "Tuple exceeds the compiler sequence-length limit" : undefined;
  const arity = term.name === "Vector" ? 2 : 1;
  if (term.args.length !== arity) return `${term.name} requires ${arity} type/size arguments`;
  const size = term.args[0];
  const range = term.name === "Uint" ? /^0\.\.(\d+)$/.exec(size.name) : undefined;
  if (!size.args.length && range) return BigInt(range[1]) >= 1n && BigInt(range[1]) <= UINT_BOUND ? undefined : `Uint range end must be between 1 and 2^${UINT_BITS}`;
  const value = naturalValue(size.name);
  if (size.args.length || value === undefined) return `${term.name} requires a resolved natural size${term.name === "Uint" ? " or a range beginning at zero" : ""}`;
  if (term.name === "Uint" && value > BigInt(UINT_BITS)) return `Uint width exceeds the compiler maximum of ${UINT_BITS} bits`;
  if (term.name !== "Uint" && value > MAX_SEQUENCE_LENGTH) return `${term.name} length exceeds the compiler maximum of ${MAX_SEQUENCE_LENGTH}`;
  return undefined;
}

export function arithmeticType(operator: string, left: string, right: string): string {
  if (left === "Field" || right === "Field") return "Field";
  const first = numericBound(left);
  const second = numericBound(right);
  if (first === undefined || second === undefined) return "unknown";
  return `Uint<0..${operator === "+" ? first + second - 1n : operator === "*" ? (first - 1n) * (second - 1n) + 1n : first}>`;
}

export function sequenceLength(type: string): number | undefined {
  const term = parseType(type);
  if (term.name === TUPLE_TYPE) return term.args.length;
  if (["Vector", "Bytes"].includes(term.name) && /^\d+$/.test(term.args[0]?.name ?? "")) return Number(term.args[0].name);
  return undefined;
}

export function elementType(type: string, index = 0): string {
  const term = parseType(type);
  if (term.name === "Bytes") return "Uint<8>";
  if (term.name === "Vector") return term.args[1] ? printType(term.args[1]) : "unknown";
  if (term.name === TUPLE_TYPE) return term.args[index] ? printType(term.args[index]) : "unknown";
  return "unknown";
}

export function compatible(actual: string, expected: string): boolean {
  if (actual === "unknown" || expected === "unknown") return true;
  const left = parseType(actual);
  const right = parseType(expected);
  if (printType(left) === printType(right)) return true;
  if (right.name === "Vector" && left.name === TUPLE_TYPE) return sequenceLength(expected) === left.args.length && left.args.every(item => compatible(printType(item), printType(right.args[1])));
  if (left.name === "Uint" && right.name === "Uint") {
    const first = numericBound(actual);
    const second = numericBound(expected);
    if (first !== undefined && second !== undefined) return first <= second;
  }
  if (left.name === TUPLE_TYPE && right.name === TUPLE_TYPE) return left.args.length === right.args.length && left.args.every((item, index) => compatible(printType(item), printType(right.args[index])));
  return false;
}
