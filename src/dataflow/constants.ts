import { Expr } from "../model.js";
import { FIELD_MODULUS, UINT_BITS, naturalValue, numericBound, parseType } from "../semantic/types.js";
import { fieldModulus, foreignField, JUBJUB_SCALAR_MODULUS } from "../semantic/fields.js";
export { FIELD_MODULUS } from "../semantic/types.js";
export const MAX_LITERAL_BYTES = 1048576;

export interface Constant {
  kind: "boolean" | "integer" | "bytes" | "enum" | "point";
  value: string;
}

export function literalConstant(expr: Expr): Constant | undefined {
  const text = expr.value ?? "";
  if (["true", "false"].includes(text)) return { kind: "boolean", value: text };
  const natural = naturalValue(text);
  if (natural !== undefined) return { kind: "integer", value: natural.toString() };
  if (expr.name === "str") return Buffer.byteLength(expr.literalString!) <= MAX_LITERAL_BYTES ? { kind: "bytes", value: Buffer.from(expr.literalString!, "utf8").toString("hex") } : undefined;
  if (expr.name === "pad") {
    const size = naturalValue(expr.paddingSize ?? "");
    if (size === undefined || size > BigInt(MAX_LITERAL_BYTES)) return undefined;
    const bytes = Buffer.from(expr.literalString!, "utf8");
    if (bytes.length > Number(size)) return undefined;
    const padded = Buffer.alloc(Number(size));
    bytes.copy(padded);
    return { kind: "bytes", value: padded.toString("hex") };
  }
  return undefined;
}

export function binaryConstant(operator: string, left: Constant | undefined, right: Constant | undefined, type: string): Constant | undefined | null {
  if (!left || !right || left.kind !== right.kind) return undefined;
  if (["==", "!="].includes(operator)) return { kind: "boolean", value: String(operator === "==" ? left.value === right.value : left.value !== right.value) };
  if (left.kind !== "integer") return undefined;
  const first = BigInt(left.value);
  const second = BigInt(right.value);
  if (operator === "<") return { kind: "boolean", value: String(first < second) };
  if (operator === "<=") return { kind: "boolean", value: String(first <= second) };
  if (operator === ">") return { kind: "boolean", value: String(first > second) };
  if (operator === ">=") return { kind: "boolean", value: String(first >= second) };
  let value: bigint;
  if (operator === "+") value = first + second;
  else if (operator === "-") value = first - second;
  else if (operator === "*") value = first * second;
  else return undefined;
  const modulus = fieldModulus(type);
  if (modulus) value = ((value % modulus) + modulus) % modulus;
  else if (value < 0n) return null;
  return { kind: "integer", value: value.toString() };
}

export function castConstant(constant: Constant | undefined, target: string): Constant | undefined | null {
  if (!constant) return undefined;
  const type = parseType(target);
  if (["integer", "boolean"].includes(constant.kind) && (foreignField(target) || target === "JubjubScalar")) {
    const value = constant.kind === "boolean" ? (constant.value === "true" ? 1n : 0n) : BigInt(constant.value);
    const modulus = target === "JubjubScalar" ? JUBJUB_SCALAR_MODULUS : fieldModulus(target)!;
    return { kind: "integer", value: String((value % modulus + modulus) % modulus) };
  }
  if (constant.kind === "bytes" && foreignField(target) && constant.value.length === 64) {
    const value = BigInt("0x" + constant.value.match(/../g)!.reverse().join(""));
    return { kind: "integer", value: String(value % fieldModulus(target)!) };
  }
  if (constant.kind === "bytes" && ["Field", "Uint"].includes(type.name)) {
    const bound = type.name === "Field" ? FIELD_MODULUS : numericBound(target);
    if (bound === undefined || constant.value.length === 0) return undefined;
    let value = 0n;
    for (let offset = constant.value.length - 2; offset >= 0; offset -= 2) {
      value = value * 256n + BigInt(parseInt(constant.value.slice(offset, offset + 2), 16));
      if (value >= bound) return null;
    }
    return { kind: "integer", value: value.toString() };
  }
  if (constant.kind === "integer" && type.name === "Bytes") {
    const length = Number(type.args[0]?.name);
    if (!Number.isSafeInteger(length) || length <= 0 || length > 1048576) return undefined;
    const value = BigInt(constant.value);
    if (value < 0n) return null;
    const hex = value.toString(16);
    if (hex.length > 2 * length) return null;
    return { kind: "bytes", value: hex.padStart(2 * length, "0").match(/../g)!.reverse().join("") };
  }
  if (constant.kind === "integer" && ["Field", "Uint"].includes(type.name)) {
    const value = BigInt(constant.value);
    if (value < 0n) return null;
    if (type.name === "Field") return value >= FIELD_MODULUS || value < 0n ? null : constant;
    const size = type.args[0]?.name ?? "";
    const range = /^0\.\.(\d+)$/.exec(size);
    if (range) return value < BigInt(range[1]) ? constant : null;
    if (/^\d+$/.test(size) && Number(size) <= UINT_BITS) return value < (1n << BigInt(size)) ? constant : null;
  }
  if (type.name === "Boolean" && constant.kind === "integer") return { kind: "boolean", value: String(BigInt(constant.value) !== 0n) };
  if (constant.kind === "boolean" && ["Field", "Uint"].includes(type.name)) return castConstant({ kind: "integer", value: constant.value === "true" ? "1" : "0" }, target);
  if (type.name === "Boolean" && constant.kind === "boolean") return constant;
  if (type.name === "Bytes" && constant.kind === "bytes" && Number(type.args[0]?.name) === constant.value.length / 2) return constant;
  return undefined;
}
