import { Expr, Span, fail } from "../model.js";
import { MAX_SEQUENCE_LENGTH, TUPLE_TYPE, elementType, naturalValue, numericBound, parseType, printType, sequenceLength } from "./types.js";

interface SequenceTypes {
  representationOf(type: string): string;
  commonType(types: string[]): string | undefined;
  requireOrdinary(type: string, location: Span): void;
}

function shape(type: string, location: Span, types: SequenceTypes): { type: string; length: number; name: string } {
  const representation = types.representationOf(type);
  const length = sequenceLength(representation);
  if (length === undefined) fail("sequence-type-mismatch", "Operation requires a tuple, Vector or Bytes value", location);
  return { type: representation, length, name: parseType(representation).name };
}

export function sequenceElementAt(type: string, index: number, location: Span, types: SequenceTypes): string {
  const sequence = shape(type, location, types);
  if (index < 0 || index >= sequence.length) fail("sequence-index-range", "Sequence index is outside the declared length", location);
  return elementType(sequence.type, index);
}

export function literalIndex(expression: Expr, depth = 0): bigint | undefined {
  if (depth > 64) return undefined;
  if (expression.kind === "literal") return naturalValue(expression.value ?? "");
  return expression.kind === "cast" && expression.castKind === "identity" ? literalIndex(expression.args[0], depth + 1) : undefined;
}

export function projectionType(expression: Expr, types: SequenceTypes): string {
  const sequence = shape(expression.args[0].inferredType ?? "unknown", expression.span, types);
  const index = expression.args[1];
  if (numericBound(types.representationOf(index.inferredType ?? "unknown")) === undefined) fail("sequence-index-type", "Sequence indices require an unsigned representation", index.span);
  const constant = literalIndex(index);
  const size = expression.kind === "slice" ? naturalValue(expression.value ?? "") : 1n;
  if (size === undefined || size > MAX_SEQUENCE_LENGTH) fail("sequence-slice-size", "Slice length requires a resolved natural within the compiler sequence limit", expression.span);
  if (constant !== undefined && constant >= MAX_SEQUENCE_LENGTH) fail("sequence-index-range", "Literal index exceeds the compiler maximum index", index.span);
  if (size > BigInt(sequence.length) || constant !== undefined && constant + size > BigInt(sequence.length)) fail("sequence-index-range", "Projection exceeds the declared sequence length", expression.span);
  if (constant !== undefined) {
    if (expression.kind === "index") return elementType(sequence.type, Number(constant));
    if (sequence.name === TUPLE_TYPE) return `[${parseType(sequence.type).args.slice(Number(constant), Number(constant + size)).map(printType).join(",")}]`;
  }
  if (sequence.name === "Bytes") return expression.kind === "index" ? "Uint<8>" : `Bytes<${size}>`;
  const element = sequence.name === TUPLE_TYPE ? types.commonType(parseType(sequence.type).args.map(printType)) : elementType(sequence.type);
  if (!element) fail("incompatible-sequence-elements", "A non-literal index requires comparable sequence element types", expression.span);
  return expression.kind === "index" ? element : `Vector<${size},${element}>`;
}

export function constructionType(expression: Expr, types: SequenceTypes): string {
  const elements: string[] = [];
  let length = 0;
  let vector = false;
  for (const argument of expression.args) {
    const type = argument.inferredType ?? "unknown";
    if (argument.kind !== "spread") {
      types.requireOrdinary(type, argument.span);
      elements.push(type);
      length++;
    } else {
      const sequence = shape(type, argument.span, types);
      length += sequence.length;
      if (sequence.name === TUPLE_TYPE) elements.push(...parseType(sequence.type).args.map(printType));
      else {
        vector = true;
        elements.push(elementType(sequence.type));
      }
    }
  }
  if (BigInt(length) > MAX_SEQUENCE_LENGTH) fail("numeric-type-range", "Sequence construction exceeds the compiler sequence-length limit", expression.span);
  if (!vector) return `[${elements.join(",")}]`;
  const element = types.commonType(elements);
  if (!element) fail("incompatible-sequence-elements", "Vector/Bytes spreads require comparable construction element types", expression.span);
  return `Vector<${length},${element}>`;
}
