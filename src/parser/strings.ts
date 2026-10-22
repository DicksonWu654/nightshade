import { Span, fail } from "../model.js";

export function decodeString(text: string, location: Span): string {
  const quote = text[0];
  if (!["'", '"'].includes(quote) || text.length < 2 || text.at(-1) !== quote) fail("invalid-string", "String literal is not terminated", location);
  const simple: Record<string, string> = { "'": "'", '"': '"', "\\": "\\", n: "\n", r: "\r", "0": "\0", b: "\b", f: "\f", t: "\t", v: "\v", "\n": "" };
  const parts: string[] = [];
  let start = 1;
  let index = 1;
  while (index < text.length - 1) {
    const point = text.codePointAt(index)!;
    if (point >= 0xd800 && point <= 0xdfff) fail("invalid-string", "String contains a non-scalar Unicode value", location);
    const character = String.fromCodePoint(point);
    if (character === quote) fail("invalid-string", "Unescaped string terminator", location);
    if (character !== "\\") { index += character.length; continue; }
    parts.push(text.slice(start, index));
    const escape = text[++index];
    if (index >= text.length - 1) fail("invalid-string", "Incomplete string escape", location);
    if (Object.hasOwn(simple, escape)) {
      parts.push(simple[escape]);
      index++;
    } else if (escape === "x" || escape === "u") {
      const length = escape === "x" ? 2 : 4;
      const digits = text.slice(index + 1, index + 1 + length);
      if (digits.length !== length || !/^[0-9a-fA-F]+$/.test(digits)) fail("invalid-string", `String escape requires exactly ${length} hexadecimal digits`, location);
      const value = Number.parseInt(digits, 16);
      if (value >= 0xd800 && value <= 0xdfff) fail("invalid-string", "Unicode escapes must denote scalar values, not UTF-16 surrogates", location);
      parts.push(String.fromCodePoint(value));
      index += length + 1;
    } else fail("invalid-string", `Unsupported Compact string escape ${JSON.stringify(escape)}`, location);
    start = index;
  }
  parts.push(text.slice(start, -1));
  return parts.join("");
}
