import assert from "node:assert/strict";
import test from "node:test";
import { IdentityAccounting } from "../src/semantic/identity-accounting.js";

// Grammar inventory comes from Program.makeScope/link/spanIdentity/meteringJoin
// (semantic/index.ts), canonicalType/canonicalArgument in the same file, and
// parseType/printType (semantic/types.ts). JSON address/key and relation wrappers
// are built by immutableCollectionAddress (dataflow/immutable-key.ts), the kernel
// query transfers in dataflow/index.ts, and equality/ordering in
// dataflow/transfers.ts (assumeScalar/binaryValue). Quoted payloads
// are source data; their text must never acquire identity-token semantics.
test("canonical type and identity grammar charges every non-path character exactly once", () => {
  interface Shape { name: string; raw: string; expected: string; count: number; pathLength: number }
  const run = (root: string) => {
    const accounting = new IdentityAccounting();
    const file = `${root}/main.compact`, other = `${root}/other.compact`;
    const token = accounting.path(file), otherToken = accounting.path(other);
    assert.equal(token.length, otherToken.length);
    const atom = (name: string, path = file, measured = token): Shape => {
      const raw = `${path}::${name}`, expected = `${measured}::${name}`;
      accounting.register(raw, expected);
      return { name, raw, expected, count: 1, pathLength: path.length };
    };
    const tag = atom("Tag"), box = atom("Box"), enumeration = atom("Color"), structure = atom("Record");
    const module = atom("Module::Nested::Tag", other, otherToken);
    const literal = (raw: string): Shape => ({ name: raw, raw, expected: raw, count: 0, pathLength: 0 });
    const combine = (name: string, parts: (Shape | string)[]): Shape => {
      const shapes = parts.map(part => typeof part === "string" ? literal(part) : part);
      return { name, raw: shapes.map(s => s.raw).join(""), expected: shapes.map(s => s.expected).join(""),
        count: shapes.reduce((n, s) => n + s.count, 0), pathLength: shapes.reduce((n, s) => n + s.pathLength, 0) };
    };
    const json = (shape: Shape): Shape => ({ ...shape, name: `JSON(${shape.name})`,
      raw: JSON.stringify(shape.raw), expected: JSON.stringify(shape.expected) });
    const registered = (shape: Shape): Shape => {
      accounting.register(shape.raw, shape.expected);
      return shape;
    };
    const span = registered({ name: "spanIdentity", raw: file + ":123", expected: token + ":123", count: 1, pathLength: file.length });
    const instance = registered(combine("import instance", [module, "::import:2:", span]));
    const constructors = [tag, module, enumeration, structure,
      literal("Field"), literal("Boolean"), literal("$empty-sequence-element"),
      literal("standard-type::JubjubScalar"), literal("Uint<248>"), literal("Uint<0..256>"), literal("Bytes<32>"),
      combine("Vector size/nominal", ["Vector<4,", tag, ">"]),
      combine("standard generic", ["standard-type::Maybe<", tag, ">"]),
      combine("multiple arguments", [box, "<", tag, ",", module, ">"]),
      combine("nested arguments", [box, "<standard-type::Maybe<", tag, ">,Vector<2,[", module, ",Field]>>"]),
      combine("tuple", ["[", tag, ",", module, ",Bytes<32>,Uint<0..256>]"]),
      literal("[]"), literal("constant:string:/short/main.compact::Tag"), literal("field:/short/main.compact::Tag"),
      literal("key:/short/main.compact::Tag"), span, instance, registered(combine("instantiated module symbol", [instance, "::Exported"])),
      registered(combine("overload", [tag, "::overload:123"])),
      registered(combine("parameter", [tag, "::parameter:sourceName"])),
      ...["local", "loop", "pending", "pattern", "lambda"].map(kind => registered(combine(kind, [tag, `::${kind}:`, span])))];
    // Opaque canonicalType emits double-quoted strings. Additional escaped and
    // delimiter-rich payloads cover the same quoted grammar without assuming
    // that commas/brackets/angle brackets inside strings delimit arguments.
    for (const payload of ["string", "Uint8Array", "JubjubPoint", 'quote"comma,angle<>tuple[]', "backslash\\\"end", "/short/main.compact::Tag"]) {
      const opaque = literal(`Opaque<${JSON.stringify(payload)}>`);
      constructors.push(opaque,
        combine(`opaque sibling ${payload}`, [box, "<", tag, ",", opaque, ",", module, ">"]),
        combine(`opaque tuple ${payload}`, ["[", tag, ",", opaque, ",standard-type::Maybe<", module, ">]"]));
    }
    const shapes = [...constructors];
    for (const shape of constructors) {
      for (const wrapper of ["!", "identity:", "id:", "key:identity:", "parameter:", "read:", "ledger:",
        "ledger:coin-index:", "ledger:kernel-context:", "ledger:kernel-predicate:", "merkle-root:", "merkle-query:",
        "collection:", "list:", "fields:", "items:", "==:", "!=:", "scalar-relation:true:", "scalar-relation:false:",
        "aggregate-relation:", "ordered:Uint<64>:<:", "ordered:Field:>=:"]) {
        shapes.push(combine(`${wrapper}${shape.name}`, [wrapper, shape]));
      }
      shapes.push(json(shape), combine(`address ${shape.name}`, ["[", json(tag), ",[", json(combine("selector", ["id:", shape])), "]]" ]),
        combine(`query ${shape.name}`, ["ledger:kernel-predicate:", tag, ":", json(shape)]),
        combine(`object ${shape.name}`, ['{"identity":', json(shape), '}']));
      for (const relation of ["scalar-relation:true:", "scalar-relation:false:", "aggregate-relation:", "ordered:Uint<64>:<:", "ordered:Field:>=:"]) {
        shapes.push(combine(`relation pair ${relation}${shape.name}`, [relation, "[", json(tag), ",", json(shape), "]"]));
      }
    }
    for (const shape of shapes) {
      const measured = accounting.text(shape.raw);
      assert.equal(measured.length - shape.count * token.length, shape.raw.length - shape.pathLength,
        `${shape.name}: every non-path character must be charged exactly once`);
      assert.equal(measured, shape.expected, `${shape.name}: only structural pathname slots may change`);
    }
    return shapes.map(shape => ({ name: shape.name, length: accounting.text(shape.raw).length }));
  };
  assert.deepEqual(run("/short"), run("/" + "long-checkout-".repeat(25)));
});
