const upstream = require("tree-sitter-compact/grammar.js");
const stringToken = () => token(choice(/"([^"\\]|\\[\s\S])*"/, /'([^'\\]|\\[\s\S])*'/));

module.exports = grammar(upstream, {
  name: "compact",
  conflicts: (grammarRules, previous) => [...previous, [grammarRules.tref]],
  rules: {
    term: (grammarRules, previous) => choice(previous, grammarRules.emit_term),
    emit_term: grammarRules => seq("emit", "(", field("expr", grammarRules.expr), ")"),
    _struct_body_comma: (grammarRules, previous) => choice(previous, seq("{", "}")),
    // Compact parses f<A,B>(x) as a generic call even in an enclosing argument
    // or tuple list. Without a dynamic preference the GLR alternative can split
    // its generic comma into two relational expressions.
    function_call_term: (grammarRules, previous) => prec.dynamic(1, previous),
    str: stringToken,
    file: stringToken,
    pattern: grammarRules => choice(
      field("id", grammarRules.id),
      field("pattern_tuple", seq(
        "[",
        repeat(seq(optional(field("pattern_tuple_elt", grammarRules.pattern_tuple_elt)), ",")),
        optional(field("pattern_tuple_elt", grammarRules.pattern_tuple_elt)),
        "]",
      )),
      field("pattern_struct", seq(
        "{",
        optional(seq(
          field("pattern_struct_elt", grammarRules.pattern_struct_elt),
          repeat(seq(",", field("pattern_struct_elt", grammarRules.pattern_struct_elt))),
          optional(","),
        )),
        "}",
      )),
    ),
    tref: grammarRules => choice(
      field("id", grammarRules.id),
      prec.dynamic(1, seq(field("id", grammarRules.id), field("gargs", grammarRules.gargs))),
    ),
    import_selection: grammarRules => seq(
      "{",
      optional(seq(
        grammarRules.import_element,
        repeat(seq(",", grammarRules.import_element)),
        optional(","),
      )),
      "}",
      "from",
    ),
    expr_seq: grammarRules => seq(
      field("expr", grammarRules.expr),
      repeat(seq(",", field("expr", grammarRules.expr))),
    ),
  },
});
