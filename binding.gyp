{
  "targets": [{
    "target_name": "nightshade_parser",
    "sources": ["src/parser/native/binding.c", "dist/parser/src/parser.c"],
    "include_dirs": ["dist/parser", "dist/parser/src"],
    "defines": ["NAPI_VERSION=8"],
    "conditions": [
      ["OS!='win'", {"cflags_c": ["-std=c11"]}, {"cflags_c": ["/std:c11", "/utf-8"]}]
    ]
  }]
}
