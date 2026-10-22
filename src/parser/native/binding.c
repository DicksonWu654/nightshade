#include <node_api.h>
#include "identity.h"

typedef struct TSLanguage TSLanguage;
extern const TSLanguage *tree_sitter_compact(void);

static napi_value initialize(napi_env environment, napi_value exports) {
  const napi_type_tag language_tag = {0x8AF2E5212AD58ABF, 0xD5006CAD83ABBA16};
  napi_value language;
  napi_value identity;
  if (napi_create_external(environment, (void *)tree_sitter_compact(), NULL, NULL, &language) != napi_ok ||
      napi_type_tag_object(environment, language, &language_tag) != napi_ok ||
      napi_set_named_property(environment, exports, "language", language) != napi_ok ||
      napi_create_string_utf8(environment, NIGHTSHADE_GRAMMAR_IDENTITY, NAPI_AUTO_LENGTH, &identity) != napi_ok ||
      napi_set_named_property(environment, exports, "identity", identity) != napi_ok) {
    napi_throw_error(environment, "NIGHTSHADE_PARSER_INIT", "Cannot initialize Compact parser binding");
    return NULL;
  }
  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, initialize)
