#!/usr/bin/env bash
set -euo pipefail

report=$(mktemp "$RUNNER_TEMP/nightshade-XXXXXX.sarif")
scan_path="$NIGHTSHADE_INPUT_PATH"
if [[ "$scan_path" != /* && "$scan_path" != [A-Za-z]:* ]]; then scan_path="$GITHUB_WORKSPACE/$scan_path"; fi
args=("$NIGHTSHADE_ACTION_PATH/dist/src/cli.js" "$scan_path" --sarif --fail-on "$NIGHTSHADE_FAIL_ON")
if [[ -n "$NIGHTSHADE_CONFIG" ]]; then
  config_path="$NIGHTSHADE_CONFIG"
  if [[ "$config_path" != /* && "$config_path" != [A-Za-z]:* ]]; then config_path="$GITHUB_WORKSPACE/$config_path"; fi
  args+=(--config "$config_path")
fi
if [[ -n "$NIGHTSHADE_COMPILER_VERSION" ]]; then args+=(--compiler-version "$NIGHTSHADE_COMPILER_VERSION"); fi
set +e
node "${args[@]}" > "$report"
scan_status=$?
set -e
echo "exit-code=$scan_status" >> "$GITHUB_OUTPUT"
if [[ -s "$report" ]]; then echo "sarif=$report" >> "$GITHUB_OUTPUT"; fi
# The composite action uploads first, then exits with this recorded status.
