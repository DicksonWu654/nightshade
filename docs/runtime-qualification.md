# Compiled runtime qualification

Normal Nightshade scans do not execute contracts. In a trusted source checkout,
three owned synthetic fixtures additionally qualify selected compiled behavior
under Compact 0.34.0 / language 0.26.0 / ZKIR2 and runtime 0.19.0. This is a
bounded development check, not a general execution or proof API.

The source checkout contains setup instructions at
`tests/runtime-fixtures/README.md` and pinned dependency inputs under
`tests/runtime-fixtures/qualification-inputs`. These development files are not
part of the npm package. With those exact external inputs restored, set
`COMPACTC_TEST` and `COMPACT_RUNTIME_TEST`, build the source, and run
`node --test dist/tests/runtime-qualified.test.js` on Node 22 and 24.
Without the runtime input the suite skips; runtime/compiler mismatches fail.
A passing ordinary scan does not establish compiled runtime compatibility.

The runtime worker has a 60-second timeout, a 256 MiB V8 heap setting and a
1 MiB output bound; compiler calls have a 30-second timeout. These controls
are neither an OS sandbox nor an RSS cap. Use a sandbox for untrusted inputs.
