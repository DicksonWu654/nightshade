# Unshielded refund endpoint review

Availability: **opt-in**; severity **info**. Qualified for compiler 0.34.0/ZKIR2
or ZKIR3; experimental Counter mode is unavailable.

`unshielded-refund-endpoint-review` is opt-in and informational. It inspects a complete straight-line pure validator, matches its unsigned bounded floor relation, and evaluates the selected formal witness B=P=A=Q=1 through every statement, assertion, arithmetic intermediate and numeric cast. The validator assertion is tied by resolved lexical snapshot identities to a direct canonical send expression B-Q. Both Q*A+A and checked (Q+1)*A upper expressions are supported.

The result is an independently complete source-local formula certificate. It proves that this selected formal witness satisfies the inspected formula and supported relevant local caller arithmetic checks, and yields zero in the tied remainder expression. It does not certify unrelated caller conditions, ledger reachability, successful histories, transaction or proof feasibility, send rejection or application impact. Intentional endpoints match. A quiet result after rejecting witness1 does not establish that another zero endpoint is impossible.

Rule coverage uses `source-local-formula`. Baseline diagnostics and completion remain intact even when a local certificate completes. It never fills `completedEntries`, fabricates runtime paths or retries a failed ordinary analysis. Experimental Counter mode explicitly refuses the source certificate. The dedicated versioned evidence carrier and issued certificates are checked against the owning Program and compiler profile before emission.

Discovery and evaluation share40k steps per entry,256 candidate mappings per entry and50k cumulative retained values per selected rule. Expression/CFG ownership, recursive operand discovery, formal evaluation, casts, assertions, key strings, source mappings and findings are metered. Failures retain scoped incomplete diagnostics without partial findings from the affected entry. Dynamic reads and raw ledger reads cannot be equated; a local initialized from storage is an opaque value snapshot. Exact tuple leaves and aliases preserve distinct lexical identity.

The initial implementation supports compiler0.34.0/ZKIR2 or3. It refuses loop-contained sends, unsupported pure-body statements/calls, relevant opaque caller checks, mutable operand/guard snapshots, lost argument provenance, unsupported checked types and exhausted budgets. Unrelated caller conditions remain explicitly outside the formula theorem. Nested relevant conditional continuations are inspected as local implications; unresolved relevant conditions refuse rather than being assumed true.

Discovery keeps a private immutable snapshot of caller expressions, source spans and resolved symbols. Public candidate maps cannot alter later certification; shared Program objects are not globally frozen. Finding preparation charges the actual emitted strings, imported source-file key lists and sorting, path normalization, discriminator replacements, fingerprint-key joining and UTF-8 hashing work before emission. These costs share the existing observation allowance.

The initial checker inventory conservatively includes pure checkers from sibling branches. A relevant checker in an exclusive branch can therefore cause an incomplete result even when that branch would not run at the selected witness. This limitation is retained instead of claiming a complete path certificate or broadening branch analysis this checkpoint.
