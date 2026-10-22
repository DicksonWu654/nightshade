# Secret binding divergence review

Availability: **opt-in** with `--detectors secret-binding-divergence-review`.
Findings are informational source comparisons requiring intent review.

The rule compares exported numeric Map mutation occurrences on the same canonical
ledger declaration. One writer already binds its affected exact key to an unchanged
pre-existing record through a private, constant-domain-qualified native hash
preimage. A completed sibling writer binds its own affected key to that binding
family and an additional family with a different canonical witness declaration,
constant domain recipe and trusted ledger declaration. Every successful sibling
history must contain an occurrence enforcing both families at its own exact key.
One sibling is enough for a comparison; no majority premise applies.

These are declaration-family descriptors, not equality of private inputs, witness
results or account values across entries. Each key equality is established only
inside its original history: ordinary Map transfer derives the recorded storage
path from the exact immutable lookup/insertion operand. The selected transfer meters
that derivation and its retained encodings. Wildcard paths never establish equality.
The matcher compares these exact operand encodings within the history, admitting
direct, transitive and late atomic key equality only through required successful
predicates. Optional and unequal-key predicates do not supply that equality. It
compares only declaration-family descriptors between writers.

The required equality graph does not rebuild different compound key encodings or
derive function congruence from equal arithmetic/native inputs. Different derived
or compound operand encodings without a graph-proved whole-operand equality produce
explicit incomplete coverage. Identical exact encodings remain admissible; a shared
wildcard path never does. This conservative boundary prevents a discarded additional
binding from becoming a false missing-binding review.
Scalar-source classification uses the canonical represented declaration type,
including when the interpreter leaves a large aggregate unexpanded. Missing runtime
`items`/`fields` metadata cannot turn an opaque compound key into a scalar key.

The admitted hash recipe contains one raw scalar `Bytes<32>` witness input and
fully represented constant components, using canonical `persistentHash`. The
descriptor retains its primitive, input type and constant recipe. Published or
publicly fixed preimages, transformed inputs, incomplete recipes, changed trusted
record revisions and different effect keys cannot supply this relation. Boolean
alternatives contribute only their required intersections. A late binding against
an unchanged exact pre-existing record remains a constraint on atomic successful
completion; its position does not manufacture a missing binding.

The comparison concerns a mutation occurrence. Subsequent writes to another balance
key do not erase an earlier occurrence. Trusted authentication-record revisions
must remain unchanged at the compared effect and assertion. Enrollment without a
base authentication binding is outside this review, as are List effects and inferred
account groupings across different ledger declarations.

Reachable canonical kernel checkpoints, including those in helpers or callbacks,
produce explicit incomplete coverage during the selected metered callable walk.
Committed-prefix semantics are outside this initial atomic-history review; an
application circuit merely named `checkpoint` does not trigger that refusal.

Selected preparation, ordinary execution, retained capture, identity traversal,
matching and finding construction share the production limits: 40,000 steps per
entry, 256 paths per entry and 50,000 cumulative abstract values per rule. Missing,
unfinished or refused evidence produces diagnostics and incomplete rule coverage;
there is no retry or quiet result from a truncated sibling inventory.

The rule does not compare authentication strength or infer required policy,
feasibility, exploitability, cryptographic independence or application impact.
An intentionally different writer with this executable relationship still matches.
This rule remains opt-in because its intent-dependent matches require independent
review.
