import { mintQuantityEvidence, MINT_MAXIMUM } from "../dataflow/mint-quantities.js";
import { hasTokenMint, MINT_CIRCUITS } from "../semantic/mint-targets.js";
import { finding, type Detector, type Finding } from "./types.js";

export const unboundedMint: Detector = {
  id: "unbounded-mint", defaultEnabled: false,
  description: "A variable mint amount has no modeled per-call cap below the native range or public ledger bound",
  requires: ["successful-predicates", "canonical-mint-observations", "numeric-bounds"],
  run(facts) {
    if (!facts.program.entries.some(entry=>hasTokenMint(facts.program,entry))) return [];
    const issue = (message: string, entry?: string) => facts.diagnostics.push({ code:"mint-quantity-evidence-incomplete",message: `${message}; mint quantity review is incomplete`,location:entry ? facts.program.functions.get(entry)!.declaration.span : facts.program.rootSource.ast.span });
    if (!facts.mintEvidence || !facts.mintQuantityEvidence || facts.predicateScope !== "all" || facts.pathSemantics !== "equivalent-states") { issue("Exact mint snapshots, numeric domains and successful predicates are required"); return []; }
    let work=0;
    const charge=(amount=1)=>{ work+=amount; if(work>200000) throw new Error("Mint quantity work allowance exhausted"); };
    const findings=new Map<string,Finding>();
    for(const path of facts.paths) {
      if(!facts.completedEntries.includes(path.entry) || facts.program.symbols.get(path.entry)!.kind==="constructor") continue;
      if (!(path.operations ?? []).some(op=>op.kind === "kernel-write" && ["mintShielded","mintUnshielded"].includes(op.name))) continue;
      try {
        charge();
        const evidence=mintQuantityEvidence(path,charge);
        for(const operation of path.operations??[]) {
          charge();
          if(operation.kind!=="kernel-write" || !["mintShielded","mintUnshielded"].includes(operation.name)) continue;
          const amount=operation.args[1];
          if(!amount || amount.constant!==undefined) continue;
          const quantity=evidence.bounds(amount,facts.program.representationOf(amount.type??"Uint<64>"));
          if(quantity.range.maximum<MINT_MAXIMUM || quantity.publicCap) continue;
          const index=operation.callPath.findIndex(id=>MINT_CIRCUITS.has(id));
          const location=index>=0 ? operation.callSites?.[index] : operation.location;
          if(!location) throw new Error("Canonical mint invocation evidence is unavailable");
          const name=facts.program.symbols.get(path.entry)!.name;
          const item=finding(facts,{
            detectorId:unboundedMint.id,severity:"medium",confidence:"low",title:"Mint quantity has no modeled application cap",
            message:`${name} reaches ${operation.name} with a variable amount whose successful-path envelope retains the native 64-bit upper limit and has no modeled public-ledger upper bound. A lower-only check or unrelated caller guard does not establish a quantity cap. Trusted-issuer and intentionally public minting can be valid; review the monetary policy.`,
            location,trace:[{kind:"effect",label:"variable native mint amount",location:operation.location}],
            callPath:operation.callPath.map(id=>facts.program.symbols.get(id)?.name??id),
            remediation:"If the monetary policy requires a per-call limit, constrain the actual minted amount before successful completion. Enforce supply, issuer authorization and cap integrity separately; this review proves none of them.",
            metadata:{entry:name,operation:operation.name,reviewRequired:true,evidence:"no-modeled-per-call-quantity-cap",pathFeasibility:"not-proven",
              amountEnvelopes:[{minimum:String(quantity.range.minimum),maximum:String(quantity.range.maximum)}],affectedEffects:[operation.location],invocationSites:[operation.callSites??[]]},
          },path.entry);
          const prior=findings.get(item.fingerprint);
          if(prior) for(const key of ["amountEnvelopes","affectedEffects","invocationSites"] as const) {
            const values=[...prior.metadata[key] as unknown[],...item.metadata[key] as unknown[]];
            prior.metadata[key]=[...new Map(values.map(value=>[JSON.stringify(value),value])).values()];
          } else findings.set(item.fingerprint,item);
        }
      } catch(error) { issue(error instanceof Error?error.message:String(error),path.entry); }
    }
    return [...findings.values()];
  },
};
