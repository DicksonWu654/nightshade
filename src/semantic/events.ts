// Native event declarations from compactc-v0.34.0, compiler/midnight-events.ss
// at 1f671fc27818df2b2676b3a97f85b2b821756243. Field order is wire order.
// Unlike ordinary stdlib helpers, the compiler generates these declarations.
export const EVENT_VERSION = 1;
export const STANDARD_EVENTS: Record<string, { tag: number; fields: Record<string, string> }> = {
  ShieldedSpend: { tag: 0, fields: { nullifier: "Bytes<32>" } },
  ShieldedReceive: { tag: 1, fields: { commitment: "Bytes<32>", ciphertext: "Maybe<Bytes<512>>", contractAddress: "Maybe<Bytes<32>>" } },
  ShieldedMint: { tag: 2, fields: { commitment: "Bytes<32>", domainSep: "Bytes<32>", amount: "Maybe<Uint<128>>" } },
  ShieldedBurn: { tag: 3, fields: { nullifier: "Bytes<32>", amount: "Maybe<Uint<128>>" } },
  UnshieldedSpend: { tag: 4, fields: { sender: "Either<ZswapCoinPublicKey,ContractAddress>", domainSep: "Bytes<32>", tokenType: "Bytes<32>", amount: "Uint<128>" } },
  UnshieldedReceive: { tag: 5, fields: { recipient: "Either<ZswapCoinPublicKey,ContractAddress>", domainSep: "Bytes<32>", tokenType: "Bytes<32>", amount: "Uint<128>" } },
  UnshieldedMint: { tag: 6, fields: { domainSep: "Bytes<32>", tokenType: "Bytes<32>", amount: "Uint<128>" } },
  UnshieldedBurn: { tag: 7, fields: { sender: "Either<ZswapCoinPublicKey,ContractAddress>", tokenType: "Bytes<32>", amount: "Uint<128>" } },
  Paused: { tag: 8, fields: {} },
  Unpaused: { tag: 9, fields: {} },
  Misc: { tag: 10, fields: { name: "Bytes<32>", payload: "Bytes<256>" } },
};
