# Live Deployment — Stellar Testnet

The full ZK Gatekeeper system was built and exercised end-to-end on Stellar testnet on
2026-07-02. These are real, verifiable on-chain receipts.

## Contract

- **Contract ID:** `CCJLQW33MJ47AEM2ZCYUTG2G5YP77LPYDY25F57B2OBZDHMKU6ANYW6F`
- **Explorer:** https://stellar.expert/explorer/testnet/contract/CCJLQW33MJ47AEM2ZCYUTG2G5YP77LPYDY25F57B2OBZDHMKU6ANYW6F
- **WASM:** `zk_gatekeeper.wasm` (9.9 KB, target `wasm32v1-none`)
- **Curve:** BLS12-381, Groth16, verified on-chain via Soroban's native `pairing_check`.

## What happened on-chain (in order, 2026-07-02 ~13:44 UTC)

1. **Upload WASM** — tx `4273c1da0fa7e212cfb19d640a00aedc5a55a4d5accd0b66684732938f2b9215`
2. **Deploy** — tx `1ec311a5707476b05e9dd6fc6791d7305af91de830d3c73e5c965baf976c2c5d`
3. **init(admin, vk)** — verification key stored —
   tx `ecfb119dc31176042415a15f006d5a28509775205235bd06c22848352b58825c`
4. **set_root(root)** — credential-set Merkle root
   `25f74c3e7ba217b0ff1cb68aa9164f59ef00aa3252d7aee3cf06407e0bb60cfb` committed —
   tx `70987843871112a5918a2b937e35de46c9ef834ee7302101df860354cbe6b541`
5. **claim_access(valid proof) → GRANTED** — proof verified on-chain, nullifier
   `67b24a52a64a3b38159fd755c46a3a9ff3a99befcf95504b237f3608bf6f590f` burned, event
   `[granted, 1]` emitted —
   tx `f047c209055ca401db02f9029c25f4548166e53aaeeec61872697c8d4ca07812`
6. **grant_count()** → `1`

## The two refusals (beats 2 & 3)

Soroban refuses doomed transactions at preflight — the contract's error is raised during
transaction simulation against real on-chain state, so the network never even lets the
transaction land. Both refusals are reproducible against the live contract above:

- **Replay attack** — resubmitting Alice's already-spent proof:
  `HostError: Error(Contract, #9)` — `NullifierAlreadySpent`.
- **Forged-tree attack** — Mallory's proof is *cryptographically valid* (passes
  `snarkjs groth16 verify` locally!) but was generated against her own fabricated
  credential tree: `HostError: Error(Contract, #8)` — `RootMismatch`. The contract
  compares the proof's public root signal to the issuer-committed root and refuses.

  Mallory cannot do better: generating a witness against the *real* root with a
  non-member secret fails the circuit's root-equality assert (`scripts/tree.js forge 1`
  reproduces this).

## Off-chain proof artifacts (in `proving/`)

Generated with circom 2.2.3 + snarkjs 0.7.6 on BLS12-381:

- `gatekeeper_final.zkey` — proving key (after trusted setup)
- `verification_key.json` / `vk.hex` — verification key (JSON + Soroban byte encoding)
- `proof.json`, `public.json` (+ `.hex`) — Alice's VALID membership proof
- `proof_mallory.json`, `public_mallory.json` (+ `.hex`) — Mallory's valid-crypto /
  wrong-root proof (locally verifies OK; on-chain rejected #8)

## Reproduce

`bash scripts/demo.sh` deploys a fresh contract and runs all of the above.

> Note: the deploying key is a throwaway testnet identity funded via friendbot. No
> mainnet, no real funds.
