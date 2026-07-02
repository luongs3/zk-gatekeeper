# ZK Gatekeeper — private credential-gated access on Stellar

**Prove you qualify. Reveal nothing else. The chain can't be fooled.**

A Soroban contract gates access to a private, permissioned action (an RWA deal-room /
accredited-investor room) to only wallets holding a valid, off-chain-issued credential —
without the chain or any observer ever learning *which* identity is behind an approved
claim. Built for **Stellar Hacks: Real-World ZK**.

## How it works

1. **Issuer** hashes each credential secret into a leaf (`Poseidon(secret)`) and commits
   one Merkle root of the credential set on-chain (`set_root`). The list itself is never
   published.
2. **Holder** proves, in zero-knowledge (Circom Groth16 on **BLS12-381**), that they know
   a secret whose leaf sits under the committed root — and derives a one-time
   `nullifierHash = Poseidon(secret, claimId)`.
3. **Contract** (`claim_access`) verifies the proof on-chain via Soroban's native
   `pairing_check`, checks the proof's root equals the committed root, and burns the
   nullifier. Forged proofs, wrong-root proofs, and replays all fail as real on-chain
   errors.

### Why the ZK is load-bearing

Without the proof, "credential-holders only" can be enforced only by publishing the full
identity list (kills privacy) or trusting an off-chain gatekeeper (kills on-chain
enforcement). The proof is the only mechanism that lets both properties coexist. Drop it
and the product doesn't exist.

## The three on-chain beats (all real testnet txs — see DEPLOYMENT.md)

| # | Actor | Action | Result |
|---|-------|--------|--------|
| 1 | Alice (credential holder) | valid membership proof | ✅ `granted` event, nullifier burned |
| 2 | Alice again | replays the *same* valid proof | ❌ `Error #9 NullifierAlreadySpent` |
| 3 | Mallory (never issued) | cryptographically-valid proof against her *own forged tree* | ❌ `Error #8 RootMismatch` |

Mallory's attack is the strong one: her proof passes `snarkjs groth16 verify` locally
(valid crypto!) — the contract still refuses it because it's not against the issuer's
committed root. And she *cannot* build a witness against the real root at all: the circuit
assert fails (reproducible — `node scripts/tree.js forge 1` then try to generate a witness).

## Stack

- **Circuit** `circuits/gatekeeper.circom` — circom 2.2.3, Poseidon Merkle-inclusion
  (depth 8 = 256 holders/root) + nullifier, compiled `-p bls12381`.
- **Contract** `contract/src/lib.rs` — Soroban (soroban-sdk 25.1), Groth16 verifier via
  native BLS12-381 `pairing_check`, root registry + spent-nullifier set.
- **Proving** snarkjs 0.7.6; artifact→Soroban byte encoding via
  [CircomStellar](https://github.com/jamesbachini/CircomStellar)'s `circom_to_soroban_hex`.
- **Tree tooling** `scripts/tree.js` — builds the credential tree with the *circuit's own*
  witness calculator so off-chain Poseidon is bit-identical to in-circuit Poseidon
  (circomlibjs is BN254-only and can't be used on this curve).

## Reproduce

```bash
npm install circomlib snarkjs@0.7.6
git clone https://github.com/jamesbachini/CircomStellar.git   # hex encoder

# 1. compile circuits (BLS12-381)
circom circuits/gatekeeper.circom       --r1cs --wasm --sym -p bls12381 -l node_modules -o build
circom circuits/poseidon_helper.circom  --r1cs --wasm       -p bls12381 -l node_modules -o build

# 2. issue 4 credentials, build member #2's input
node scripts/tree.js issue 4
node scripts/tree.js input 2 1

# 3. trusted setup + prove + local verify (also runs the forged-witness negative test)
bash scripts/setup-prove.sh

# 4. deploy + run all three beats on testnet
bash scripts/demo.sh
```

## Honest limitations

- **Groth16 trusted setup** is a single-contributor dev ceremony — fine for a hackathon,
  a real deployment needs a proper MPC ceremony (or a universal-setup scheme).
- **Depth-8 tree (256 holders)** — capacity is a compile-time constant; bumping it is a
  one-line change but requires a new setup.
- The "deal room" unlock is the `granted` event + grant record, not real downstream
  business logic — the load-bearing part is the proof gate itself.
- Root rotation is issuer-trusted (standard for credential registries); revocation =
  rotate to a root without the revoked leaf.

## Relation to our other entry

Same proven BLS12-381 verifier core as [SolvencyProof](https://github.com/luongs3/solvency-proof),
completely different product and math: hash-based *membership + nullifier* (access
control) vs linear *threshold comparison* (attestation). No shared circuit logic.
