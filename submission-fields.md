# DoraHacks BUIDL submission fields — ZK Gatekeeper

Hackathon: https://dorahacks.io/hackathon/stellar-hacks-zk/detail (deadline Jul 4 00:00)
Submit via: hackathon page → Submit BUIDL → Create new BUIDL (2nd entry, distinct product)

## BUIDL name
ZK Gatekeeper

## Tagline / one-liner
Private credential-gated access on Stellar — prove you qualify, reveal nothing else. Groth16 membership proofs + one-time nullifiers verified on-chain in Soroban.

## Description (paste)
ZK Gatekeeper gates access to a private, permissioned action (an RWA deal-room / accredited-investor room) to only wallets holding a valid off-chain-issued credential — without the chain or any observer ever learning WHICH identity is behind an approved claim.

How: the issuer commits one Poseidon-Merkle root of hashed credential secrets on-chain. A holder proves membership in zero-knowledge (Circom Groth16 on BLS12-381) and burns a one-time nullifier (Poseidon(secret, claimId)); the Soroban contract verifies the proof via native pairing_check, checks the proof's root equals the committed root, and refuses replays.

The ZK is load-bearing: without it, "credential-holders only" requires either publishing the full identity list (kills privacy) or trusting an off-chain gatekeeper (kills on-chain enforcement). The proof is the only mechanism letting both properties coexist.

Three real on-chain beats (Stellar testnet, contract CCJLQW33MJ47AEM2ZCYUTG2G5YP77LPYDY25F57B2OBZDHMKU6ANYW6F):
1) Alice (credential holder) claims access → GRANTED, nullifier burned, event emitted (tx f047c209…).
2) Alice replays the same valid proof → REFUSED, Error #9 NullifierAlreadySpent.
3) Mallory forges her own credential tree and generates a cryptographically VALID proof (passes snarkjs verify locally!) → the contract still refuses it, Error #8 RootMismatch. And she cannot prove against the real root at all — the circuit's root-equality assert makes witness generation fail.

Honest limitations documented in the README (single-contributor Groth16 setup, depth-8 tree, mock deal-room unlock).

Note: distinct product from our other entry SolvencyProof — hash-based membership + nullifier (access control) vs linear threshold comparison (attestation); no shared circuit logic, same proven verifier core.

## Links
- Repo: https://github.com/luongs3/zk-gatekeeper
- Video: https://youtu.be/mpQGFTT5L4w (unlisted, 1:57)
- Contract explorer: https://stellar.expert/explorer/testnet/contract/CCJLQW33MJ47AEM2ZCYUTG2G5YP77LPYDY25F57B2OBZDHMKU6ANYW6F
- Grant tx: https://stellar.expert/explorer/testnet/tx/f047c209055ca401db02f9029c25f4548166e53aaeeec61872697c8d4ca07812

## Tech tags
Stellar, Soroban, ZK, Circom, Groth16, BLS12-381, Rust
