#!/usr/bin/env bash
# End-to-end ZK Gatekeeper demo: compile -> setup -> prove -> deploy -> the 3 beats.
# Prereqs: circom 2.2.3, node 18+, rust + stellar-cli, CircomStellar cloned alongside.
# Usage: bash scripts/demo.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
NETWORK="${NETWORK:-testnet}"
CS="${CS:-$ROOT/CircomStellar}"
HEX="cargo run --quiet --manifest-path $CS/tools/circom_to_soroban_hex/Cargo.toml --"
mkdir -p build

echo "==> 1 compile circuits (BLS12-381)"
[ -d node_modules/circomlib ] || npm install circomlib snarkjs@0.7.6
circom circuits/gatekeeper.circom      --r1cs --wasm --sym -p bls12381 -l node_modules -o build
circom circuits/poseidon_helper.circom --r1cs --wasm       -p bls12381 -l node_modules -o build

echo "==> 2 issue credentials + build inputs"
node scripts/tree.js issue 4
node scripts/tree.js input 2 1

echo "==> 3 trusted setup + prove + local verify (incl. forged-witness negative test)"
bash scripts/setup-prove.sh

echo "==> 4 encode artifacts to Soroban hex"
$HEX vk     build/verification_key.json > build/vk.hex
$HEX proof  build/proof.json            > build/proof.hex
$HEX public build/public.json           > build/public.hex

echo "==> 5 build + deploy contract"
(cd contract && stellar contract build --optimize)
WASM="$ROOT/contract/target/wasm32v1-none/release/zk_gatekeeper.wasm"
CID="$(stellar contract deploy --wasm "$WASM" --network "$NETWORK" --source alice | grep -Eo 'C[A-Z0-9]{55}' | tail -1)"
echo "   contract: $CID"; echo "$CID" > build/contract_id.txt

echo "==> 6 init + commit credential root"
ADMIN="$(stellar keys address alice)"
ROOT_HEX=$(python3 -c "import json; print(format(int(json.load(open('build/public.json'))[1]),'064x'))")
stellar contract invoke --id "$CID" --network "$NETWORK" --source alice -- init \
  --admin "$ADMIN" --vk_bytes "$(tr -d '\r\n' < build/vk.hex)" >/dev/null
stellar contract invoke --id "$CID" --network "$NETWORK" --source alice -- set_root --root "$ROOT_HEX" >/dev/null
echo "   root committed: $ROOT_HEX"

echo "==> BEAT 1: Alice claims access (valid membership proof) — GRANTED"
stellar contract invoke --id "$CID" --network "$NETWORK" --source alice -- claim_access \
  --proof_bytes "$(tr -d '\r\n' < build/proof.hex)" \
  --pub_signals_bytes "$(tr -d '\r\n' < build/public.hex)" --claim_id 1

echo "==> BEAT 2: Alice replays the same proof — MUST refuse Error #9 (NullifierAlreadySpent)"
stellar contract invoke --id "$CID" --network "$NETWORK" --source alice -- claim_access \
  --proof_bytes "$(tr -d '\r\n' < build/proof.hex)" \
  --pub_signals_bytes "$(tr -d '\r\n' < build/public.hex)" --claim_id 1 \
  && echo "UNEXPECTED SUCCESS" || echo "   refused, as designed"

echo "==> BEAT 3: Mallory's forged-tree proof (valid crypto, wrong root) — MUST refuse Error #8 (RootMismatch)"
node scripts/mallory.js
node build/gatekeeper_js/generate_witness.js build/gatekeeper_js/gatekeeper.wasm build/input_mallory.json build/witness_mallory.wtns
npx snarkjs groth16 prove build/gatekeeper_final.zkey build/witness_mallory.wtns build/proof_mallory.json build/public_mallory.json
npx snarkjs groth16 verify build/verification_key.json build/public_mallory.json build/proof_mallory.json
$HEX proof  build/proof_mallory.json  > build/proof_mallory.hex
$HEX public build/public_mallory.json > build/public_mallory.hex
stellar contract invoke --id "$CID" --network "$NETWORK" --source alice -- claim_access \
  --proof_bytes "$(tr -d '\r\n' < build/proof_mallory.hex)" \
  --pub_signals_bytes "$(tr -d '\r\n' < build/public_mallory.hex)" --claim_id 1 \
  && echo "UNEXPECTED SUCCESS" || echo "   refused, as designed"

echo ""
echo "==> final grant_count (must be 1):"
stellar contract invoke --id "$CID" --network "$NETWORK" --source alice -- grant_count
echo "DONE. Explorer: https://stellar.expert/explorer/testnet/contract/$CID"
