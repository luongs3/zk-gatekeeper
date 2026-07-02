#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
# trusted setup (bls12381, pot14) — cached
if [ ! -f build/pot_final.ptau ]; then
  npx snarkjs powersoftau new bls12381 14 build/pot_0.ptau
  npx snarkjs powersoftau contribute build/pot_0.ptau build/pot_1.ptau --name=c1 -e="gatekeeper entropy"
  npx snarkjs powersoftau prepare phase2 build/pot_1.ptau build/pot_final.ptau
fi
npx snarkjs groth16 setup build/gatekeeper.r1cs build/pot_final.ptau build/gatekeeper_0.zkey
npx snarkjs zkey contribute build/gatekeeper_0.zkey build/gatekeeper_final.zkey --name=c1 -e="more entropy"
npx snarkjs zkey export verificationkey build/gatekeeper_final.zkey build/verification_key.json
echo "=== SETUP DONE ==="
# prove for member 2
node build/gatekeeper_js/generate_witness.js build/gatekeeper_js/gatekeeper.wasm build/input_member2.json build/witness.wtns
npx snarkjs groth16 prove build/gatekeeper_final.zkey build/witness.wtns build/proof.json build/public.json
npx snarkjs groth16 verify build/verification_key.json build/public.json build/proof.json
echo "=== PUBLIC SIGNALS ==="; cat build/public.json
echo "=== forged witness attempt (MUST FAIL) ==="
node build/gatekeeper_js/generate_witness.js build/gatekeeper_js/gatekeeper.wasm build/input_forged.json build/witness_forged.wtns && echo "UNEXPECTED: forged witness succeeded" || echo "EXPECTED FAILURE: forged input cannot satisfy circuit"
