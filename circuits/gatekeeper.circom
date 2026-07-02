pragma circom 2.0.0;

// ZK Gatekeeper — prove membership in a credential Merkle tree WITHOUT revealing
// which leaf you are, plus a one-time nullifier so each credential claims once.
//
// Private inputs : secret, pathElements[DEPTH], pathIndices[DEPTH]
// Public inputs  : root (credential-set Merkle root), claimId (scope of the claim)
// Public output  : nullifierHash = Poseidon(secret, claimId)
//
// The ZK is load-bearing: without it, gating requires either publishing the full
// identity list (kills privacy) or trusting an off-chain gatekeeper (kills
// on-chain enforcement). The proof lets both properties coexist.
//
// Curve: compile with -p bls12381 to match the Soroban BLS12-381 verifier.
//   circom circuits/gatekeeper.circom --r1cs --wasm --sym -p bls12381 -l node_modules -o build

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";

// Standard Merkle-inclusion step: hash (left,right) ordered by the path bit.
template MerkleLevel() {
    signal input in;           // hash coming up from below
    signal input sibling;      // sibling node at this level
    signal input pathIndex;    // 0 => in is left child, 1 => in is right child
    signal output out;

    pathIndex * (1 - pathIndex) === 0;  // boolean-constrain the bit

    // left  = pathIndex ? sibling : in
    // right = pathIndex ? in      : sibling
    signal left;
    signal right;
    left  <== in + pathIndex * (sibling - in);
    right <== sibling + pathIndex * (in - sibling);

    component h = Poseidon(2);
    h.inputs[0] <== left;
    h.inputs[1] <== right;
    out <== h.out;
}

template Gatekeeper(DEPTH) {
    // -------- private --------
    signal input secret;                  // the credential secret
    signal input pathElements[DEPTH];     // Merkle siblings
    signal input pathIndices[DEPTH];      // Merkle path bits
    // -------- public ---------
    signal input root;                    // on-chain committed credential-set root
    signal input claimId;                 // claim scope (deal-room id / epoch)
    signal output nullifierHash;          // one-time spend tag

    // 1) leaf = Poseidon(secret) — the credential leaf as issued
    component leafH = Poseidon(1);
    leafH.inputs[0] <== secret;

    // 2) walk the Merkle path up to the root
    component levels[DEPTH];
    for (var i = 0; i < DEPTH; i++) {
        levels[i] = MerkleLevel();
        levels[i].in <== (i == 0) ? leafH.out : levels[i-1].out;
        levels[i].sibling <== pathElements[i];
        levels[i].pathIndex <== pathIndices[i];
    }

    // 3) computed root MUST equal the public root — this is the membership proof
    root === levels[DEPTH-1].out;

    // 4) nullifier binds the same secret to this claim scope; contract stores
    //    spent nullifiers so one credential cannot claim twice.
    component nullH = Poseidon(2);
    nullH.inputs[0] <== secret;
    nullH.inputs[1] <== claimId;
    nullifierHash <== nullH.out;
}

// Depth 8 => up to 256 credential holders per root. Cheap to bump.
component main {public [root, claimId]} = Gatekeeper(8);
