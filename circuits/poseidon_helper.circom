pragma circom 2.0.0;

// Helper circuit — computes Poseidon(1) and Poseidon(2) on the SAME curve the
// gatekeeper circuit compiles to (BLS12-381). Used off-chain (via its witness
// calculator) to build the credential Merkle tree with hashes that are
// bit-identical to what the gatekeeper circuit computes in-proof.
// circomlibjs can't do this: its Poseidon is hardcoded to BN254.

include "circomlib/circuits/poseidon.circom";

template PoseidonHelper() {
    signal input a;
    signal input b;
    signal output h1;   // Poseidon(1)(a)   — leaf hash
    signal output h2;   // Poseidon(2)(a,b) — node / nullifier hash

    component p1 = Poseidon(1);
    p1.inputs[0] <== a;
    h1 <== p1.out;

    component p2 = Poseidon(2);
    p2.inputs[0] <== a;
    p2.inputs[1] <== b;
    h2 <== p2.out;
}

component main = PoseidonHelper();
