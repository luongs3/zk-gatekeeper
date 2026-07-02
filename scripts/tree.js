#!/usr/bin/env node
// Credential Merkle tree builder + gatekeeper input generator.
//
// Uses the compiled poseidon_helper circuit's witness calculator to compute
// Poseidon hashes on BLS12-381 — bit-identical to what the gatekeeper circuit
// computes in-proof (circomlibjs is BN254-only, so it can't be used here).
//
// Usage:
//   node scripts/tree.js issue  <n_members> <claim_id>       > build/tree.json
//   node scripts/tree.js input  <member_idx> <claim_id>      > build/input_member.json
//   node scripts/tree.js forge  <claim_id>                   > build/input_forged.json
const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const DEPTH = 8;
const wcBuilder = require(path.join(ROOT, "build/poseidon_helper_js/witness_calculator.js"));
const wasm = fs.readFileSync(path.join(ROOT, "build/poseidon_helper_js/poseidon_helper.wasm"));

let wc;
async function poseidon(a, b) {
  // returns { h1: Poseidon(1)(a), h2: Poseidon(2)(a,b) }
  if (!wc) wc = await wcBuilder(wasm);
  const w = await wc.calculateWitness({ a: a.toString(), b: b.toString() }, 0);
  return { h1: w[1], h2: w[2] }; // outputs sit at witness[1], witness[2]
}

const ZERO = 0n; // padding leaf value for empty slots

async function buildTree(leaves) {
  const layers = [leaves.slice()];
  // pad to full width
  while (layers[0].length < 2 ** DEPTH) layers[0].push(ZERO);
  for (let d = 0; d < DEPTH; d++) {
    const prev = layers[d];
    const next = [];
    for (let i = 0; i < prev.length; i += 2) {
      next.push((await poseidon(prev[i], prev[i + 1])).h2);
    }
    layers.push(next);
  }
  return layers; // layers[DEPTH][0] is the root
}

function merklePath(layers, idx) {
  const pathElements = [], pathIndices = [];
  for (let d = 0; d < DEPTH; d++) {
    const sib = idx ^ 1;
    pathElements.push(layers[d][sib].toString());
    pathIndices.push((idx & 1).toString());
    idx >>= 1;
  }
  return { pathElements, pathIndices };
}

async function main() {
  const [cmd, arg1, arg2] = process.argv.slice(2);
  const treeFile = path.join(ROOT, "build/tree.json");

  if (cmd === "issue") {
    // deterministic-but-arbitrary secrets so the demo is reproducible
    const n = parseInt(arg1 || "4", 10);
    const secrets = [];
    for (let i = 0; i < n; i++) secrets.push((10n ** 18n + BigInt(i) * 7919n).toString());
    const leaves = [];
    for (const s of secrets) leaves.push((await poseidon(BigInt(s), 0n)).h1);
    const layers = await buildTree(leaves);
    const out = {
      depth: DEPTH,
      secrets,
      leaves: leaves.map(String),
      layers: layers.map(l => l.map(String)),
      root: layers[DEPTH][0].toString(),
    };
    fs.writeFileSync(treeFile, JSON.stringify(out, null, 2));
    console.log(JSON.stringify({ root: out.root, members: n }, null, 2));
  } else if (cmd === "input") {
    const idx = parseInt(arg1, 10);
    const claimId = BigInt(arg2 || "1");
    const t = JSON.parse(fs.readFileSync(treeFile));
    const layers = t.layers.map(l => l.map(BigInt));
    const { pathElements, pathIndices } = merklePath(layers, idx);
    const secret = BigInt(t.secrets[idx]);
    const null_ = (await poseidon(secret, claimId)).h2;
    const input = {
      secret: secret.toString(),
      pathElements, pathIndices,
      root: t.root,
      claimId: claimId.toString(),
    };
    fs.writeFileSync(path.join(ROOT, `build/input_member${idx}.json`), JSON.stringify(input, null, 2));
    console.log(JSON.stringify({ wrote: `build/input_member${idx}.json`, expectedNullifier: null_.toString() }, null, 2));
  } else if (cmd === "forge") {
    // Mallory: not in the tree. Uses a secret nobody issued + a fabricated path.
    const claimId = BigInt(arg1 || "1");
    const t = JSON.parse(fs.readFileSync(treeFile));
    const layers = t.layers.map(l => l.map(BigInt));
    const { pathElements, pathIndices } = merklePath(layers, 0); // real path shape, wrong secret
    const secret = 666666666666666666666n;
    const input = {
      secret: secret.toString(),
      pathElements, pathIndices,
      root: t.root,
      claimId: claimId.toString(),
    };
    fs.writeFileSync(path.join(ROOT, "build/input_forged.json"), JSON.stringify(input, null, 2));
    console.log(JSON.stringify({ wrote: "build/input_forged.json", note: "witness generation MUST fail (root mismatch)" }, null, 2));
  } else {
    console.error("usage: tree.js issue <n> | input <idx> <claimId> | forge <claimId>");
    process.exit(1);
  }
  process.exit(0);
}
main().catch(e => { console.error(e); process.exit(1); });
