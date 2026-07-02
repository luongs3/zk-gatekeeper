#!/usr/bin/env node
// Mallory's attack: build her OWN credential tree containing HER secret and
// generate a real proof against HER root. Cryptographically valid — but the
// on-chain contract compares the proof's root to the issuer's committed root
// and refuses it (Error #8 RootMismatch).
const fs = require("fs"), path = require("path");
const ROOT = path.join(__dirname, "..");
const wcB = require(path.join(ROOT, "build/poseidon_helper_js/witness_calculator.js"));
const wasm = fs.readFileSync(path.join(ROOT, "build/poseidon_helper_js/poseidon_helper.wasm"));

(async () => {
  const wc = await wcB(wasm);
  const P = async (a, b) => {
    const w = await wc.calculateWitness({ a: a.toString(), b: b.toString() }, 0);
    return { h1: w[1], h2: w[2] };
  };
  const DEPTH = 8, secret = 666666666666666666666n;
  const leaf = (await P(secret, 0n)).h1;
  const leaves = [leaf];
  while (leaves.length < 2 ** DEPTH) leaves.push(0n);
  const layers = [leaves];
  for (let d = 0; d < DEPTH; d++) {
    const prev = layers[d], next = [];
    for (let i = 0; i < prev.length; i += 2) next.push((await P(prev[i], prev[i + 1])).h2);
    layers.push(next);
  }
  const pathElements = [], pathIndices = [];
  let idx = 0;
  for (let d = 0; d < DEPTH; d++) {
    pathElements.push(layers[d][idx ^ 1].toString());
    pathIndices.push((idx & 1).toString());
    idx >>= 1;
  }
  fs.writeFileSync(path.join(ROOT, "build/input_mallory.json"), JSON.stringify({
    secret: secret.toString(), pathElements, pathIndices,
    root: layers[DEPTH][0].toString(), claimId: "1",
  }, null, 2));
  console.log("mallory's forged root:", layers[DEPTH][0].toString());
  process.exit(0);
})();
