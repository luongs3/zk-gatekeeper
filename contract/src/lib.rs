#![no_std]
//! ZK Gatekeeper — private credential-gated access on Stellar.
//!
//! An issuer commits a Merkle root of hashed credential leaves on-chain. A
//! holder proves membership in zero-knowledge (Circom Groth16, BLS12-381) and
//! burns a one-time nullifier to claim access — without revealing which leaf,
//! wallet, or identity is behind the claim. Forged proofs and replayed
//! nullifiers both fail as real on-chain transactions.
//!
//! The Groth16 verifier core is adapted from the Stellar `soroban-examples` /
//! CircomStellar BLS12-381 verifier (same core as our SolvencyProof entry).
//! The root-registry + nullifier-set access layer is the project-specific part.
//!
//! Public signal contract (order fixed by circom: outputs first, then public inputs):
//!   [0] nullifierHash = Poseidon(secret, claimId)
//!   [1] root          — must equal the issuer-committed root
//!   [2] claimId       — the claim scope this access is for

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype,
    crypto::bls12_381::{Fr, G1Affine, G2Affine, G1_SERIALIZED_SIZE, G2_SERIALIZED_SIZE},
    symbol_short, vec, Address, Bytes, BytesN, Env, Symbol, Vec, U256,
};

const VK_KEY: Symbol = symbol_short!("VK");
const ADMIN: Symbol = symbol_short!("ADMIN");
const ROOT: Symbol = symbol_short!("ROOT");
const GRANTS: Symbol = symbol_short!("GRANTS");

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    MalformedVerifyingKey = 1,
    VerificationKeyNotSet = 2,
    MalformedProof = 3,
    MalformedPublicSignals = 4,
    AlreadyInitialized = 5,
    NotInitialized = 6,
    ProofInvalid = 7,
    RootMismatch = 8,
    NullifierAlreadySpent = 9,
    RootNotSet = 10,
}

/// One granted access, publicly readable — note it records only the nullifier,
/// never which credential holder it was.
#[contracttype]
#[derive(Clone, Debug)]
pub struct AccessGrant {
    pub nullifier: BytesN<32>,
    pub claim_id: u64,
    pub ledger: u32,
    pub timestamp: u64,
}

// ---------------------------------------------------------------------------
// Groth16 verifier core (BLS12-381) — proven verbatim in SolvencyProof
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct VerificationKey {
    alpha: G1Affine,
    beta: G2Affine,
    gamma: G2Affine,
    delta: G2Affine,
    ic: Vec<G1Affine>,
}

#[derive(Clone)]
struct ProofData {
    a: G1Affine,
    b: G2Affine,
    c: G1Affine,
}

fn take<const N: usize>(bytes: &Bytes, pos: &mut u32, err: Error) -> Result<[u8; N], Error> {
    let end = pos.checked_add(N as u32).ok_or(err)?;
    if end > bytes.len() {
        return Err(err);
    }
    let mut arr = [0u8; N];
    bytes.slice(*pos..end).copy_into_slice(&mut arr);
    *pos = end;
    Ok(arr)
}

impl VerificationKey {
    fn from_bytes(env: &Env, bytes: &Bytes) -> Result<Self, Error> {
        let mut pos = 0u32;
        let alpha = G1Affine::from_array(
            env,
            &take::<G1_SERIALIZED_SIZE>(bytes, &mut pos, Error::MalformedVerifyingKey)?,
        );
        let beta = G2Affine::from_array(
            env,
            &take::<G2_SERIALIZED_SIZE>(bytes, &mut pos, Error::MalformedVerifyingKey)?,
        );
        let gamma = G2Affine::from_array(
            env,
            &take::<G2_SERIALIZED_SIZE>(bytes, &mut pos, Error::MalformedVerifyingKey)?,
        );
        let delta = G2Affine::from_array(
            env,
            &take::<G2_SERIALIZED_SIZE>(bytes, &mut pos, Error::MalformedVerifyingKey)?,
        );
        let ic_len = u32::from_be_bytes(take::<4>(bytes, &mut pos, Error::MalformedVerifyingKey)?);
        let mut ic = Vec::new(env);
        for _ in 0..ic_len {
            let g1 = G1Affine::from_array(
                env,
                &take::<G1_SERIALIZED_SIZE>(bytes, &mut pos, Error::MalformedVerifyingKey)?,
            );
            ic.push_back(g1);
        }
        if pos != bytes.len() || ic_len == 0 {
            return Err(Error::MalformedVerifyingKey);
        }
        Ok(Self { alpha, beta, gamma, delta, ic })
    }
}

impl ProofData {
    fn from_bytes(env: &Env, bytes: &Bytes) -> Result<Self, Error> {
        let mut pos = 0u32;
        let a = G1Affine::from_array(
            env,
            &take::<G1_SERIALIZED_SIZE>(bytes, &mut pos, Error::MalformedProof)?,
        );
        let b = G2Affine::from_array(
            env,
            &take::<G2_SERIALIZED_SIZE>(bytes, &mut pos, Error::MalformedProof)?,
        );
        let c = G1Affine::from_array(
            env,
            &take::<G1_SERIALIZED_SIZE>(bytes, &mut pos, Error::MalformedProof)?,
        );
        if pos != bytes.len() {
            return Err(Error::MalformedProof);
        }
        Ok(Self { a, b, c })
    }
}

fn parse_public_signals(env: &Env, bytes: &Bytes) -> Result<Vec<Fr>, Error> {
    let mut pos = 0u32;
    let len = u32::from_be_bytes(take::<4>(bytes, &mut pos, Error::MalformedPublicSignals)?);
    let mut sigs = Vec::new(env);
    for _ in 0..len {
        let arr = take::<32>(bytes, &mut pos, Error::MalformedPublicSignals)?;
        let u256 = U256::from_be_bytes(env, &Bytes::from_array(env, &arr));
        sigs.push_back(Fr::from_u256(u256));
    }
    if pos != bytes.len() {
        return Err(Error::MalformedPublicSignals);
    }
    Ok(sigs)
}

fn verify_proof(env: &Env, vk: VerificationKey, proof: ProofData, pub_signals: Vec<Fr>) -> Result<bool, Error> {
    if pub_signals.len() + 1 != vk.ic.len() {
        return Err(Error::MalformedVerifyingKey);
    }
    let bls = env.crypto().bls12_381();
    let mut vk_x = vk.ic.get(0).unwrap();
    for (s, v) in pub_signals.iter().zip(vk.ic.iter().skip(1)) {
        let prod = bls.g1_mul(&v, &s);
        vk_x = bls.g1_add(&vk_x, &prod);
    }
    let neg_a = -proof.a;
    let vp1 = vec![env, neg_a, vk.alpha, vk_x, proof.c];
    let vp2 = vec![env, proof.b, vk.beta, vk.gamma, vk.delta];
    Ok(bls.pairing_check(vp1, vp2))
}

/// Raw 32-byte big-endian value of public signal `idx` (0-based), for
/// root-equality and nullifier bookkeeping without field-element round-trips.
fn signal_bytes32(env: &Env, pub_signals_bytes: &Bytes, idx: u32) -> Result<BytesN<32>, Error> {
    let mut pos = 0u32;
    let len = u32::from_be_bytes(take::<4>(pub_signals_bytes, &mut pos, Error::MalformedPublicSignals)?);
    if idx >= len {
        return Err(Error::MalformedPublicSignals);
    }
    pos += idx * 32;
    let arr = take::<32>(pub_signals_bytes, &mut pos, Error::MalformedPublicSignals)?;
    Ok(BytesN::from_array(env, &arr))
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct ZkGatekeeper;

#[contractimpl]
impl ZkGatekeeper {
    /// One-time init: set the circuit's verification key and the issuer/admin.
    pub fn init(env: Env, admin: Address, vk_bytes: Bytes) -> Result<(), Error> {
        if env.storage().instance().has(&ADMIN) {
            return Err(Error::AlreadyInitialized);
        }
        let _ = VerificationKey::from_bytes(&env, &vk_bytes)?;
        env.storage().instance().set(&ADMIN, &admin);
        env.storage().instance().set(&VK_KEY, &vk_bytes);
        env.storage().instance().set(&GRANTS, &0u32);
        Ok(())
    }

    /// Issuer publishes / rotates the credential-set Merkle root (admin only).
    pub fn set_root(env: Env, root: BytesN<32>) -> Result<(), Error> {
        let admin: Address = env.storage().instance().get(&ADMIN).ok_or(Error::NotInitialized)?;
        admin.require_auth();
        env.storage().instance().set(&ROOT, &root);
        env.events().publish((symbol_short!("root"),), root);
        Ok(())
    }

    /// Current committed credential-set root.
    pub fn get_root(env: Env) -> Result<BytesN<32>, Error> {
        env.storage().instance().get(&ROOT).ok_or(Error::RootNotSet)
    }

    /// Claim access: verify the ZK membership proof, check the proof's root
    /// matches the committed root, burn the nullifier. Anyone may call —
    /// the proof, not the caller's identity, is what grants access.
    pub fn claim_access(
        env: Env,
        proof_bytes: Bytes,
        pub_signals_bytes: Bytes,
        claim_id: u64,
    ) -> Result<BytesN<32>, Error> {
        let vk_bytes: Bytes = env.storage().instance().get(&VK_KEY).ok_or(Error::VerificationKeyNotSet)?;
        let committed_root: BytesN<32> = env.storage().instance().get(&ROOT).ok_or(Error::RootNotSet)?;

        let vk = VerificationKey::from_bytes(&env, &vk_bytes)?;
        let proof = ProofData::from_bytes(&env, &proof_bytes)?;
        let sigs = parse_public_signals(&env, &pub_signals_bytes)?;
        if sigs.len() != 3 {
            return Err(Error::MalformedPublicSignals);
        }

        // 1) the cryptographic proof itself
        if !verify_proof(&env, vk, proof, sigs)? {
            return Err(Error::ProofInvalid);
        }
        // 2) the proof must be against the issuer's committed root (signal [1])
        let proof_root = signal_bytes32(&env, &pub_signals_bytes, 1)?;
        if proof_root != committed_root {
            return Err(Error::RootMismatch);
        }
        // 3) the claimId baked into the proof (signal [2]) must match the call
        let claim_sig = signal_bytes32(&env, &pub_signals_bytes, 2)?;
        let mut want = [0u8; 32];
        want[24..].copy_from_slice(&claim_id.to_be_bytes());
        if claim_sig != BytesN::from_array(&env, &want) {
            return Err(Error::MalformedPublicSignals);
        }
        // 4) one credential, one claim: burn the nullifier (signal [0])
        let nullifier = signal_bytes32(&env, &pub_signals_bytes, 0)?;
        if env.storage().persistent().has(&nullifier) {
            return Err(Error::NullifierAlreadySpent);
        }

        let grant = AccessGrant {
            nullifier: nullifier.clone(),
            claim_id,
            ledger: env.ledger().sequence(),
            timestamp: env.ledger().timestamp(),
        };
        env.storage().persistent().set(&nullifier, &grant);
        let n: u32 = env.storage().instance().get(&GRANTS).unwrap_or(0);
        env.storage().instance().set(&GRANTS, &(n + 1));
        env.events().publish((symbol_short!("granted"), claim_id), nullifier.clone());
        Ok(nullifier)
    }

    /// Has this nullifier already been used?
    pub fn is_spent(env: Env, nullifier: BytesN<32>) -> bool {
        env.storage().persistent().has(&nullifier)
    }

    /// Total number of access grants issued.
    pub fn grant_count(env: Env) -> u32 {
        env.storage().instance().get(&GRANTS).unwrap_or(0)
    }
}

#[cfg(test)]
mod test;
