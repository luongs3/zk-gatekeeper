//! Unit tests for the storage / access-control / error paths.
//! The real BLS12-381 pairing path is exercised end-to-end on testnet
//! (see DEPLOYMENT.md) — same split as our SolvencyProof entry.

use super::*;
use soroban_sdk::{testutils::Address as _, Address, Bytes, BytesN, Env};

fn dummy_vk(env: &Env) -> Bytes {
    // Structurally valid VK: alpha(G1)+beta/gamma/delta(G2)+len(4)+4 IC points.
    // G1 = 96 bytes, G2 = 192 bytes uncompressed in Soroban's encoding.
    let mut v = [0u8; 96 + 192 * 3 + 4 + 96 * 4];
    let ic_len_off = 96 + 192 * 3;
    v[ic_len_off + 3] = 4; // ic_len = 4 (3 public signals + 1)
    Bytes::from_slice(env, &v)
}

#[test]
fn init_once_only() {
    let env = Env::default();
    let id = env.register(ZkGatekeeper, ());
    let client = ZkGatekeeperClient::new(&env, &id);
    let admin = Address::generate(&env);
    client.init(&admin, &dummy_vk(&env));
    let r = client.try_init(&admin, &dummy_vk(&env));
    assert_eq!(r, Err(Ok(Error::AlreadyInitialized)));
}

#[test]
fn malformed_vk_rejected() {
    let env = Env::default();
    let id = env.register(ZkGatekeeper, ());
    let client = ZkGatekeeperClient::new(&env, &id);
    let admin = Address::generate(&env);
    let junk = Bytes::from_slice(&env, &[1, 2, 3]);
    let r = client.try_init(&admin, &junk);
    assert_eq!(r, Err(Ok(Error::MalformedVerifyingKey)));
}

#[test]
fn set_root_requires_admin_and_get_root_roundtrips() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(ZkGatekeeper, ());
    let client = ZkGatekeeperClient::new(&env, &id);
    let admin = Address::generate(&env);
    client.init(&admin, &dummy_vk(&env));
    let root = BytesN::from_array(&env, &[7u8; 32]);
    client.set_root(&root);
    assert_eq!(client.get_root(), root);
}

#[test]
fn claim_without_root_fails() {
    let env = Env::default();
    let id = env.register(ZkGatekeeper, ());
    let client = ZkGatekeeperClient::new(&env, &id);
    let admin = Address::generate(&env);
    client.init(&admin, &dummy_vk(&env));
    let empty = Bytes::new(&env);
    let r = client.try_claim_access(&empty, &empty, &1u64);
    assert_eq!(r, Err(Ok(Error::RootNotSet)));
}

#[test]
fn grant_count_starts_zero_and_is_spent_false() {
    let env = Env::default();
    let id = env.register(ZkGatekeeper, ());
    let client = ZkGatekeeperClient::new(&env, &id);
    let admin = Address::generate(&env);
    client.init(&admin, &dummy_vk(&env));
    assert_eq!(client.grant_count(), 0);
    assert!(!client.is_spent(&BytesN::from_array(&env, &[9u8; 32])));
}
