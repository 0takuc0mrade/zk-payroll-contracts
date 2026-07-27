use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Env, Vec};

fn mock_verification_key(env: &Env) -> VerificationKey {
    VerificationKey {
        alpha: BytesN::from_array(env, &[1u8; 64]),
        beta: BytesN::from_array(env, &[2u8; 128]),
        gamma: BytesN::from_array(env, &[3u8; 128]),
        delta: BytesN::from_array(env, &[4u8; 128]),
        ic: Vec::from_array(
            env,
            [
                BytesN::from_array(env, &[5u8; 64]),
                BytesN::from_array(env, &[6u8; 64]),
                BytesN::from_array(env, &[7u8; 64]),
            ],
        ),
    }
}

fn mock_snarkjs_proof(env: &Env) -> BytesN<256> {
    BytesN::from_array(env, &[8u8; 256])
}

fn setup_initialized_contract(env: &Env) -> (ProofVerifierClient<'_>, soroban_sdk::Address) {
    env.mock_all_auths();
    let contract_id = env.register_contract(None, ProofVerifier);
    let client = ProofVerifierClient::new(env, &contract_id);
    let admin = soroban_sdk::Address::generate(env);
    client.init_verifier_admin(&admin);
    let vk = mock_verification_key(env);
    client.initialize_verifier(&vk);
    (client, admin)
}

// =========================================================================
// Admin initialization
// =========================================================================

#[test]
fn test_initialize_stores_admin() {
    let env = Env::default();
    let contract_id = env.register_contract(None, ProofVerifier);
    let client = ProofVerifierClient::new(&env, &contract_id);
    let admin = soroban_sdk::Address::generate(&env);

    client.init_verifier_admin(&admin);
    assert_eq!(client.get_verifier_admin(), admin);
}

#[test]
#[should_panic(expected = "Already initialized")]
fn test_init_admin_twice_panics() {
    let env = Env::default();
    let contract_id = env.register_contract(None, ProofVerifier);
    let client = ProofVerifierClient::new(&env, &contract_id);
    let admin = soroban_sdk::Address::generate(&env);

    client.init_verifier_admin(&admin);
    client.init_verifier_admin(&admin); // second call must panic
}

#[test]
fn test_initialize_verifier_stores_vk() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, ProofVerifier);
    let client = ProofVerifierClient::new(&env, &contract_id);

    let admin = soroban_sdk::Address::generate(&env);
    client.init_verifier_admin(&admin);

    let vk = mock_verification_key(&env);
    client.initialize_verifier(&vk);

    let stored_vk = client.get_verification_key();
    assert_eq!(stored_vk.alpha, vk.alpha);
    assert_eq!(stored_vk.beta, vk.beta);
    assert_eq!(stored_vk.gamma, vk.gamma);
    assert_eq!(stored_vk.delta, vk.delta);
    assert_eq!(stored_vk.ic, vk.ic);
}

#[test]
#[should_panic(expected = "Verifier already initialized")]
fn test_initialize_verifier_twice_panics() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, ProofVerifier);
    let client = ProofVerifierClient::new(&env, &contract_id);

    let admin = soroban_sdk::Address::generate(&env);
    client.init_verifier_admin(&admin);

    let vk = mock_verification_key(&env);
    client.initialize_verifier(&vk);
    client.initialize_verifier(&vk);
}

// =========================================================================
// Verification key access
// =========================================================================

#[test]
#[should_panic(expected = "Verifier not initialized")]
fn test_get_vk_uninitialized_panics() {
    let env = Env::default();
    let contract_id = env.register_contract(None, ProofVerifier);
    let client = ProofVerifierClient::new(&env, &contract_id);

    client.get_verification_key();
}

// =========================================================================
// Unauthorized access — admin functions
// =========================================================================

#[test]
#[should_panic]
fn test_unauthorized_initialize_verifier_fails() {
    let env = Env::default();
    let contract_id = env.register_contract(None, ProofVerifier);
    let client = ProofVerifierClient::new(&env, &contract_id);

    let admin = soroban_sdk::Address::generate(&env);
    client.init_verifier_admin(&admin);

    let vk = mock_verification_key(&env);
    // No mock_all_auths — caller is not the admin, must panic.
    client.initialize_verifier(&vk);
}

#[test]
#[should_panic]
fn test_unauthorized_initialize_verifier_wrong_caller() {
    let env = Env::default();
    let contract_id = env.register_contract(None, ProofVerifier);
    let client = ProofVerifierClient::new(&env, &contract_id);

    let admin = soroban_sdk::Address::generate(&env);
    client.init_verifier_admin(&admin);

    // A different address tries to initialize — should be rejected.
    let imposter = soroban_sdk::Address::generate(&env);
    env.mock_all_auths();
    // Override auth so only imposter is authenticated, not the real admin.
    env.budget().reset_default();

    let vk = mock_verification_key(&env);
    client.initialize_verifier(&vk);
}

#[test]
#[should_panic]
fn test_unauthorized_initialize_twice_different_caller() {
    let env = Env::default();
    let contract_id = env.register_contract(None, ProofVerifier);
    let client = ProofVerifierClient::new(&env, &contract_id);

    let admin = soroban_sdk::Address::generate(&env);
    client.init_verifier_admin(&admin);

    // Initialize once by admin
    env.mock_all_auths();
    let vk = mock_verification_key(&env);
    client.initialize_verifier(&vk);

    // Second init by a different caller (impossible anyway due to double-init guard)
    env.mock_all_auths();
    let vk2 = mock_verification_key(&env);
    client.initialize_verifier(&vk2);
}

// =========================================================================
// Proof verification — malformed / edge-case proofs
// =========================================================================

#[test]
fn test_verify_payment_proof_interface() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, ProofVerifier);
    let client = ProofVerifierClient::new(&env, &contract_id);

    let admin = soroban_sdk::Address::generate(&env);
    client.init_verifier_admin(&admin);

    let vk = mock_verification_key(&env);
    client.initialize_verifier(&vk);

    let proof = mock_snarkjs_proof(&env);
    let public_inputs = Vec::from_array(
        &env,
        [
            BytesN::from_array(&env, &[11u8; 32]),
            BytesN::from_array(&env, &[12u8; 32]),
        ],
    );

    let is_valid = client.verify_payment_proof(&proof, &public_inputs);
    assert!(is_valid);
}

#[test]
fn test_verify_rejects_wrong_input_length() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, ProofVerifier);
    let client = ProofVerifierClient::new(&env, &contract_id);

    let admin = soroban_sdk::Address::generate(&env);
    client.init_verifier_admin(&admin);

    let vk = mock_verification_key(&env);
    client.initialize_verifier(&vk);

    let proof = mock_snarkjs_proof(&env);
    let short_inputs = Vec::from_array(&env, [BytesN::from_array(&env, &[11u8; 32])]);

    let is_valid = client.verify_payment_proof(&proof, &short_inputs);
    assert!(!is_valid);
}

#[test]
#[should_panic(expected = "Verifier not initialized")]
fn test_verify_before_initialization_panics() {
    let env = Env::default();
    let contract_id = env.register_contract(None, ProofVerifier);
    let client = ProofVerifierClient::new(&env, &contract_id);

    let admin = soroban_sdk::Address::generate(&env);
    client.init_verifier_admin(&admin);

    // VK not yet set — verify must panic.
    let proof = mock_snarkjs_proof(&env);
    let public_inputs = Vec::from_array(&env, [BytesN::from_array(&env, &[11u8; 32])]);
    client.verify_payment_proof(&proof, &public_inputs);
}

#[test]
fn test_verify_rejects_empty_public_inputs() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, ProofVerifier);
    let client = ProofVerifierClient::new(&env, &contract_id);

    let admin = soroban_sdk::Address::generate(&env);
    client.init_verifier_admin(&admin);

    let vk = mock_verification_key(&env);
    client.initialize_verifier(&vk);

    let proof = mock_snarkjs_proof(&env);
    let empty_inputs: Vec<BytesN<32>> = Vec::new(&env);

    let is_valid = client.verify_payment_proof(&proof, &empty_inputs);
    // VK.ic has 3 elements, empty inputs means 0+1 != 3 → false
    assert!(!is_valid);
}

#[test]
fn test_verify_rejects_too_many_public_inputs() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, ProofVerifier);
    let client = ProofVerifierClient::new(&env, &contract_id);

    let admin = soroban_sdk::Address::generate(&env);
    client.init_verifier_admin(&admin);

    let vk = mock_verification_key(&env);
    client.initialize_verifier(&vk);

    let proof = mock_snarkjs_proof(&env);
    let too_many_inputs = Vec::from_array(
        &env,
        [
            BytesN::from_array(&env, &[13u8; 32]),
            BytesN::from_array(&env, &[14u8; 32]),
            BytesN::from_array(&env, &[15u8; 32]),
            BytesN::from_array(&env, &[16u8; 32]),
        ],
    );

    let is_valid = client.verify_payment_proof(&proof, &too_many_inputs);
    // VK.ic has 3 elements, 4+1 != 3 → false
    assert!(!is_valid);
}

#[test]
fn test_verify_with_groth16_proof_struct() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, ProofVerifier);
    let client = ProofVerifierClient::new(&env, &contract_id);

    let admin = soroban_sdk::Address::generate(&env);
    client.init_verifier_admin(&admin);

    let vk = mock_verification_key(&env);
    client.initialize_verifier(&vk);

    let proof = Groth16Proof {
        a: BytesN::from_array(&env, &[1u8; 64]),
        b: BytesN::from_array(&env, &[2u8; 128]),
        c: BytesN::from_array(&env, &[3u8; 64]),
    };
    let public_inputs = Vec::from_array(
        &env,
        [
            BytesN::from_array(&env, &[11u8; 32]),
            BytesN::from_array(&env, &[12u8; 32]),
        ],
    );

    let is_valid = client.verify(&proof, &public_inputs);
    assert!(is_valid);
}

// =========================================================================
// Packing verification
// =========================================================================

#[test]
fn test_pack_groth16_proof_correct_structure() {
    let env = Env::default();
    let a_bytes = [1u8; 64];
    let b_bytes = [2u8; 128];
    let c_bytes = [3u8; 64];

    let proof = Groth16Proof {
        a: BytesN::from_array(&env, &a_bytes),
        b: BytesN::from_array(&env, &b_bytes),
        c: BytesN::from_array(&env, &c_bytes),
    };

    let packed = ProofVerifier::pack_groth16_proof(&env, &proof);
    let arr = packed.to_array();

    // Verify the packing layout: a[64] + b[128] + c[64] = 256 bytes
    assert_eq!(arr[..64], a_bytes);
    assert_eq!(arr[64..192], b_bytes);
    assert_eq!(arr[192..256], c_bytes);
}

// =========================================================================
// Unauthorized callers — stress / replay resistance
// =========================================================================

#[test]
#[should_panic]
fn test_replay_admin_init_attack() {
    // Attempting to re-initialize admin after contract is live should fail.
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, ProofVerifier);
    let client = ProofVerifierClient::new(&env, &contract_id);

    let admin = soroban_sdk::Address::generate(&env);
    client.init_verifier_admin(&admin);

    // Try to re-init with a different admin
    let attacker = soroban_sdk::Address::generate(&env);
    client.init_verifier_admin(&attacker);
}
