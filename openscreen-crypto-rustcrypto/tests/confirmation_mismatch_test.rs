// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Test to reproduce the confirmation mismatch bug
//!
//! This test simulates the E2E flow and verifies that:
//! 1. Each side computes their OWN confirmation correctly
//! 2. Each side sends THEIR OWN confirmation (not the peer's)
//! 3. Each side can verify the PEER's confirmation

use openscreen_crypto::{CryptoOpKind, CryptoProvider, CryptoRequest, Spake2Operation};
use openscreen_crypto_rustcrypto::RustCryptoCryptoProvider;

#[test]
fn test_confirmation_mismatch() {
    // Setup: Same password, different roles
    let password = b"test-password";
    let mut initiator = RustCryptoCryptoProvider::new();
    let mut responder = RustCryptoCryptoProvider::new();

    // Step 1: Both start SPAKE2
    let init_start = initiator
        .execute(&CryptoRequest {
            op_id: 1,
            kind: CryptoOpKind::Spake2(Spake2Operation::Start {
                password_id: None,
                password,
                is_responder: false, // Initiator
            }),
        })
        .unwrap();

    let resp_start = responder
        .execute(&CryptoRequest {
            op_id: 2,
            kind: CryptoOpKind::Spake2(Spake2Operation::Start {
                password_id: None,
                password,
                is_responder: true, // Responder
            }),
        })
        .unwrap();

    // Step 2: Build a test transcript (90 bytes like in real E2E)
    let transcript: [u8; 90] = [b'A'; 90]; // Simple 90-byte transcript

    let init_tls_fp = [1u8; 32];
    let resp_tls_fp = [2u8; 32];

    // Step 3: Initiator calls FinishWithConfirmation
    let init_finish = initiator
        .execute(&CryptoRequest {
            op_id: 3,
            kind: CryptoOpKind::Spake2(Spake2Operation::FinishWithConfirmation {
                state: &init_start.data,
                peer_public: &resp_start.data,
                message_transcript: &transcript,
                my_tls_fingerprint: &init_tls_fp,
                peer_tls_fingerprint: &resp_tls_fp,
                is_responder: false,
            }),
        })
        .unwrap();

    // Step 4: Responder calls FinishWithConfirmation
    let resp_finish = responder
        .execute(&CryptoRequest {
            op_id: 4,
            kind: CryptoOpKind::Spake2(Spake2Operation::FinishWithConfirmation {
                state: &resp_start.data,
                peer_public: &init_start.data,
                message_transcript: &transcript, // SAME transcript
                my_tls_fingerprint: &resp_tls_fp,
                peer_tls_fingerprint: &init_tls_fp,
                is_responder: true,
            }),
        })
        .unwrap();

    // Step 5: Extract confirmations and keys
    // Result = shared_secret (32) || confirmation (32) || initiator_key (32) || responder_key (32)
    let init_shared_secret = &init_finish.data[0..32];
    let init_confirmation = &init_finish.data[32..64];
    let init_initiator_key = &init_finish.data[64..96];
    let _init_responder_key = &init_finish.data[96..128];

    let resp_shared_secret = &resp_finish.data[0..32];
    let resp_confirmation = &resp_finish.data[32..64];
    let _resp_initiator_key = &resp_finish.data[64..96];
    let _resp_responder_key = &resp_finish.data[96..128];

    // Print what each side computed
    println!("Initiator confirmation: {:02x?}", &init_confirmation[..8]);
    println!("Responder confirmation: {:02x?}", &resp_confirmation[..8]);

    // Step 6: Verify shared secrets match
    assert_eq!(
        init_shared_secret, resp_shared_secret,
        "BUG: Shared secrets don't match!"
    );

    // Step 7: Verify confirmations are DIFFERENT (role differentiation)
    assert_ne!(
        init_confirmation, resp_confirmation,
        "BUG: Confirmations should be different for different roles!"
    );

    // Step 8: SIMULATION OF THE BUG
    // In the real E2E test, the receiver expects init_confirmation but receives resp_confirmation
    // This simulates what happens when the initiator accidentally sends the responder's confirmation

    println!("\n=== SIMULATING THE BUG ===");
    println!(
        "Responder expects to receive: {:02x?}",
        &init_confirmation[..8]
    );
    println!("But somehow receives: {:02x?}", &resp_confirmation[..8]);

    // Construct verification context: transcript || initiator_key
    let mut verify_context = heapless::Vec::<u8, 512>::new();
    verify_context.extend_from_slice(&transcript).unwrap();
    verify_context
        .extend_from_slice(init_initiator_key)
        .unwrap();

    // Try to verify with WRONG confirmation
    let wrong_verify = responder.execute(&CryptoRequest {
        op_id: 5,
        kind: CryptoOpKind::Spake2(Spake2Operation::VerifyConfirmation {
            context: &verify_context, // Initiator's context (contains initiator's key)
            peer_confirmation: resp_confirmation, // BUG: Using responder's conf instead of initiator's!
        }),
    });

    // This MUST fail
    assert!(
        wrong_verify.is_err(),
        "BUG REPRODUCED: Wrong confirmation should fail verification!"
    );

    // Step 9: Verify with CORRECT confirmations (this should pass)
    println!("\n=== CORRECT VERIFICATION ===");

    // Responder verifies initiator's confirmation
    let correct_verify = responder.execute(&CryptoRequest {
        op_id: 6,
        kind: CryptoOpKind::Spake2(Spake2Operation::VerifyConfirmation {
            context: &verify_context, // Same context: transcript || initiator's key
            peer_confirmation: init_confirmation, // CORRECT: Initiator's confirmation
        }),
    });

    assert!(
        correct_verify.is_ok(),
        "Correct confirmation MUST verify successfully"
    );

    println!("OK: TEST PASSED: Bug reproduced and correct behavior verified");
}
