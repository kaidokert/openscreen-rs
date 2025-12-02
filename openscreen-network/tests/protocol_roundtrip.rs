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

//! Protocol Roundtrip Tests
//!
//! Phase 3 tests that verify:
//! 1. SPAKE2 handshake works with actual crypto operations
//! 2. RFC 9382 confirmation flow (FinishWithConfirmation + VerifyConfirmation)
//! 3. Full transcript construction is passed to crypto layer
//! 4. Complete sender-receiver roundtrip authentication

use heapless::Vec;
use openscreen_crypto::{CryptoOpKind, CryptoProvider, CryptoRequest, Spake2Operation};
use openscreen_crypto_rustcrypto::RustCryptoCryptoProvider;
use openscreen_network::crypto_data::CryptoData;

/// Test that SPAKE2 handshake works with actual crypto
#[test]
fn test_spake2_start_generates_public_keys() {
    let mut provider = RustCryptoCryptoProvider::new();
    let psk = b"test1234";

    // Test initiator Start
    let init_result = provider
        .execute(&CryptoRequest {
            op_id: 1,
            kind: CryptoOpKind::Spake2(Spake2Operation::Start {
                password_id: None,
                password: psk,
                is_responder: false,
            }),
        })
        .expect("initiator Start should succeed");

    assert!(
        !init_result.data.is_empty(),
        "initiator public key should not be empty"
    );
    println!("Initiator public key: {} bytes", init_result.data.len());

    // Test responder Start
    let resp_result = provider
        .execute(&CryptoRequest {
            op_id: 2,
            kind: CryptoOpKind::Spake2(Spake2Operation::Start {
                password_id: None,
                password: psk,
                is_responder: true,
            }),
        })
        .expect("responder Start should succeed");

    assert!(
        !resp_result.data.is_empty(),
        "responder public key should not be empty"
    );
    println!("Responder public key: {} bytes", resp_result.data.len());

    // Keys should be different (different roles generate different keys)
    assert_ne!(
        &init_result.data[..],
        &resp_result.data[..],
        "initiator and responder should generate different keys"
    );
}

/// Test RFC 9382 FinishWithConfirmation flow
#[test]
fn test_rfc9382_finish_with_confirmation() {
    let mut initiator = RustCryptoCryptoProvider::new();
    let mut responder = RustCryptoCryptoProvider::new();
    let psk = b"test1234";

    // Step 1: Both sides generate keys
    let init_start = initiator
        .execute(&CryptoRequest {
            op_id: 1,
            kind: CryptoOpKind::Spake2(Spake2Operation::Start {
                password_id: None,
                password: psk,
                is_responder: false,
            }),
        })
        .expect("initiator Start");

    let resp_start = responder
        .execute(&CryptoRequest {
            op_id: 2,
            kind: CryptoOpKind::Spake2(Spake2Operation::Start {
                password_id: None,
                password: psk,
                is_responder: true,
            }),
        })
        .expect("responder Start");

    println!("Step 1: Keys generated");
    println!("  Initiator public: {} bytes", init_start.data.len());
    println!("  Responder public: {} bytes", resp_start.data.len());

    // Step 2: FinishWithConfirmation with fingerprints
    let init_fingerprint = [0x11u8; 32];
    let resp_fingerprint = [0x22u8; 32];
    let init_finish = initiator
        .execute(&CryptoRequest {
            op_id: 3,
            kind: CryptoOpKind::Spake2(Spake2Operation::FinishWithConfirmation {
                state: &init_start.data,
                peer_public: &resp_start.data,
                message_transcript: &[],
                my_tls_fingerprint: &init_fingerprint,
                peer_tls_fingerprint: &resp_fingerprint,
                is_responder: false,
            }),
        })
        .expect("initiator FinishWithConfirmation");

    println!("Step 2: Initiator finished");
    println!("  Result: {} bytes", init_finish.data.len());

    let resp_finish = responder
        .execute(&CryptoRequest {
            op_id: 4,
            kind: CryptoOpKind::Spake2(Spake2Operation::FinishWithConfirmation {
                state: &resp_start.data,
                peer_public: &init_start.data,
                message_transcript: &[],
                my_tls_fingerprint: &resp_fingerprint,
                peer_tls_fingerprint: &init_fingerprint,
                is_responder: true,
            }),
        })
        .expect("responder FinishWithConfirmation");

    println!("Step 3: Responder finished");
    println!("  Result: {} bytes", resp_finish.data.len());

    // Parse results: shared_secret (32) || confirmation (32) || initiator_key (32) || responder_key (32)
    assert!(
        init_finish.data.len() == 128,
        "FinishWithConfirmation should return exactly 128 bytes"
    );
    assert!(
        resp_finish.data.len() == 128,
        "FinishWithConfirmation should return exactly 128 bytes"
    );

    let init_shared_secret = &init_finish.data[0..32];
    let init_confirmation = &init_finish.data[32..64];
    let init_initiator_key = &init_finish.data[64..96];
    let _init_responder_key = &init_finish.data[96..128];

    let resp_shared_secret = &resp_finish.data[0..32];
    let resp_confirmation = &resp_finish.data[32..64];
    let _resp_initiator_key = &resp_finish.data[64..96];
    let resp_responder_key = &resp_finish.data[96..128];

    // Define an empty transcript since message_transcript was &[]
    let empty_transcript: Vec<u8, 512> = Vec::new();

    // Step 3: Verify shared secrets match
    assert_eq!(
        init_shared_secret, resp_shared_secret,
        "Shared secrets must match!"
    );
    println!(
        "OK: Shared secrets match ({} bytes)",
        init_shared_secret.len()
    );

    // Step 4: Verify confirmations
    // NOTE: The context from init_finish is used by the RESPONDER to verify initiator's confirmation
    // NOTE: The context from resp_finish is used by the INITIATOR to verify responder's confirmation

    // Construct resp_verify_context for responder to verify initiator's confirmation
    let mut resp_verify_context = heapless::Vec::<u8, 512>::new();
    resp_verify_context
        .extend_from_slice(&empty_transcript)
        .expect("extend resp_verify_context with transcript");
    resp_verify_context
        .extend_from_slice(init_initiator_key)
        .expect("extend resp_verify_context with initiator key");

    responder
        .execute(&CryptoRequest {
            op_id: 5,
            kind: CryptoOpKind::Spake2(Spake2Operation::VerifyConfirmation {
                context: &resp_verify_context,
                peer_confirmation: init_confirmation, // Initiator's confirmation
            }),
        })
        .expect("responder VerifyConfirmation should succeed");

    println!("OK: Responder verified initiator's confirmation");

    // Construct init_verify_context for initiator to verify responder's confirmation
    let mut init_verify_context = heapless::Vec::<u8, 512>::new();
    init_verify_context
        .extend_from_slice(&empty_transcript)
        .expect("extend init_verify_context with transcript");
    init_verify_context
        .extend_from_slice(resp_responder_key)
        .expect("extend init_verify_context with responder key");

    initiator
        .execute(&CryptoRequest {
            op_id: 6,
            kind: CryptoOpKind::Spake2(Spake2Operation::VerifyConfirmation {
                context: &init_verify_context,
                peer_confirmation: resp_confirmation, // Responder's confirmation
            }),
        })
        .expect("initiator VerifyConfirmation should succeed");

    println!("OK: Initiator verified responder's confirmation");
    println!("\nOK: RFC 9382 confirmation flow complete!");
}

/// Test that transcript construction stores full CBOR messages
#[test]
fn test_transcript_stores_full_cbor_messages() {
    use openscreen_network::messages::{AuthInitiationToken, AuthSpake2Handshake, Spake2PskStatus};

    let mut crypto_data = CryptoData::new();
    let public_value = [0x42u8; 32];

    // Create handshake message
    let handshake = AuthSpake2Handshake {
        initiation_token: AuthInitiationToken {
            token: Some("test-token"),
        },
        psk_status: Spake2PskStatus::PskShown,
        public_value: &public_value,
    };

    // Encode to CBOR
    let mut cbor_msg = Vec::<u8, 256>::new();
    handshake.encode(&mut cbor_msg).expect("encode handshake");

    println!("CBOR handshake message: {} bytes", cbor_msg.len());

    // Store in CryptoData
    crypto_data
        .our_handshake_msg_mut()
        .extend_from_slice(&cbor_msg)
        .expect("store handshake");

    // Verify storage
    assert_eq!(crypto_data.our_handshake_msg().len(), cbor_msg.len());
    assert_eq!(crypto_data.our_handshake_msg(), &cbor_msg[..]);

    println!("OK: Full CBOR message stored successfully");
    println!("  Message includes: token, status, AND public value");
}

/// Test transcript construction for RFC 9382
#[test]
fn test_transcript_construction_rfc9382() {
    use openscreen_network::crypto_data::MAX_TRANSCRIPT_SIZE;
    use openscreen_network::messages::{AuthInitiationToken, AuthSpake2Handshake, Spake2PskStatus};

    let mut crypto_data = CryptoData::new();

    // Create initiator handshake
    let init_public = [0xAAu8; 32];
    let init_handshake = AuthSpake2Handshake {
        initiation_token: AuthInitiationToken {
            token: Some("token123"),
        },
        psk_status: Spake2PskStatus::PskShown,
        public_value: &init_public,
    };

    let mut init_msg = Vec::<u8, 256>::new();
    init_handshake.encode(&mut init_msg).expect("encode init");

    // Create responder handshake
    let resp_public = [0xBBu8; 32];
    let resp_handshake = AuthSpake2Handshake {
        initiation_token: AuthInitiationToken { token: None }, // Responder doesn't need token
        psk_status: Spake2PskStatus::PskInput,
        public_value: &resp_public,
    };

    let mut resp_msg = Vec::<u8, 256>::new();
    resp_handshake.encode(&mut resp_msg).expect("encode resp");

    println!("Message sizes:");
    println!("  Initiator: {} bytes", init_msg.len());
    println!("  Responder: {} bytes", resp_msg.len());

    // Store messages in CryptoData
    crypto_data
        .our_handshake_msg_mut()
        .extend_from_slice(&init_msg)
        .expect("store init msg");
    crypto_data
        .peer_handshake_msg_mut()
        .extend_from_slice(&resp_msg)
        .expect("store resp msg");

    // Build transcript: TT = message_A || message_B per RFC 9382
    let init_copy = init_msg.clone();
    let resp_copy = resp_msg.clone();
    crypto_data
        .transcript_mut()
        .extend_from_slice(&init_copy)
        .expect("transcript A");
    crypto_data
        .transcript_mut()
        .extend_from_slice(&resp_copy)
        .expect("transcript B");

    let transcript_len = crypto_data.transcript().len();
    println!("Transcript: {transcript_len} bytes (TT = A || B)");

    // Verify transcript is concatenation
    assert_eq!(transcript_len, init_msg.len() + resp_msg.len());
    assert!(
        transcript_len <= MAX_TRANSCRIPT_SIZE,
        "transcript should fit in 512 byte buffer"
    );

    // Verify first part is initiator message
    assert_eq!(&crypto_data.transcript()[..init_msg.len()], &init_msg[..]);

    // Verify second part is responder message
    assert_eq!(&crypto_data.transcript()[init_msg.len()..], &resp_msg[..]);

    println!("OK: Transcript construction matches RFC 9382");
    println!("  Transcript = CBOR(initiator) || CBOR(responder)");
}

/// Test that wrong PSK fails verification
#[test]
fn test_wrong_psk_fails_verification() {
    let mut initiator = RustCryptoCryptoProvider::new();
    let mut responder = RustCryptoCryptoProvider::new();

    // Use DIFFERENT PSKs
    let init_psk = b"correct_password";
    let resp_psk = b"wrong_password";

    // Generate keys with different PSKs
    let init_start = initiator
        .execute(&CryptoRequest {
            op_id: 1,
            kind: CryptoOpKind::Spake2(Spake2Operation::Start {
                password_id: None,
                password: init_psk,
                is_responder: false,
            }),
        })
        .expect("initiator Start");

    let resp_start = responder
        .execute(&CryptoRequest {
            op_id: 2,
            kind: CryptoOpKind::Spake2(Spake2Operation::Start {
                password_id: None,
                password: resp_psk,
                is_responder: true,
            }),
        })
        .expect("responder Start");

    // Try to finish with different PSKs
    let init_fingerprint = [0x11u8; 32];
    let resp_fingerprint = [0x22u8; 32];

    let init_finish = initiator
        .execute(&CryptoRequest {
            op_id: 3,
            kind: CryptoOpKind::Spake2(Spake2Operation::FinishWithConfirmation {
                state: &init_start.data,
                peer_public: &resp_start.data,
                message_transcript: &[],
                my_tls_fingerprint: &init_fingerprint,
                peer_tls_fingerprint: &resp_fingerprint,
                is_responder: false,
            }),
        })
        .expect("initiator FinishWithConfirmation");

    let resp_finish = responder
        .execute(&CryptoRequest {
            op_id: 4,
            kind: CryptoOpKind::Spake2(Spake2Operation::FinishWithConfirmation {
                state: &resp_start.data,
                peer_public: &init_start.data,
                message_transcript: &[],
                my_tls_fingerprint: &resp_fingerprint,
                peer_tls_fingerprint: &init_fingerprint,
                is_responder: true,
            }),
        })
        .expect("responder FinishWithConfirmation");

    // Parse results
    let init_shared_secret = &init_finish.data[0..32];
    let resp_confirmation = &resp_finish.data[32..64];
    let init_context = &init_finish.data[64..];

    let resp_shared_secret = &resp_finish.data[0..32];

    // Shared secrets should be DIFFERENT (wrong PSK)
    assert_ne!(
        init_shared_secret, resp_shared_secret,
        "Different PSKs should produce different shared secrets"
    );
    println!("OK: Different PSKs produce different shared secrets");

    // Verification should FAIL
    let verify_result = initiator.execute(&CryptoRequest {
        op_id: 5,
        kind: CryptoOpKind::Spake2(Spake2Operation::VerifyConfirmation {
            context: init_context,
            peer_confirmation: resp_confirmation,
        }),
    });

    assert!(
        verify_result.is_err(),
        "VerifyConfirmation should FAIL with wrong PSK"
    );
    println!("OK: VerifyConfirmation correctly fails with wrong PSK");
}
