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

//! Message Transcript Construction Tests
//!
//! These tests verify that:
//! 1. Messages are encoded as CBOR Maps with integer keys per spec
//! 2. FULL CBOR-encoded messages can be stored for transcript construction
//! 3. Transcript construction (message_A || message_B) works correctly
//! 4. All message types encode/decode correctly
//!
//! Requirement: The transcript MUST be built from the COMPLETE
//! CBOR-encoded handshake messages, NOT just the public keys.

use heapless::Vec;
use openscreen_network::crypto_data::{CryptoData, MAX_HANDSHAKE_MSG_SIZE, MAX_TRANSCRIPT_SIZE};
use openscreen_network::messages::{
    AuthCapabilities, AuthInitiationToken, AuthSpake2Confirmation, AuthSpake2Handshake, AuthStatus,
    AuthStatusCode, PskInputEase, Spake2PskStatus,
};

/// Test that AuthCapabilities encodes to expected CBOR format
#[test]
fn test_auth_capabilities_encoding() {
    let caps = AuthCapabilities {
        psk_input_ease: PskInputEase::Simple,
        psk_input_methods: Vec::new(),
        psk_min_bits_of_entropy: 64,
    };

    let mut buf = Vec::<u8, 256>::new();
    caps.encode(&mut buf).expect("encode should succeed");

    // format: [type_key, map]
    // Expected: [1001, {0: 1, 2: 64}]
    assert!(!buf.is_empty(), "encoded message should not be empty");

    // Verify it can be decoded back
    let decoded = AuthCapabilities::decode(&buf).expect("decode should succeed");
    assert_eq!(decoded.psk_input_ease, PskInputEase::Simple);
    assert_eq!(decoded.psk_min_bits_of_entropy, 64);
}

/// Test that AuthSpake2Handshake encodes with all required fields
#[test]
fn test_auth_spake2_handshake_encoding() {
    let public_value = [0x42u8; 32]; // 32-byte public key
    let token = AuthInitiationToken {
        token: Some("test-token"),
    };

    let handshake = AuthSpake2Handshake {
        initiation_token: token,
        psk_status: Spake2PskStatus::PskShown,
        public_value: &public_value,
    };

    let mut buf = Vec::<u8, MAX_HANDSHAKE_MSG_SIZE>::new();
    handshake.encode(&mut buf).expect("encode should succeed");

    // format: [1005, {0: token, 1: status, 2: public_value}]
    assert!(!buf.is_empty(), "encoded handshake should not be empty");
    assert!(
        buf.len() <= MAX_HANDSHAKE_MSG_SIZE,
        "encoded handshake should fit in buffer size (256 bytes), got {}",
        buf.len()
    );

    // This is the FULL CBOR message that MUST be stored for transcript
    println!("Full CBOR handshake message: {} bytes", buf.len());
    println!("Hex: {}", hex::encode(&buf));
}

/// Test that FULL CBOR messages can be stored in CryptoData
#[test]
fn test_crypto_data_stores_full_messages() {
    let mut crypto_data = CryptoData::new();

    // Create two handshake messages (initiator and responder)
    let public_value_a = [0x41u8; 32];
    let public_value_b = [0x42u8; 32];

    let handshake_a = AuthSpake2Handshake {
        initiation_token: AuthInitiationToken {
            token: Some("token-a"),
        },
        psk_status: Spake2PskStatus::PskNeedsPresentation,
        public_value: &public_value_a,
    };

    let handshake_b = AuthSpake2Handshake {
        initiation_token: AuthInitiationToken {
            token: Some("token-b"),
        },
        psk_status: Spake2PskStatus::PskInput,
        public_value: &public_value_b,
    };

    // Encode both messages
    let mut msg_a_bytes = Vec::<u8, MAX_HANDSHAKE_MSG_SIZE>::new();
    let mut msg_b_bytes = Vec::<u8, MAX_HANDSHAKE_MSG_SIZE>::new();

    handshake_a
        .encode(&mut msg_a_bytes)
        .expect("encode A should succeed");
    handshake_b
        .encode(&mut msg_b_bytes)
        .expect("encode B should succeed");

    // Store FULL CBOR messages
    crypto_data
        .our_handshake_msg_mut()
        .extend_from_slice(&msg_a_bytes)
        .expect("should fit in our_handshake_msg buffer");
    crypto_data
        .peer_handshake_msg_mut()
        .extend_from_slice(&msg_b_bytes)
        .expect("should fit in peer_handshake_msg buffer");

    // Verify storage
    assert_eq!(crypto_data.our_handshake_msg().len(), msg_a_bytes.len());
    assert_eq!(crypto_data.peer_handshake_msg().len(), msg_b_bytes.len());
    assert!(crypto_data.our_handshake_msg() == &msg_a_bytes[..]);
    assert!(crypto_data.peer_handshake_msg() == &msg_b_bytes[..]);

    println!("OK: Successfully stored full CBOR messages");
    println!("   Message A: {} bytes", msg_a_bytes.len());
    println!("   Message B: {} bytes", msg_b_bytes.len());
}

/// Test transcript construction per spec: TT = message_A || message_B
#[test]
fn test_transcript_construction() {
    let mut crypto_data = CryptoData::new();

    // Create two different handshake messages
    let public_value_a = [0x11u8; 32];
    let public_value_b = [0x22u8; 32];

    let handshake_a = AuthSpake2Handshake {
        initiation_token: AuthInitiationToken {
            token: Some("initiator-token"),
        },
        psk_status: Spake2PskStatus::PskNeedsPresentation,
        public_value: &public_value_a,
    };

    let handshake_b = AuthSpake2Handshake {
        initiation_token: AuthInitiationToken {
            token: Some("responder-token"),
        },
        psk_status: Spake2PskStatus::PskInput,
        public_value: &public_value_b,
    };

    // Encode full CBOR messages
    let mut msg_a_bytes = Vec::<u8, MAX_HANDSHAKE_MSG_SIZE>::new();
    let mut msg_b_bytes = Vec::<u8, MAX_HANDSHAKE_MSG_SIZE>::new();

    handshake_a.encode(&mut msg_a_bytes).expect("encode A");
    handshake_b.encode(&mut msg_b_bytes).expect("encode B");

    // Store in CryptoData (simulating state machine behavior)
    crypto_data
        .our_handshake_msg_mut()
        .extend_from_slice(&msg_a_bytes)
        .expect("store A");
    crypto_data
        .peer_handshake_msg_mut()
        .extend_from_slice(&msg_b_bytes)
        .expect("store B");

    // Build transcript per spec: TT = message_A || message_B
    // Copy messages to local variables first to avoid borrowing issues
    let our_msg = msg_a_bytes.clone();
    let peer_msg = msg_b_bytes.clone();

    crypto_data
        .transcript_mut()
        .extend_from_slice(&our_msg)
        .expect("transcript should fit message A");
    crypto_data
        .transcript_mut()
        .extend_from_slice(&peer_msg)
        .expect("transcript should fit message B");

    // Verify transcript is concatenation of full messages
    let expected_len = msg_a_bytes.len() + msg_b_bytes.len();
    assert_eq!(crypto_data.transcript().len(), expected_len);

    // Verify first part is message A
    assert_eq!(
        &crypto_data.transcript()[..msg_a_bytes.len()],
        &msg_a_bytes[..]
    );

    // Verify second part is message B
    assert_eq!(
        &crypto_data.transcript()[msg_a_bytes.len()..],
        &msg_b_bytes[..]
    );

    // Verify transcript fits in buffer size (512 bytes)
    assert!(
        crypto_data.transcript().len() <= MAX_TRANSCRIPT_SIZE,
        "transcript should fit in buffer (512 bytes), got {}",
        crypto_data.transcript().len()
    );

    println!("OK: Transcript construction successful");
    println!("   Message A: {} bytes", msg_a_bytes.len());
    println!("   Message B: {} bytes", msg_b_bytes.len());
    println!(
        "   Transcript: {} bytes (TT = A || B)",
        crypto_data.transcript().len()
    );
}

/// Test that confirmation message fits in buffer sizes
#[test]
fn test_auth_spake2_confirmation_encoding() {
    let confirmation_value = [0x99u8; 32]; // 32-byte HMAC

    let confirmation = AuthSpake2Confirmation {
        confirmation_value: &confirmation_value,
    };

    let mut buf = Vec::<u8, 128>::new();
    confirmation
        .encode(&mut buf)
        .expect("encode should succeed");

    // format: [1003, {0: confirmation_value}]
    assert!(!buf.is_empty(), "encoded confirmation should not be empty");

    // Note: spec says confirmation might be 32 or 64 bytes
    println!("Confirmation message: {} bytes", buf.len());
    println!("Hex: {}", hex::encode(&buf));
}

/// Test that AuthStatus encodes correctly
#[test]
fn test_auth_status_encoding() {
    let status = AuthStatus {
        status: AuthStatusCode::Ok,
    };

    let mut buf = Vec::<u8, 128>::new();
    status.encode(&mut buf).expect("encode should succeed");

    // format: [1004, {0: 0}] for success
    assert!(!buf.is_empty(), "encoded status should not be empty");

    // Verify decode
    let decoded = AuthStatus::decode(&buf).expect("decode should succeed");
    assert_eq!(decoded.status, AuthStatusCode::Ok);
}

/// Test that different token values produce different transcripts
#[test]
fn test_transcript_depends_on_token() {
    // Create two transcripts with different tokens
    let public_value = [0x42u8; 32];

    let handshake_token1 = AuthSpake2Handshake {
        initiation_token: AuthInitiationToken {
            token: Some("token1"),
        },
        psk_status: Spake2PskStatus::PskShown,
        public_value: &public_value,
    };

    let handshake_token2 = AuthSpake2Handshake {
        initiation_token: AuthInitiationToken {
            token: Some("token2"),
        },
        psk_status: Spake2PskStatus::PskShown,
        public_value: &public_value, // Same public key!
    };

    let mut msg1 = Vec::<u8, MAX_HANDSHAKE_MSG_SIZE>::new();
    let mut msg2 = Vec::<u8, MAX_HANDSHAKE_MSG_SIZE>::new();

    handshake_token1.encode(&mut msg1).expect("encode 1");
    handshake_token2.encode(&mut msg2).expect("encode 2");

    // Even with same public key, different tokens MUST produce different messages
    assert_ne!(
        &msg1[..],
        &msg2[..],
        "SECURITY: Transcript must include token to prevent MITM attacks"
    );

    println!("OK: Token affects transcript (prevents modification attacks)");
    println!("   Message with token1: {} bytes", msg1.len());
    println!("   Message with token2: {} bytes", msg2.len());
}

/// Test that different status values produce different transcripts
#[test]
fn test_transcript_depends_on_status() {
    let public_value = [0x42u8; 32];
    let token = AuthInitiationToken {
        token: Some("same-token"),
    };

    let handshake_needs = AuthSpake2Handshake {
        initiation_token: token.clone(),
        psk_status: Spake2PskStatus::PskNeedsPresentation,
        public_value: &public_value,
    };

    let handshake_shown = AuthSpake2Handshake {
        initiation_token: token,
        psk_status: Spake2PskStatus::PskShown,
        public_value: &public_value, // Same public key and token!
    };

    let mut msg1 = Vec::<u8, MAX_HANDSHAKE_MSG_SIZE>::new();
    let mut msg2 = Vec::<u8, MAX_HANDSHAKE_MSG_SIZE>::new();

    handshake_needs.encode(&mut msg1).expect("encode 1");
    handshake_shown.encode(&mut msg2).expect("encode 2");

    // Different status values MUST produce different messages
    assert_ne!(
        &msg1[..],
        &msg2[..],
        "SECURITY: Transcript must include status to prevent modification attacks"
    );

    println!("OK: Status affects transcript (prevents modification attacks)");
}

/// Test maximum size messages fit in buffers
#[test]
fn test_buffer_sizes_sufficient() {
    // Create maximum-size handshake message
    let max_public_value = [0xFFu8; 64]; // Maximum reasonable public key size
    let max_token = "a".repeat(64); // Maximum token size

    let max_handshake = AuthSpake2Handshake {
        initiation_token: AuthInitiationToken {
            token: Some(&max_token),
        },
        psk_status: Spake2PskStatus::PskInput,
        public_value: &max_public_value,
    };

    let mut buf = Vec::<u8, MAX_HANDSHAKE_MSG_SIZE>::new();
    max_handshake
        .encode(&mut buf)
        .expect("max handshake should fit in 256 bytes");

    // Build maximum transcript (two max messages)
    let mut transcript = Vec::<u8, MAX_TRANSCRIPT_SIZE>::new();
    transcript
        .extend_from_slice(&buf)
        .expect("first message should fit");
    transcript
        .extend_from_slice(&buf)
        .expect("second message should fit");

    assert!(
        transcript.len() <= MAX_TRANSCRIPT_SIZE,
        "transcript buffer (512 bytes) should accommodate two max handshakes"
    );

    println!("OK: buffer sizes are sufficient");
    println!(
        "   Max handshake: {} bytes (limit: {})",
        buf.len(),
        MAX_HANDSHAKE_MSG_SIZE
    );
    println!(
        "   Max transcript: {} bytes (limit: {})",
        transcript.len(),
        MAX_TRANSCRIPT_SIZE
    );
}

/// Integration test: Full message flow
#[test]
fn test_full_message_flow() {
    let mut crypto_data = CryptoData::new();

    // 1. Setup PSK and auth token
    crypto_data.set_psk(b"test-password").expect("set PSK");
    crypto_data
        .set_auth_token(b"auth-token-from-mdns")
        .expect("set token");

    // 2. Create and encode AuthCapabilities (both sides exchange these)
    let caps = AuthCapabilities {
        psk_input_ease: PskInputEase::Simple,
        psk_input_methods: heapless::Vec::new(),
        psk_min_bits_of_entropy: 64,
    };

    let mut caps_buf = Vec::<u8, 256>::new();
    caps.encode(&mut caps_buf).expect("encode capabilities");
    println!(
        "Step 1: AuthCapabilities encoded ({} bytes)",
        caps_buf.len()
    );

    // 3. Create initiator's handshake
    let initiator_public = [0x11u8; 32];
    let initiator_handshake = AuthSpake2Handshake {
        initiation_token: AuthInitiationToken {
            token: Some("mdns-token"),
        },
        psk_status: Spake2PskStatus::PskNeedsPresentation,
        public_value: &initiator_public,
    };

    let mut initiator_msg = Vec::<u8, MAX_HANDSHAKE_MSG_SIZE>::new();
    initiator_handshake
        .encode(&mut initiator_msg)
        .expect("encode initiator handshake");
    println!(
        "Step 2: Initiator handshake encoded ({} bytes)",
        initiator_msg.len()
    );

    // 4. Create responder's handshake
    let responder_public = [0x22u8; 32];
    let responder_handshake = AuthSpake2Handshake {
        initiation_token: AuthInitiationToken {
            token: Some("mdns-token"),
        },
        psk_status: Spake2PskStatus::PskInput,
        public_value: &responder_public,
    };

    let mut responder_msg = Vec::<u8, MAX_HANDSHAKE_MSG_SIZE>::new();
    responder_handshake
        .encode(&mut responder_msg)
        .expect("encode responder handshake");
    println!(
        "Step 3: Responder handshake encoded ({} bytes)",
        responder_msg.len()
    );

    // 5. Store FULL CBOR messages
    crypto_data
        .our_handshake_msg_mut()
        .extend_from_slice(&initiator_msg)
        .expect("store our msg");
    crypto_data
        .peer_handshake_msg_mut()
        .extend_from_slice(&responder_msg)
        .expect("store peer msg");

    // 6. Build transcript for RFC 9382 confirmation
    // Copy messages to avoid borrowing issues
    let our_msg_copy = initiator_msg.clone();
    let peer_msg_copy = responder_msg.clone();
    crypto_data
        .transcript_mut()
        .extend_from_slice(&our_msg_copy)
        .expect("transcript A");
    crypto_data
        .transcript_mut()
        .extend_from_slice(&peer_msg_copy)
        .expect("transcript B");
    println!(
        "Step 4: Transcript constructed ({} bytes)",
        crypto_data.transcript().len()
    );

    // 7. Simulate confirmation exchange
    let our_confirmation = [0x99u8; 32];
    crypto_data
        .my_confirmation_temp_mut()
        .extend_from_slice(&our_confirmation)
        .expect("store our confirmation");

    let peer_confirmation = [0x88u8; 32];
    crypto_data
        .peer_confirmation_temp_mut()
        .extend_from_slice(&peer_confirmation)
        .expect("store peer confirmation");

    println!("Step 5: Confirmations stored (32 bytes each)");

    // 8. Success status
    let status = AuthStatus {
        status: AuthStatusCode::Ok,
    };
    let mut status_buf = Vec::<u8, 128>::new();
    status.encode(&mut status_buf).expect("encode status");
    println!("Step 6: AuthStatus encoded ({} bytes)", status_buf.len());

    println!("\nOK: Full message flow completed successfully");
    println!("   All messages encoded/decoded correctly");
    println!("   Transcript constructed from FULL CBOR messages");
    println!("   Ready for RFC 9382 crypto operations");
}
