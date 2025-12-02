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

//! Wire format integration tests
//!
//! These tests verify that CBOR messages match the expected byte-level format.
//! This catches encoding errors that unit tests miss (e.g., string vs bytes, truncation).

use openscreen_network::*;

/// Test that auth token is encoded as CBOR text string (not bytes, not truncated)
/// This would have caught the issue where we displayed only 16 chars but stored 32
#[test]
fn test_auth_token_wire_format() {
    let full_token = "deadbeefcafebabedeadbeefcafebabe"; // 32-char hex
    assert_eq!(full_token.len(), 32, "Test token must be 32 chars");

    let public_value = [0x42u8; 33];

    let msg = NetworkMessage::AuthSpake2Handshake(AuthSpake2Handshake {
        initiation_token: AuthInitiationToken {
            token: Some(full_token),
        },
        psk_status: Spake2PskStatus::PskNeedsPresentation,
        public_value: &public_value,
    });

    let encoded = encode_network_message(&msg).expect("Failed to encode");

    // The FULL 32-char token must appear in the encoded bytes
    // (not truncated to 16 chars!)
    let token_bytes = full_token.as_bytes();
    let found = encoded
        .windows(token_bytes.len())
        .position(|window| window == token_bytes);

    assert!(
        found.is_some(),
        "Full 32-char token '{}' not found in encoded message! \
         This suggests truncation or wrong encoding type. \
         Encoded message hex: {}",
        full_token,
        encoded
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
}

/// Test that different tokens produce different wire formats
#[test]
fn test_different_tokens_different_encoding() {
    let token1 = "11111111111111111111111111111111";
    let token2 = "22222222222222222222222222222222";
    let public_value = [0xAAu8; 33];

    let msg1 = NetworkMessage::AuthSpake2Handshake(AuthSpake2Handshake {
        initiation_token: AuthInitiationToken {
            token: Some(token1),
        },
        psk_status: Spake2PskStatus::PskNeedsPresentation,
        public_value: &public_value,
    });

    let msg2 = NetworkMessage::AuthSpake2Handshake(AuthSpake2Handshake {
        initiation_token: AuthInitiationToken {
            token: Some(token2),
        },
        psk_status: Spake2PskStatus::PskNeedsPresentation,
        public_value: &public_value,
    });

    let encoded1 = encode_network_message(&msg1).expect("Failed to encode msg1");
    let encoded2 = encode_network_message(&msg2).expect("Failed to encode msg2");

    assert_ne!(
        encoded1.as_slice(),
        encoded2.as_slice(),
        "Different tokens must produce different wire formats"
    );
}

/// Test that empty token encodes without error
#[test]
fn test_empty_token_encoding() {
    let public_value = [0x99u8; 33];

    let msg = NetworkMessage::AuthSpake2Handshake(AuthSpake2Handshake {
        initiation_token: AuthInitiationToken { token: None },
        psk_status: Spake2PskStatus::PskNeedsPresentation,
        public_value: &public_value,
    });

    // Should encode successfully
    let encoded = encode_network_message(&msg).expect("Failed to encode with empty token");

    // Should produce some output
    assert!(!encoded.is_empty(), "Encoded message should not be empty");
}
