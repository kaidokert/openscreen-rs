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

//! Crypto data storage for the OpenScreen Network Protocol
//!
//! This module contains data structures that need to be borrowed with lifetime 'a
//! for NetworkOutput. By separating this from NetworkState, we allow independent borrowing.

use heapless::Vec;

/// Maximum password/PSK size (128 bytes should be sufficient for most PSKs)
pub const MAX_PSK_SIZE: usize = 128;

/// Maximum authentication token size (from mDNS TXT record)
pub const MAX_AUTH_TOKEN_SIZE: usize = 64;

/// Maximum fingerprint size (SHA-256 hash of TLS certificate)
pub const MAX_FINGERPRINT_SIZE: usize = 32;

/// Maximum size for handshake CBOR messages (includes token, status, public key)
pub const MAX_HANDSHAKE_MSG_SIZE: usize = 256;

/// Maximum transcript size (concatenation of two handshake messages)
pub const MAX_TRANSCRIPT_SIZE: usize = 512;

/// Maximum confirmation context size per spec
/// Context = peer_key (32) + transcript (512) = 544 bytes
pub const MAX_CONFIRMATION_CONTEXT_SIZE: usize = 544;

/// Maximum confirmation value size (spec says 32 or 64, we use 64 to be safe)
pub const MAX_CONFIRMATION_SIZE: usize = 64;

/// Crypto data that needs to be borrowed with lifetime 'a for NetworkOutput.
/// This is managed separately from NetworkState to allow independent borrowing.
#[derive(Debug)]
pub struct CryptoData {
    /// Storage for SPAKE2 public value (up to MAX_CRYPTO_OUTPUT bytes)
    pub(crate) spake2_public: Vec<u8, { openscreen_crypto::MAX_CRYPTO_OUTPUT }>,
    /// Storage for peer's public value (extracted from ConnectionState for borrowing)
    pub(crate) peer_public_temp: Vec<u8, { crate::state::PEER_PUBLIC_MAX_SIZE }>,
    /// Storage for shared secret from SPAKE2 handshake
    pub(crate) shared_secret: Vec<u8, { openscreen_crypto::MAX_CRYPTO_OUTPUT }>,
    /// Storage for derived session keys (encryption and MAC)
    #[allow(dead_code)] // Will be used for application protocol encryption
    pub(crate) session_keys: Vec<u8, { openscreen_crypto::MAX_CRYPTO_OUTPUT }>,
    /// Pre-shared key (PSK) for authentication - must be set before authentication begins
    pub(crate) psk: Vec<u8, MAX_PSK_SIZE>,
    /// Authentication token from mDNS advertisement - should be set before authentication
    pub(crate) auth_token: Vec<u8, MAX_AUTH_TOKEN_SIZE>,
    /// Temporary owned copy of auth token for message lifetime management
    /// Used to avoid lifetime issues when constructing messages with tokens
    pub(crate) auth_token_temp: heapless::String<MAX_AUTH_TOKEN_SIZE>,

    // --- Full CBOR Message Storage ---
    /// Our full CBOR-encoded handshake message (Type 1005)
    /// MUST store complete message including token, status, and public value
    /// Spec: Transcript = cbor(message_A) || cbor(message_B)
    pub(crate) our_handshake_msg: Vec<u8, MAX_HANDSHAKE_MSG_SIZE>,

    /// Peer's full CBOR-encoded handshake message (Type 1005)
    /// MUST store complete message including token, status, and public value
    pub(crate) peer_handshake_msg: Vec<u8, MAX_HANDSHAKE_MSG_SIZE>,

    /// Transcript for RFC 9382 confirmation
    /// = our_handshake_msg || peer_handshake_msg (full CBOR bytes)
    pub(crate) transcript: Vec<u8, MAX_TRANSCRIPT_SIZE>,

    // --- NEW: RFC 9382 Transcript Fields ---
    /// Our TLS certificate fingerprint (identity for RFC 9382 transcript)
    pub(crate) my_fingerprint: Vec<u8, MAX_FINGERPRINT_SIZE>,
    /// Peer's TLS certificate fingerprint (identity for RFC 9382 transcript)
    pub(crate) peer_fingerprint: Vec<u8, MAX_FINGERPRINT_SIZE>,
    /// Our role in the SPAKE2 exchange (Initiator/Client or Responder/Server)
    pub(crate) is_responder: bool,

    /// Opaque context from FinishWithConfirmation (for VerifyConfirmation)
    /// increased size: peer_key (32) + transcript (512) = 544 bytes
    pub(crate) confirmation_context: Vec<u8, MAX_CONFIRMATION_CONTEXT_SIZE>,

    /// Derived initiator confirmation key (from HKDF after SPAKE2)
    /// Both sides derive this from shared secret - used to compute/verify initiator's confirmation
    pub(crate) initiator_confirmation_key: Vec<u8, 32>,

    /// Derived responder confirmation key (from HKDF after SPAKE2)
    /// Both sides derive this from shared secret - used to compute/verify responder's confirmation
    pub(crate) responder_confirmation_key: Vec<u8, 32>,

    /// Temporary storage for our confirmation message (for SendMessage borrowing)
    /// spec: 32 or 64 bytes (reviewer says try 32 first, we allocate 64 to be safe)
    pub(crate) my_confirmation_temp: Vec<u8, MAX_CONFIRMATION_SIZE>,

    /// Temporary storage for peer's confirmation message (for RequestCrypto borrowing)
    /// 32 or 64 bytes
    pub(crate) peer_confirmation_temp: Vec<u8, MAX_CONFIRMATION_SIZE>,

    /// Buffered peer confirmation message (full CBOR bytes) received while Computing
    /// race condition: peer may send confirmation before our FinishWithConfirmation completes
    /// We store the raw CBOR bytes here (~40 bytes) and process after crypto completes
    pub(crate) pending_confirmation_bytes: Vec<u8, MAX_HANDSHAKE_MSG_SIZE>,
}

impl CryptoData {
    /// Create new empty crypto data storage
    pub fn new() -> Self {
        Self {
            spake2_public: Vec::new(),
            peer_public_temp: Vec::new(),
            shared_secret: Vec::new(),
            session_keys: Vec::new(),
            psk: Vec::new(),
            auth_token: Vec::new(),
            auth_token_temp: heapless::String::new(),
            our_handshake_msg: Vec::new(),
            peer_handshake_msg: Vec::new(),
            transcript: Vec::new(),
            my_fingerprint: Vec::new(),
            peer_fingerprint: Vec::new(),
            is_responder: false,
            confirmation_context: Vec::new(),
            initiator_confirmation_key: Vec::new(),
            responder_confirmation_key: Vec::new(),
            my_confirmation_temp: Vec::new(),
            peer_confirmation_temp: Vec::new(),
            pending_confirmation_bytes: Vec::new(),
        }
    }

    /// Set the pre-shared key (PSK) for authentication
    ///
    /// This must be called before authentication begins. The PSK is used in the
    /// SPAKE2 handshake to derive shared secrets.
    ///
    /// # Parameters
    /// * `password` - The pre-shared key bytes
    ///
    /// # Returns
    /// * `Ok(())` if PSK was set successfully
    /// * `Err(NetworkError::BufferFull)` if PSK is too large (> MAX_PSK_SIZE bytes)
    pub fn set_psk(&mut self, password: &[u8]) -> Result<(), crate::NetworkError> {
        self.psk.clear();
        self.psk
            .extend_from_slice(password)
            .map_err(|_| crate::NetworkError::BufferFull)
    }

    /// Set the authentication token (at) from mDNS advertisement
    ///
    /// The authentication token is advertised by the receiver in its mDNS TXT record
    /// and must be included in the first auth message to prevent off-network attacks.
    ///
    /// # Parameters
    /// * `token` - The authentication token bytes from mDNS
    ///
    /// # Returns
    /// * `Ok(())` if token was set successfully
    /// * `Err(NetworkError::BufferFull)` if token is too large (> MAX_AUTH_TOKEN_SIZE bytes)
    pub fn set_auth_token(&mut self, token: &[u8]) -> Result<(), crate::NetworkError> {
        self.auth_token.clear();
        self.auth_token
            .extend_from_slice(token)
            .map_err(|_| crate::NetworkError::BufferFull)
    }

    /// Get the authentication token as a str (if valid UTF-8)
    ///
    /// Returns `Some(&str)` if auth_token is non-empty and valid UTF-8, `None` otherwise.
    pub fn auth_token_str(&self) -> Option<&str> {
        if self.auth_token.is_empty() {
            None
        } else {
            core::str::from_utf8(&self.auth_token).ok()
        }
    }

    /// Set our TLS certificate fingerprint (identity for RFC 9382)
    ///
    /// # Parameters
    /// * `fingerprint` - SHA-256 hash of our TLS certificate
    ///
    /// # Returns
    /// * `Ok(())` if fingerprint was set successfully
    /// * `Err(NetworkError::BufferFull)` if fingerprint is too large
    pub fn set_my_fingerprint(&mut self, fingerprint: &[u8]) -> Result<(), crate::NetworkError> {
        self.my_fingerprint.clear();
        self.my_fingerprint
            .extend_from_slice(fingerprint)
            .map_err(|_| crate::NetworkError::BufferFull)
    }

    /// Set peer's TLS certificate fingerprint (identity for RFC 9382)
    ///
    /// # Parameters
    /// * `fingerprint` - SHA-256 hash of peer's TLS certificate
    ///
    /// # Returns
    /// * `Ok(())` if fingerprint was set successfully
    /// * `Err(NetworkError::BufferFull)` if fingerprint is too large
    pub fn set_peer_fingerprint(&mut self, fingerprint: &[u8]) -> Result<(), crate::NetworkError> {
        self.peer_fingerprint.clear();
        self.peer_fingerprint
            .extend_from_slice(fingerprint)
            .map_err(|_| crate::NetworkError::BufferFull)
    }

    /// Set our role in the SPAKE2 exchange
    ///
    /// # Parameters
    /// * `is_responder` - true if we are the responder (server), false if initiator (client)
    pub fn set_role(&mut self, is_responder: bool) {
        self.is_responder = is_responder;
    }

    // --- Accessor methods for testing ---

    /// Get reference to our full CBOR handshake message
    pub fn our_handshake_msg(&self) -> &[u8] {
        &self.our_handshake_msg
    }

    /// Get mutable reference to our full CBOR handshake message storage
    pub fn our_handshake_msg_mut(&mut self) -> &mut Vec<u8, MAX_HANDSHAKE_MSG_SIZE> {
        &mut self.our_handshake_msg
    }

    /// Get reference to peer's full CBOR handshake message
    pub fn peer_handshake_msg(&self) -> &[u8] {
        &self.peer_handshake_msg
    }

    /// Get mutable reference to peer's full CBOR handshake message storage
    pub fn peer_handshake_msg_mut(&mut self) -> &mut Vec<u8, MAX_HANDSHAKE_MSG_SIZE> {
        &mut self.peer_handshake_msg
    }

    /// Get reference to transcript (concatenation of handshake messages)
    pub fn transcript(&self) -> &[u8] {
        &self.transcript
    }

    /// Get mutable reference to transcript storage
    pub fn transcript_mut(&mut self) -> &mut Vec<u8, MAX_TRANSCRIPT_SIZE> {
        &mut self.transcript
    }

    /// Get mutable reference to our confirmation value storage
    pub fn my_confirmation_temp_mut(&mut self) -> &mut Vec<u8, MAX_CONFIRMATION_SIZE> {
        &mut self.my_confirmation_temp
    }

    /// Get mutable reference to peer's confirmation value storage
    pub fn peer_confirmation_temp_mut(&mut self) -> &mut Vec<u8, MAX_CONFIRMATION_SIZE> {
        &mut self.peer_confirmation_temp
    }
}

impl Default for CryptoData {
    fn default() -> Self {
        Self::new()
    }
}
