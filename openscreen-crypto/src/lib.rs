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

//! OpenScreen Protocol - Cryptographic Type Definitions
//!
//! This crate defines the types and traits for cryptographic operations in the
//! OpenScreen protocol. It contains NO implementations - only type definitions.
//!
//! The actual cryptographic implementations are provided by separate crates like:
//! - `openscreen-crypto-rustcrypto` (pure Rust using RustCrypto ecosystem)
//! - `openscreen-crypto-ring` (using the `ring` library)
//! - `openscreen-crypto-platform` (hardware-accelerated implementations)
//!
//! ## Architecture
//!
//! Cryptography is treated as an "effect" in the Sans-IO architecture:
//! - The core state machine requests crypto operations via `CryptoRequest`
//! - Adapters execute the operations using a crypto provider
//! - Results are fed back to the core via `CryptoResult`

#![cfg_attr(not(test), no_std)]

use heapless::Vec;

/// Maximum size for cryptographic output (public keys, signatures, etc.)
/// Set to 640 bytes to accommodate FinishWithConfirmation:
/// - shared_secret (32 bytes)
/// - confirmation (32 bytes)
/// - context (544 bytes: transcript (512) + key (32))
///
///   Total: 608 bytes (640 with some headroom)
pub const MAX_CRYPTO_OUTPUT: usize = 640;

/// Maximum size for certificate data
pub const MAX_CERT_SIZE: usize = 2048;

/// Unique identifier for a crypto operation
pub type CryptoOpId = u64;

/// Error kinds for cryptographic operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// Invalid input parameters
    InvalidInput,
    /// Cryptographic operation failed
    OperationFailed,
    /// Verification failed
    VerificationFailed,
    /// Buffer too small for output
    BufferTooSmall,
    /// Unsupported operation
    Unsupported,
}

/// SPAKE2 password-authenticated key exchange operation kinds
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Spake2Operation<'a> {
    /// Start SPAKE2 handshake - generate our public value
    Start {
        /// Password identifier (optional)
        password_id: Option<&'a [u8]>,
        /// Password/PIN
        password: &'a [u8],
        /// True if we are the responder (server/side B), false if initiator (client/side A)
        /// SPAKE2 requires different group generators for each role
        is_responder: bool,
    },
    /// Finish SPAKE2 handshake - compute shared secret
    Finish {
        /// Our SPAKE2 state from Start operation
        state: &'a [u8],
        /// Peer's public value
        peer_public: &'a [u8],
    },
    /// Protocol: SPAKE2 finish with confirmation using full message transcript
    ///
    /// This operation implements the OpenScreen protocol confirmation flow:
    /// 1. Complete SPAKE2 key exchange to get shared_secret
    /// 2. Build confirmation key using RFC 9382 transcript (shared_secret || ID_A || ID_B)
    /// 3. Compute HMAC over message transcript (cbor(message_A) || cbor(message_B))
    ///
    /// Returns:
    /// - Shared secret (K_main)
    /// - Our confirmation HMAC (to send to peer)
    /// - Opaque context (for verifying peer's confirmation)
    FinishWithConfirmation {
        /// Our SPAKE2 state from Start operation
        state: &'a [u8],
        /// Peer's public value (handshake message)
        peer_public: &'a [u8],
        /// message transcript: cbor(message_A) || cbor(message_B)
        /// This is the full CBOR-encoded handshake messages (up to 512 bytes)
        message_transcript: &'a [u8],
        /// Our TLS certificate fingerprint (32 bytes SHA-256)
        /// Used for RFC 9382 key derivation context
        my_tls_fingerprint: &'a [u8],
        /// Peer's TLS certificate fingerprint (32 bytes SHA-256)
        /// Used for RFC 9382 key derivation context
        peer_tls_fingerprint: &'a [u8],
        /// Our role (needed for RFC 9382 key derivation)
        is_responder: bool,
    },
    /// RFC 9382 compliant confirmation verification
    ///
    /// Verifies the peer's confirmation message against the expected value
    /// computed from the RFC 9382 transcript.
    VerifyConfirmation {
        /// Opaque context from FinishWithConfirmation
        context: &'a [u8],
        /// Peer's confirmation message (received)
        peer_confirmation: &'a [u8],
    },
}

/// Certificate operation kinds
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertOperation<'a> {
    /// Generate a self-signed certificate
    Generate {
        /// Common name for the certificate
        common_name: &'a str,
    },
    /// Verify a certificate
    Verify {
        /// Certificate to verify
        cert: &'a [u8],
    },
}

/// Hash operation kinds
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-256
    Sha256,
    /// SHA-384
    Sha384,
    /// SHA-512
    Sha512,
}

/// Hash operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashOperation<'a> {
    /// Hash algorithm to use
    pub algorithm: HashAlgorithm,
    /// Data to hash
    pub data: &'a [u8],
}

/// HMAC operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HmacOperation<'a> {
    /// Hash algorithm for HMAC
    pub algorithm: HashAlgorithm,
    /// HMAC key
    pub key: &'a [u8],
    /// Data to authenticate
    pub data: &'a [u8],
}

/// HKDF key derivation operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HkdfOperation<'a> {
    /// Hash algorithm for HKDF
    pub algorithm: HashAlgorithm,
    /// Input key material
    pub ikm: &'a [u8],
    /// Salt (optional)
    pub salt: Option<&'a [u8]>,
    /// Info context
    pub info: &'a [u8],
    /// Output length in bytes
    pub length: usize,
}

/// ECDSA signature operation kinds
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EcdsaOperation<'a> {
    /// Sign data
    Sign {
        /// Private key
        private_key: &'a [u8],
        /// Data to sign
        data: &'a [u8],
    },
    /// Verify signature
    Verify {
        /// Public key
        public_key: &'a [u8],
        /// Data that was signed
        data: &'a [u8],
        /// Signature to verify
        signature: &'a [u8],
    },
}

/// Cryptographic operation kind
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoOpKind<'a> {
    /// SPAKE2 password-authenticated key exchange
    Spake2(Spake2Operation<'a>),
    /// Certificate operations
    Certificate(CertOperation<'a>),
    /// Hash computation
    Hash(HashOperation<'a>),
    /// HMAC computation
    Hmac(HmacOperation<'a>),
    /// HKDF key derivation
    Hkdf(HkdfOperation<'a>),
    /// ECDSA signature operations
    Ecdsa(EcdsaOperation<'a>),
}

/// A cryptographic operation request
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoRequest<'a> {
    /// Unique identifier for this operation
    pub op_id: CryptoOpId,
    /// The operation to perform
    pub kind: CryptoOpKind<'a>,
}

/// Result of a cryptographic operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoResult {
    /// Operation ID this result corresponds to
    pub op_id: CryptoOpId,
    /// Result data (public key, signature, hash, shared secret, etc.)
    pub data: Vec<u8, MAX_CRYPTO_OUTPUT>,
}

/// Trait for cryptographic operation providers
///
/// Implementations of this trait provide the actual cryptographic operations.
/// The core protocol state machine is generic over this trait.
///
/// ## Design Philosophy
///
/// This trait provides a unified interface for cryptographic operations, allowing
/// the protocol implementation to be decoupled from specific crypto libraries.
/// Implementations can use:
/// - Pure Rust libraries (RustCrypto ecosystem)
/// - C libraries (ring, openssl)
/// - Hardware acceleration (platform-specific)
/// - Mock implementations (for testing)
///
/// ## Sans-IO Integration
///
/// The protocol state machine emits `CryptoRequest` values via `NetworkOutput::RequestCrypto`.
/// Adapters execute these requests using a `CryptoProvider` implementation and feed
/// back `CryptoResult` values via `NetworkInput::CryptoCompleted`.
///
/// This maintains the Sans-IO architecture while allowing pluggable crypto backends.
pub trait CryptoProvider {
    /// Execute a cryptographic operation
    ///
    /// This is the main entry point for performing crypto operations. Implementations
    /// should dispatch to specific methods based on the operation kind.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if the operation fails
    fn execute(&mut self, request: &CryptoRequest) -> Result<CryptoResult, CryptoError>;

    /// Perform SPAKE2 start operation (optional optimization)
    ///
    /// Implementations can override this for more efficient SPAKE2 handling.
    /// Default implementation delegates to `execute`.
    fn spake2_start(
        &mut self,
        op_id: CryptoOpId,
        password_id: Option<&[u8]>,
        password: &[u8],
        is_responder: bool,
    ) -> Result<CryptoResult, CryptoError> {
        let request = CryptoRequest {
            op_id,
            kind: CryptoOpKind::Spake2(Spake2Operation::Start {
                password_id,
                password,
                is_responder,
            }),
        };
        self.execute(&request)
    }

    /// Perform SPAKE2 finish operation (optional optimization)
    ///
    /// Implementations can override this for more efficient SPAKE2 handling.
    /// Default implementation delegates to `execute`.
    fn spake2_finish(
        &mut self,
        op_id: CryptoOpId,
        state: &[u8],
        peer_public: &[u8],
    ) -> Result<CryptoResult, CryptoError> {
        let request = CryptoRequest {
            op_id,
            kind: CryptoOpKind::Spake2(Spake2Operation::Finish { state, peer_public }),
        };
        self.execute(&request)
    }

    /// Perform HKDF key derivation (optional optimization)
    ///
    /// Implementations can override this for more efficient HKDF handling.
    /// Default implementation delegates to `execute`.
    fn hkdf_derive(
        &mut self,
        op_id: CryptoOpId,
        algorithm: HashAlgorithm,
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: &[u8],
        length: usize,
    ) -> Result<CryptoResult, CryptoError> {
        let request = CryptoRequest {
            op_id,
            kind: CryptoOpKind::Hkdf(HkdfOperation {
                algorithm,
                ikm,
                salt,
                info,
                length,
            }),
        };
        self.execute(&request)
    }

    /// Compute a hash (optional optimization)
    ///
    /// Implementations can override this for more efficient hash computation.
    /// Default implementation delegates to `execute`.
    fn hash(
        &mut self,
        op_id: CryptoOpId,
        algorithm: HashAlgorithm,
        data: &[u8],
    ) -> Result<CryptoResult, CryptoError> {
        let request = CryptoRequest {
            op_id,
            kind: CryptoOpKind::Hash(HashOperation { algorithm, data }),
        };
        self.execute(&request)
    }

    /// Compute an HMAC (optional optimization)
    ///
    /// Implementations can override this for more efficient HMAC computation.
    /// Default implementation delegates to `execute`.
    fn hmac(
        &mut self,
        op_id: CryptoOpId,
        algorithm: HashAlgorithm,
        key: &[u8],
        data: &[u8],
    ) -> Result<CryptoResult, CryptoError> {
        let request = CryptoRequest {
            op_id,
            kind: CryptoOpKind::Hmac(HmacOperation {
                algorithm,
                key,
                data,
            }),
        };
        self.execute(&request)
    }
}

/// Helper function to execute a crypto request with any provider
///
/// This is a convenience function for adapters that want to execute
/// crypto requests without storing the provider in a struct.
pub fn execute_crypto_request<P: CryptoProvider>(
    provider: &mut P,
    request: &CryptoRequest,
) -> Result<CryptoResult, CryptoError> {
    provider.execute(request)
}

/// Mock crypto provider for testing
///
/// This implementation returns fixed test data for all operations.
/// Useful for unit testing protocol logic without real cryptography.
pub struct MockCryptoProvider {
    /// Fixed output data to return for all operations
    pub fixed_output: Vec<u8, MAX_CRYPTO_OUTPUT>,
}

impl MockCryptoProvider {
    /// Create a new mock provider with fixed output
    pub fn new(output: &[u8]) -> Self {
        let mut fixed_output = Vec::new();
        fixed_output.extend_from_slice(output).unwrap();
        Self { fixed_output }
    }

    /// Create a mock provider with empty output
    pub fn empty() -> Self {
        Self {
            fixed_output: Vec::new(),
        }
    }
}

impl CryptoProvider for MockCryptoProvider {
    fn execute(&mut self, request: &CryptoRequest) -> Result<CryptoResult, CryptoError> {
        // Return fixed output for all operations
        Ok(CryptoResult {
            op_id: request.op_id,
            data: self.fixed_output.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_request_creation() {
        let req = CryptoRequest {
            op_id: 123,
            kind: CryptoOpKind::Hash(HashOperation {
                algorithm: HashAlgorithm::Sha256,
                data: b"test data",
            }),
        };
        assert_eq!(req.op_id, 123);
    }

    #[test]
    fn test_crypto_result_creation() {
        let mut data = Vec::new();
        data.extend_from_slice(b"result").unwrap();

        let result = CryptoResult { op_id: 456, data };
        assert_eq!(result.op_id, 456);
        assert_eq!(&result.data[..], b"result");
    }

    #[test]
    fn test_mock_crypto_provider() {
        let mut provider = MockCryptoProvider::new(b"mock_output");

        let req = CryptoRequest {
            op_id: 789,
            kind: CryptoOpKind::Hash(HashOperation {
                algorithm: HashAlgorithm::Sha256,
                data: b"test",
            }),
        };

        let result = provider.execute(&req).unwrap();
        assert_eq!(result.op_id, 789);
        assert_eq!(&result.data[..], b"mock_output");
    }

    #[test]
    fn test_crypto_provider_default_methods() {
        let mut provider = MockCryptoProvider::new(b"spake2_key");

        // Test spake2_start helper
        let result = provider
            .spake2_start(100, None, b"password", false)
            .unwrap();
        assert_eq!(result.op_id, 100);
        assert_eq!(&result.data[..], b"spake2_key");

        // Test spake2_finish helper
        let result = provider.spake2_finish(101, b"state", b"peer").unwrap();
        assert_eq!(result.op_id, 101);

        // Test hash helper
        let result = provider.hash(102, HashAlgorithm::Sha256, b"data").unwrap();
        assert_eq!(result.op_id, 102);

        // Test hmac helper
        let result = provider
            .hmac(103, HashAlgorithm::Sha256, b"key", b"data")
            .unwrap();
        assert_eq!(result.op_id, 103);

        // Test hkdf_derive helper
        let result = provider
            .hkdf_derive(
                104,
                HashAlgorithm::Sha256,
                b"ikm",
                Some(b"salt"),
                b"info",
                32,
            )
            .unwrap();
        assert_eq!(result.op_id, 104);
    }

    #[test]
    fn test_execute_crypto_request_helper() {
        let mut provider = MockCryptoProvider::new(b"helper_test");

        let req = CryptoRequest {
            op_id: 200,
            kind: CryptoOpKind::Hash(HashOperation {
                algorithm: HashAlgorithm::Sha256,
                data: b"data",
            }),
        };

        let result = execute_crypto_request(&mut provider, &req).unwrap();
        assert_eq!(result.op_id, 200);
        assert_eq!(&result.data[..], b"helper_test");
    }
}
