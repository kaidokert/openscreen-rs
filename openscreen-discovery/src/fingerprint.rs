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

//! Certificate fingerprint calculation
//!
//! Per W3C OpenScreen spec: "Compute the SPKI Fingerprint... using SHA-256."
//!
//! The fingerprint is SHA-256 of the **SPKI (Subject Public Key Info)**,
//! NOT the full certificate. This is the stable cryptographic identity of the device.

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

/// Certificate fingerprint (SPKI SHA-256)
///
/// This is the SHA-256 hash of the SubjectPublicKeyInfo from an X.509 certificate.
/// It serves as the stable cryptographic identity of a device, used for Trust-On-First-Use
/// (TOFU) and preventing MITM attacks.
///
/// # Security Note
///
/// The fingerprint is computed from the **SPKI only**, not the entire certificate.
/// This means the same key pair will produce the same fingerprint across different
/// certificate serial numbers, validity periods, etc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// Calculate fingerprint from DER-encoded certificate
    ///
    /// This extracts the SPKI (Subject Public Key Info) and hashes it with SHA-256.
    ///
    /// # Important
    ///
    /// DO NOT hash the entire certificate - only the SPKI bytes.
    ///
    /// # Errors
    ///
    /// Returns `FingerprintError::InvalidCertificate` if the certificate cannot be parsed.
    ///
    /// # Example
    ///
    /// ```
    /// # use openscreen_discovery::Fingerprint;
    /// # fn example(cert_der: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    /// let fingerprint = Fingerprint::from_der_cert(cert_der)?;
    /// assert!(fingerprint.to_base64().len() > 0);
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_der_cert(cert_der: &[u8]) -> Result<Self, FingerprintError> {
        let (_, cert) = X509Certificate::from_der(cert_der)
            .map_err(|_| FingerprintError::InvalidCertificate)?;

        // Extract the Subject Public Key Info (SPKI) bytes
        // This is the raw DER of the SPKI sequence
        let spki_bytes = cert.public_key().raw;

        let mut hasher = Sha256::new();
        hasher.update(spki_bytes);
        let result = hasher.finalize();

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&result);
        Ok(Self(arr))
    }

    /// Create a fingerprint from raw 32 bytes
    ///
    /// # Example
    ///
    /// ```
    /// # use openscreen_discovery::Fingerprint;
    /// let bytes = [42u8; 32];
    /// let fingerprint = Fingerprint::from_bytes(bytes);
    /// ```
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Encode as base64 for TXT record
    ///
    /// This produces the value for the `fp=` TXT record in mDNS.
    ///
    /// # Example
    ///
    /// ```
    /// # use openscreen_discovery::Fingerprint;
    /// # let fingerprint = Fingerprint::from_bytes([42u8; 32]);
    /// let txt_value = fingerprint.to_base64();
    /// assert!(txt_value.len() > 0);
    /// ```
    pub fn to_base64(&self) -> String {
        BASE64_STANDARD.encode(self.0)
    }

    /// Decode from base64 TXT record
    ///
    /// This parses the value from the `fp=` TXT record in mDNS.
    ///
    /// # Errors
    ///
    /// Returns `FingerprintError::InvalidBase64` if the string is not valid base64.
    /// Returns `FingerprintError::InvalidLength` if the decoded bytes are not exactly 32.
    ///
    /// # Example
    ///
    /// ```
    /// # use openscreen_discovery::Fingerprint;
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let fingerprint = Fingerprint::from_base64("KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio=")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_base64(s: &str) -> Result<Self, FingerprintError> {
        let bytes = BASE64_STANDARD
            .decode(s)
            .map_err(|_| FingerprintError::InvalidBase64)?;
        if bytes.len() != 32 {
            return Err(FingerprintError::InvalidLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Get raw bytes
    ///
    /// # Example
    ///
    /// ```
    /// # use openscreen_discovery::Fingerprint;
    /// # let fingerprint = Fingerprint::from_bytes([42u8; 32]);
    /// let bytes: &[u8; 32] = fingerprint.as_bytes();
    /// ```
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to hex string (for debugging)
    ///
    /// # Example
    ///
    /// ```
    /// # use openscreen_discovery::Fingerprint;
    /// # let fingerprint = Fingerprint::from_bytes([42u8; 32]);
    /// assert!(fingerprint.to_hex().len() == 64);
    /// ```
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// Errors that can occur during fingerprint calculation
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintError {
    /// Certificate format is invalid or cannot be parsed
    #[error("Invalid certificate format")]
    InvalidCertificate,

    /// Base64 encoding is invalid
    #[error("Invalid base64 encoding")]
    InvalidBase64,

    /// Fingerprint length is not exactly 32 bytes
    #[error("Invalid fingerprint length (expected 32 bytes)")]
    InvalidLength,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_base64_roundtrip() {
        let fp = Fingerprint::from_bytes([42u8; 32]);
        let base64 = fp.to_base64();
        let decoded = Fingerprint::from_base64(&base64).unwrap();
        assert_eq!(fp, decoded);
    }

    #[test]
    fn test_fingerprint_from_base64_invalid() {
        // Invalid base64
        assert!(matches!(
            Fingerprint::from_base64("not-base64!"),
            Err(FingerprintError::InvalidBase64)
        ));

        // Valid base64 but wrong length
        let short = BASE64_STANDARD.encode([1u8; 16]);
        assert!(matches!(
            Fingerprint::from_base64(&short),
            Err(FingerprintError::InvalidLength)
        ));
    }

    #[test]
    fn test_fingerprint_equality() {
        let fp1 = Fingerprint::from_bytes([1u8; 32]);
        let fp2 = Fingerprint::from_bytes([1u8; 32]);
        let fp3 = Fingerprint::from_bytes([2u8; 32]);

        assert_eq!(fp1, fp2);
        assert_ne!(fp1, fp3);
    }

    #[test]
    fn test_fingerprint_hex() {
        let fp = Fingerprint::from_bytes([
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
            0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78,
            0x9a, 0xbc, 0xde, 0xf0,
        ]);
        let hex = fp.to_hex();
        assert_eq!(
            hex,
            "123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0"
        );
    }

    // Note: Testing from_der_cert requires generating a test certificate.
    // This will be added in integration tests once we have rcgen integration.
}
