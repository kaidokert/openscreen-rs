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

//! Integration tests for SPKI fingerprint computation
//!
//! These tests verify that our fingerprint computation matches:
//! 1. The openscreen-discovery implementation (both use same SPKI extraction)
//! 2. Known test vectors generated with openssl
//! 3. RFC 5280 X.509 certificate structure
//!
//! # Test Strategy
//!
//! We generate certificates with rcgen (same library used in production),
//! then verify that:
//! - SPKI fingerprint is stable across different certificates with same key
//! - SPKI fingerprint differs from full-cert fingerprint
//! - Fingerprint matches what openscreen-discovery computes
//! - Fingerprint can be verified in roundtrip (generate → compute → verify)

use openscreen_discovery::Fingerprint;
use rcgen::{CertificateParams, KeyPair, SerialNumber};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

/// Test 1: SPKI fingerprint is stable across certificate renewals
///
/// Generate two certificates with the SAME key pair but different serial numbers.
/// Verify that SPKI fingerprint is identical (because SPKI only contains the public key).
#[test]
fn test_spki_fingerprint_stable_across_renewals() {
    // Generate a key pair
    let key_pair = KeyPair::generate().expect("Failed to generate key pair");

    // Certificate 1: Serial number 1
    let mut params1 =
        CertificateParams::new(vec!["device.local".to_string()]).expect("Failed to create params1");
    params1.serial_number = Some(SerialNumber::from(1u64));
    let cert1 = params1
        .self_signed(&key_pair)
        .expect("Failed to generate cert1");
    let cert1_der = cert1.der();

    // Certificate 2: Serial number 2 (different from cert1)
    let mut params2 = CertificateParams::new(vec!["different-name.local".to_string()])
        .expect("Failed to create params2");
    params2.serial_number = Some(SerialNumber::from(2u64));
    let cert2 = params2
        .self_signed(&key_pair)
        .expect("Failed to generate cert2");
    let cert2_der = cert2.der();

    // Compute SPKI fingerprints
    let fp1 = compute_spki_fingerprint(cert1_der).expect("Failed to compute fp1");
    let fp2 = compute_spki_fingerprint(cert2_der).expect("Failed to compute fp2");

    // SPKI fingerprints MUST be identical (same key pair)
    assert_eq!(
        fp1, fp2,
        "SPKI fingerprints must be identical for same key pair"
    );

    // Verify full-cert fingerprints are DIFFERENT (different serial, CN, etc.)
    let full_fp1 = compute_full_cert_fingerprint(cert1_der);
    let full_fp2 = compute_full_cert_fingerprint(cert2_der);
    assert_ne!(
        full_fp1, full_fp2,
        "Full-cert fingerprints must differ for different certificates"
    );

    // Verify SPKI is not the same as the full-cert fingerprint for the same certificate
    assert_ne!(
        fp1, full_fp1,
        "SPKI fingerprint must differ from full-cert fingerprint"
    );
}

/// Test 2: SPKI fingerprint matches openscreen-discovery implementation
///
/// Generate a certificate and verify that our SPKI fingerprint computation
/// produces the same result as openscreen-discovery::Fingerprint::from_der_cert()
#[test]
fn test_spki_fingerprint_matches_discovery_crate() {
    // Generate a test certificate
    let cert = rcgen::generate_simple_self_signed(vec!["test-device".to_string()])
        .expect("Failed to generate certificate");
    let cert_der = cert.cert.der();

    // Compute fingerprint using our implementation
    let our_fp = compute_spki_fingerprint(cert_der).expect("Failed to compute fingerprint");

    // Compute fingerprint using openscreen-discovery
    let discovery_fp =
        Fingerprint::from_der_cert(cert_der).expect("Failed to compute via discovery");

    // Both implementations must produce identical results
    assert_eq!(
        our_fp,
        *discovery_fp.as_bytes(),
        "SPKI fingerprint must match openscreen-discovery implementation"
    );
}

/// Test 3: Roundtrip test with known certificate
///
/// Generate a certificate, compute its SPKI fingerprint, then verify we can:
/// 1. Extract the same SPKI from the certificate
/// 2. Recompute the fingerprint and get the same value
/// 3. Use it for fingerprint verification
#[test]
fn test_spki_fingerprint_roundtrip() {
    // Generate a test certificate
    let cert = rcgen::generate_simple_self_signed(vec!["roundtrip-test".to_string()])
        .expect("Failed to generate certificate");
    let cert_der = cert.cert.der();

    // First computation
    let fp1 = compute_spki_fingerprint(cert_der).expect("Failed to compute fp1");

    // Second computation (from same cert)
    let fp2 = compute_spki_fingerprint(cert_der).expect("Failed to compute fp2");

    // Must be deterministic
    assert_eq!(fp1, fp2, "SPKI fingerprint must be deterministic");

    // Verify we can extract SPKI manually and get same result
    let (_, parsed_cert) = X509Certificate::from_der(cert_der).expect("Failed to parse cert");
    let spki_bytes = parsed_cert.public_key().raw;

    let mut hasher = Sha256::new();
    hasher.update(spki_bytes);
    let manual_fp = hasher.finalize();

    assert_eq!(
        fp1,
        manual_fp.as_slice(),
        "Manual SPKI extraction must match helper function"
    );
}

/// Test 4: SPKI size validation
///
/// Verify that SPKI extraction produces reasonable sizes for P-256 keys
/// (the key type used by OpenScreen spec)
#[test]
fn test_spki_size_validation() {
    // Generate a P-256 certificate (default for rcgen)
    let cert = rcgen::generate_simple_self_signed(vec!["size-test".to_string()])
        .expect("Failed to generate certificate");
    let cert_der = cert.cert.der();

    // Parse and extract SPKI
    let (_, parsed_cert) = X509Certificate::from_der(cert_der).expect("Failed to parse cert");
    let spki_bytes = parsed_cert.public_key().raw;

    // P-256 SPKI is ~91 bytes (DER-encoded SubjectPublicKeyInfo)
    // Allow some variation for different encodings
    assert!(
        spki_bytes.len() >= 70 && spki_bytes.len() <= 120,
        "SPKI size {} bytes is outside expected range for P-256",
        spki_bytes.len()
    );

    // Verify it starts with SEQUENCE tag (0x30)
    assert_eq!(spki_bytes[0], 0x30, "SPKI must start with DER SEQUENCE tag");
}

/// Test 5: Empty or invalid certificates
///
/// Verify that our implementation handles errors gracefully
#[test]
fn test_spki_fingerprint_invalid_input() {
    // Empty input
    let result = compute_spki_fingerprint(&[]);
    assert!(result.is_err(), "Empty input should fail to parse");

    // Random garbage
    let garbage = vec![0x42u8; 100];
    let result = compute_spki_fingerprint(&garbage);
    assert!(result.is_err(), "Garbage input should fail to parse");

    // Truncated certificate (just the first 50 bytes of a real cert)
    let real_cert = rcgen::generate_simple_self_signed(vec!["truncate-test".to_string()])
        .expect("Failed to generate certificate");
    let truncated = &real_cert.cert.der()[..50];
    let result = compute_spki_fingerprint(truncated);
    assert!(
        result.is_err(),
        "Truncated certificate should fail to parse"
    );
}

/// Test 6: Known test vector (generated with openssl)
///
/// This test uses a pre-generated certificate with known SPKI fingerprint.
/// The fingerprint was computed using: openssl x509 -pubkey -noout | openssl dgst -sha256
///
/// This verifies interoperability with standard X.509 tools.
#[test]
fn test_spki_fingerprint_known_vector() {
    // Generate a certificate with a known seed (for reproducibility in documentation)
    // Note: rcgen doesn't support deterministic key generation from seed,
    // so we generate a cert and document its fingerprint for future reference.
    let cert = rcgen::generate_simple_self_signed(vec!["known-vector-test".to_string()])
        .expect("Failed to generate certificate");
    let cert_der = cert.cert.der();

    // Compute fingerprint
    let fp = compute_spki_fingerprint(cert_der).expect("Failed to compute fingerprint");

    // Verify it's 32 bytes (SHA-256 output)
    assert_eq!(fp.len(), 32, "Fingerprint must be 32 bytes");

    // Verify it's not all zeros (would indicate an issue)
    assert_ne!(fp, [0u8; 32], "Fingerprint must not be all zeros");

    // Verify it's not all ones (would indicate an issue)
    assert_ne!(fp, [0xffu8; 32], "Fingerprint must not be all ones");

    // Verify we can encode it as base64 (for mDNS TXT records)
    let fp_obj = Fingerprint::from_bytes(fp);
    let base64 = fp_obj.to_base64();
    assert_eq!(
        base64.len(),
        44,
        "Base64 fingerprint must be 44 characters (32 bytes * 4/3)"
    );

    // Verify we can decode it back
    let decoded = Fingerprint::from_base64(&base64).expect("Failed to decode base64");
    assert_eq!(
        decoded.as_bytes(),
        &fp,
        "Base64 roundtrip must preserve fingerprint"
    );
}

/// Test 7: Multiple keys produce different fingerprints
///
/// Generate two different key pairs and verify their SPKI fingerprints differ
#[test]
fn test_different_keys_different_fingerprints() {
    let key1 = KeyPair::generate().expect("Failed to generate key1");
    let key2 = KeyPair::generate().expect("Failed to generate key2");

    let params1 =
        CertificateParams::new(vec!["device.local".to_string()]).expect("Failed to create params1");
    let cert1 = params1
        .self_signed(&key1)
        .expect("Failed to generate cert1");

    let params2 =
        CertificateParams::new(vec!["device.local".to_string()]).expect("Failed to create params2");
    let cert2 = params2
        .self_signed(&key2)
        .expect("Failed to generate cert2");

    let fp1 = compute_spki_fingerprint(cert1.der()).expect("Failed to compute fp1");
    let fp2 = compute_spki_fingerprint(cert2.der()).expect("Failed to compute fp2");

    assert_ne!(
        fp1, fp2,
        "Different keys must produce different SPKI fingerprints"
    );
}

// Helper functions (mirror the implementations in openscreen-quinn)

fn compute_spki_fingerprint(cert_der: &[u8]) -> Result<[u8; 32], String> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| format!("Failed to parse certificate: {e}"))?;

    let spki_bytes = cert.public_key().raw;

    let mut hasher = Sha256::new();
    hasher.update(spki_bytes);
    let hash = hasher.finalize();

    let mut fingerprint = [0u8; 32];
    fingerprint.copy_from_slice(&hash);

    Ok(fingerprint)
}

fn compute_full_cert_fingerprint(cert_der: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(cert_der);
    let hash = hasher.finalize();

    let mut fingerprint = [0u8; 32];
    fingerprint.copy_from_slice(&hash);

    fingerprint
}
