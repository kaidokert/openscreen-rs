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

//! Integration tests for fingerprint calculation with real certificates

use openscreen_discovery::Fingerprint;

/// Test fingerprint calculation with a generated certificate
///
/// This verifies that SPKI extraction works correctly with rcgen-generated certs.
#[test]
fn test_fingerprint_from_generated_cert() {
    // Generate a test certificate (same method used by Quinn)
    let cert = rcgen::generate_simple_self_signed(vec!["test.local".to_string()]).unwrap();
    let cert_der = cert.cert.der();

    // Calculate fingerprint
    let fp1 = Fingerprint::from_der_cert(cert_der).expect("Failed to calculate fingerprint");

    // Calculate again to verify determinism
    let fp2 = Fingerprint::from_der_cert(cert_der).expect("Failed to calculate fingerprint");

    // Same certificate should produce same fingerprint
    assert_eq!(fp1, fp2);

    // Fingerprint should be 32 bytes (SHA-256)
    assert_eq!(fp1.as_bytes().len(), 32);

    // Should be able to roundtrip through base64
    let base64 = fp1.to_base64();
    let fp3 = Fingerprint::from_base64(&base64).expect("Failed to decode base64");
    assert_eq!(fp1, fp3);
}

/// Test that different certificates produce different fingerprints
#[test]
fn test_different_certs_different_fingerprints() {
    // Generate two different certificates
    let cert1 = rcgen::generate_simple_self_signed(vec!["device1.local".to_string()]).unwrap();
    let cert1_der = cert1.cert.der();

    let cert2 = rcgen::generate_simple_self_signed(vec!["device2.local".to_string()]).unwrap();
    let cert2_der = cert2.cert.der();

    let fp1 = Fingerprint::from_der_cert(cert1_der).expect("Failed to calculate fingerprint 1");
    let fp2 = Fingerprint::from_der_cert(cert2_der).expect("Failed to calculate fingerprint 2");

    // Different certificates should produce different fingerprints
    assert_ne!(fp1, fp2);
}

/// Test that the same key produces the same fingerprint even with different serial numbers
#[test]
fn test_same_key_same_fingerprint() {
    // Generate a key pair
    let key_pair = rcgen::KeyPair::generate().unwrap();

    // Create two certificates with the same key but different serial numbers
    let mut params1 = rcgen::CertificateParams::new(vec!["device.local".to_string()]).unwrap();
    params1.serial_number = Some(rcgen::SerialNumber::from(1u64));
    let cert1 = params1.self_signed(&key_pair).unwrap();
    let cert1_der = cert1.der();

    let mut params2 = rcgen::CertificateParams::new(vec!["device.local".to_string()]).unwrap();
    params2.serial_number = Some(rcgen::SerialNumber::from(2u64));
    let cert2 = params2.self_signed(&key_pair).unwrap();
    let cert2_der = cert2.der();

    let fp1 = Fingerprint::from_der_cert(cert1_der).expect("Failed to calculate fingerprint 1");
    let fp2 = Fingerprint::from_der_cert(cert2_der).expect("Failed to calculate fingerprint 2");

    // Same key pair should produce same fingerprint (SPKI is identical)
    assert_eq!(fp1, fp2);
}
