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

//! Integration test: SPAKE2 authentication end-to-end via script
//!
//! This test locks in the current working authentication behavior before
//! refactoring the server API. It runs the actual binaries via the e2e test script.
//!
//! NOTE: This test is ignored by default because:
//! 1. It spawns actual binaries which can leave orphaned processes
//! 2. It takes 5+ seconds to run
//! 3. It's more of a smoke test than a unit test
//!
//! Run with: cargo test --test spake2_authentication -- --ignored

use std::process::Command;

#[test]
#[ignore] // Ignored by default - run with --ignored flag
fn test_spake2_authentication_via_e2e_script() {
    // Build the binaries first to ensure they're up to date
    println!("Building release binaries...");
    let build_result = Command::new("cargo")
        .args(["build", "--release", "--bin", "openscreen-test"])
        .current_dir("/opt/m/rust/openscreen_rs_priv")
        .output()
        .expect("Failed to build binaries");

    assert!(
        build_result.status.success(),
        "Failed to build binaries:\n{}",
        String::from_utf8_lossy(&build_result.stderr)
    );

    // Run the E2E test script with timeout
    println!("Running E2E test script with 10 second timeout...");

    // Use timeout command to prevent hanging
    let output = Command::new("timeout")
        .args(["10s", "bash", "./scripts/test-e2e.sh"])
        .env("LOG_LEVEL", "openscreen=info,quinn=warn")
        .env("TIMEOUT", "5")
        .current_dir("/opt/m/rust/openscreen_rs_priv")
        .output()
        .expect("Failed to run E2E script");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    println!("=== STDOUT ===\n{stdout}");
    if !stderr.is_empty() {
        println!("=== STDERR ===\n{stderr}");
    }

    // Clean up any orphaned processes
    let _ = Command::new("pkill").args(["-f", "openscreen"]).output();

    // Check exit code (124 = timeout, 0 = success)
    match output.status.code() {
        Some(0) => {
            // Success!
            println!("OK: E2E test completed successfully");
        }
        Some(124) => {
            panic!("FAIL: E2E test timed out after 10 seconds");
        }
        Some(code) => {
            panic!(
                "FAIL: E2E test failed with exit code: {code}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
            );
        }
        None => {
            panic!("FAIL: E2E test was terminated by signal");
        }
    }

    // Verify key success indicators in output
    assert!(
        stdout.contains("Test completed successfully") || stdout.contains("authenticated"),
        "Expected authentication success markers in output"
    );
}
