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

//! Authentication token generation
//!
//! Auth tokens are used to prevent brute-force attacks on the PSK authentication.
//! They are included in mDNS TXT records and must be presented during connection.

/// Authentication token (for rate limiting brute force)
///
/// Per W3C spec, the auth token (`at` TXT record) is used to prevent brute-force
/// attacks on the PSK. The token must be obtained from mDNS before attempting to connect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthToken(String);

impl AuthToken {
    /// Generate a cryptographically secure random auth token
    ///
    /// This creates a cryptographically random 16-byte token using the system's
    /// secure random number generator (CSPRNG), then hex-encodes it to 32 characters.
    ///
    /// # Security
    ///
    /// Uses `getrandom` which provides cryptographically secure random bytes from
    /// the operating system's entropy source (e.g., `/dev/urandom` on Unix,
    /// `BCryptGenRandom` on Windows).
    ///
    /// # Example
    ///
    /// ```
    /// # use openscreen_discovery::AuthToken;
    /// let token = AuthToken::generate();
    /// assert!(token.as_str().len() >= 16);
    /// ```
    pub fn generate() -> Self {
        // Generate 16 cryptographically secure random bytes
        let mut token_bytes = [0u8; 16];
        getrandom::getrandom(&mut token_bytes)
            .expect("Failed to generate random bytes from system entropy source");

        // Hex-encode to 32-character string
        let token_hex = hex::encode(token_bytes);
        Self(token_hex)
    }

    /// Create from an existing string
    ///
    /// # Example
    ///
    /// ```
    /// # use openscreen_discovery::AuthToken;
    /// let token = AuthToken::from_string("0123456789abcdef0123456789abcdef".to_string());
    /// ```
    pub fn from_string(s: String) -> Self {
        Self(s)
    }

    /// Get the token as a string slice
    ///
    /// # Example
    ///
    /// ```
    /// # use openscreen_discovery::AuthToken;
    /// # let token = AuthToken::generate();
    /// let txt_value = format!("at={}", token.as_str());
    /// ```
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Validate token format
    ///
    /// Tokens should be at least 16 characters and contain only hex digits.
    ///
    /// # Example
    ///
    /// ```
    /// # use openscreen_discovery::AuthToken;
    /// let token = AuthToken::generate();
    /// assert!(token.validate());
    ///
    /// let invalid = AuthToken::from_string("short".to_string());
    /// assert!(!invalid.validate());
    /// ```
    pub fn validate(&self) -> bool {
        self.0.len() >= 16 && self.0.chars().all(|c| c.is_ascii_hexdigit())
    }
}

impl From<String> for AuthToken {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl AsRef<str> for AuthToken {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_token_generate() {
        let token = AuthToken::generate();
        assert!(token.validate());
        assert!(token.as_str().len() >= 16);
    }

    #[test]
    fn test_auth_token_validation() {
        let valid = AuthToken::from_string("0123456789abcdef0123456789abcdef".to_string());
        assert!(valid.validate());

        let too_short = AuthToken::from_string("short".to_string());
        assert!(!too_short.validate());

        let invalid_chars = AuthToken::from_string("not_hex_chars!!!".to_string());
        assert!(!invalid_chars.validate());
    }

    #[test]
    fn test_auth_token_uniqueness() {
        let token1 = AuthToken::generate();
        let token2 = AuthToken::generate();
        // Tokens should be different (very high probability)
        assert_ne!(token1, token2);
    }
}
