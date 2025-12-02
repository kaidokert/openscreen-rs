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

//! Storage abstractions for OpenScreen application
//!
//! Defines traits for persistence of identity and peer information.

use anyhow::Result;
use std::path::PathBuf;

/// Trait for storing and retrieving identity credentials (certificate and private key)
pub trait IdentityStore {
    /// Save the certificate and private key PEM strings
    fn save_identity(&self, cert_pem: &str, key_pem: &str) -> Result<()>;

    /// Load the certificate and private key PEM strings
    /// Returns Ok(Some((cert_pem, key_pem))) if found, Ok(None) if not found
    fn load_identity(&self) -> Result<Option<(String, String)>>;
}

/// Default filesystem-based implementation of IdentityStore
pub struct FileStore {
    storage_dir: PathBuf,
}

impl FileStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            storage_dir: path.into(),
        }
    }
}

impl IdentityStore for FileStore {
    fn save_identity(&self, cert_pem: &str, key_pem: &str) -> Result<()> {
        std::fs::create_dir_all(&self.storage_dir)?;

        let cert_path = self.storage_dir.join("cert.pem");
        let key_path = self.storage_dir.join("key.pem");

        std::fs::write(&cert_path, cert_pem)?;
        std::fs::write(&key_path, key_pem)?;

        Ok(())
    }

    fn load_identity(&self) -> Result<Option<(String, String)>> {
        let cert_path = self.storage_dir.join("cert.pem");
        let key_path = self.storage_dir.join("key.pem");

        if !cert_path.exists() || !key_path.exists() {
            return Ok(None);
        }

        let cert_pem = std::fs::read_to_string(&cert_path)?;
        let key_pem = std::fs::read_to_string(&key_path)?;

        Ok(Some((cert_pem, key_pem)))
    }
}
