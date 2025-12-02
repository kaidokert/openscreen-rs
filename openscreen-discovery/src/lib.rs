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

//! OpenScreen Discovery Protocol
//!
//! This crate provides traits and types for discovering OpenScreen devices on the network
//! using DNS-SD (mDNS). It defines the core abstractions without being tied to a specific
//! mDNS implementation.
//!
//! ## Architecture
//!
//! - **Core traits**: `DiscoveryPublisher` and `DiscoveryBrowser` for advertising and discovering devices
//! - **Common types**: `ServiceInfo`, `Fingerprint`, `AuthToken` for device metadata
//! - **Pluggable backends**: Implementations are provided in separate crates (e.g., `openscreen-discovery-mdns`)
//!
//! ## Security Model
//!
//! Discovery provides the **expected fingerprint** from mDNS TXT records, but does NOT verify it.
//! The TLS layer (Quinn) is responsible for enforcing fingerprint verification during the handshake.
//!
//! ```text
//! mDNS TXT (fp=abc...) -> ServiceInfo.fingerprint -> QuinnClient.connect(expected_fp)
//! -> TLS Handshake -> ServerCertVerifier -> Accept/Reject
//! ```

pub mod auth_token;
pub mod browser;
pub mod error;
pub mod fingerprint;
pub mod publisher;
pub mod service_info;

pub use auth_token::AuthToken;
pub use browser::{DiscoveryBrowser, DiscoveryEvent};
pub use error::DiscoveryError;
pub use fingerprint::{Fingerprint, FingerprintError};
pub use publisher::DiscoveryPublisher;
pub use service_info::{PublishInfo, ServiceInfo, TxtRecords};
