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

//! mDNS implementation of OpenScreen discovery using mdns-sd
//!
//! This crate provides production implementations of the discovery traits
//! using the `mdns-sd` library for multicast DNS service discovery.
//!
//! # Example
//!
//! ```no_run
//! use openscreen_discovery::{DiscoveryPublisher, PublishInfo, Fingerprint, AuthToken};
//! use openscreen_discovery_mdns::MdnsPublisher;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut publisher = MdnsPublisher::new()?;
//!
//! let info = PublishInfo {
//!     display_name: "My Device".to_string(),
//!     port: 4433,
//!     fingerprint: Fingerprint::from_bytes([1u8; 32]),
//!     metadata_version: 1,
//!     auth_token: AuthToken::generate(),
//!     hostname: "my-device.local".to_string(),
//! };
//!
//! publisher.publish(info).await?;
//! # Ok(())
//! # }
//! ```

mod browser;
mod publisher;
mod utils;

pub use browser::MdnsBrowser;
pub use publisher::MdnsPublisher;

/// W3C OpenScreen service name
pub const SERVICE_NAME: &str = "_openscreen._udp.local.";
