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

//! Mock implementation of OpenScreen discovery for testing
//!
//! This crate provides in-memory implementations of the discovery traits,
//! useful for testing applications without requiring actual mDNS networking.
//!
//! # Example
//!
//! ```
//! use openscreen_discovery::{DiscoveryPublisher, DiscoveryBrowser, PublishInfo, Fingerprint, AuthToken};
//! use openscreen_discovery_mock::{MockPublisher, MockBrowser, MockBackend};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create shared backend
//! let backend = MockBackend::new();
//!
//! // Create publisher and browser sharing the same backend
//! let mut publisher = MockPublisher::new(backend.clone());
//! let mut browser = MockBrowser::new(backend.clone());
//!
//! // Publish a service
//! let info = PublishInfo {
//!     display_name: "Test Device".to_string(),
//!     port: 4433,
//!     fingerprint: Fingerprint::from_bytes([1u8; 32]),
//!     metadata_version: 1,
//!     auth_token: AuthToken::generate(),
//!     hostname: "test.example.local".to_string(),
//! };
//! publisher.publish(info).await?;
//!
//! // Browse for services
//! browser.start_browsing().await?;
//! let services = browser.discovered_services();
//! assert_eq!(services.len(), 1);
//! # Ok(())
//! # }
//! ```

mod backend;
mod browser;
mod publisher;

pub use backend::MockBackend;
pub use browser::MockBrowser;
pub use publisher::MockPublisher;
