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

//! Discovery publisher trait

use crate::{DiscoveryError, PublishInfo, TxtRecords};
use async_trait::async_trait;

/// Advertises this device as an OpenScreen receiver
///
/// Implementations publish the service on mDNS with the service name `_openscreen._udp`
/// and include TXT records with the fingerprint, metadata version, and auth token.
#[async_trait]
pub trait DiscoveryPublisher: Send + Sync {
    /// Start advertising the service
    ///
    /// This registers the service with mDNS and begins advertising it on the network.
    ///
    /// # Errors
    ///
    /// Returns `DiscoveryError::PublishFailed` if the service cannot be registered.
    async fn publish(&mut self, info: PublishInfo) -> Result<(), DiscoveryError>;

    /// Stop advertising
    ///
    /// This unregisters the service from mDNS and stops advertising it.
    ///
    /// # Errors
    ///
    /// Returns `DiscoveryError::UnpublishFailed` if the service cannot be unregistered.
    async fn unpublish(&mut self) -> Result<(), DiscoveryError>;

    /// Update TXT records (e.g., new auth token)
    ///
    /// Note: Some implementations (mdns-sd) require unregister+register, causing
    /// the device to "blink" (disappear and reappear) on the network.
    ///
    /// # Errors
    ///
    /// Returns `DiscoveryError::PublishFailed` if the TXT records cannot be updated.
    async fn update_txt_records(&mut self, txt: TxtRecords) -> Result<(), DiscoveryError>;
}
