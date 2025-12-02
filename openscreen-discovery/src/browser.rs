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

//! Discovery browser trait

use crate::{DiscoveryError, ServiceInfo};
use async_trait::async_trait;
use futures::stream::BoxStream;

/// Discovers OpenScreen devices on the network
///
/// Implementations browse for services on mDNS with the service name `_openscreen._udp`
/// and parse TXT records to extract device information.
#[async_trait]
pub trait DiscoveryBrowser: Send + Sync {
    /// Start browsing for services
    ///
    /// This begins listening for mDNS announcements on the network.
    ///
    /// # Errors
    ///
    /// Returns `DiscoveryError::BrowseFailed` if browsing cannot be started.
    async fn start_browsing(&mut self) -> Result<(), DiscoveryError>;

    /// Stop browsing
    ///
    /// This stops listening for mDNS announcements.
    ///
    /// # Errors
    ///
    /// Returns `DiscoveryError::StopBrowseFailed` if browsing cannot be stopped.
    async fn stop_browsing(&mut self) -> Result<(), DiscoveryError>;

    /// Get currently discovered services (snapshot)
    ///
    /// Returns a snapshot of all services discovered so far.
    fn discovered_services(&self) -> Vec<ServiceInfo>;

    /// Stream of discovery events (services added/removed)
    ///
    /// Returns a stream that yields `DiscoveryEvent` items as services are
    /// discovered, removed, or updated on the network.
    fn event_stream(&self) -> BoxStream<'_, DiscoveryEvent>;
}

/// Discovery events (add/remove)
#[derive(Debug, Clone)]
pub enum DiscoveryEvent {
    /// A new service was discovered
    ServiceDiscovered(ServiceInfo),

    /// A service was removed (device went offline)
    ServiceRemoved {
        /// Instance name of the removed service
        instance_name: String,
    },

    /// A service was updated (TXT records changed)
    ServiceUpdated(ServiceInfo),
}
