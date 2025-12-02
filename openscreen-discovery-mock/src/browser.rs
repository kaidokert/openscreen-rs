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

//! Mock discovery browser implementation

use crate::backend::{BackendEvent, MockBackend};
use async_trait::async_trait;
use futures::stream::{BoxStream, StreamExt};
use openscreen_discovery::{DiscoveryBrowser, DiscoveryError, DiscoveryEvent, ServiceInfo};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Mock implementation of DiscoveryBrowser
///
/// This browser reads services from an in-memory backend shared with MockPublisher instances.
pub struct MockBrowser {
    backend: MockBackend,
    browsing: Arc<RwLock<bool>>,
}

impl MockBrowser {
    /// Create a new mock browser
    ///
    /// # Example
    ///
    /// ```
    /// use openscreen_discovery_mock::{MockBrowser, MockBackend};
    ///
    /// let backend = MockBackend::new();
    /// let browser = MockBrowser::new(backend);
    /// ```
    pub fn new(backend: MockBackend) -> Self {
        Self {
            backend,
            browsing: Arc::new(RwLock::new(false)),
        }
    }
}

#[async_trait]
impl DiscoveryBrowser for MockBrowser {
    async fn start_browsing(&mut self) -> Result<(), DiscoveryError> {
        *self.browsing.write().await = true;
        Ok(())
    }

    async fn stop_browsing(&mut self) -> Result<(), DiscoveryError> {
        *self.browsing.write().await = false;
        Ok(())
    }

    fn discovered_services(&self) -> Vec<ServiceInfo> {
        // For mock implementation, we do a blocking read
        // This works with both current_thread and multi_thread runtimes
        futures::executor::block_on(async { self.backend.get_services().await })
    }

    fn event_stream(&self) -> BoxStream<'_, DiscoveryEvent> {
        let mut receiver = self.backend.subscribe();
        let browsing = self.browsing.clone();

        async_stream::stream! {
            loop {
                // Only yield events if we're actively browsing
                if !*browsing.read().await {
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    continue;
                }

                match receiver.recv().await {
                    Ok(BackendEvent::ServicePublished(info)) => {
                        yield DiscoveryEvent::ServiceDiscovered(info);
                    }
                    Ok(BackendEvent::ServiceUnpublished(instance_name)) => {
                        yield DiscoveryEvent::ServiceRemoved { instance_name };
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        // Some events were missed, continue to next iteration
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        // Channel closed, stop streaming
                        break;
                    }
                }
            }
        }
        .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::publisher::MockPublisher;
    use futures::StreamExt;
    use openscreen_discovery::{AuthToken, DiscoveryPublisher, Fingerprint, PublishInfo};

    #[tokio::test]
    async fn test_mock_browser_discovered_services() {
        let backend = MockBackend::new();
        let mut publisher = MockPublisher::new(backend.clone());
        let mut browser = MockBrowser::new(backend.clone());

        // Publish a service
        let info = PublishInfo {
            display_name: "Test Device".to_string(),
            hostname: "test-device._openscreen._tcp.local".to_string(),
            port: 4433,
            fingerprint: Fingerprint::from_bytes([1u8; 32]),
            metadata_version: 1,
            auth_token: AuthToken::generate(),
        };
        publisher.publish(info).await.unwrap();

        // Start browsing
        browser.start_browsing().await.unwrap();

        // Get discovered services
        let services = browser.discovered_services();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].display_name, "Test Device");
    }

    #[tokio::test]
    async fn test_mock_browser_event_stream() {
        let backend = MockBackend::new();
        let mut publisher = MockPublisher::new(backend.clone());
        let mut browser = MockBrowser::new(backend.clone());

        // Start browsing first
        browser.start_browsing().await.unwrap();

        // Get event stream
        let mut events = browser.event_stream();

        // Publish a service (should trigger an event)
        let info = PublishInfo {
            display_name: "Test Device".to_string(),
            hostname: "test-device._openscreen._tcp.local".to_string(),
            port: 4433,
            fingerprint: Fingerprint::from_bytes([1u8; 32]),
            metadata_version: 1,
            auth_token: AuthToken::generate(),
        };
        publisher.publish(info).await.unwrap();

        // Wait for event
        let event = tokio::time::timeout(tokio::time::Duration::from_millis(500), events.next())
            .await
            .expect("Timeout waiting for event")
            .expect("Stream ended");

        match event {
            DiscoveryEvent::ServiceDiscovered(service) => {
                assert_eq!(service.display_name, "Test Device");
            }
            _ => panic!("Expected ServiceDiscovered event"),
        }
    }

    #[tokio::test]
    async fn test_mock_browser_stop_browsing() {
        let backend = MockBackend::new();
        let mut browser = MockBrowser::new(backend.clone());

        browser.start_browsing().await.unwrap();
        assert!(*browser.browsing.read().await);

        browser.stop_browsing().await.unwrap();
        assert!(!*browser.browsing.read().await);
    }
}
