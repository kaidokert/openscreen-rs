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

//! Integration tests for mock discovery backend

use futures::StreamExt;
use openscreen_discovery::{
    AuthToken, DiscoveryBrowser, DiscoveryEvent, DiscoveryPublisher, Fingerprint, PublishInfo,
};
use openscreen_discovery_mock::{MockBackend, MockBrowser, MockPublisher};

#[tokio::test]
async fn test_publish_and_discover() {
    let backend = MockBackend::new();
    let mut publisher = MockPublisher::new(backend.clone());
    let mut browser = MockBrowser::new(backend.clone());

    // Publish a service
    let info = PublishInfo {
        display_name: "Test Device".to_string(),
        hostname: "test-device._openscreen._tcp.local".to_string(),
        port: 4433,
        fingerprint: Fingerprint::from_bytes([42u8; 32]),
        metadata_version: 1,
        auth_token: AuthToken::generate(),
    };
    publisher.publish(info).await.unwrap();

    // Browse and verify
    browser.start_browsing().await.unwrap();
    let services = browser.discovered_services();

    assert_eq!(services.len(), 1);
    assert_eq!(services[0].display_name, "Test Device");
    assert_eq!(services[0].port, 4433);
    assert_eq!(services[0].fingerprint, Fingerprint::from_bytes([42u8; 32]));
}

#[tokio::test]
async fn test_multiple_services() {
    let backend = MockBackend::new();
    let mut pub1 = MockPublisher::new(backend.clone());
    let mut pub2 = MockPublisher::new(backend.clone());
    let mut browser = MockBrowser::new(backend.clone());

    // Publish two services
    let info1 = PublishInfo {
        display_name: "Device 1".to_string(),
        hostname: "device1._openscreen._tcp.local".to_string(),
        port: 4433,
        fingerprint: Fingerprint::from_bytes([1u8; 32]),
        metadata_version: 1,
        auth_token: AuthToken::generate(),
    };
    pub1.publish(info1).await.unwrap();

    let info2 = PublishInfo {
        display_name: "Device 2".to_string(),
        hostname: "device2._openscreen._tcp.local".to_string(),
        port: 5544,
        fingerprint: Fingerprint::from_bytes([2u8; 32]),
        metadata_version: 1,
        auth_token: AuthToken::generate(),
    };
    pub2.publish(info2).await.unwrap();

    // Browse and verify
    browser.start_browsing().await.unwrap();
    let services = browser.discovered_services();

    assert_eq!(services.len(), 2);

    let names: Vec<_> = services.iter().map(|s| s.display_name.as_str()).collect();
    assert!(names.contains(&"Device 1"));
    assert!(names.contains(&"Device 2"));
}

#[tokio::test]
async fn test_unpublish() {
    let backend = MockBackend::new();
    let mut publisher = MockPublisher::new(backend.clone());
    let mut browser = MockBrowser::new(backend.clone());

    // Publish and verify
    let info = PublishInfo {
        display_name: "Test Device".to_string(),
        hostname: "test-device._openscreen._tcp.local".to_string(),
        port: 4433,
        fingerprint: Fingerprint::from_bytes([42u8; 32]),
        metadata_version: 1,
        auth_token: AuthToken::generate(),
    };
    publisher.publish(info).await.unwrap();

    browser.start_browsing().await.unwrap();
    assert_eq!(browser.discovered_services().len(), 1);

    // Unpublish and verify
    publisher.unpublish().await.unwrap();
    assert_eq!(browser.discovered_services().len(), 0);
}

#[tokio::test]
async fn test_event_stream() {
    let backend = MockBackend::new();
    let mut publisher = MockPublisher::new(backend.clone());
    let mut browser = MockBrowser::new(backend.clone());

    // Start browsing and get event stream
    browser.start_browsing().await.unwrap();
    let mut events = browser.event_stream();

    // Publish a service
    let info = PublishInfo {
        display_name: "Test Device".to_string(),
        hostname: "test-device._openscreen._tcp.local".to_string(),
        port: 4433,
        fingerprint: Fingerprint::from_bytes([42u8; 32]),
        metadata_version: 1,
        auth_token: AuthToken::generate(),
    };
    publisher.publish(info).await.unwrap();

    // Wait for ServiceDiscovered event
    let event = tokio::time::timeout(tokio::time::Duration::from_secs(1), events.next())
        .await
        .expect("Timeout waiting for event")
        .expect("Stream ended");

    match event {
        DiscoveryEvent::ServiceDiscovered(service) => {
            assert_eq!(service.display_name, "Test Device");
        }
        _ => panic!("Expected ServiceDiscovered event"),
    }

    // Unpublish the service
    publisher.unpublish().await.unwrap();

    // Wait for ServiceRemoved event
    let event = tokio::time::timeout(tokio::time::Duration::from_secs(1), events.next())
        .await
        .expect("Timeout waiting for event")
        .expect("Stream ended");

    match event {
        DiscoveryEvent::ServiceRemoved { instance_name } => {
            assert_eq!(instance_name, "Test Device");
        }
        _ => panic!("Expected ServiceRemoved event"),
    }
}

#[tokio::test]
async fn test_service_equality_by_fingerprint() {
    let backend = MockBackend::new();
    let mut pub1 = MockPublisher::new(backend.clone());
    let mut pub2 = MockPublisher::new(backend.clone());
    let mut browser = MockBrowser::new(backend.clone());

    let fingerprint = Fingerprint::from_bytes([42u8; 32]);

    // Publish two services with same fingerprint but different names
    let info1 = PublishInfo {
        display_name: "Device Name 1".to_string(),
        hostname: "device1._openscreen._tcp.local".to_string(),
        port: 4433,
        fingerprint,
        metadata_version: 1,
        auth_token: AuthToken::generate(),
    };
    pub1.publish(info1).await.unwrap();

    let info2 = PublishInfo {
        display_name: "Device Name 2".to_string(),
        hostname: "device2._openscreen._tcp.local".to_string(),
        port: 5544,
        fingerprint,
        metadata_version: 1,
        auth_token: AuthToken::generate(),
    };
    pub2.publish(info2).await.unwrap();

    // Browse and verify
    browser.start_browsing().await.unwrap();
    let services = browser.discovered_services();

    // Both services should be present (different instance names)
    assert_eq!(services.len(), 2);

    // But they should be equal based on fingerprint
    assert_eq!(services[0], services[1]);
}
