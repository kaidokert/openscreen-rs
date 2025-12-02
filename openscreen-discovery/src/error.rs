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

//! Discovery error types

/// Errors that can occur during discovery operations
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    /// Failed to publish service
    #[error("Failed to publish service: {0}")]
    PublishFailed(String),

    /// Failed to unpublish service
    #[error("Failed to unpublish service: {0}")]
    UnpublishFailed(String),

    /// Failed to start browsing
    #[error("Failed to start browsing: {0}")]
    BrowseFailed(String),

    /// Failed to stop browsing
    #[error("Failed to stop browsing: {0}")]
    StopBrowseFailed(String),

    /// Invalid service information
    #[error("Invalid service info: {0}")]
    InvalidServiceInfo(String),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Other error
    #[error("{0}")]
    Other(String),
}
