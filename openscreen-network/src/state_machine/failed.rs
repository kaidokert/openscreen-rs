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

//! Failed State - Terminal failure state

use crate::NetworkError;

/// Authentication failed (terminal state)
///
/// This is a terminal state that stores the error that caused the failure.
#[derive(Debug)]
pub struct Failed {
    pub(crate) error: NetworkError,
}

impl Failed {
    /// Create a new Failed state with the given error
    pub fn new(error: NetworkError) -> Self {
        Self { error }
    }

    /// Get the error that caused the failure
    pub fn error(&self) -> &NetworkError {
        &self.error
    }
}
