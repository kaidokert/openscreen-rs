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

//! Authenticated State - Terminal success state

/// Authentication succeeded (terminal state)
///
/// This is a terminal state. Once reached, no further state transitions occur.
#[derive(Debug)]
pub struct Authenticated {
    // In the future, this could store session keys or other authenticated state
}

impl Authenticated {
    /// Create a new Authenticated state
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for Authenticated {
    fn default() -> Self {
        Self::new()
    }
}
