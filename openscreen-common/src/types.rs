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

//! Common types shared across OpenScreen protocol layers.

/// A unique identifier for a QUIC stream
pub type StreamId = u64;

/// Maximum size for encoded CBOR messages
pub const MAX_CBOR_SIZE: usize = 1024;

/// Maximum number of URLs in a URL availability request
pub const MAX_URLS: usize = 16;

/// Maximum length for a string field
pub const MAX_STRING_LENGTH: usize = 256;
