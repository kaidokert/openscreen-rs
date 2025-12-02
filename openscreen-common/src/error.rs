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

//! Error types shared across OpenScreen protocol layers.

/// Error kinds for message encoding/decoding
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageError {
    /// CBOR encoding failed
    EncodeFailed,
    /// CBOR decoding failed
    DecodeFailed,
    /// Buffer too small
    BufferFull,
    /// Invalid message type key
    InvalidMessageType,
    /// Missing required field
    MissingField,
    /// Invalid field value
    InvalidField,
    /// Field exceeds maximum allowed length
    FieldTooLong,
}
