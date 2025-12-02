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

//! State machine types for the OpenScreen Network Protocol

use heapless::Vec;

/// Maximum size for peer's public value in SPAKE2
pub(crate) const PEER_PUBLIC_MAX_SIZE: usize = 65;

/// Maximum size for confirmation value (typically 32-64 bytes)
pub(crate) const CONFIRMATION_VALUE_MAX_SIZE: usize = 64;

/// Network protocol connection states
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkConnectionState {
    /// No connection established
    Idle,
    /// Negotiating authentication capabilities (PSK input methods)
    Negotiating,
    /// Doing SPAKE2 handshake (initiator)
    Handshaking,
    /// Initiator: received peer's public value, ready to finish SPAKE2
    FinishingSpake2 {
        peer_public: Vec<u8, PEER_PUBLIC_MAX_SIZE>,
    },
    /// Responder: received AuthInitiate, issuing SPAKE2 Start
    ResponderHandshaking,
    /// Responder: got own public value, ready to finish SPAKE2 and send AuthChallenge
    ResponderFinishing {
        peer_public: Vec<u8, PEER_PUBLIC_MAX_SIZE>,
    },
    /// Confirming mutual authentication with peer
    ConfirmingAuth {
        confirmation_value: Vec<u8, CONFIRMATION_VALUE_MAX_SIZE>,
    },
    /// Authentication complete
    Authenticated,
}

/// Pending crypto operation tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Reserved for future async crypto operation tracking
pub(crate) enum PendingCryptoOp {
    Spake2Start,
    Spake2Finish,
    HkdfDeriveKeys,
    HmacConfirmation,
}
