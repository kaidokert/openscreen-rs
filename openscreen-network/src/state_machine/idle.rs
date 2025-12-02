// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law of an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Idle State - Initial state before connection

use super::{AwaitingCapabilities, State};
use crate::messages::PskInputEase;
use crate::{
    crypto_data::CryptoData, AuthCapabilities, NetworkError, NetworkInput, NetworkMessage,
    NetworkOutput,
};
use heapless::Vec;

/// Initial state before the QUIC connection is established
///
/// This state waits for `NetworkInput::TransportConnected` to begin authentication.
/// The CryptoData (PSK, fingerprints, role) is stored in the parent `Spake2StateMachine`
/// and passed by reference following the State Context Pattern.
#[derive(Debug)]
pub struct Idle {
    // No fields - state data is in parent Spake2StateMachine
}

impl Idle {
    /// Create a new Idle state
    ///
    /// The crypto data (PSK, fingerprints, role) must be configured in the parent
    /// `Spake2StateMachine` before calling `handle()`.
    pub fn new() -> Self {
        Self {}
    }

    /// Handle input events in the Idle state
    ///
    /// Expected input: `NetworkInput::TransportConnected`
    /// Transitions to: `AwaitingCapabilities`
    ///
    /// # Protocol Flow
    /// Per W3C OpenScreen Protocol:
    /// 1. Both sides send AuthCapabilities message
    /// 2. Both sides wait for peer's AuthCapabilities
    /// 3. Role differentiation happens in AwaitingCapabilities state
    ///
    /// # State Context Pattern
    /// This method receives `crypto_data` by mutable reference from the parent
    /// `Spake2StateMachine`, allowing it to borrow data for `NetworkOutput<'out>`
    /// while consuming `self` for state transitions.
    ///
    /// # Lifetime Parameters
    /// - `'a`: Lifetime of outputs - tied to `crypto_data`, allowing outputs to borrow from it
    /// - `'b`: Lifetime of input - independent of outputs
    pub fn handle<'a, 'b>(
        self,
        _crypto_data: &'a mut CryptoData,
        input: &'b NetworkInput<'b>,
        outputs: &mut Vec<NetworkOutput<'a>, 16>,
    ) -> Result<State, NetworkError> {
        match input {
            NetworkInput::TransportConnected => {
                // Both sides send AuthCapabilities message
                // Note: Using default configuration values (proper configuration deferred to future work)
                let auth_capabilities = AuthCapabilities {
                    psk_input_ease: PskInputEase::Simple,
                    psk_input_methods: Vec::new(), // Empty for now
                    psk_min_bits_of_entropy: 64,   // Minimum required
                };

                let msg = NetworkMessage::AuthCapabilities(auth_capabilities);
                outputs
                    .push(NetworkOutput::SendMessage(msg))
                    .map_err(|_| NetworkError::BufferFull)?;

                // Transition to AwaitingCapabilities state (consume self)
                // Wait for peer's AuthCapabilities message
                Ok(State::AwaitingCapabilities(AwaitingCapabilities::new()))
            }
            NetworkInput::Tick(_) => {
                // Tick is fine, just stay in current state
                Ok(State::Idle(self))
            }
            _ => {
                panic!(
                    "Idle: unexpected input {:?} - only TransportConnected or Tick expected",
                    input
                );
            }
        }
    }
}

impl Default for Idle {
    fn default() -> Self {
        Self::new()
    }
}
