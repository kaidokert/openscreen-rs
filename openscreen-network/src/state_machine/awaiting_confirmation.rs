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

//! AwaitingConfirmation State - Waiting for peer's confirmation message

use super::{Computing, State};
use crate::{
    crypto_data::CryptoData, messages::NetworkMessage, NetworkError, NetworkInput, NetworkOutput,
};
use heapless::Vec;
use openscreen_crypto::{CryptoOpKind, CryptoRequest, Spake2Operation};

/// Waiting for peer's confirmation message
///
/// We've sent our confirmation and are waiting to verify the peer's.
///
/// Following the State Context Pattern, `CryptoData` is passed by reference.
#[derive(Debug)]
pub struct AwaitingConfirmation {
    // No fields - state data is in parent Spake2StateMachine
}

impl AwaitingConfirmation {
    /// Create a new AwaitingConfirmation state
    pub fn new() -> Self {
        Self {}
    }

    /// Handle input events in the AwaitingConfirmation state
    ///
    /// Expected input: `DataReceived` - Peer's confirmation message
    /// Transitions to: `Computing` (for verification)
    ///
    /// # Lifetime Parameters
    /// - `'a`: Lifetime of outputs - tied to `crypto_data`
    /// - `'b`: Lifetime of input - independent of outputs
    pub fn handle<'a, 'b>(
        self,
        crypto_data: &'a mut CryptoData,
        input: &'b NetworkInput<'b>,
        outputs: &mut Vec<NetworkOutput<'a>, 16>,
    ) -> Result<State, NetworkError> {
        match input {
            NetworkInput::DataReceived(_stream, peer_confirmation_cbor) => {
                // Decode the CBOR message to extract the confirmation value
                let msg = NetworkMessage::decode(peer_confirmation_cbor)
                    .map_err(|_| NetworkError::DecodeFailed)?;

                let confirmation_value = match msg {
                    NetworkMessage::AuthSpake2Confirmation(conf) => conf.confirmation_value,
                    _ => return Err(NetworkError::DecodeFailed), // Wrong message type
                };

                // Store peer's confirmation value in crypto_data for borrowing
                crypto_data.peer_confirmation_temp.clear();
                crypto_data
                    .peer_confirmation_temp
                    .extend_from_slice(confirmation_value)
                    .map_err(|_| NetworkError::BufferFull)?;

                log::debug!(
                    "AwaitingConfirmation: RECEIVED peer confirmation from network: {:02x?}",
                    &crypto_data.peer_confirmation_temp[..8]
                );

                // Build verification context: transcript || peer_key
                // The peer computed their confirmation as HMAC(peer_key, transcript)
                // So we need to use the peer's key to verify it
                let peer_key = if crypto_data.is_responder {
                    // We are responder, peer is initiator
                    &crypto_data.initiator_confirmation_key
                } else {
                    // We are initiator, peer is responder
                    &crypto_data.responder_confirmation_key
                };

                crypto_data.confirmation_context.clear();
                crypto_data
                    .confirmation_context
                    .extend_from_slice(&crypto_data.transcript)
                    .map_err(|_| NetworkError::BufferFull)?;
                crypto_data
                    .confirmation_context
                    .extend_from_slice(peer_key)
                    .map_err(|_| NetworkError::BufferFull)?;

                log::debug!(
                    "AwaitingConfirmation: Built context with peer_key={:02x?}, is_responder={}",
                    &peer_key[..8],
                    crypto_data.is_responder
                );

                // Request VerifyConfirmation to verify peer's confirmation (borrow from crypto_data)
                let op_id = 4; // TODO: proper op_id generation
                let request = CryptoRequest {
                    op_id,
                    kind: CryptoOpKind::Spake2(Spake2Operation::VerifyConfirmation {
                        context: &crypto_data.confirmation_context,
                        peer_confirmation: &crypto_data.peer_confirmation_temp,
                    }),
                };

                outputs
                    .push(NetworkOutput::RequestCrypto(request))
                    .map_err(|_| NetworkError::BufferFull)?;

                // Transition back to Computing - waiting for verification result
                // If verification succeeds (empty result), Computing will transition to Authenticated
                // If verification fails, it will transition to Failed
                Ok(State::Computing(Computing::new()))
            }

            NetworkInput::Tick(_) => {
                // Tick is fine, just stay in current state
                Ok(State::AwaitingConfirmation(self))
            }
            _ => {
                panic!("AwaitingConfirmation: unexpected input {:?} - only DataReceived or Tick expected", input);
            }
        }
    }
}

impl Default for AwaitingConfirmation {
    fn default() -> Self {
        Self::new()
    }
}
