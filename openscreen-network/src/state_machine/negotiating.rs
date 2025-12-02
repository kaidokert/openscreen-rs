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

//! Negotiating State - Initial crypto setup and first message exchange

use super::{AwaitingHandshake, Computing, State};
use crate::messages::{AuthInitiationToken, AuthSpake2Handshake, Spake2PskStatus};
use crate::{crypto_data::CryptoData, NetworkError, NetworkInput, NetworkMessage, NetworkOutput};
use heapless::Vec;
use openscreen_crypto::{CryptoOpKind, CryptoRequest, Spake2Operation};

/// Negotiating initial crypto setup
///
/// This state handles the handshake message exchange:
/// - Initiator: Has called Start in Idle, waits for CryptoCompleted -> sends handshake -> AwaitingHandshake
/// - Responder: Passively waits for peer's handshake -> calls Start -> waits for own handshake -> Computing
///
/// Following the State Context Pattern, `CryptoData` is passed by reference.
#[derive(Debug)]
pub struct Negotiating {
    // No fields - state data is in parent Spake2StateMachine
}

impl Negotiating {
    /// Create a new Negotiating state
    pub fn new() -> Self {
        Self {}
    }

    /// Handle input events in the Negotiating state
    ///
    /// Expected inputs:
    /// - `CryptoCompleted` - Our handshake message ready (initiator)
    /// - `DataReceived` - Peer's handshake message (responder)
    ///
    /// Transitions to: `AwaitingHandshake` or `Computing`
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
            // CryptoCompleted: SPAKE2 Start operation completed with our handshake
            NetworkInput::CryptoCompleted(result) => {
                if result.data.is_empty() {
                    return Err(NetworkError::CryptoFailed);
                }

                // Store our handshake message in spake2_public
                crypto_data.spake2_public.clear();
                crypto_data
                    .spake2_public
                    .extend_from_slice(&result.data)
                    .map_err(|_| NetworkError::BufferFull)?;

                // Check if we're initiator or responder
                if crypto_data.is_responder {
                    // RESPONDER: We have both handshakes now, proceed to FinishWithConfirmation
                    // peer_public_temp was stored when we received DataReceived earlier
                    if crypto_data.peer_public_temp.is_empty() {
                        return Err(NetworkError::InvalidState);
                    }

                    let op_id = 2; // TODO: proper op_id generation
                    let request = CryptoRequest {
                        op_id,
                        kind: CryptoOpKind::Spake2(Spake2Operation::FinishWithConfirmation {
                            state: &crypto_data.spake2_public,
                            peer_public: &crypto_data.peer_public_temp,
                            message_transcript: &crypto_data.transcript,
                            my_tls_fingerprint: &crypto_data.my_fingerprint,
                            peer_tls_fingerprint: &crypto_data.peer_fingerprint,
                            is_responder: crypto_data.is_responder,
                        }),
                    };

                    outputs
                        .push(NetworkOutput::RequestCrypto(request))
                        .map_err(|_| NetworkError::BufferFull)?;

                    // Transition to Computing - waiting for crypto to derive keys
                    Ok(State::Computing(Computing::new()))
                } else {
                    // INITIATOR: Send handshake to peer and wait for response
                    let handshake_msg = AuthSpake2Handshake {
                        initiation_token: AuthInitiationToken { token: None },
                        psk_status: Spake2PskStatus::PskShown,
                        public_value: &crypto_data.spake2_public,
                    };

                    outputs
                        .push(NetworkOutput::SendMessage(
                            NetworkMessage::AuthSpake2Handshake(handshake_msg),
                        ))
                        .map_err(|_| NetworkError::BufferFull)?;

                    // Transition to AwaitingHandshake - waiting for peer's response
                    Ok(State::AwaitingHandshake(AwaitingHandshake::new()))
                }
            }

            // Responder: Received peer's handshake message
            NetworkInput::DataReceived(_stream, peer_handshake) => {
                // Store peer's handshake for later use in FinishWithConfirmation
                crypto_data.peer_public_temp.clear();
                crypto_data
                    .peer_public_temp
                    .extend_from_slice(peer_handshake)
                    .map_err(|_| NetworkError::BufferFull)?;

                // Responder hasn't started SPAKE2 yet (passive role) - start it now
                let op_id = 1; // TODO: proper op_id generation
                let request = CryptoRequest {
                    op_id,
                    kind: CryptoOpKind::Spake2(Spake2Operation::Start {
                        password_id: None,
                        password: &crypto_data.psk,
                        is_responder: crypto_data.is_responder,
                    }),
                };
                outputs
                    .push(NetworkOutput::RequestCrypto(request))
                    .map_err(|_| NetworkError::BufferFull)?;

                // Stay in Negotiating - wait for CryptoCompleted with our handshake
                // Then CryptoCompleted handler will call FinishWithConfirmation
                Ok(State::Negotiating(self))
            }

            NetworkInput::Tick(_) => {
                // Tick is fine, just stay in current state
                Ok(State::Negotiating(self))
            }
            _ => {
                panic!("Negotiating: unexpected input {:?} - only CryptoCompleted, DataReceived, or Tick expected", input);
            }
        }
    }
}

impl Default for Negotiating {
    fn default() -> Self {
        Self::new()
    }
}
