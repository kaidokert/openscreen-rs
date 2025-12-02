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

//! GeneratingHandshake State - Responder generates its handshake after receiving initiator's

use crate::messages::{AuthInitiationToken, AuthSpake2Handshake, Spake2PskStatus};
use crate::state_machine::{Computing, State};
use crate::{CryptoData, NetworkError, NetworkInput, NetworkMessage, NetworkOutput};
use openscreen_crypto::{CryptoOpKind, CryptoRequest, Spake2Operation};

/// State: Responder is generating its own handshake message
#[derive(Debug)]
pub struct GeneratingHandshake;

impl Default for GeneratingHandshake {
    fn default() -> Self {
        Self::new()
    }
}

impl GeneratingHandshake {
    pub fn new() -> Self {
        Self
    }

    pub fn handle<'a>(
        self,
        crypto_data: &'a mut CryptoData,
        input: &NetworkInput,
        outputs: &mut heapless::Vec<NetworkOutput<'a>, 16>,
    ) -> Result<State, NetworkError> {
        match input {
            NetworkInput::CryptoCompleted(result) => {
                // Extract public value from crypto result (SPAKE2 public key)
                let public_value = &result.data;

                // Store public value in crypto_data
                crypto_data.spake2_public.clear();
                crypto_data
                    .spake2_public
                    .extend_from_slice(public_value)
                    .map_err(|_| NetworkError::BufferFull)?;

                // Copy auth token to owned string in CryptoData (for message lifetime)
                crypto_data.auth_token_temp.clear();
                if !crypto_data.auth_token.is_empty() {
                    // Convert bytes to UTF-8 string
                    let token_str = core::str::from_utf8(&crypto_data.auth_token)
                        .map_err(|_| NetworkError::DecodeFailed)?;
                    crypto_data
                        .auth_token_temp
                        .push_str(token_str)
                        .map_err(|_| NetworkError::BufferFull)?;
                }

                // Encode full CBOR message and store it first
                // This is done before SendMessage to ensure transcript is correct
                crypto_data.our_handshake_msg.clear();
                {
                    let token_ref = if crypto_data.auth_token_temp.is_empty() {
                        None
                    } else {
                        Some(crypto_data.auth_token_temp.as_str())
                    };
                    let handshake_msg = AuthSpake2Handshake {
                        initiation_token: AuthInitiationToken { token: token_ref },
                        psk_status: Spake2PskStatus::PskInput, // Responder: user inputs PSK
                        public_value: &crypto_data.spake2_public,
                    };
                    NetworkMessage::AuthSpake2Handshake(handshake_msg)
                        .encode(&mut crypto_data.our_handshake_msg)
                        .map_err(|_| NetworkError::EncodeFailed)?;
                }

                // Send our handshake message to peer
                let token_ref = if crypto_data.auth_token_temp.is_empty() {
                    None
                } else {
                    Some(crypto_data.auth_token_temp.as_str())
                };
                let handshake_msg = AuthSpake2Handshake {
                    initiation_token: AuthInitiationToken { token: token_ref },
                    psk_status: Spake2PskStatus::PskInput,
                    public_value: &crypto_data.spake2_public,
                };
                outputs
                    .push(NetworkOutput::SendMessage(
                        NetworkMessage::AuthSpake2Handshake(handshake_msg),
                    ))
                    .map_err(|_| NetworkError::BufferFull)?;

                // Build transcript = peer_handshake_msg || our_handshake_msg
                crypto_data.transcript.clear();
                crypto_data
                    .transcript
                    .extend_from_slice(&crypto_data.peer_handshake_msg)
                    .map_err(|_| NetworkError::BufferFull)?;
                crypto_data
                    .transcript
                    .extend_from_slice(&crypto_data.our_handshake_msg)
                    .map_err(|_| NetworkError::BufferFull)?;

                // Responder now has BOTH handshakes (ours + peer's already received)
                // Call FinishWithConfirmation to compute shared secret and confirmation
                let op = CryptoOpKind::Spake2(Spake2Operation::FinishWithConfirmation {
                    state: &crypto_data.spake2_public,               // Our SPAKE2 state
                    peer_public: &crypto_data.peer_public_temp,      // Initiator's public key
                    message_transcript: &crypto_data.transcript,     // Full CBOR messages
                    my_tls_fingerprint: &crypto_data.my_fingerprint, // TLS cert fingerprint
                    peer_tls_fingerprint: &crypto_data.peer_fingerprint, // Peer's TLS fingerprint
                    is_responder: crypto_data.is_responder,
                });
                let op_id = 2; // TODO: Use proper op_id tracking
                outputs
                    .push(NetworkOutput::RequestCrypto(CryptoRequest {
                        op_id,
                        kind: op,
                    }))
                    .map_err(|_| NetworkError::BufferFull)?;

                // Transition to Computing to wait for FinishWithConfirmation result
                Ok(State::Computing(Computing::new()))
            }
            NetworkInput::Tick(_) => {
                // Tick is fine, just stay in current state
                Ok(State::GeneratingHandshake(self))
            }
            _ => {
                panic!("GeneratingHandshake: unexpected input {:?} - only CryptoCompleted or Tick expected", input);
            }
        }
    }
}
