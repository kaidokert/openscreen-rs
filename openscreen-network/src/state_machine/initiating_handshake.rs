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

//! InitiatingHandshake State - Initiator waits for crypto to generate its handshake

use crate::messages::{AuthInitiationToken, AuthSpake2Handshake, Spake2PskStatus};
use crate::state_machine::{AwaitingHandshake, State};
use crate::{CryptoData, NetworkError, NetworkInput, NetworkMessage, NetworkOutput};

/// State: Initiator is waiting for crypto backend to generate its handshake message
#[derive(Debug)]
pub struct InitiatingHandshake;

impl InitiatingHandshake {
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

                // Store public value in crypto_data for later use
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
                        psk_status: Spake2PskStatus::PskShown, // TODO: Configurable based on device type
                        public_value: &crypto_data.spake2_public,
                    };
                    NetworkMessage::AuthSpake2Handshake(handshake_msg)
                        .encode(&mut crypto_data.our_handshake_msg)
                        .map_err(|_| NetworkError::EncodeFailed)?;
                }

                // Send handshake message to peer
                let token_ref = if crypto_data.auth_token_temp.is_empty() {
                    None
                } else {
                    Some(crypto_data.auth_token_temp.as_str())
                };
                let handshake_msg = AuthSpake2Handshake {
                    initiation_token: AuthInitiationToken { token: token_ref },
                    psk_status: Spake2PskStatus::PskShown,
                    public_value: &crypto_data.spake2_public,
                };
                outputs
                    .push(NetworkOutput::SendMessage(
                        NetworkMessage::AuthSpake2Handshake(handshake_msg),
                    ))
                    .map_err(|_| NetworkError::BufferFull)?;

                // Transition to AwaitingHandshake to wait for responder's handshake
                Ok(State::AwaitingHandshake(AwaitingHandshake::new()))
            }
            NetworkInput::Tick(_) => {
                // Tick is fine, just stay in current state
                Ok(State::InitiatingHandshake(self))
            }
            _ => {
                panic!("InitiatingHandshake: unexpected input {:?} - only CryptoCompleted or Tick expected", input);
            }
        }
    }
}

impl Default for InitiatingHandshake {
    fn default() -> Self {
        Self::new()
    }
}
