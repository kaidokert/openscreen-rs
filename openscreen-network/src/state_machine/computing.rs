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

//! Computing State - Waiting for cryptographic operations

use super::{AwaitingConfirmation, AwaitingStatus, State};
use crate::messages::{AuthSpake2Confirmation, AuthStatus, AuthStatusCode};
use crate::{crypto_data::CryptoData, NetworkError, NetworkInput, NetworkMessage, NetworkOutput};
use heapless::Vec;
use openscreen_crypto::{CryptoOpKind, CryptoRequest, Spake2Operation};

/// Computing cryptographic operations
///
/// This state handles two different crypto operations:
/// 1. FinishWithConfirmation - Derives keys and our confirmation
/// 2. VerifyConfirmation - Verifies peer's confirmation
///
/// Following the State Context Pattern, `CryptoData` is passed by reference.
#[derive(Debug)]
pub struct Computing {
    // No fields - state data is in parent Spake2StateMachine
}

impl Computing {
    /// Create a new Computing state
    pub fn new() -> Self {
        Self {}
    }

    /// Handle input events in the Computing state
    ///
    /// Expected inputs:
    /// - `CryptoCompleted` from FinishWithConfirmation - Keys and our confirmation ready
    /// - `CryptoCompleted` from VerifyConfirmation - Peer's confirmation verified
    ///
    /// Transitions to: `AwaitingConfirmation` or `AwaitingStatus` or `Failed`
    ///
    /// After VerifyConfirmation succeeds, both sides send auth-status message
    /// and wait for peer's auth-status before transitioning to Authenticated.
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
            NetworkInput::CryptoCompleted(result) => {
                if result.data.is_empty() {
                    // Empty result means VerifyConfirmation succeeded!
                    // Send auth-status message and wait for peer's auth-status
                    let auth_status = AuthStatus {
                        status: AuthStatusCode::Ok,
                    };

                    outputs
                        .push(NetworkOutput::SendMessage(NetworkMessage::AuthStatus(
                            auth_status,
                        )))
                        .map_err(|_| NetworkError::BufferFull)?;

                    // Transition to AwaitingStatus - wait for peer's auth-status
                    return Ok(State::AwaitingStatus(AwaitingStatus::new()));
                }

                // Non-empty result is from FinishWithConfirmation
                // Format: shared_secret (32) || my_confirmation (32) || initiator_key (32) || responder_key (32)
                const SECRET_SIZE: usize = 32;
                const CONFIRMATION_SIZE: usize = 32;
                const KEY_SIZE: usize = 32;
                const MIN_SIZE: usize = SECRET_SIZE + CONFIRMATION_SIZE + KEY_SIZE + KEY_SIZE;

                if result.data.len() < MIN_SIZE {
                    return Err(NetworkError::CryptoFailed);
                }

                // Parse the result
                let shared_secret = &result.data[0..SECRET_SIZE];
                let my_confirmation = &result.data[SECRET_SIZE..SECRET_SIZE + CONFIRMATION_SIZE];
                let initiator_key = &result.data
                    [SECRET_SIZE + CONFIRMATION_SIZE..SECRET_SIZE + CONFIRMATION_SIZE + KEY_SIZE];
                let responder_key = &result.data[SECRET_SIZE + CONFIRMATION_SIZE + KEY_SIZE
                    ..SECRET_SIZE + CONFIRMATION_SIZE + KEY_SIZE + KEY_SIZE];

                // Store shared secret
                crypto_data.shared_secret.clear();
                crypto_data
                    .shared_secret
                    .extend_from_slice(shared_secret)
                    .map_err(|_| NetworkError::BufferFull)?;

                // Store BOTH derived confirmation keys
                // Both sides derive the same keys from shared secret
                // We use our_key to compute our confirmation, peer uses their_key to verify it
                crypto_data.initiator_confirmation_key.clear();
                crypto_data
                    .initiator_confirmation_key
                    .extend_from_slice(initiator_key)
                    .map_err(|_| NetworkError::BufferFull)?;

                crypto_data.responder_confirmation_key.clear();
                crypto_data
                    .responder_confirmation_key
                    .extend_from_slice(responder_key)
                    .map_err(|_| NetworkError::BufferFull)?;

                log::debug!(
                    "Computing: Stored derived keys, initiator_key={:02x?}, responder_key={:02x?}",
                    &initiator_key[..8],
                    &responder_key[..8]
                );

                // Store our confirmation message in crypto_data for borrowing
                crypto_data.my_confirmation_temp.clear();
                crypto_data
                    .my_confirmation_temp
                    .extend_from_slice(my_confirmation)
                    .map_err(|_| NetworkError::BufferFull)?;

                log::debug!(
                    "Computing: Extracted MY confirmation from crypto result: {:02x?}",
                    &my_confirmation[..8]
                );

                // Send AuthSpake2Confirmation message (with proper struct)
                let confirmation_msg = AuthSpake2Confirmation {
                    confirmation_value: &crypto_data.my_confirmation_temp,
                };

                log::debug!(
                    "Computing: Sending MY confirmation message: {:02x?}",
                    &crypto_data.my_confirmation_temp[..8]
                );

                outputs
                    .push(NetworkOutput::SendMessage(
                        NetworkMessage::AuthSpake2Confirmation(confirmation_msg),
                    ))
                    .map_err(|_| NetworkError::BufferFull)?;

                // Check if we buffered peer's confirmation while waiting for crypto
                if crypto_data.pending_confirmation_bytes.is_empty() {
                    // No buffered confirmation - transition to AwaitingConfirmation normally
                    Ok(State::AwaitingConfirmation(AwaitingConfirmation::new()))
                } else {
                    log::debug!(
                        "Computing: processing buffered confirmation ({} bytes)",
                        crypto_data.pending_confirmation_bytes.len()
                    );

                    // Decode the buffered CBOR message
                    let buffered_msg =
                        NetworkMessage::decode(&crypto_data.pending_confirmation_bytes)
                            .map_err(|_| NetworkError::DecodeFailed)?;

                    // Extract confirmation value
                    let confirmation_value = match buffered_msg {
                        NetworkMessage::AuthSpake2Confirmation(conf) => conf.confirmation_value,
                        _ => return Err(NetworkError::DecodeFailed), // Wrong message type
                    };

                    // Store in peer_confirmation_temp for verification
                    crypto_data.peer_confirmation_temp.clear();
                    crypto_data
                        .peer_confirmation_temp
                        .extend_from_slice(confirmation_value)
                        .map_err(|_| NetworkError::BufferFull)?;

                    // Clear the buffer
                    crypto_data.pending_confirmation_bytes.clear();

                    // Build verification context: transcript || peer_key
                    // The peer computed their confirmation as HMAC(peer_key, transcript)
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

                    // Request VerifyConfirmation
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

                    // Transition back to Computing - wait for verification result
                    Ok(State::Computing(Computing::new()))
                }
            }

            NetworkInput::DataReceived(_, data) => {
                // race condition: peer's confirmation may arrive before our FinishWithConfirmation completes
                // Buffer the raw CBOR bytes and process after crypto completes
                log::debug!(
                    "Computing: buffering {} bytes of peer confirmation (race condition)",
                    data.len()
                );

                crypto_data.pending_confirmation_bytes.clear();
                crypto_data
                    .pending_confirmation_bytes
                    .extend_from_slice(data)
                    .map_err(|_| NetworkError::BufferFull)?;

                // Stay in Computing, wait for our crypto to complete
                Ok(State::Computing(self))
            }

            NetworkInput::Tick(_) => {
                // Tick is fine, just stay in current state waiting for crypto
                Ok(State::Computing(self))
            }
            _ => {
                panic!("Computing: unexpected input {:?} - only CryptoCompleted, DataReceived, or Tick expected", input);
            }
        }
    }
}

impl Default for Computing {
    fn default() -> Self {
        Self::new()
    }
}
