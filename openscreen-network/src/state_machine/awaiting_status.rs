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

//! AwaitingStatus State - Both sides wait for peer's auth-status

use crate::messages::AuthStatusCode;
use crate::state_machine::{Authenticated, Failed, State};
use crate::{AuthStatus, CryptoData, NetworkError, NetworkEvent, NetworkInput, NetworkOutput};

/// State: Waiting for peer's auth-status message
#[derive(Debug)]
pub struct AwaitingStatus;

impl Default for AwaitingStatus {
    fn default() -> Self {
        Self::new()
    }
}

impl AwaitingStatus {
    pub fn new() -> Self {
        Self
    }

    pub fn handle<'a>(
        self,
        _crypto_data: &'a mut CryptoData,
        input: &NetworkInput,
        outputs: &mut heapless::Vec<NetworkOutput<'a>, 16>,
    ) -> Result<State, NetworkError> {
        match input {
            NetworkInput::DataReceived(_stream_id, data) => {
                // Decode AuthStatus message from CBOR
                let status = AuthStatus::decode(data).map_err(|_| NetworkError::DecodeFailed)?;

                // Check if authentication succeeded
                if status.status != AuthStatusCode::Ok {
                    // Authentication failed - transition to Failed state
                    return Ok(State::Failed(Failed::new(
                        NetworkError::AuthenticationFailed,
                    )));
                }

                // Emit Authenticated event to notify application layer
                outputs
                    .push(NetworkOutput::Event(NetworkEvent::Authenticated))
                    .map_err(|_| NetworkError::BufferFull)?;

                // Transition to Authenticated terminal state
                Ok(State::Authenticated(Authenticated::new()))
            }
            NetworkInput::Tick(_) => {
                // Tick is fine, just stay in current state
                Ok(State::AwaitingStatus(self))
            }
            _ => {
                panic!(
                    "AwaitingStatus: unexpected input {:?} - only DataReceived or Tick expected",
                    input
                );
            }
        }
    }
}
