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

//! SPAKE2 Authentication State Machine
//!
//! This module implements a typestate-based state machine for SPAKE2 authentication
//! following RFC 9382. The design uses the typestate pattern to make invalid state
//! transitions impossible at compile time.
//!
//! ## Architecture
//!
//! Each state is a distinct struct that owns its data. State transitions consume
//! the old state and return a new state, preventing accidental misuse.
//!
//! ## State Flow
//!
//! ```text
//! Idle
//!   ↓ TransportConnected
//! Negotiating (initiator sends handshake)
//!   ↓ CryptoCompleted(handshake) / DataReceived(peer handshake)
//! AwaitingHandshake (waiting for peer handshake)
//!   ↓ DataReceived(peer handshake)
//! Computing (crypto: finish + confirmation)
//!   ↓ CryptoCompleted(keys, confirmation)
//! AwaitingConfirmation (sent our confirmation)
//!   ↓ DataReceived(peer confirmation)
//! Computing (crypto: verify peer confirmation)
//!   ↓ CryptoCompleted(verify OK)
//! Authenticated (success!)
//!   or
//! Failed (any error)
//! ```
//!
//! ## Reference
//!
//! See `notes/NEW_STATEMACHINE_V2.md` for the approved specification.
//! See `notes/IMPLEMENTATION_APPROACH.md` for implementation decisions.

mod authenticated;
mod awaiting_capabilities;
mod awaiting_confirmation;
mod awaiting_handshake;
mod awaiting_status;
mod computing;
mod failed;
mod generating_handshake;
mod idle;
mod initiating_handshake;
mod negotiating;

pub use authenticated::Authenticated;
pub use awaiting_capabilities::AwaitingCapabilities;
pub use awaiting_confirmation::AwaitingConfirmation;
pub use awaiting_handshake::AwaitingHandshake;
pub use awaiting_status::AwaitingStatus;
pub use computing::Computing;
pub use failed::Failed;
pub use generating_handshake::GeneratingHandshake;
pub use idle::Idle;
pub use initiating_handshake::InitiatingHandshake;
pub use negotiating::Negotiating;

use crate::{NetworkError, NetworkInput, NetworkOutput};
use heapless::Vec;

/// The main state enum that wraps all possible states
#[derive(Debug)]
pub enum State {
    /// Initial state before connection
    Idle(Idle),
    /// Waiting for peer's auth-capabilities message (both sides)
    AwaitingCapabilities(AwaitingCapabilities),
    /// Initiator waiting for crypto to generate handshake (initiator only)
    InitiatingHandshake(InitiatingHandshake),
    /// Negotiating initial handshake
    Negotiating(Negotiating),
    /// Responder generating its handshake (responder only)
    GeneratingHandshake(GeneratingHandshake),
    /// Waiting for peer's handshake message
    AwaitingHandshake(AwaitingHandshake),
    /// Computing cryptographic operations
    Computing(Computing),
    /// Waiting for peer's confirmation message
    AwaitingConfirmation(AwaitingConfirmation),
    /// Waiting for peer's auth-status message (both sides)
    AwaitingStatus(AwaitingStatus),
    /// Authentication succeeded (terminal)
    Authenticated(Authenticated),
    /// Authentication failed (terminal)
    Failed(Failed),
    /// Temporary invalid state during transitions (for panic safety)
    Poisoned,
}

/// The state machine coordinator
///
/// This struct manages state transitions using the typestate pattern with
/// an enum wrapper to allow storage in a single field.
///
/// Following the "State Context Pattern", shared data (`CryptoData`) is stored
/// here and passed by reference to state handlers, avoiding lifetime conflicts
/// with borrowed `NetworkOutput<'a>`.
pub struct Spake2StateMachine {
    state: State,
    crypto_data: crate::CryptoData,
}

impl Spake2StateMachine {
    /// Create a new state machine in the Idle state with configured crypto data
    ///
    /// The `crypto_data` should have PSK, fingerprints, and role configured before
    /// calling this function.
    pub fn new(crypto_data: crate::CryptoData) -> Self {
        Self {
            state: State::Idle(Idle::new()),
            crypto_data,
        }
    }

    /// Handle an input event and produce output events
    ///
    /// This is the main entry point for the state machine. It uses `mem::replace`
    /// with `State::Poisoned` to ensure panic safety during transitions.
    ///
    /// Following the State Context Pattern, this method passes `&mut self.crypto_data`
    /// to state handlers, allowing them to borrow data for `NetworkOutput<'out>` while
    /// consuming themselves for state transitions.
    ///
    /// ## Lifetime Parameters
    ///
    /// - `'a`: Lifetime of outputs - tied to `self` (CryptoData), allowing outputs to borrow from state machine
    /// - `'b`: Lifetime of input - independent of outputs, allowing temporary inputs
    ///
    /// This separation prevents lifetime conflicts when using temporary inputs like `NetworkInput::Tick(0)`.
    pub fn handle<'a, 'b>(
        &'a mut self,
        input: &'b NetworkInput<'b>,
        outputs: &mut Vec<NetworkOutput<'a>, 16>,
    ) -> Result<(), NetworkError> {
        use core::mem;

        // Log incoming input and current state
        log::trace!(
            "STATE_MACHINE: input={:?} current_state={}",
            input,
            state_name(&self.state)
        );

        // Replace state with Poisoned temporarily for panic safety
        let old_state = mem::replace(&mut self.state, State::Poisoned);

        // Dispatch to the appropriate handler, passing crypto_data by mutable reference
        let new_state = match old_state {
            State::Idle(s) => {
                let next = s.handle(&mut self.crypto_data, input, outputs)?;
                log::trace!("STATE_TRANSITION: Idle -> {}", state_name(&next));
                next
            }
            State::AwaitingCapabilities(s) => {
                let next = s.handle(&mut self.crypto_data, input, outputs)?;
                log::trace!(
                    "STATE_TRANSITION: AwaitingCapabilities -> {}",
                    state_name(&next)
                );
                next
            }
            State::InitiatingHandshake(s) => {
                let next = s.handle(&mut self.crypto_data, input, outputs)?;
                log::trace!(
                    "STATE_TRANSITION: InitiatingHandshake -> {}",
                    state_name(&next)
                );
                next
            }
            State::Negotiating(s) => {
                let next = s.handle(&mut self.crypto_data, input, outputs)?;
                log::trace!("STATE_TRANSITION: Negotiating -> {}", state_name(&next));
                next
            }
            State::GeneratingHandshake(s) => {
                let next = s.handle(&mut self.crypto_data, input, outputs)?;
                log::trace!(
                    "STATE_TRANSITION: GeneratingHandshake -> {}",
                    state_name(&next)
                );
                next
            }
            State::AwaitingHandshake(s) => {
                let next = s.handle(&mut self.crypto_data, input, outputs)?;
                log::trace!(
                    "STATE_TRANSITION: AwaitingHandshake -> {}",
                    state_name(&next)
                );
                next
            }
            State::Computing(s) => {
                let next = s.handle(&mut self.crypto_data, input, outputs)?;
                log::trace!("STATE_TRANSITION: Computing -> {}", state_name(&next));
                next
            }
            State::AwaitingConfirmation(s) => {
                let next = s.handle(&mut self.crypto_data, input, outputs)?;
                log::trace!(
                    "STATE_TRANSITION: AwaitingConfirmation -> {}",
                    state_name(&next)
                );
                next
            }
            State::AwaitingStatus(s) => {
                let next = s.handle(&mut self.crypto_data, input, outputs)?;
                log::trace!("STATE_TRANSITION: AwaitingStatus -> {}", state_name(&next));
                next
            }
            State::Authenticated(s) => State::Authenticated(s), // Terminal state
            State::Failed(s) => State::Failed(s),               // Terminal state
            State::Poisoned => {
                // Should not happen unless a previous handle() panicked
                return Err(NetworkError::InvalidState);
            }
        };

        log::trace!("STATE_MACHINE: outputs_produced={}", outputs.len());
        self.state = new_state;
        Ok(())
    }

    /// Get the current state (for debugging/testing)
    pub fn state(&self) -> &State {
        &self.state
    }

    /// Check if authentication succeeded
    pub fn is_authenticated(&self) -> bool {
        matches!(self.state, State::Authenticated(_))
    }

    /// Check if authentication failed
    pub fn is_failed(&self) -> bool {
        matches!(self.state, State::Failed(_))
    }

    /// Get mutable access to crypto data (for setting PSK, auth token, etc.)
    pub fn crypto_data_mut(&mut self) -> &mut crate::CryptoData {
        &mut self.crypto_data
    }
}

impl Default for Spake2StateMachine {
    fn default() -> Self {
        Self::new(crate::CryptoData::new())
    }
}

/// Helper function to get state name for logging
fn state_name(state: &State) -> &'static str {
    match state {
        State::Idle(_) => "Idle",
        State::AwaitingCapabilities(_) => "AwaitingCapabilities",
        State::InitiatingHandshake(_) => "InitiatingHandshake",
        State::Negotiating(_) => "Negotiating",
        State::GeneratingHandshake(_) => "GeneratingHandshake",
        State::AwaitingHandshake(_) => "AwaitingHandshake",
        State::Computing(_) => "Computing",
        State::AwaitingConfirmation(_) => "AwaitingConfirmation",
        State::AwaitingStatus(_) => "AwaitingStatus",
        State::Authenticated(_) => "Authenticated",
        State::Failed(_) => "Failed",
        State::Poisoned => "Poisoned",
    }
}
