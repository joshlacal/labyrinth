//! Oblivious Revocable Function over Ristretto255 (paper p.18–20, SPEC §3.6).
//! The server half runs on mls-ds ([CB-17]).

use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct OrfClientState(pub(crate) [u8; 32]);
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct OrfServerState(pub(crate) [u8; 32]);
/// Random scalar `r` handed to the server on evolve.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EvolveToken(pub [u8; 32]);
/// Compressed Ristretto point sent from client to server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObliviousId(pub [u8; 32]);

impl OrfClientState {
    pub fn to_bytes(&self) -> [u8; 32] { self.0 }
    pub fn from_bytes(b: [u8; 32]) -> crate::Result<Self> { todo!() }
}
impl OrfServerState {
    pub fn to_bytes(&self) -> [u8; 32] { self.0 }
    pub fn from_bytes(b: [u8; 32]) -> crate::Result<Self> { todo!() }
}

pub fn orf_client_init() -> crate::Result<OrfClientState> { todo!() }
pub fn orf_server_init() -> crate::Result<OrfServerState> { todo!() }
pub fn orf_client_map(state: &OrfClientState, domain: &[u8], input: &[u8]) -> ObliviousId { todo!() }
pub fn orf_server_map(state: &OrfServerState, domain: &[u8], id: &ObliviousId) -> crate::Result<[u8; 32]> { todo!() }
pub fn orf_client_evolve(state: &OrfClientState) -> crate::Result<(OrfClientState, EvolveToken)> { todo!() }
pub fn orf_server_evolve(state: &OrfServerState, token: &EvolveToken) -> crate::Result<OrfServerState> { todo!() }
