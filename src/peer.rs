use crate::dtls::{DtlsContext, DtlsSession};
use crate::engine::{Action, Event};
use crate::srtp::SrtpContext;
use std::net::SocketAddr;

pub struct Peer {
    pub address: SocketAddr,
    dtls: Option<DtlsSession>,
    srtp: Option<SrtpContext>,
}

impl Peer {
    pub fn new(address: SocketAddr) -> Self {
        Self {
            address,
            dtls: None,
            srtp: None,
        }
    }

    pub fn handle_dtls(
        &mut self,
        dtls_context: &DtlsContext,
        packet: &[u8],
        buffer: &mut Vec<u8>,
        actions: &mut Vec<Action>,
    ) -> Option<Vec<u8>> {
        if self.dtls.is_none() {
            self.dtls = Some(DtlsSession::new(dtls_context).ok()?);
        }

        let session = self.dtls.as_mut()?;

        let payload = match session.handle_input(packet, buffer) {
            Ok(payload) => payload,
            Err(error) => {
                log::warn!("dtls session with {} failed: {}", self.address, error);
                self.dtls = None;
                // do we need to remove the srtp session too?
                // self.srtp = None;
                return None;
            }
        };

        if session.is_connected() && self.srtp.is_none() {
            log::info!("peer's srtp context established: {}", self.address);

            self.srtp = Some(SrtpContext::from_dtls(session.ssl()).ok()?);
            actions.push(Action::Event(Event::PeerMediaReady(self.address)));
        }

        payload
    }

    pub fn protect(&mut self, buffer: &mut [u8], length: usize) -> Option<usize> {
        self.srtp.as_mut()?.protect(buffer, length)
    }

    pub fn unprotect(&mut self, packet: &mut [u8]) -> Option<usize> {
        self.srtp.as_mut()?.unprotect(packet)
    }

    pub fn protect_rtcp(&mut self, packet: &mut [u8]) -> Option<usize> {
        None // unimplemented
    }

    pub fn unprotect_srtcp(&mut self, packet: &mut [u8]) -> Option<usize> {
        self.srtp.as_mut()?.unprotect_srtcp(packet)
    }
}
