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

    pub fn protect(&mut self, packet: &[u8], buffer: &mut Vec<u8>) -> bool {
        match self.srtp.as_mut() {
            Some(srtp) => srtp.protect(packet, buffer).is_ok(),
            None => false,
        }
    }

    pub fn protect_rtcp(&mut self, packet: &[u8], buffer: &mut Vec<u8>) -> bool {
        match self.srtp.as_mut() {
            Some(srtp) => srtp.protect_rtcp(packet, buffer).is_ok(),
            None => false,
        }
    }

    pub fn unprotect(&mut self, packet: &[u8], buffer: &mut Vec<u8>) -> bool {
        match self.srtp.as_mut() {
            Some(srtp) => srtp.unprotect(packet, buffer).is_ok(),
            None => false,
        }
    }

    pub fn unprotect_rtcp(&mut self, packet: &[u8], buffer: &mut Vec<u8>) -> bool {
        match self.srtp.as_mut() {
            Some(srtp) => srtp.unprotect_rtcp(packet, buffer).is_ok(),
            None => false,
        }
    }
}
