use ::srtp::openssl::{Config, Error, InboundSession, OutboundSession, session_pair};
use openssl::ssl::SslRef;

pub struct SrtpContext {
    inbound: InboundSession,
    outbound: OutboundSession,
}

impl SrtpContext {
    pub fn from_dtls(ssl: &SslRef) -> Result<Self, Error> {
        let result = session_pair(ssl, Config::default());
        let _ = openssl::error::ErrorStack::get(); // we drain some annoying error out

        let (inbound, outbound) = result?;
        Ok(Self { inbound, outbound })
    }

    pub fn protect(&mut self, packet: &[u8], buffer: &mut Vec<u8>) -> Result<(), ::srtp::Error> {
        buffer.clear();
        buffer.extend_from_slice(packet);
        self.outbound.protect(buffer)?;
        Ok(())
    }

    pub fn unprotect(&mut self, packet: &[u8], buffer: &mut Vec<u8>) -> Result<(), ::srtp::Error> {
        buffer.clear();
        buffer.extend_from_slice(packet);
        self.inbound.unprotect(buffer)?;
        Ok(())
    }

    pub fn protect_rtcp(
        &mut self,
        packet: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<(), ::srtp::Error> {
        buffer.clear();
        buffer.extend_from_slice(packet);
        self.outbound.protect_rtcp(buffer)?;
        Ok(())
    }

    pub fn unprotect_rtcp(
        &mut self,
        packet: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<(), ::srtp::Error> {
        buffer.clear();
        buffer.extend_from_slice(packet);
        self.inbound.unprotect_rtcp(buffer)?;
        Ok(())
    }
}
