use crate::sctp::Sctp;
use openssl::error::ErrorStack;
use openssl::pkey::{PKeyRef, Private};
use openssl::ssl::{
    Error as SslError, ErrorCode, Ssl, SslAcceptor, SslMethod, SslOptions, SslRef, SslStream,
    SslVerifyMode,
};
use openssl::x509::X509Ref;
use std::io::{self, Read, Write};

const SRTP_PROFILES: &str = "SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32";
const MTU: u32 = 1200;

pub struct DatagramBio {
    incoming: Vec<u8>,
    outgoing: Vec<u8>,
}

impl DatagramBio {
    fn new() -> Self {
        Self {
            incoming: Vec::new(),
            outgoing: Vec::new(),
        }
    }

    fn push(&mut self, packet: &[u8]) {
        self.incoming.extend_from_slice(packet);
    }

    fn take_outgoing(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.outgoing)
    }
}

impl Read for DatagramBio {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.incoming.is_empty() {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "no datagram"));
        }

        let n = buffer.len().min(self.incoming.len());
        buffer[..n].copy_from_slice(&self.incoming[..n]);
        self.incoming.drain(..n);
        Ok(n)
    }
}

impl Write for DatagramBio {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.outgoing.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct DtlsContext {
    acceptor: SslAcceptor,
}

impl DtlsContext {
    pub fn new(cert: &X509Ref, key: &PKeyRef<Private>) -> Result<Self, ErrorStack> {
        let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::dtls_server())?;
        acceptor.set_options(SslOptions::NO_DTLSV1 | SslOptions::SINGLE_ECDH_USE);
        acceptor.set_certificate(cert)?;
        acceptor.set_private_key(key)?;
        acceptor.check_private_key()?;
        acceptor.set_verify(SslVerifyMode::NONE);
        acceptor.set_tlsext_use_srtp(SRTP_PROFILES)?;

        Ok(Self {
            acceptor: acceptor.build(),
        })
    }

    pub fn acceptor(&self) -> &SslAcceptor {
        &self.acceptor
    }
}

#[derive(PartialEq)]
enum State {
    Handshaking,
    Connected,
}

pub struct DtlsSession {
    stream: SslStream<DatagramBio>,
    sctp: Sctp,
    state: State,
}

impl DtlsSession {
    pub fn new(ctx: &DtlsContext) -> Result<Self, ErrorStack> {
        let mut ssl = Ssl::new(ctx.acceptor().context())?;
        ssl.set_accept_state();
        ssl.set_mtu(MTU)?;
        let stream = SslStream::new(ssl, DatagramBio::new())?;
        Ok(Self {
            stream,
            sctp: Sctp::new(),
            state: State::Handshaking,
        })
    }

    pub fn ssl(&self) -> &SslRef {
        self.stream.ssl()
    }

    pub fn is_connected(&self) -> bool {
        self.state == State::Connected
    }

    pub fn handle_input(
        &mut self,
        packet: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<Option<Vec<u8>>, SslError> {
        // we push the packet into the buffer
        self.stream.get_mut().push(packet);

        // openssl is handling everything here pretty much
        match self.state {
            State::Handshaking => self.handle_handshake()?,
            State::Connected => self.handle_data(buffer)?,
        }

        let reply = self.stream.get_mut().take_outgoing();
        Ok((!reply.is_empty()).then_some(reply))
    }

    fn handle_handshake(&mut self) -> Result<(), SslError> {
        loop {
            match self.stream.accept() {
                Ok(()) => {
                    self.state = State::Connected;
                    return Ok(());
                }
                Err(e) if e.code() == ErrorCode::WANT_READ => return Ok(()),
                Err(e) if e.code() == ErrorCode::WANT_WRITE => continue,
                Err(e) => return Err(e),
            }
        }
    }

    fn handle_data(&mut self, buffer: &mut Vec<u8>) -> Result<(), SslError> {
        let mut ssl_buffer = [0u8; 2048];
        loop {
            match self.stream.ssl_read(&mut ssl_buffer) {
                Ok(0) => return Ok(()),
                Ok(n) => self
                    .sctp
                    .handle(&mut self.stream, &ssl_buffer[..n], buffer)?,
                Err(e) if e.code() == ErrorCode::WANT_READ => return Ok(()),
                Err(e) if e.code() == ErrorCode::WANT_WRITE => continue,
                // apparently an error will only ever be reported if it would tear down the session
                Err(e) => return Err(e),
            }
        }
    }
}
