use crate::association::Association;
use crate::chunk::{COOKIE_ECHO, DATA, INIT};
use crate::chunk::{Chunk, CookieEcho, Data, Init};
use crate::dtls::DatagramBio;
use openssl::ssl::Error as SslError;
use openssl::ssl::SslStream;

pub const HEADER_LEN: usize = 12;

pub struct Sctp {
    association: Option<Association>,
}

impl Sctp {
    pub fn new() -> Self {
        Self { association: None }
    }
    pub fn handle(
        &mut self,
        stream: &mut SslStream<DatagramBio>,
        packet: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<(), SslError> {
        log::trace!(
            "received sctp packet {} bytes type {}",
            packet.len(),
            packet[HEADER_LEN]
        );

        let sctp = SctpPacket::new(packet);

        match &sctp.chunk {
            Chunk::Init(init) => {
                let association = match &mut self.association {
                    Some(association) if association.peer_tag == init.initiate_tag => association,
                    slot => slot.insert(Association::new(init)),
                };
                association.build_init_ack(&sctp.header, buffer);
                stream.ssl_write(buffer)?;

                return Ok(());
            }

            Chunk::CookieEcho(cookie_echo) if let Some(association) = self.association.as_mut() => {
                if cookie_echo.cookie(&packet) == association.cookie.to_be_bytes() {
                    association.establish();
                    SctpPacket::build_cookie_ack(&sctp.header, association.peer_tag, buffer);
                    stream.ssl_write(&buffer)?;

                    log::info!("association established");
                } else {
                    log::warn!("establishing association failed: cookie mismatch");
                }

                Ok(())
            }
            Chunk::Data(data) if let Some(association) = self.association.as_mut() => {
                association.handle(stream, &sctp, buffer)
            }
            _ => {
                log::warn!(
                    "could not handle sctp packet, chunk type {}",
                    packet[HEADER_LEN]
                );

                Ok(())
            }
        }
    }
}

pub struct SctpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub verification_tag: u32,
    pub checksum: u32,
}

impl SctpHeader {
    fn parse(packet: &[u8]) -> Self {
        let source_port = u16::from_be_bytes([packet[0], packet[1]]);
        let destination_port = u16::from_be_bytes([packet[2], packet[3]]);
        let verification_tag = u32::from_be_bytes(packet[4..8].try_into().unwrap());
        let checksum = u32::from_le_bytes(packet[8..12].try_into().unwrap());

        Self {
            source_port,
            destination_port,
            verification_tag,
            checksum,
        }
    }

    fn write_to(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(&self.source_port.to_be_bytes());
        buffer.extend_from_slice(&self.destination_port.to_be_bytes());
        buffer.extend_from_slice(&self.verification_tag.to_be_bytes());
        buffer.extend_from_slice(&self.checksum.to_le_bytes());
    }
}

pub struct SctpPacket<'a> {
    pub header: SctpHeader,
    pub chunk: Chunk,
    pub raw: &'a [u8],
}

impl<'a> SctpPacket<'a> {
    pub fn new(packet: &'a [u8]) -> Self {
        let header = SctpHeader::parse(packet);
        let chunk_type = packet[HEADER_LEN];
        let mut chunk = Chunk::Unknown(packet[HEADER_LEN]);

        match chunk_type {
            DATA => {
                chunk = Chunk::Data(Data::parse(&packet[HEADER_LEN..]));
            }
            INIT => {
                chunk = Chunk::Init(Init::parse(&packet[HEADER_LEN..]));
            }
            COOKIE_ECHO => {
                chunk = Chunk::CookieEcho(CookieEcho::parse(&packet[HEADER_LEN..]));
            }
            _ => {
                log::warn!("unknown sctp packet type {}", chunk_type);
            }
        }

        Self {
            header,
            chunk,
            raw: packet,
        }
    }

    pub fn begin(header: &SctpHeader, verification_tag: u32, buffer: &mut Vec<u8>) {
        buffer.clear();

        buffer.extend_from_slice(&header.destination_port.to_be_bytes());
        buffer.extend_from_slice(&header.source_port.to_be_bytes());
        buffer.extend_from_slice(&verification_tag.to_be_bytes());
        buffer.extend_from_slice(&0_u32.to_be_bytes());
    }

    pub fn finish(buffer: &mut [u8]) {
        let checksum = crc32c::crc32c(buffer);
        buffer[8..12].copy_from_slice(&checksum.to_le_bytes());
    }

    pub fn build(header: &SctpHeader, verification_tag: u32, chunks: &[u8]) -> Vec<u8> {
        let mut packet = Vec::with_capacity(1024);

        let header = SctpHeader {
            source_port: header.destination_port,
            destination_port: header.source_port,
            verification_tag: verification_tag,
            checksum: 0,
        };
        header.write_to(&mut packet);

        packet.extend_from_slice(chunks);

        let checksum = crc32c::crc32c(&packet);
        packet[8..12].copy_from_slice(&checksum.to_le_bytes());

        packet
    }

    pub fn build_cookie_ack(header: &SctpHeader, verification_tag: u32, buffer: &mut Vec<u8>) {
        Self::begin(&header, verification_tag, buffer);
        CookieEcho::build_cookie_ack(buffer);
        SctpPacket::finish(buffer);
    }
}
