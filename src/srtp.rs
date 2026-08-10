use crate::rtp::RtpPacket;
use aes::Aes128;
use aes::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use hmac::{Hmac, KeyInit, Mac};
use openssl::error::ErrorStack;
use openssl::ssl::SslRef;
use sha1::Sha1;

const RTP_KEY_LABEL: u8 = 0x00;
const RTP_AUTH_LABEL: u8 = 0x01;
const RTP_SALT_LABEL: u8 = 0x02;
const RTCP_KEY_LABEL: u8 = 0x03;
const RTCP_AUTH_LABEL: u8 = 0x04;
const RTCP_SALT_LABEL: u8 = 0x05;

const TAG_LEN: usize = 10;

#[derive(Default)]
struct Stream {
    ssrc: u32,
    roc: u64,
}

impl Stream {
    fn new(ssrc: u32) -> Self {
        Self { ssrc, roc: 0 }
    }

    fn index_of(&mut self, sequence_number: u16) -> u64 {
        if sequence_number == 0 {
            self.roc += 1;
        }

        (self.roc << 16) | sequence_number as u64
    }
}

#[derive(Default)]
struct Session {
    rtp_key: [u8; 16],
    rtp_auth: [u8; 20],
    rtp_salt: [u8; 14],
    rtcp_key: [u8; 16],
    rtcp_auth: [u8; 20],
    rtcp_salt: [u8; 14],
    streams: Vec<Stream>,
}

impl Session {
    fn stream(&mut self, ssrc: u32) -> &mut Stream {
        if let Some(index) = self.streams.iter().position(|stream| stream.ssrc == ssrc) {
            return &mut self.streams[index];
        }

        self.streams.push(Stream::new(ssrc));
        self.streams.last_mut().unwrap()
    }
}

pub struct SrtpContext {
    outbound: Session,
    inbound: Session,
}

impl SrtpContext {
    pub fn from_dtls(ssl: &SslRef) -> Result<Self, ErrorStack> {
        let mut material = [0u8; 60];
        ssl.export_keying_material(&mut material, "EXTRACTOR-dtls_srtp", None)?;

        let in_key = (&material[0..16]).try_into().unwrap();
        let out_key = (&material[16..32]).try_into().unwrap();
        let in_salt = (&material[32..46]).try_into().unwrap();
        let out_salt = (&material[46..60]).try_into().unwrap();

        let mut outbound = Session::default();
        SrtpContext::derive(out_key, out_salt, RTP_KEY_LABEL, &mut outbound.rtp_key);
        SrtpContext::derive(out_key, out_salt, RTP_AUTH_LABEL, &mut outbound.rtp_auth);
        SrtpContext::derive(out_key, out_salt, RTP_SALT_LABEL, &mut outbound.rtp_salt);
        SrtpContext::derive(out_key, out_salt, RTCP_KEY_LABEL, &mut outbound.rtcp_key);
        SrtpContext::derive(out_key, out_salt, RTCP_AUTH_LABEL, &mut outbound.rtcp_auth);
        SrtpContext::derive(out_key, out_salt, RTCP_SALT_LABEL, &mut outbound.rtcp_salt);

        let mut inbound = Session::default();
        SrtpContext::derive(in_key, in_salt, RTP_KEY_LABEL, &mut inbound.rtp_key);
        SrtpContext::derive(in_key, in_salt, RTP_AUTH_LABEL, &mut inbound.rtp_auth);
        SrtpContext::derive(in_key, in_salt, RTP_SALT_LABEL, &mut inbound.rtp_salt);
        SrtpContext::derive(in_key, in_salt, RTCP_KEY_LABEL, &mut inbound.rtcp_key);
        SrtpContext::derive(in_key, in_salt, RTCP_AUTH_LABEL, &mut inbound.rtcp_auth);
        SrtpContext::derive(in_key, in_salt, RTCP_SALT_LABEL, &mut inbound.rtcp_salt);

        Ok(Self { outbound, inbound })
    }

    fn derive(key: &[u8; 16], salt: &[u8; 14], label: u8, buffer: &mut [u8]) {
        let mut canvas = [0u8; 16];
        canvas[..14].copy_from_slice(salt);
        canvas[7] ^= label;

        let mut cipher = Ctr128BE::<Aes128>::new(key.into(), (&canvas).into());
        buffer.fill(0);
        cipher.apply_keystream(buffer);
    }

    fn iv(salt: &[u8; 14], ssrc: u32, index: u64) -> [u8; 16] {
        let mut canvas = [0u8; 16];
        canvas[..14].copy_from_slice(salt);

        for (canvas_byte, ssrc_byte) in canvas[4..8].iter_mut().zip(ssrc.to_be_bytes()) {
            *canvas_byte ^= ssrc_byte;
        }
        for (canvas_byte, index_byte) in canvas[8..14].iter_mut().zip(&index.to_be_bytes()[2..]) {
            *canvas_byte ^= index_byte;
        }

        canvas
    }

    fn cipher(
        key: &[u8; 16],
        salt: &[u8; 14],
        packet: &mut [u8],
        start: usize,
        end: usize,
        ssrc: u32,
        index: u64,
    ) {
        let iv = Self::iv(salt, ssrc, index);

        let mut cipher = Ctr128BE::<Aes128>::new(key.into(), (&iv).into());
        cipher.apply_keystream(&mut packet[start..end]);
    }

    fn authenticate(auth: &[u8; 20], packet: &[u8], index: u64) -> Hmac<Sha1> {
        let mut mac = Hmac::<Sha1>::new_from_slice(auth).unwrap();
        mac.update(packet);
        mac.update(&((index >> 16) as u32).to_be_bytes());

        mac
    }

    fn authenticate_srtcp(auth: &[u8; 20], packet: &[u8]) -> Hmac<Sha1> {
        let mut mac = Hmac::<Sha1>::new_from_slice(auth).unwrap();
        mac.update(packet);

        mac
    }

    pub fn protect(&mut self, buffer: &mut [u8], length: usize) -> Option<usize> {
        let start = RtpPacket::header_size(buffer.get(..length)?)?;
        let end = length + TAG_LEN;
        if buffer.len() < end {
            return None;
        }
        let ssrc = u32::from_be_bytes(buffer[8..12].try_into().ok()?);
        let sequence_number = u16::from_be_bytes([buffer[2], buffer[3]]);
        let index = self.outbound.stream(ssrc).index_of(sequence_number);

        Self::cipher(
            &self.outbound.rtp_key,
            &self.outbound.rtp_salt,
            buffer,
            start,
            end,
            ssrc,
            index,
        );

        let tag = Self::authenticate(&self.outbound.rtp_auth, &buffer[..length], index)
            .finalize()
            .into_bytes();
        buffer[length..end].copy_from_slice(&tag[..TAG_LEN]);

        Some(end)
    }

    pub fn unprotect(&mut self, packet: &mut [u8]) -> Option<usize> {
        let end = packet.len().checked_sub(TAG_LEN)?;
        let start = RtpPacket::header_size(packet.get(..end)?)?;
        let ssrc = u32::from_be_bytes(packet[8..12].try_into().ok()?);
        let sequence_number = u16::from_be_bytes([packet[2], packet[3]]);
        let index = self.inbound.stream(ssrc).index_of(sequence_number);

        Self::authenticate(&self.inbound.rtp_auth, &packet[..end], index)
            .verify_truncated_left(&packet[end..])
            .ok()?;

        Self::cipher(
            &self.inbound.rtp_key,
            &self.inbound.rtp_salt,
            packet,
            start,
            end,
            ssrc,
            index,
        );

        Some(end)
    }

    pub fn unprotect_srtcp(&mut self, packet: &mut [u8]) -> Option<usize> {
        let end = packet.len().checked_sub(TAG_LEN)?;
        let payload_end = end.checked_sub(4)?;

        Self::authenticate_srtcp(&self.inbound.rtcp_auth, &packet[..end])
            .verify_truncated_left(&packet[end..])
            .ok()?;

        let trailer = u32::from_be_bytes(packet[payload_end..end].try_into().ok()?);
        let encrypted = trailer >> 31 == 1;
        let index = (trailer & 0x7fff_ffff) as u64;

        if encrypted {
            let ssrc = u32::from_be_bytes(packet[4..8].try_into().ok()?);
            Self::cipher(
                &self.inbound.rtcp_key,
                &self.inbound.rtcp_salt,
                packet,
                8,
                payload_end,
                ssrc,
                index,
            );
        }

        Some(payload_end)
    }
}
