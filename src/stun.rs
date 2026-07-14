use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use std::net::{IpAddr, SocketAddr};

const MAGIC_COOKIE: u32 = 0x2112_a442;
const FINGERPRINT_XOR: u32 = 0x5354_554e;

const BINDING_REQUEST_MESSAGE: u16 = 0x0001;
const BINDING_RESPONSE_MESSAGE: u16 = 0x0101;

const USERNAME_ATTRIBUTE: u16 = 0x0006;
const MESSAGE_INTEGRITY_ATTRIBUTE: u16 = 0x0008;
const XOR_MAPPED_ADDRESS_ATTRIBUTE: u16 = 0x0020;
const FINGERPRINT_ATTRIBUTE: u16 = 0x8028;

#[repr(u16)]
pub enum MessageType {
    BindingRequest = BINDING_REQUEST_MESSAGE,
    BindingResponse = BINDING_RESPONSE_MESSAGE,
    Unknown = 0,
}

enum Attribute {
    Username(String),
    MessageIntegrity(Vec<u8>),
}

impl Attribute {
    fn new(attribute_type: u16, attribute_value: &[u8]) -> Option<Self> {
        match attribute_type {
            USERNAME_ATTRIBUTE => Some(Attribute::Username(
                String::from_utf8_lossy(attribute_value).into_owned(),
            )),
            MESSAGE_INTEGRITY_ATTRIBUTE => {
                Some(Attribute::MessageIntegrity(attribute_value.to_vec()))
            }
            _ => None,
        }
    }
}

pub struct Message<'a> {
    pub message_type: u16,
    pub transaction_id: [u8; 12],
    pub username: String,
    pub message_integrity: Vec<u8>,
    message_integrity_offset: Option<usize>,
    pub raw: &'a [u8],
}

impl<'a> Message<'a> {
    fn new(raw: &'a [u8]) -> Self {
        let (username, message_integrity, message_integrity_offset) = Self::parse_attributes(raw);
        Self {
            message_type: u16::from_be_bytes([raw[0], raw[1]]),
            transaction_id: raw[8..20].try_into().unwrap(),
            username,
            message_integrity,
            message_integrity_offset,
            raw,
        }
    }

    pub fn parse(raw: &'a [u8]) -> Option<Self> {
        if !Self::is_stun(raw) {
            return None;
        }

        Some(Self::new(raw))
    }

    pub fn is_stun(raw: &[u8]) -> bool {
        raw.len() >= 20
            && raw[0] & 0xc0 == 0 // first 2 bits must be 0b00
            && u32::from_be_bytes(raw[4..8].try_into().unwrap()) == MAGIC_COOKIE
    }

    pub fn message_type(&self) -> MessageType {
        match self.message_type {
            BINDING_REQUEST_MESSAGE => MessageType::BindingRequest,
            BINDING_RESPONSE_MESSAGE => MessageType::BindingResponse,
            _ => MessageType::Unknown,
        }
    }

    fn parse_attributes(raw: &[u8]) -> (String, Vec<u8>, Option<usize>) {
        let mut username = String::new();
        let mut message_integrity = Vec::new();
        let mut message_integrity_offset = None;

        let length = u16::from_be_bytes([raw[2], raw[3]]) as usize;
        let limit = (20 + length).min(raw.len());
        let mut offset = 20;

        while offset + 4 <= limit {
            let attribute_type = u16::from_be_bytes([raw[offset], raw[offset + 1]]);
            let attribute_length = u16::from_be_bytes([raw[offset + 2], raw[offset + 3]]) as usize;
            let value_offset = offset + 4;
            let value_end = value_offset + attribute_length;
            if value_end > limit {
                break;
            }

            match Attribute::new(attribute_type, &raw[value_offset..value_end]) {
                Some(Attribute::Username(value)) => username = value,
                Some(Attribute::MessageIntegrity(value)) => {
                    message_integrity = value;
                    message_integrity_offset = Some(offset);
                    break;
                }
                None => {}
            }

            offset = value_offset + attribute_length.next_multiple_of(4);
        }

        (username, message_integrity, message_integrity_offset)
    }

    pub fn is_valid_message_integrity(&self, password: &str) -> bool {
        let Some(offset) = self.message_integrity_offset else {
            return false;
        };

        let adjusted_length = (offset - 20 + 24) as u16;
        let mut mac = Hmac::<Sha1>::new_from_slice(password.as_bytes()).unwrap();
        mac.update(&self.raw[0..2]);
        mac.update(&adjusted_length.to_be_bytes());
        mac.update(&self.raw[4..offset]);
        mac.verify_slice(&self.message_integrity).is_ok()
    }

    pub fn build_binding_response(&self, source: SocketAddr, password: &str) -> Vec<u8> {
        let ip = match source.ip() {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
                Some(ip) => ip,
                None => return Vec::new(),
            },
        };

        let mut response = Vec::with_capacity(20 + 12 + 24 + 8);
        Self::append_header(
            &mut response,
            self.transaction_id,
            MessageType::BindingResponse as u16,
        );
        Self::append_xor_mapped_address(&mut response, ip, source.port());
        Self::append_message_integrity(&mut response, password);
        Self::append_fingerprint(&mut response);
        response
    }

    fn append_header(response: &mut Vec<u8>, transaction_id: [u8; 12], message_type: u16) {
        response.extend_from_slice(&message_type.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        response.extend_from_slice(&transaction_id);
    }

    fn append_xor_mapped_address(response: &mut Vec<u8>, ip: std::net::Ipv4Addr, port: u16) {
        let cookie = MAGIC_COOKIE.to_be_bytes();
        let xor_port = port ^ (MAGIC_COOKIE >> 16) as u16;
        let mut xor_addr = ip.octets();
        for i in 0..4 {
            xor_addr[i] ^= cookie[i];
        }

        response.extend_from_slice(&XOR_MAPPED_ADDRESS_ATTRIBUTE.to_be_bytes());
        response.extend_from_slice(&8u16.to_be_bytes());
        response.push(0);
        response.push(0x01);
        response.extend_from_slice(&xor_port.to_be_bytes());
        response.extend_from_slice(&xor_addr);
    }

    fn append_message_integrity(response: &mut Vec<u8>, password: &str) {
        let length = (response.len() - 20 + 24) as u16;
        response[2..4].copy_from_slice(&length.to_be_bytes());
        let mut mac = Hmac::<Sha1>::new_from_slice(password.as_bytes()).unwrap();
        mac.update(response);
        let integrity = mac.finalize().into_bytes();
        response.extend_from_slice(&MESSAGE_INTEGRITY_ATTRIBUTE.to_be_bytes());
        response.extend_from_slice(&20u16.to_be_bytes());
        response.extend_from_slice(&integrity);
    }

    fn append_fingerprint(response: &mut Vec<u8>) {
        let length = (response.len() - 20 + 8) as u16;
        response[2..4].copy_from_slice(&length.to_be_bytes());
        let fingerprint = crc32fast::hash(response) ^ FINGERPRINT_XOR;
        response.extend_from_slice(&FINGERPRINT_ATTRIBUTE.to_be_bytes());
        response.extend_from_slice(&4u16.to_be_bytes());
        response.extend_from_slice(&fingerprint.to_be_bytes());
    }
}
