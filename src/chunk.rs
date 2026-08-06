use crate::association::DEFAULT_A_RWND;
use crate::sctp::HEADER_LEN;

const CHUNK_HEADER_LEN: usize = 4;

const DEFAULT_FLAGS: u8 = 0x00;

const SACK: u8 = 0x03;
const SACK_LEN: u16 = 16;

pub const INIT: u8 = 0x01;
const INIT_LEN: u16 = 20;

const INIT_ACK: u8 = 0x02;
const PARAM_STATE_COOKIE: u16 = 0x0007;
const STATE_COOKIE_LEN: u16 = 8;
const INIT_ACK_LEN: u16 = INIT_LEN + STATE_COOKIE_LEN;

pub const COOKIE_ECHO: u8 = 0x0a;

const COOKIE_ACK: u8 = 0x0b;
const COOKIE_ACK_LEN: u16 = 0x0004;

pub const DATA: u8 = 0x00;
const DATA_HEADER_LEN: usize = 16;
pub const DATA_UNFRAGMENTED_FLAGS: u8 = 0x03; // sets B and E to 1
pub const DATA_CHANNEL_OPEN: u8 = 0x03;
pub const DATA_CHANNEL_ACK: u8 = 0x02;
pub const PPID_DCEP: u32 = 0x0000_0032;
pub const PPID_STRING: u32 = 0x0000_0033;

pub struct Parameter {
    pub parameter_type: u16,
    pub length: u16,
    pub data_start: usize,
    pub data_end: usize,
}

pub enum Chunk {
    Init(Init),
    CookieEcho(CookieEcho),
    Data(Data),
    Unknown(u8),
}

pub struct Sack;

impl Sack {
    pub fn write_to(cumulative_tsn: u32, a_rwnd: u32, buffer: &mut Vec<u8>) {
        buffer.push(SACK);
        buffer.push(DEFAULT_FLAGS);
        buffer.extend_from_slice(&SACK_LEN.to_be_bytes());
        buffer.extend_from_slice(&cumulative_tsn.to_be_bytes());
        buffer.extend_from_slice(&a_rwnd.to_be_bytes());
        buffer.extend_from_slice(&0_u16.to_be_bytes());
        buffer.extend_from_slice(&0_u16.to_be_bytes());
    }
}

pub struct Init {
    pub chunk_type: u8,
    pub flags: u8,
    pub length: u16,
    pub initiate_tag: u32,
    pub a_rwnd: u32,
    pub outbound_streams: u16,
    pub inbound_streams: u16,
    pub initial_tsn: u32,
}

impl Init {
    pub fn parse(buffer: &[u8]) -> Self {
        let chunk_type = buffer[0];
        let flags = buffer[1];
        let length = u16::from_be_bytes([buffer[2], buffer[3]]);
        let initiate_tag = u32::from_be_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);
        let a_rwnd = u32::from_be_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]);
        let outbound_streams = u16::from_be_bytes([buffer[12], buffer[13]]);
        let inbound_streams = u16::from_be_bytes([buffer[14], buffer[15]]);
        let initial_tsn = u32::from_be_bytes([buffer[16], buffer[17], buffer[18], buffer[19]]);

        Self {
            chunk_type,
            flags,
            length,
            initiate_tag,
            a_rwnd,
            outbound_streams,
            inbound_streams,
            initial_tsn,
        }
    }

    pub fn build_init_ack(
        tag: u32,
        tsn: u32,
        outbound_streams: u16,
        inbound_streams: u16,
        cookie: u32,
        buffer: &mut Vec<u8>,
    ) {
        let chunk = Init {
            chunk_type: INIT_ACK,
            flags: DEFAULT_FLAGS,
            length: INIT_ACK_LEN,
            initiate_tag: tag,
            a_rwnd: DEFAULT_A_RWND,
            outbound_streams,
            inbound_streams,
            initial_tsn: tsn,
        };

        chunk.write_to(buffer);

        buffer.extend_from_slice(&PARAM_STATE_COOKIE.to_be_bytes());
        buffer.extend_from_slice(&STATE_COOKIE_LEN.to_be_bytes());
        buffer.extend_from_slice(&cookie.to_be_bytes());
    }

    fn write_to(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(&self.chunk_type.to_be_bytes());
        buffer.extend_from_slice(&self.flags.to_be_bytes());
        buffer.extend_from_slice(&self.length.to_be_bytes());
        buffer.extend_from_slice(&self.initiate_tag.to_be_bytes());
        buffer.extend_from_slice(&self.a_rwnd.to_be_bytes());
        buffer.extend_from_slice(&self.outbound_streams.to_be_bytes());
        buffer.extend_from_slice(&self.inbound_streams.to_be_bytes());
        buffer.extend_from_slice(&self.initial_tsn.to_be_bytes());
    }
}

pub struct CookieEcho {
    pub chunk_type: u8,
    pub flags: u8,
    cookie_start: usize,
    cookie_end: usize,
}

impl CookieEcho {
    pub fn parse(buffer: &[u8]) -> Self {
        let chunk_type = buffer[0];
        let flags = buffer[1];
        let length = u16::from_be_bytes([buffer[2], buffer[3]]);
        let cookie_start = HEADER_LEN + CHUNK_HEADER_LEN;
        let cookie_end = HEADER_LEN + length as usize;

        Self {
            chunk_type,
            flags,
            cookie_start,
            cookie_end,
        }
    }

    pub fn cookie<'a>(&self, buffer: &'a [u8]) -> &'a [u8] {
        &buffer[self.cookie_start..self.cookie_end]
    }

    pub fn build_cookie_ack(buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(&COOKIE_ACK.to_be_bytes());
        buffer.extend_from_slice(&DEFAULT_FLAGS.to_be_bytes());
        buffer.extend_from_slice(&COOKIE_ACK_LEN.to_be_bytes());
    }
}

pub struct Data {
    pub chunk_type: u8,
    // 8-11 is reserved!!
    //      12  13  14  15
    // ...   I   U   B   E
    i: bool,
    u: bool,
    b: bool,
    e: bool,
    pub tsn: u32,
    pub stream_id: u16,
    stream_seq: u16,
    pub payload_id: u32,
    pub data_start: usize,
    pub data_end: usize,
}

impl Data {
    pub fn parse(buffer: &[u8]) -> Self {
        let chunk_type = buffer[0];
        let i = (buffer[1] & 0x08) >> 3 == 1;
        let u = (buffer[1] & 0x04) >> 2 == 1;
        let b = (buffer[1] & 0x02) >> 1 == 1;
        let e = (buffer[1] & 0x01) == 1;
        let length = u16::from_be_bytes([buffer[2], buffer[3]]);
        let tsn = u32::from_be_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);
        let stream_id = u16::from_be_bytes([buffer[8], buffer[9]]);
        let stream_seq = u16::from_be_bytes([buffer[10], buffer[11]]);
        let payload_id = u32::from_be_bytes([buffer[12], buffer[13], buffer[14], buffer[15]]);
        let data_start = HEADER_LEN + DATA_HEADER_LEN;
        let data_end = HEADER_LEN + length as usize;

        Self {
            chunk_type,
            i,
            u,
            b,
            e,
            tsn,
            stream_id,
            stream_seq,
            payload_id,
            data_start,
            data_end,
        }
    }

    pub fn write_to(
        tsn: u32,
        stream_id: u16,
        stream_seq: u16,
        payload_id: u32,
        flags: u8,
        payload: &[u8],
        buffer: &mut Vec<u8>,
    ) {
        buffer.push(DATA);
        buffer.push(flags);
        buffer.extend_from_slice(&(DATA_HEADER_LEN as u16 + payload.len() as u16).to_be_bytes());
        buffer.extend_from_slice(&tsn.to_be_bytes());
        buffer.extend_from_slice(&stream_id.to_be_bytes());
        buffer.extend_from_slice(&stream_seq.to_be_bytes());
        buffer.extend_from_slice(&payload_id.to_be_bytes());
        buffer.extend_from_slice(payload);

        while buffer.len() % 4 != 0 {
            buffer.push(0);
        }
    }
}
