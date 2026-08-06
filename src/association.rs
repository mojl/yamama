use crate::chunk::{Chunk, Data, Init, Sack};
use crate::chunk::{
    DATA_CHANNEL_ACK, DATA_CHANNEL_OPEN, DATA_UNFRAGMENTED_FLAGS, PPID_DCEP, PPID_STRING,
};
use crate::dtls::DatagramBio;
use crate::sctp::{SctpHeader, SctpPacket};
use openssl::ssl::{Error as SslError, SslStream};

pub const DEFAULT_A_RWND: u32 = 1024 * 1024;
pub const DEFAULT_OUTBOUND_STREAMS: u16 = 1024;
pub const DEFAULT_INBOUND_STREAMS: u16 = 1024;

enum State {
    CookieWait,
    Established,
}

pub struct Association {
    tag: u32,
    pub peer_tag: u32,
    tsn: u32,
    cumulative_tsn: u32,
    a_rwnd: u32,
    outbound_streams: u16,
    inbound_streams: u16,
    pub cookie: u32,
    state: State,
}

impl Association {
    pub fn new(init: &Init) -> Self {
        let tag = rand::random_range(1..=u32::MAX);
        let peer_tag = init.initiate_tag;
        let tsn = rand::random();
        let cumulative_tsn = init.initial_tsn.wrapping_sub(1);
        let a_rwnd = init.a_rwnd;
        let outbound_streams = DEFAULT_OUTBOUND_STREAMS.min(init.outbound_streams);
        let inbound_streams = DEFAULT_INBOUND_STREAMS.min(init.inbound_streams);
        let cookie = rand::random();
        let state = State::CookieWait;

        Self {
            tag,
            peer_tag,
            tsn,
            cumulative_tsn,
            a_rwnd,
            outbound_streams,
            inbound_streams,
            cookie,
            state,
        }
    }

    pub fn establish(&mut self) {
        self.state = State::Established;
    }

    pub fn build_init_ack(&self, header: &SctpHeader, buffer: &mut Vec<u8>) {
        SctpPacket::begin(header, self.peer_tag, buffer);
        Init::build_init_ack(
            self.tag,
            self.tsn,
            self.outbound_streams,
            self.inbound_streams,
            self.cookie,
            buffer,
        );
        SctpPacket::finish(buffer);
    }

    pub fn handle(
        &mut self,
        stream: &mut SslStream<DatagramBio>,
        sctp: &SctpPacket,
        buffer: &mut Vec<u8>,
    ) -> Result<(), SslError> {
        let Chunk::Data(data) = &sctp.chunk else {
            log::error!("expected a data chunk");

            return Ok(());
        };

        self.cumulative_tsn = data.tsn;

        SctpPacket::begin(&sctp.header, self.peer_tag, buffer);
        Sack::write_to(self.cumulative_tsn, DEFAULT_A_RWND, buffer);

        let payload = &sctp.raw[data.data_start..data.data_end];
        match data.payload_id {
            PPID_DCEP => {
                if payload.first() == Some(&DATA_CHANNEL_OPEN) {
                    Data::write_to(
                        self.tsn,
                        data.stream_id,
                        0,
                        PPID_DCEP,
                        DATA_UNFRAGMENTED_FLAGS,
                        &[DATA_CHANNEL_ACK],
                        buffer,
                    );

                    self.tsn = self.tsn.wrapping_add(1);
                }
            }
            PPID_STRING => {
                if let Ok(string) = str::from_utf8(payload) {
                    log::debug!("string received: {}", string);
                } else {
                    log::error!("can't parse string");
                }
            }
            _ => log::warn!("unsupported payload id {}", data.payload_id),
        }

        SctpPacket::finish(buffer);
        stream.ssl_write(buffer)?;

        Ok(())
    }
}
