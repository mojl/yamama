use crate::rtp::RtpPacket;

pub enum TrackKind {
    Audio(u8),
    Video(u8),
    Unknown,
}

pub struct Track {
    pub ssrc: u32,
    pub kind: TrackKind,
}

impl Track {
    pub fn new(rtp: &RtpPacket) -> Self {
        Self {
            ssrc: rtp.header.ssrc,
            kind: track_kind(rtp.header.payload_type),
        }
    }
}

fn track_kind(payload_type: u8) -> TrackKind {
    match payload_type {
        111 => TrackKind::Audio(111),
        96 => TrackKind::Video(96),
        _ => TrackKind::Unknown,
    }
}
