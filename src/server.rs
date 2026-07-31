use crate::dtls::DtlsContext;
use crate::peer::Peer;
use crate::rtp::RtpPacket;
use crate::stun::{Message, MessageType};
use openssl::error::ErrorStack;
use openssl::pkey::{PKeyRef, Private};
use openssl::x509::X509Ref;
use std::net::SocketAddr;

pub enum Event {
    PeerAuthenticated(Peer),
    PeerMediaReady(SocketAddr),
}

pub enum Action {
    Event(Event),
    Transmit {
        destination: SocketAddr,
        payload: Vec<u8>,
    },
}

pub enum PacketKind {
    Stun,
    Dtls,
    Srtp,
    Srtcp,
    Unknown,
}

pub struct Server {
    pub dtls_context: DtlsContext,
}

impl Server {
    pub fn new(cert: &X509Ref, key: &PKeyRef<Private>) -> Result<Self, ErrorStack> {
        Ok(Self {
            dtls_context: DtlsContext::new(cert, key)?,
        })
    }

    pub fn drive<'b>(
        &mut self,
        packet: &[u8],
        from: SocketAddr,
        peer: Option<&mut Peer>,
        buffer: &'b mut Vec<u8>,
        actions: &mut Vec<Action>,
        authenticate: impl Fn(&str) -> Option<&str>,
    ) -> Option<RtpPacket<'b>> {
        log::trace!("received {} bytes from {}", packet.len(), from);
        actions.clear();

        match Self::classify(packet) {
            PacketKind::Stun => {
                if let Some(payload) = self.handle_stun(packet, from, peer, actions, &authenticate)
                {
                    actions.push(Action::Transmit {
                        destination: from,
                        payload,
                    });
                }
            }
            PacketKind::Dtls => {
                if let Some(peer) = peer {
                    if let Some(payload) = peer.handle_dtls(&self.dtls_context, packet, actions) {
                        actions.push(Action::Transmit {
                            destination: from,
                            payload,
                        });
                    }
                }
            }
            PacketKind::Srtp => {
                if let Some(peer) = peer {
                    if peer.unprotect(packet, buffer) {
                        return Some(RtpPacket::new(buffer));
                    }
                }
            }
            PacketKind::Srtcp => {
                if let Some(peer) = peer {
                    peer.unprotect_rtcp(packet, buffer);
                }
            }
            PacketKind::Unknown => log::debug!("ignoring unknown packet from {}", from),
        }

        None
    }

    fn handle_stun(
        &mut self,
        packet: &[u8],
        from: SocketAddr,
        peer: Option<&mut Peer>,
        actions: &mut Vec<Action>,
        authenticate: &impl Fn(&str) -> Option<&str>,
    ) -> Option<Vec<u8>> {
        let message = Message::parse(packet)?;
        match message.message_type() {
            MessageType::BindingResponse => {
                log::debug!("ignoring binding response from {}", from);
                None
            }
            MessageType::BindingRequest => {
                let local_username = message.username.split(':').next()?;
                let Some(password) = authenticate(local_username) else {
                    log::warn!(
                        "could not find password for username {} from {}",
                        local_username,
                        from
                    );
                    return None;
                };

                if !message.is_valid_message_integrity(password) {
                    log::warn!("invalid password for binding request from {}", from);
                    return None;
                }

                if peer.is_none() {
                    log::info!("peer authenticated: {}", from);

                    let peer = Peer::new(from);
                    actions.push(Action::Event(Event::PeerAuthenticated(peer)));
                }

                let payload = message.build_binding_response(from, password);

                if payload.is_empty() {
                    log::warn!("could not build binding response for {}", from);
                    return None;
                }

                log::debug!("sending binding response to {}", from);
                Some(payload)
            }
            MessageType::Unknown => {
                log::debug!("ignoring unknown message type from {}", from);
                None
            }
        }
    }

    pub fn classify(packet: &[u8]) -> PacketKind {
        log::trace!("classifying packet ({} bytes)", packet.len());

        if packet.is_empty() {
            return PacketKind::Unknown;
        }
        match packet[0] {
            // first byte in *our* case is either 0 or 1
            0..=1 if Message::is_stun(packet) => PacketKind::Stun,
            20..=63 => PacketKind::Dtls,
            128..=191 if packet.len() > 1 && (192..=223).contains(&packet[1]) => PacketKind::Srtcp,
            128..=191 => PacketKind::Srtp,
            _ => PacketKind::Unknown,
        }
    }
}
