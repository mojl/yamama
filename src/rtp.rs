const FIXED_HEADER_LEN: usize = 12;
const CSRC_LEN: usize = 4;
const EXTENSION_HEADER_LEN: usize = 4;
const WORD_LEN: usize = 4;

pub struct RtpExtension {
    pub id: u8,
    pub data_start: usize,
    pub data_end: usize,
}

impl RtpExtension {
    fn parse(buffer: &[u8], offset: usize) -> (Vec<Self>, usize) {
        let profile = u16::from_be_bytes([buffer[0], buffer[1]]);
        let length_in_words = u16::from_be_bytes([buffer[2], buffer[3]]) as usize;
        let size = EXTENSION_HEADER_LEN + length_in_words * WORD_LEN;
        let mut i = EXTENSION_HEADER_LEN; // skip extention header

        let mut extensions = Vec::new();

        match profile {
            0xbede => {
                while i < size {
                    if buffer[i] == 0 {
                        // skip the padding
                        break;
                    }

                    let id = buffer[i] >> 4;
                    let length = (buffer[i] & 0x0f) as usize + 1;
                    i += 1;
                    extensions.push(Self {
                        id,
                        data_start: offset + i,
                        data_end: offset + i + length,
                    });
                    i += length;
                }
            }
            0x1000 => {
                while i < size {
                    if buffer[i] == 0 {
                        // skip the padding
                        break;
                    }

                    let id = buffer[i];
                    let length = u16::from_be_bytes([buffer[i + 1], buffer[i + 2]]) as usize;
                    i += 3;
                    extensions.push(Self {
                        id,
                        data_start: offset + i,
                        data_end: offset + i + length,
                    });
                    i += length;
                }
            }
            _ => {
                log::error!("unsupported extension profile: {}", profile);
            }
        }

        (extensions, size)
    }
}

pub struct RtpHeader {
    pub version: u8,
    pub has_padding: bool,
    pub has_extension: bool,
    pub csrc_count: u8,
    pub payload_type: u8,
    pub sequence_number: u16,
    pub ssrc: u32,
}

impl RtpHeader {
    fn parse(packet: &[u8]) -> Self {
        let version = packet[0] >> 6;
        let csrc_count = packet[0] & 0x0f;
        let has_padding = (packet[0] & 0x20) >> 5 != 0;
        let has_extension = (packet[0] & 0x10) >> 4 != 0;
        let payload_type = packet[1] & 0x7f;
        let sequence_number = u16::from_be_bytes([packet[2], packet[3]]);
        let ssrc = u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]);
        Self {
            version,
            has_padding,
            has_extension,
            csrc_count,
            payload_type,
            sequence_number,
            ssrc,
        }
    }

    fn size(&self) -> usize {
        FIXED_HEADER_LEN + (self.csrc_count as usize) * CSRC_LEN
    }
}

pub struct RtpPacket<'a> {
    pub header: RtpHeader,
    pub extensions: Option<Vec<RtpExtension>>,
    pub raw: &'a [u8],
    pub payload_start: usize,
    pub payload_end: usize,
}

impl<'a> RtpPacket<'a> {
    pub fn new(packet: &'a [u8]) -> Self {
        let header = RtpHeader::parse(packet);

        let mut payload_start = header.size();
        let extensions = if header.has_extension {
            let (extensions, length) = RtpExtension::parse(&packet[payload_start..], payload_start);
            payload_start += length;

            log::debug!(
                "parsed {} extension{} for {}",
                extensions.len(),
                if extensions.len() == 1 { "" } else { "s" },
                header.ssrc
            );
            Some(extensions)
        } else {
            log::debug!("no extensions found for {}", header.ssrc);
            None
        };

        let padding_length = if header.has_padding {
            packet[packet.len() - 1] as usize
        } else {
            0
        };
        let payload_end = packet.len() - padding_length;

        Self {
            header,
            extensions,
            raw: packet,
            payload_start,
            payload_end,
        }
    }

    pub fn extension(&self, id: u8) -> Option<&[u8]> {
        let extension = self
            .extensions
            .as_ref()?
            .iter()
            .find(|extension| extension.id == id)?;

        Some(&self.raw[extension.data_start..extension.data_end])
    }

    pub fn payload_type(&self) -> u8 {
        self.header.payload_type
    }

    pub fn payload(&self) -> &[u8] {
        &self.raw[self.payload_start..self.payload_end]
    }

    pub fn header_size(packet: &[u8]) -> Option<usize> {
        let csrc_count = (packet[0] & 0x0f) as usize;

        let mut size = FIXED_HEADER_LEN + csrc_count * CSRC_LEN;

        if (packet[0] & 0x10) >> 4 != 0 {
            let length_in_words = u16::from_be_bytes([packet[size + 2], packet[size + 3]]) as usize;
            size += EXTENSION_HEADER_LEN + length_in_words * WORD_LEN;
        }

        Some(size)
    }
}
