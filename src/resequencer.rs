use crate::rtp::RtpPacket;

const SIZE: usize = 64;
const DEFAULT_LOOKAHEAD: u16 = 3;

struct Slot<'a> {
    seq: u16,
    packet: Option<RtpPacket<'a>>,
}

impl Slot<'_> {
    fn empty() -> Self {
        Self {
            seq: 0,
            packet: None,
        }
    }
}

pub struct Resequencer<'a> {
    slots: [Slot<'a>; SIZE],
    lookahead: u16,
    expected_seq: u16,
    highest_seq: u16,
}

impl<'a> Resequencer<'a> {
    pub fn new(start_sequence_number: u16) -> Self {
        Self::with_lookahead(start_sequence_number, DEFAULT_LOOKAHEAD)
    }

    pub fn with_lookahead(start_sequence_number: u16, lookahead: u16) -> Self {
        Self {
            slots: core::array::from_fn(|_| Slot::empty()),
            lookahead: lookahead.min(SIZE as u16 - 1),
            expected_seq: start_sequence_number,
            highest_seq: start_sequence_number,
        }
    }

    pub fn add(&mut self, packet: RtpPacket<'a>) {
        let seq = packet.header.sequence_number;

        let behind = self.expected_seq.wrapping_sub(seq);
        if behind != 0 && behind < 1 << 15 {
            return;
        }

        let ahead = seq.wrapping_sub(self.expected_seq);
        if ahead >= SIZE as u16 && ahead < 1 << 15 {
            self.reset_to(seq);
        }

        let slot = &mut self.slots[self.index(seq)];
        if slot.packet.is_some() && slot.seq != seq {
            return;
        }

        slot.seq = seq;
        slot.packet = Some(packet);

        if seq.wrapping_sub(self.highest_seq) < 1 << 15 {
            self.highest_seq = seq;
        }
    }

    pub fn read(&mut self) -> Option<RtpPacket<'a>> {
        let expected = self.expected_seq;
        let slot = &mut self.slots[self.index(expected)];

        if slot.seq == expected {
            if let Some(packet) = slot.packet.take() {
                self.expected_seq = expected.wrapping_add(1);
                return Some(packet);
            }
        }

        let distance = self.highest_seq.wrapping_sub(self.expected_seq);
        if distance < 1 << 15 && distance > self.lookahead {
            let mut potential_seq = self.expected_seq;

            loop {
                potential_seq = potential_seq.wrapping_add(1);

                let slot = &mut self.slots[self.index(potential_seq)];

                if slot.seq == potential_seq {
                    if let Some(packet) = slot.packet.take() {
                        self.expected_seq = potential_seq.wrapping_add(1);
                        return Some(packet);
                    }
                }

                if potential_seq.wrapping_sub(self.highest_seq) < 1 << 15 {
                    return None;
                }
            }
        }

        None
    }

    fn index(&self, seq: u16) -> usize {
        seq as usize & (SIZE - 1)
    }

    fn reset_to(&mut self, seq: u16) {
        self.slots = core::array::from_fn(|_| Slot::empty());
        if seq.wrapping_sub(self.expected_seq) < 1 << 15 {
            self.expected_seq = seq;
            self.highest_seq = seq;
        }
    }
}
