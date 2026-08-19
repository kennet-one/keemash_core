// SPDX-License-Identifier: Apache-2.0

pub const VERSION: u8 = 1;
pub const HEADER_SIZE: usize = 32;
pub const TLV_HEADER_SIZE: usize = 6;
pub const MAX_PAYLOAD: usize = 4096;
const MAGIC: &[u8; 4] = b"KLNK";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Hello = 1,
    Welcome = 2,
    Request = 3,
    Response = 4,
    Event = 5,
    Snapshot = 6,
    Gap = 7,
    Heartbeat = 8,
    Error = 9,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecError {
    TooShort,
    TooLarge,
    InvalidMagic,
    InvalidVersion,
    InvalidHeader,
    Unsupported,
    TruncatedTlv,
    InvalidTlv,
}

impl TryFrom<u8> for Kind {
    type Error = CodecError;
    fn try_from(value: u8) -> Result<Self, CodecError> {
        Ok(match value {
            1 => Self::Hello,
            2 => Self::Welcome,
            3 => Self::Request,
            4 => Self::Response,
            5 => Self::Event,
            6 => Self::Snapshot,
            7 => Self::Gap,
            8 => Self::Heartbeat,
            9 => Self::Error,
            _ => return Err(CodecError::Unsupported),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub kind: Kind,
    pub flags: u16,
    pub channel: u16,
    pub payload_len: u32,
    pub session_id: u64,
    pub message_id: u32,
    pub correlation_id: u32,
}

impl Header {
    pub fn encode(self) -> Result<[u8; HEADER_SIZE], CodecError> {
        if self.payload_len as usize > MAX_PAYLOAD {
            return Err(CodecError::TooLarge);
        }
        let mut out = [0u8; HEADER_SIZE];
        out[0..4].copy_from_slice(MAGIC);
        out[4] = VERSION;
        out[5] = self.kind as u8;
        out[6..8].copy_from_slice(&self.flags.to_le_bytes());
        out[8..10].copy_from_slice(&self.channel.to_le_bytes());
        out[10..12].copy_from_slice(&(HEADER_SIZE as u16).to_le_bytes());
        out[12..16].copy_from_slice(&self.payload_len.to_le_bytes());
        out[16..24].copy_from_slice(&self.session_id.to_le_bytes());
        out[24..28].copy_from_slice(&self.message_id.to_le_bytes());
        out[28..32].copy_from_slice(&self.correlation_id.to_le_bytes());
        Ok(out)
    }
    pub fn decode(frame: &[u8]) -> Result<Self, CodecError> {
        if frame.len() < HEADER_SIZE {
            return Err(CodecError::TooShort);
        }
        if &frame[0..4] != MAGIC {
            return Err(CodecError::InvalidMagic);
        }
        if frame[4] != VERSION {
            return Err(CodecError::InvalidVersion);
        }
        if u16::from_le_bytes([frame[10], frame[11]]) as usize != HEADER_SIZE {
            return Err(CodecError::InvalidHeader);
        }
        let payload_len = u32::from_le_bytes(frame[12..16].try_into().unwrap());
        if payload_len as usize > MAX_PAYLOAD {
            return Err(CodecError::TooLarge);
        }
        if frame.len() != HEADER_SIZE + payload_len as usize {
            return Err(CodecError::InvalidHeader);
        }
        Ok(Self {
            kind: Kind::try_from(frame[5])?,
            flags: u16::from_le_bytes(frame[6..8].try_into().unwrap()),
            channel: u16::from_le_bytes(frame[8..10].try_into().unwrap()),
            payload_len,
            session_id: u64::from_le_bytes(frame[16..24].try_into().unwrap()),
            message_id: u32::from_le_bytes(frame[24..28].try_into().unwrap()),
            correlation_id: u32::from_le_bytes(frame[28..32].try_into().unwrap()),
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Tlv<'a> {
    pub field_id: u16,
    pub value_type: u8,
    pub flags: u8,
    pub value: &'a [u8],
}
pub struct TlvIter<'a> {
    data: &'a [u8],
    offset: usize,
}
impl<'a> TlvIter<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }
}
impl<'a> Iterator for TlvIter<'a> {
    type Item = Result<Tlv<'a>, CodecError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.offset == self.data.len() {
            return None;
        }
        if self.offset + TLV_HEADER_SIZE > self.data.len() {
            self.offset = self.data.len();
            return Some(Err(CodecError::TruncatedTlv));
        }
        let p = &self.data[self.offset..];
        let field_id = u16::from_le_bytes([p[0], p[1]]);
        let len = u16::from_le_bytes([p[4], p[5]]) as usize;
        if field_id == 0 || self.offset + TLV_HEADER_SIZE + len > self.data.len() {
            self.offset = self.data.len();
            return Some(Err(CodecError::InvalidTlv));
        }
        let value = &p[TLV_HEADER_SIZE..TLV_HEADER_SIZE + len];
        self.offset += TLV_HEADER_SIZE + len;
        Some(Ok(Tlv {
            field_id,
            value_type: p[2],
            flags: p[3],
            value,
        }))
    }
}

pub fn put_tlv(
    out: &mut Vec<u8>,
    field_id: u16,
    value_type: u8,
    flags: u8,
    value: &[u8],
) -> Result<(), CodecError> {
    if field_id == 0
        || value.len() > u16::MAX as usize
        || out.len() + TLV_HEADER_SIZE + value.len() > MAX_PAYLOAD
    {
        return Err(CodecError::TooLarge);
    }
    out.extend_from_slice(&field_id.to_le_bytes());
    out.push(value_type);
    out.push(flags);
    out.extend_from_slice(&(value.len() as u16).to_le_bytes());
    out.extend_from_slice(value);
    Ok(())
}
pub fn put_u32(out: &mut Vec<u8>, field_id: u16, value: u32) -> Result<(), CodecError> {
    put_tlv(out, field_id, 1, 0, &value.to_le_bytes())
}
pub fn put_u64(out: &mut Vec<u8>, field_id: u16, value: u64) -> Result<(), CodecError> {
    put_tlv(out, field_id, 2, 0, &value.to_le_bytes())
}
pub fn put_bool(out: &mut Vec<u8>, field_id: u16, value: bool) -> Result<(), CodecError> {
    put_tlv(out, field_id, 4, 0, &[u8::from(value)])
}
pub fn put_utf8(out: &mut Vec<u8>, field_id: u16, value: &str) -> Result<(), CodecError> {
    put_tlv(out, field_id, 6, 0, value.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn golden_header_and_tlv() {
        let mut p = Vec::new();
        put_utf8(&mut p, 1, "node0").unwrap();
        put_u32(&mut p, 2, 0x12345678).unwrap();
        let h = Header {
            kind: Kind::Hello,
            flags: 0,
            channel: 1,
            payload_len: p.len() as u32,
            session_id: 0x0102030405060708,
            message_id: 9,
            correlation_id: 0,
        };
        let mut f = h.encode().unwrap().to_vec();
        f.extend_from_slice(&p);
        let expected = hex::decode("4b4c4e4b010100000100200015000000080706050403020109000000000000000100060005006e6f64653002000100040078563412").unwrap();
        assert_eq!(f, expected);
        assert_eq!(Header::decode(&f).unwrap(), h);
        assert_eq!(TlvIter::new(&f[HEADER_SIZE..]).count(), 2)
    }
    #[test]
    fn rejects_truncation() {
        let h = Header {
            kind: Kind::Hello,
            flags: 0,
            channel: 1,
            payload_len: 1,
            session_id: 0,
            message_id: 0,
            correlation_id: 0,
        };
        assert!(Header::decode(&h.encode().unwrap()).is_err());
        assert!(TlvIter::new(&[1, 0, 6]).next().unwrap().is_err())
    }
}
