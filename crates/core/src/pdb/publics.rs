//! Public symbols: the S_PUB32 records that name a function or data item by section offset.
//!
//! The DBI header names two streams: the public symbol stream, which carries the index the link
//! tools wrote, and the symbol record stream, which carries every CodeView record. Address
//! lookup only needs the `S_PUB32` records, so this module reads the public stream header for
//! shape validation and walks the record stream once.
//!
//! A record is `u16 length, u16 kind, body` where the length covers the kind and the body. An
//! `S_PUB32` body is `u32 flags, u32 offset, u16 section, name` with a NUL-terminated name. Other
//! record kinds are skipped: the record stream has many of them and only this one carries a
//! public address.

use super::{PdbError, PdbErrorKind, half, word};

/// CodeView record kind for a public symbol.
pub const S_PUB32: u16 = 0x110E;

/// Bytes of the public symbol stream header this reader validates.
const PUBLIC_HEADER_SIZE: usize = 28;
/// Bytes before the name inside the record payload: flags, offset and section.
const PUBLIC_PAYLOAD_BEFORE_NAME: usize = 10;
/// Bounds on plausible header fields, so a stream from the wrong slot fails instead of being read.
const MAX_THUNKS: u32 = 1 << 20;
const MAX_SECTIONS: u32 = 1 << 16;
const MAX_NAME_BYTES: usize = 2048;

/// Header of the public symbol stream, as the link tools write it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicsHeader {
    /// Byte offset inside the public stream that holds the name hash table.
    pub sym_hash: u32,
    /// Byte offset inside the public stream that holds the address map.
    pub addr_map: u32,
    pub num_thunks: u32,
    pub size_of_thunk: u32,
    pub isect_thunk_table: u16,
    pub off_thunk_table: u32,
    pub num_sections: u32,
}

/// One public symbol record, still in section-relative form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicSymbol {
    pub name: String,
    /// 1-based section number, as a PE image carries it.
    pub section: u16,
    /// Byte offset from the start of that section.
    pub offset: u32,
    pub flags: u32,
}

/// The public stream header plus every public symbol record it indexes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicSymbolTable {
    pub header: PublicsHeader,
    pub symbols: Vec<PublicSymbol>,
}

impl PublicSymbolTable {
    /// Resolves the symbols to RVAs through the section table of the image they belong to.
    pub fn index(&self, sections: &[crate::pe::SectionHeader]) -> Result<super::FunctionIndex, PdbError> {
        super::FunctionIndex::build(&self.symbols, sections)
    }
}

/// Validates the public symbol stream header and collects the records it indexes.
pub fn load(public_stream: &[u8], records: &[u8]) -> Result<PublicSymbolTable, PdbError> {
    let header = parse_header(public_stream, public_stream.len() as u32)?;
    let symbols = scan_symbols(records)?;
    Ok(PublicSymbolTable { header, symbols })
}

/// Reads and validates the public symbol stream header.
///
/// Offsets are checked against the stream length: a header that points past its own stream
/// cannot describe this file, and a stream this reader cannot trust is a failure.
pub fn parse_header(bytes: &[u8], stream_len: u32) -> Result<PublicsHeader, PdbError> {
    if bytes.len() < PUBLIC_HEADER_SIZE {
        return Err(PdbError::new(
            PdbErrorKind::Truncated,
            format!("public symbol stream is {} bytes but its header needs {PUBLIC_HEADER_SIZE}", bytes.len()),
        ));
    }
    let sym_hash = word(bytes, 0).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "public symbol stream is truncated"))?;
    let addr_map = word(bytes, 4).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "public symbol stream is truncated"))?;
    let num_thunks = word(bytes, 8).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "public symbol stream is truncated"))?;
    let size_of_thunk = word(bytes, 12).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "public symbol stream is truncated"))?;
    let isect_thunk_table = half(bytes, 16).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "public symbol stream is truncated"))?;
    let off_thunk_table = word(bytes, 20).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "public symbol stream is truncated"))?;
    let num_sections = word(bytes, 24).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "public symbol stream is truncated"))?;

    for (label, offset) in [("hash table", sym_hash), ("address map", addr_map), ("thunk table", off_thunk_table)] {
        if offset > stream_len {
            return Err(PdbError::new(
                PdbErrorKind::OutOfRange,
                format!("public symbol stream is {stream_len} bytes but its {label} starts at {offset}"),
            ));
        }
    }
    if num_thunks > MAX_THUNKS || num_sections > MAX_SECTIONS {
        return Err(PdbError::new(
            PdbErrorKind::UnknownStreamConvention,
            format!("public symbol stream declares {num_thunks} thunks in {num_sections} sections"),
        ));
    }
    if num_thunks > 0 && size_of_thunk == 0 {
        return Err(PdbError::new(
            PdbErrorKind::UnknownStreamConvention,
            format!("public symbol stream declares {num_thunks} thunks of zero bytes"),
        ));
    }
    Ok(PublicsHeader { sym_hash, addr_map, num_thunks, size_of_thunk, isect_thunk_table, off_thunk_table, num_sections })
}

/// Walks every CodeView record and collects the `S_PUB32` entries.
///
/// A record occupies `2 + length` bytes: the length field itself is not counted, the record kind
/// is.
pub fn scan_symbols(records: &[u8]) -> Result<Vec<PublicSymbol>, PdbError> {
    let mut symbols = Vec::new();
    let mut cursor = 0usize;
    while cursor < records.len() {
        let remainder = records.len() - cursor;
        if remainder < 4 {
            return Err(PdbError::new(
                PdbErrorKind::Truncated,
                format!("symbol record stream ends with {remainder} bytes that cannot hold a record header"),
            ));
        }
        let length = usize::from(u16::from_le_bytes([records[cursor], records[cursor + 1]]));
        let kind = u16::from_le_bytes([records[cursor + 2], records[cursor + 3]]);
        let total = length + 2;
        if length < 2 || total > remainder {
            return Err(PdbError::new(
                PdbErrorKind::OutOfRange,
                format!("symbol record at offset {cursor} declares {length} body bytes with {remainder} left"),
            ));
        }
        if kind == S_PUB32 {
            symbols.push(read_public(records, cursor, length)?);
        }
        cursor += total;
    }
    if symbols.is_empty() {
        return Err(PdbError::new(
            PdbErrorKind::UnknownStreamConvention,
            "the symbol record stream holds no `S_PUB32` record, so it is not the stream the DBI header names",
        ));
    }
    Ok(symbols)
}

fn read_public(records: &[u8], start: usize, length: usize) -> Result<PublicSymbol, PdbError> {
    // The length covers the record kind, which occupies the first two body bytes.
    let payload = &records[start + 4..start + 2 + length];
    if payload.len() < PUBLIC_PAYLOAD_BEFORE_NAME + 1 {
        return Err(PdbError::new(
            PdbErrorKind::OutOfRange,
            format!("`S_PUB32` record at offset {start} carries {} payload bytes, too short for a name", payload.len()),
        ));
    }
    let flags = word(payload, 0).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "`S_PUB32` record is truncated"))?;
    let offset = word(payload, 4).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "`S_PUB32` record is truncated"))?;
    let section = half(payload, 8).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "`S_PUB32` record is truncated"))?;
    let tail = &payload[PUBLIC_PAYLOAD_BEFORE_NAME..];
    let name_end = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| PdbError::new(PdbErrorKind::UnsupportedSymbolFormat, format!("`S_PUB32` name at offset {start} has no terminator")))?;
    if name_end == 0 {
        return Err(PdbError::new(PdbErrorKind::UnsupportedSymbolFormat, format!("`S_PUB32` record at offset {start} has an empty name")));
    }
    if name_end > MAX_NAME_BYTES {
        return Err(PdbError::new(PdbErrorKind::UnsupportedSymbolFormat, format!("`S_PUB32` name at offset {start} is {name_end} bytes")));
    }
    let name = std::str::from_utf8(&tail[..name_end]).map_err(|error| {
        PdbError::new(PdbErrorKind::UnsupportedSymbolFormat, format!("`S_PUB32` name at offset {start} is not UTF-8: {error}"))
    })?;
    if section == 0 {
        return Err(PdbError::new(
            PdbErrorKind::OutOfRange,
            format!("`S_PUB32` record at offset {start} names `{name}` in section 0, which no PE image has"),
        ));
    }
    Ok(PublicSymbol { name: name.to_owned(), section, offset, flags })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public_record(flags: u32, offset: u32, section: u16, name: &str) -> Vec<u8> {
        let payload_len = PUBLIC_PAYLOAD_BEFORE_NAME + name.len() + 1;
        let length = (payload_len + 2) as u16;
        let mut bytes = Vec::new();
        bytes.extend(length.to_le_bytes());
        bytes.extend(S_PUB32.to_le_bytes());
        bytes.extend(flags.to_le_bytes());
        bytes.extend(offset.to_le_bytes());
        bytes.extend(section.to_le_bytes());
        bytes.extend(name.as_bytes());
        bytes.push(0);
        bytes
    }

    fn other_record(kind: u16, body_len: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(((body_len + 2) as u16).to_le_bytes());
        bytes.extend(kind.to_le_bytes());
        bytes.extend(vec![0u8; body_len]);
        bytes
    }

    #[test]
    fn collects_public_symbols_and_skips_other_record_kinds() {
        let mut records = other_record(0x1127, 20);
        records.extend(public_record(0x0000_0002, 0x1234, 5, "SomeFunction"));
        records.extend(other_record(0x1101, 8));
        records.extend(public_record(0x0000_0000, 0x0010, 1, "Data"));
        let symbols = scan_symbols(&records).expect("both public records are valid");
        assert_eq!(symbols.len(), 2);
        assert_eq!(symbols[0], PublicSymbol { name: "SomeFunction".to_string(), section: 5, offset: 0x1234, flags: 2 });
        assert_eq!(symbols[1].section, 1);
    }

    #[test]
    fn reads_the_public_stream_header() {
        let mut bytes = vec![0u8; PUBLIC_HEADER_SIZE];
        bytes[0..4].copy_from_slice(&100u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&400u32.to_le_bytes());
        bytes[24..28].copy_from_slice(&7u32.to_le_bytes());
        let header = parse_header(&bytes, 500).expect("the header points inside its stream");
        assert_eq!(header.sym_hash, 100);
        assert_eq!(header.addr_map, 400);
        assert_eq!(header.num_sections, 7);
    }

    #[test]
    fn a_header_that_points_past_the_stream_is_rejected() {
        let mut bytes = vec![0u8; PUBLIC_HEADER_SIZE];
        bytes[0..4].copy_from_slice(&600u32.to_le_bytes());
        let error = parse_header(&bytes, 500).expect_err("an offset past the stream cannot describe this file");
        assert_eq!(error.kind(), PdbErrorKind::OutOfRange);
        assert_eq!(error.code(), "out_of_range");
    }

    #[test]
    fn a_record_stream_without_a_public_symbol_is_rejected() {
        let records = other_record(0x1127, 20);
        let error = scan_symbols(&records).expect_err("a stream with no public symbol is not the one the DBI header names");
        assert_eq!(error.kind(), PdbErrorKind::UnknownStreamConvention);
    }

    #[test]
    fn a_record_that_runs_past_the_stream_is_rejected() {
        let mut records = public_record(0, 0x1000, 3, "F");
        records[0..2].copy_from_slice(&200u16.to_le_bytes());
        let error = scan_symbols(&records).expect_err("a record longer than the stream is truncated");
        assert_eq!(error.kind(), PdbErrorKind::OutOfRange);
    }

    #[test]
    fn a_public_symbol_without_a_name_terminator_is_rejected() {
        let mut records = public_record(0, 0x1000, 3, "F");
        let length = records.len();
        records[length - 1] = b'F';
        let error = scan_symbols(&records).expect_err("an unterminated name cannot be trusted");
        assert_eq!(error.kind(), PdbErrorKind::UnsupportedSymbolFormat);
    }
}
