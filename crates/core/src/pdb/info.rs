//! PDB info stream: version gate, build identity and the named stream map.
//!
//! The info stream is stream 1. Its fixed header carries the PDB version, the link signature,
//! the age and the GUID. After it comes the named stream map: a string buffer, then a hash
//! table written as an entry count, a bucket count, a sparse presence bit vector, a sparse
//! deletion bit vector and one `(name offset, stream number)` pair per entry, then the `niMac`
//! word and the producer feature stamp. A version or layout this reader does not recognize is
//! a failure, never an empty result.

use super::{PdbError, PdbErrorKind, word};

/// The only info stream version this reader accepts, observed on a real kernel PDB.
pub const SUPPORTED_VERSION: u32 = 20_000_404;

const HEADER_SIZE: usize = 28;
const NAMES_SIZE_OFFSET: usize = 28;
const NAMES_START: usize = 32;
const MAX_NAMED_STREAMS: u32 = 1 << 20;

#[derive(Debug, Clone)]
pub struct PdbInfo {
    version: u32,
    signature: u32,
    age: u32,
    guid: [u8; 16],
    named_streams: Vec<(String, u32)>,
    features: u32,
}

impl PdbInfo {
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Timestamp of the image the PDB was linked for.
    pub fn signature(&self) -> u32 {
        self.signature
    }

    /// Age recorded inside the PDB. It is not the value a symbol store path uses.
    pub fn age(&self) -> u32 {
        self.age
    }

    pub fn guid(&self) -> [u8; 16] {
        self.guid
    }

    /// Canonical uppercase GUID text, the form a symbol store directory name uses.
    pub fn guid_text(&self) -> String {
        guid_text(&self.guid)
    }

    /// Producer feature stamp. On a real kernel PDB this is a newer value than `version`, so it
    /// is reported separately instead of being folded into the version gate.
    pub fn features(&self) -> u32 {
        self.features
    }

    /// Named streams as `(name, stream number)` pairs, in the order the map stores them.
    pub fn named_streams(&self) -> &[(String, u32)] {
        &self.named_streams
    }
}

pub fn parse(bytes: &[u8]) -> Result<PdbInfo, PdbError> {
    if bytes.len() < HEADER_SIZE {
        return Err(PdbError::new(PdbErrorKind::Truncated, "PDB info stream is shorter than its 28-byte header"));
    }
    let version = word(bytes, 0).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "PDB info stream is truncated"))?;
    if version != SUPPORTED_VERSION {
        return Err(PdbError::new(
            PdbErrorKind::UnsupportedPdbVersion,
            format!("PDB info stream version {version} (0x{version:08X}) is not supported, only {SUPPORTED_VERSION} (0x{SUPPORTED_VERSION:08X}) is"),
        ));
    }
    let signature = word(bytes, 4).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "PDB info stream is truncated"))?;
    let age = word(bytes, 8).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "PDB info stream is truncated"))?;
    let guid = bytes
        .get(12..28)
        .and_then(|slice| <[u8; 16]>::try_from(slice).ok())
        .ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "PDB info stream is truncated"))?;

    let names_size = word(bytes, NAMES_SIZE_OFFSET).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "PDB info stream is truncated"))?;
    let names_end = NAMES_START
        .checked_add(names_size as usize)
        .ok_or_else(|| PdbError::new(PdbErrorKind::OutOfRange, format!("PDB info stream declares {names_size} name bytes")))?;
    if names_end > bytes.len() {
        return Err(PdbError::new(PdbErrorKind::Truncated, format!("PDB info stream is too short for its {names_size} name bytes")));
    }
    let names = &bytes[NAMES_START..names_end];

    let mut cursor = names_end;
    let entry_count = take_word(bytes, &mut cursor)?;
    let bucket_count = take_word(bytes, &mut cursor)?;
    if bucket_count == 0 || entry_count > bucket_count || bucket_count > MAX_NAMED_STREAMS {
        return Err(PdbError::new(
            PdbErrorKind::UnknownStreamConvention,
            format!("PDB named stream map declares {entry_count} entries in {bucket_count} buckets"),
        ));
    }
    let present = take_bit_vector(bytes, &mut cursor, bucket_count)?;
    if present != entry_count {
        return Err(PdbError::new(
            PdbErrorKind::UnknownStreamConvention,
            format!("PDB named stream map declares {entry_count} entries but its presence bitmap marks {present}"),
        ));
    }
    let deleted = take_bit_vector(bytes, &mut cursor, bucket_count)?;
    if deleted & present != 0 {
        return Err(PdbError::new(
            PdbErrorKind::UnknownStreamConvention,
            format!("PDB named stream map marks {deleted} buckets both present and deleted"),
        ));
    }

    let mut named_streams = Vec::with_capacity(entry_count as usize);
    for _ in 0..entry_count {
        let key = take_word(bytes, &mut cursor)?;
        let value = take_word(bytes, &mut cursor)?;
        named_streams.push((name_at(names, key)?, value));
    }
    // Both words follow the map on a real kernel PDB. `niMac` is validated for presence only.
    let _nimac = take_word(bytes, &mut cursor)?;
    let features = take_word(bytes, &mut cursor)?;

    Ok(PdbInfo { version, signature, age, guid, named_streams, features })
}

fn take_word(bytes: &[u8], cursor: &mut usize) -> Result<u32, PdbError> {
    let value = word(bytes, *cursor).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "PDB info stream is truncated"))?;
    *cursor += 4;
    Ok(value)
}

/// Reads a sparse presence bitmap and returns how many bits it set.
///
/// Each set bit is a bucket index, so a bit past the bucket count means the bitmap does not
/// describe this table and the encoding is not one this reader knows.
fn take_bit_vector(bytes: &[u8], cursor: &mut usize, bucket_count: u32) -> Result<u32, PdbError> {
    let words = take_word(bytes, cursor)?;
    let allowed = bucket_count.div_ceil(32);
    if words > allowed {
        return Err(PdbError::new(
            PdbErrorKind::UnknownStreamConvention,
            format!("PDB named stream map bitmap declares {words} words for {bucket_count} buckets"),
        ));
    }
    let mut set = 0u32;
    for word_index in 0..words {
        let bits = take_word(bytes, cursor)?;
        for bit in 0..32 {
            if bits & (1 << bit) == 0 {
                continue;
            }
            let index = word_index * 32 + bit;
            if index >= bucket_count {
                return Err(PdbError::new(
                    PdbErrorKind::UnknownStreamConvention,
                    format!("PDB named stream map bitmap marks bucket {index} but only {bucket_count} exist"),
                ));
            }
            set += 1;
        }
    }
    Ok(set)
}

/// Resolves a string table offset, which must point at a `/`-prefixed name.
fn name_at(names: &[u8], offset: u32) -> Result<String, PdbError> {
    let start = usize::try_from(offset).map_err(|_| PdbError::new(PdbErrorKind::OutOfRange, format!("name offset {offset} is out of range")))?;
    let Some(tail) = names.get(start..)
    else {
        return Err(PdbError::new(PdbErrorKind::OutOfRange, format!("name offset {offset} is past the {}-byte string table", names.len())));
    };
    let end = tail.iter().position(|byte| *byte == 0).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, format!("name at offset {offset} has no terminator")))?;
    let name = &tail[..end];
    if !name.starts_with(b"/") {
        return Err(PdbError::new(
            PdbErrorKind::UnknownStreamConvention,
            format!("string table entry at offset {offset} does not begin with `/`, so this name table encoding is not recognized"),
        ));
    }
    std::str::from_utf8(name)
        .map(str::to_owned)
        .map_err(|error| PdbError::new(PdbErrorKind::UnsupportedSymbolFormat, format!("name at offset {offset} is not UTF-8: {error}")))
}

/// Formats a CodeView GUID as uppercase text.
///
/// CodeView stores the first three groups little-endian while the canonical text form does not,
/// so each group is decoded before it is printed. Raw byte order produces a name that does not
/// exist in a symbol store.
pub fn guid_text(guid: &[u8; 16]) -> String {
    let first = u32::from_le_bytes([guid[0], guid[1], guid[2], guid[3]]);
    let second = u16::from_le_bytes([guid[4], guid[5]]);
    let third = u16::from_le_bytes([guid[6], guid[7]]);
    let tail = guid[8..16].iter().map(|byte| format!("{byte:02X}")).collect::<String>();
    format!("{first:08X}{second:04X}{third:04X}{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdb::fixtures;

    #[test]
    fn reads_the_build_identity_and_named_streams() {
        let bytes = fixtures::info_stream(SUPPORTED_VERSION, &[("/names", 8), ("/src/headerblock", 9)]);
        let info = parse(&bytes).expect("the synthetic info stream is valid");
        assert_eq!(info.version(), SUPPORTED_VERSION);
        assert_eq!(info.signature(), 0x1234_5678);
        assert_eq!(info.age(), 1);
        assert_eq!(info.guid_text(), "C3C2C1C0C5C4C7C6C8C9CACBCCCDCECF");
        assert_eq!(info.named_streams(), &[("/names".to_string(), 8), ("/src/headerblock".to_string(), 9)]);
        assert_eq!(info.features(), 0);
    }

    #[test]
    fn an_unknown_version_is_a_structured_failure() {
        let bytes = fixtures::info_stream(20_130_501, &[]);
        let error = parse(&bytes).expect_err("an unrecognized version must not parse");
        assert_eq!(error.kind(), PdbErrorKind::UnsupportedPdbVersion);
        assert_eq!(error.code(), "unsupported_pdb_version");
        assert!(error.to_string().contains("20130501"));
    }

    #[test]
    fn a_name_table_without_the_slash_prefix_is_rejected() {
        let mut bytes = fixtures::info_stream(SUPPORTED_VERSION, &[]);
        bytes.truncate(HEADER_SIZE);
        let names = b"plain\0";
        bytes.extend((names.len() as u32).to_le_bytes());
        bytes.extend(names);
        bytes.extend(1u32.to_le_bytes());
        bytes.extend(8u32.to_le_bytes());
        bytes.extend(1u32.to_le_bytes());
        bytes.extend(1u32.to_le_bytes());
        bytes.extend(0u32.to_le_bytes());
        bytes.extend(0u32.to_le_bytes());
        bytes.extend(8u32.to_le_bytes());
        bytes.extend(0u32.to_le_bytes());
        bytes.extend(0u32.to_le_bytes());
        let error = parse(&bytes).expect_err("a name table that does not follow the `/` convention must fail");
        assert_eq!(error.kind(), PdbErrorKind::UnknownStreamConvention);
        assert_eq!(error.code(), "unknown_stream_convention");
    }

    #[test]
    fn a_name_offset_past_the_table_is_rejected() {
        let mut bytes = fixtures::info_stream(SUPPORTED_VERSION, &[]);
        bytes.truncate(HEADER_SIZE);
        let names = b"/names\0";
        bytes.extend((names.len() as u32).to_le_bytes());
        bytes.extend(names);
        bytes.extend(1u32.to_le_bytes());
        bytes.extend(8u32.to_le_bytes());
        bytes.extend(1u32.to_le_bytes());
        bytes.extend(1u32.to_le_bytes());
        bytes.extend(0u32.to_le_bytes());
        bytes.extend(64u32.to_le_bytes());
        bytes.extend(8u32.to_le_bytes());
        bytes.extend(0u32.to_le_bytes());
        bytes.extend(0u32.to_le_bytes());
        let error = parse(&bytes).expect_err("a name offset past the table must fail");
        assert_eq!(error.kind(), PdbErrorKind::OutOfRange);
    }

    #[test]
    fn a_presence_bitmap_that_disagrees_with_the_entry_count_is_rejected() {
        let mut bytes = fixtures::info_stream(SUPPORTED_VERSION, &[("/names", 8)]);
        let names_end = NAMES_START + word(&bytes, NAMES_SIZE_OFFSET).expect("names size") as usize;
        let entry_count_offset = names_end;
        bytes[entry_count_offset..entry_count_offset + 4].copy_from_slice(&2u32.to_le_bytes());
        let error = parse(&bytes).expect_err("a table that claims more entries than its bitmap marks must fail");
        assert_eq!(error.kind(), PdbErrorKind::UnknownStreamConvention);
    }
}
