//! Global symbol hash stream: the index the link tools wrote over the symbol records.
//!
//! The DBI header names a stream that holds a hash table over the symbol record stream. Its layout
//! is a 16-byte header, then the reference records, then the bucket area:
//!
//! * Header: `0xFFFFFFFF`, a version word, the byte size of the reference records, and the byte
//!   size of the bucket area.
//! * Reference records: `(record offset, reference count)` pairs of `u32`. The offset is one
//!   greater than the byte position of the record it names, so `0` can mean "no record".
//! * Bucket area: 32-bit name hashes, one per hash bucket.
//!
//! This reader validates the header and every reference against the symbol record stream: each
//! offset must be non-zero, must land on a record start and must carry a non-zero reference count.
//!
//! Nothing in this product looks an address up through this table. Names come from the public
//! symbol records, which carry a section and an offset, so the hash table has no consumer here
//! beyond the checks below. Its bucket area is therefore only checked for size, not interpreted.

use std::collections::BTreeSet;

use super::{PdbError, PdbErrorKind, publics, word};

/// Signature every global symbol hash stream starts with.
pub const GSI_SIGNATURE: u32 = 0xFFFF_FFFF;
/// Version word of the hash stream the current link tools write.
pub const GSI_VERSION_80: u32 = 0xF12F_091A;
/// Version word of the older `v70` hash stream, which differs only in the record spellings it
/// hashes and uses the same layout.
pub const GSI_VERSION_70: u32 = 0xF12E_BA2D;

/// Bytes of the hash stream header.
const HEADER_SIZE: usize = 16;
/// Bytes of one reference record: the record offset and its reference count.
const REFERENCE_SIZE: usize = 8;
/// Bytes of one bucket entry.
const BUCKET_SIZE: usize = 4;
/// Upper bound on the bucket area, so a corrupt size field fails instead of allocating it.
const MAX_BUCKET_BYTES: u32 = 1 << 30;

/// Header of the global symbol hash stream, as the link tools write it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GlobalsHeader {
    /// `GSI_VERSION_70` or `GSI_VERSION_80`.
    pub version: u32,
    /// Bytes of reference records that follow the header.
    pub record_bytes: u32,
    /// Bytes of the bucket area that follows the reference records.
    pub bucket_bytes: u32,
}

impl GlobalsHeader {
    /// Number of reference records the header declares.
    pub fn reference_count(&self) -> usize {
        self.record_bytes as usize / REFERENCE_SIZE
    }

    /// Number of hash buckets the header declares.
    pub fn bucket_count(&self) -> usize {
        self.bucket_bytes as usize / BUCKET_SIZE
    }
}

/// One reference record: a symbol record the hash table indexes, and how many names point at it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GlobalsReference {
    /// One greater than the referenced record's byte offset in the symbol record stream.
    pub record_offset: u32,
    pub reference_count: u32,
}

/// The validated hash stream: its header and every reference it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalsHash {
    pub header: GlobalsHeader,
    pub references: Vec<GlobalsReference>,
}

/// Validates the hash stream header and its reference records against the symbol record stream.
///
/// `records` is the stream the DBI header names as the symbol record stream, because a reference
/// is only meaningful if it lands on a record inside it.
pub fn load(globals: &[u8], records: &[u8]) -> Result<GlobalsHash, PdbError> {
    let header = parse_header(globals)?;
    let end = HEADER_SIZE + header.record_bytes as usize + header.bucket_bytes as usize;
    if end != globals.len() {
        return Err(PdbError::new(
            PdbErrorKind::UnknownStreamConvention,
            format!(
                "global symbol hash stream declares {} header, {} record and {} bucket bytes but holds {}",
                HEADER_SIZE,
                header.record_bytes,
                header.bucket_bytes,
                globals.len()
            ),
        ));
    }
    let references = parse_references(&globals[HEADER_SIZE..HEADER_SIZE + header.record_bytes as usize], records)?;
    Ok(GlobalsHash { header, references })
}

/// Reads and validates the 16-byte hash stream header.
pub fn parse_header(globals: &[u8]) -> Result<GlobalsHeader, PdbError> {
    if globals.len() < HEADER_SIZE {
        return Err(PdbError::new(
            PdbErrorKind::Truncated,
            format!("global symbol hash stream is {} bytes but its header needs {HEADER_SIZE}", globals.len()),
        ));
    }
    let signature = word(globals, 0).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "global symbol hash stream is truncated"))?;
    if signature != GSI_SIGNATURE {
        return Err(PdbError::new(
            PdbErrorKind::UnknownStreamConvention,
            format!("global symbol hash stream starts with 0x{signature:08X} instead of 0x{GSI_SIGNATURE:08X}"),
        ));
    }
    let version = word(globals, 4).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "global symbol hash stream is truncated"))?;
    if version != GSI_VERSION_70 && version != GSI_VERSION_80 {
        return Err(PdbError::new(
            PdbErrorKind::UnknownStreamConvention,
            format!(
                "global symbol hash stream declares version 0x{version:08X}, which is neither 0x{GSI_VERSION_70:08X} nor 0x{GSI_VERSION_80:08X}"
            ),
        ));
    }
    let record_bytes = word(globals, 8).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "global symbol hash stream is truncated"))?;
    let bucket_bytes = word(globals, 12).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "global symbol hash stream is truncated"))?;
    if !(record_bytes as usize).is_multiple_of(REFERENCE_SIZE) {
        return Err(PdbError::new(
            PdbErrorKind::UnknownStreamConvention,
            format!("global symbol hash stream declares {record_bytes} record bytes, which do not hold whole {REFERENCE_SIZE}-byte references"),
        ));
    }
    if !(bucket_bytes as usize).is_multiple_of(BUCKET_SIZE) || bucket_bytes > MAX_BUCKET_BYTES {
        return Err(PdbError::new(
            PdbErrorKind::UnknownStreamConvention,
            format!("global symbol hash stream declares {bucket_bytes} bucket bytes, which are not whole {BUCKET_SIZE}-byte buckets"),
        ));
    }
    Ok(GlobalsHeader { version, record_bytes, bucket_bytes })
}

/// Reads every reference record and checks that it names a record start with a live reference.
fn parse_references(bytes: &[u8], records: &[u8]) -> Result<Vec<GlobalsReference>, PdbError> {
    let starts = publics::record_starts(records)?.into_iter().collect::<BTreeSet<_>>();
    let mut references = Vec::with_capacity(bytes.len() / REFERENCE_SIZE);
    for (position, chunk) in bytes.as_chunks::<REFERENCE_SIZE>().0.iter().enumerate() {
        let record_offset = word(chunk, 0).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "global symbol reference is truncated"))?;
        let reference_count = word(chunk, 4).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "global symbol reference is truncated"))?;
        if record_offset == 0 {
            return Err(PdbError::new(
                PdbErrorKind::OutOfRange,
                format!("global symbol reference {position} names no record, so it cannot be resolved"),
            ));
        }
        if reference_count == 0 {
            return Err(PdbError::new(
                PdbErrorKind::UnsupportedSymbolFormat,
                format!("global symbol reference {position} names record 0x{:X} with a reference count of zero", record_offset - 1),
            ));
        }
        if !starts.contains(&(record_offset as usize - 1)) {
            return Err(PdbError::new(
                PdbErrorKind::OutOfRange,
                format!(
                    "global symbol reference {position} names byte 0x{:X}, which is not a record start in a stream of {} bytes",
                    record_offset - 1,
                    records.len()
                ),
            ));
        }
        references.push(GlobalsReference { record_offset, reference_count });
    }
    Ok(references)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a record stream whose records occupy the offsets the references name.
    fn records() -> (Vec<u8>, Vec<u32>) {
        let mut bytes = Vec::new();
        let mut offsets = Vec::new();
        for body in [6usize, 10, 4] {
            offsets.push((bytes.len() + 1) as u32);
            bytes.extend(((body + 2) as u16).to_le_bytes());
            bytes.extend(0x110Eu16.to_le_bytes());
            bytes.extend(vec![0u8; body]);
        }
        (bytes, offsets)
    }

    fn hash_stream(references: &[(u32, u32)], buckets: usize) -> Vec<u8> {
        let record_bytes = (references.len() * REFERENCE_SIZE) as u32;
        let bucket_bytes = (buckets * BUCKET_SIZE) as u32;
        let mut bytes = Vec::new();
        bytes.extend(GSI_SIGNATURE.to_le_bytes());
        bytes.extend(GSI_VERSION_80.to_le_bytes());
        bytes.extend(record_bytes.to_le_bytes());
        bytes.extend(bucket_bytes.to_le_bytes());
        for (offset, count) in references {
            bytes.extend(offset.to_le_bytes());
            bytes.extend(count.to_le_bytes());
        }
        bytes.extend(vec![0xA5u8; bucket_bytes as usize]);
        bytes
    }

    #[test]
    fn validates_a_hash_stream_whose_references_name_record_starts() {
        let (records, offsets) = records();
        let references = offsets.iter().map(|offset| (*offset, 1u32)).collect::<Vec<_>>();
        let hash = load(&hash_stream(&references, 4), &records).expect("every reference names a record start");

        assert_eq!(hash.header.version, GSI_VERSION_80);
        assert_eq!(hash.header.reference_count(), 3);
        assert_eq!(hash.header.bucket_count(), 4);
        assert_eq!(
            hash.references,
            offsets.iter().map(|offset| GlobalsReference { record_offset: *offset, reference_count: 1 }).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_reference_into_the_middle_of_a_record_is_rejected() {
        let (records, offsets) = records();
        let references = [(offsets[0], 1u32), (offsets[1] + 1, 1)];
        let error = load(&hash_stream(&references, 1), &records).expect_err("a mid-record offset cannot name a symbol");
        assert_eq!(error.kind(), PdbErrorKind::OutOfRange);
        assert!(error.detail().contains("not a record start"), "{error}");
    }

    #[test]
    fn a_zero_offset_or_a_zero_reference_count_is_rejected() {
        let (records, offsets) = records();
        let error = load(&hash_stream(&[(0, 1)], 1), &records).expect_err("offset zero names no record");
        assert_eq!(error.kind(), PdbErrorKind::OutOfRange);
        let error = load(&hash_stream(&[(offsets[0], 0)], 1), &records).expect_err("a deleted reference is not live");
        assert_eq!(error.kind(), PdbErrorKind::UnsupportedSymbolFormat);
    }

    #[test]
    fn an_unknown_signature_or_version_is_a_structured_failure() {
        let (records, offsets) = records();
        let mut stream = hash_stream(&[(offsets[0], 1)], 1);
        stream[..4].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        let error = load(&stream, &records).expect_err("a wrong signature is not this stream");
        assert_eq!(error.kind(), PdbErrorKind::UnknownStreamConvention);
        assert!(error.detail().contains("0x12345678"), "{error}");

        let mut stream = hash_stream(&[(offsets[0], 1)], 1);
        stream[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        let error = load(&stream, &records).expect_err("an unknown version has no layout this reader knows");
        assert_eq!(error.kind(), PdbErrorKind::UnknownStreamConvention);
        assert!(error.detail().contains("0xDEADBEEF"), "{error}");
    }

    #[test]
    fn a_declared_size_that_does_not_match_the_stream_is_rejected() {
        let (records, offsets) = records();
        let stream = hash_stream(&[(offsets[0], 1)], 2);
        let error = load(&stream[..stream.len() - 4], &records).expect_err("a short stream contradicts its header");
        assert_eq!(error.kind(), PdbErrorKind::UnknownStreamConvention);
        assert!(error.detail().contains("bucket bytes"), "{error}");
    }

    #[test]
    fn a_header_shorter_than_its_fields_is_truncated() {
        let error = parse_header(&[0xFFu8; 12]).expect_err("a header needs 16 bytes");
        assert_eq!(error.kind(), PdbErrorKind::Truncated);
    }
}
