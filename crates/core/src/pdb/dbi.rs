//! DBI stream header: the stream numbers that hold the symbol hash tables and symbol records.
//!
//! Only the fixed header is read. Module information, section contributions, type server maps
//! and the optional debug header follow it and belong to later stages, so their sizes are
//! ignored here.

use super::{PdbError, PdbErrorKind, half, word};

const HEADER_SIZE: usize = 68;
const SIGNATURE: u32 = 0xFFFF_FFFF;
/// Build stamp the DBI header carries when it is written by the link tools.
///
/// A real kernel PDB reports `0x01310977`, which is the plain decimal `19990903`. The
/// `0xEFFE0000` prefix used by symbol-table headers does not appear here.
const VERSION_HEADER: u32 = 19_990_903;

const AGE_OFFSET: usize = 0x08;
const GLOBAL_STREAM_OFFSET: usize = 0x0C;
const PUBLIC_STREAM_OFFSET: usize = 0x10;
const SYMBOL_RECORD_STREAM_OFFSET: usize = 0x14;

#[derive(Debug, Clone, Copy)]
pub struct DbiHeader {
    pub age: u32,
    /// Stream holding the global symbol hash table.
    pub global_stream: u16,
    /// Stream holding the public symbol hash table.
    pub public_stream: u16,
    /// Stream holding the symbol records the hash tables index into.
    pub symbol_record_stream: u16,
}

pub fn parse_header(bytes: &[u8]) -> Result<DbiHeader, PdbError> {
    if bytes.len() < HEADER_SIZE {
        return Err(PdbError::new(PdbErrorKind::Truncated, format!("DBI stream is {} bytes but its header needs {HEADER_SIZE}", bytes.len())));
    }
    let signature = word(bytes, 0).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "DBI header is truncated"))?;
    if signature != SIGNATURE {
        return Err(PdbError::new(
            PdbErrorKind::UnknownStreamConvention,
            format!("DBI header begins with 0x{signature:08X} instead of 0x{SIGNATURE:08X}, so this stream is not a DBI header"),
        ));
    }
    let version = word(bytes, 4).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "DBI header is truncated"))?;
    if version != VERSION_HEADER {
        return Err(PdbError::new(
            PdbErrorKind::UnknownStreamConvention,
            format!("DBI header version stamp is 0x{version:08X} but 0x{VERSION_HEADER:08X} is the only recognized value"),
        ));
    }
    let age = word(bytes, AGE_OFFSET).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "DBI header is truncated"))?;
    let global_stream = half(bytes, GLOBAL_STREAM_OFFSET).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "DBI header is truncated"))?;
    let public_stream = half(bytes, PUBLIC_STREAM_OFFSET).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "DBI header is truncated"))?;
    let symbol_record_stream = half(bytes, SYMBOL_RECORD_STREAM_OFFSET).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "DBI header is truncated"))?;
    Ok(DbiHeader { age, global_stream, public_stream, symbol_record_stream })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdb::fixtures;

    #[test]
    fn reads_the_symbol_stream_numbers() {
        let bytes = fixtures::dbi_stream(4, 5, 6);
        let header = parse_header(&bytes).expect("the synthetic DBI header is valid");
        assert_eq!(header.age, 1);
        assert_eq!(header.global_stream, 4);
        assert_eq!(header.public_stream, 5);
        assert_eq!(header.symbol_record_stream, 6);
    }

    #[test]
    fn an_unknown_version_stamp_is_a_structured_failure() {
        let mut bytes = fixtures::dbi_stream(4, 5, 6);
        bytes[4..8].copy_from_slice(&0u32.to_le_bytes());
        let error = parse_header(&bytes).expect_err("an unrecognized stamp must not be treated as a DBI header");
        assert_eq!(error.kind(), PdbErrorKind::UnknownStreamConvention);
        assert_eq!(error.code(), "unknown_stream_convention");
    }

    #[test]
    fn a_stream_shorter_than_the_header_is_rejected() {
        let error = parse_header(&[0; 8]).expect_err("a short stream cannot hold a DBI header");
        assert_eq!(error.kind(), PdbErrorKind::Truncated);
    }
}
