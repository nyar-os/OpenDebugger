//! Module symbol streams: the CodeView records one compiler object file contributed.
//!
//! The DBI module list names, for each object file, the stream that holds its symbols and the
//! declared byte size of that substream. That substream is the only place a PDB records the byte
//! length of a procedure: a public symbol carries a name, a section and an offset and nothing
//! else, so the rule that rejects a nearest-symbol answer outside the function it belongs to can
//! only be applied once the procedure record of that function is read.
//!
//! A module symbol substream opens with the CodeView C13 signature, followed by CodeView records.
//! Only procedure records are read: each carries the 1-based section, the byte offset inside that
//! section (the same frame the public symbols use), the byte length and the name. Records of other
//! kinds are counted and skipped. A substream that opens with a different signature, or a record
//! whose declared length runs past the substream, is a structured failure rather than an empty
//! result.

use super::{PdbError, PdbErrorKind, half, word};

/// Signature that opens a module symbol substream: the CodeView C13 symbol signature.
///
/// A real kernel PDB writes the plain `4` in its first four bytes, and every module substream of
/// it carries the same value. The older C6, C7 and FPO signatures denote record layouts this
/// reader does not parse, so they fail instead of being read with the C13 offsets.
const SIGNATURE: u32 = 4;

/// CodeView record kinds that describe a procedure and carry its byte length.
pub const S_LPROC32: u16 = 0x110F;
pub const S_GPROC32: u16 = 0x1110;
pub const S_LPROC32_ID: u16 = 0x1146;
pub const S_GPROC32_ID: u16 = 0x1147;

/// Offsets inside a procedure record payload, counted from the byte after the record kind.
///
/// The payload opens with three 32-bit offsets that link the record into the module's scope tree,
/// then the length, the two debug offsets of the prologue and epilogue, the type index, the byte
/// offset inside the section, the section number and the flags. The name follows the flags.
const PROC_LENGTH_OFFSET: usize = 12;
const PROC_OFFSET_OFFSET: usize = 28;
const PROC_SECTION_OFFSET: usize = 32;
const PROC_NAME_OFFSET: usize = 35;
const MAX_NAME_BYTES: usize = 2048;

/// One procedure record: where it starts, how long it is and what it is called.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleFunction {
    /// The name as the compiler wrote it, which can be a decorated spelling.
    pub name: String,
    /// 1-based section number the offset is relative to.
    pub section: u16,
    /// Byte offset from the start of that section.
    pub offset: u32,
    /// Byte length the compiler recorded for this procedure.
    pub length: u32,
    /// CodeView kind, so a caller can tell an `_ID` record from the plain one.
    pub kind: u16,
}

/// Every procedure record of one module substream, with a count of the records not read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModuleSymbols {
    pub functions: Vec<ModuleFunction>,
    /// Records of other kinds, which address lookup does not read.
    pub other_records: usize,
}

impl ModuleSymbols {
    /// Finds the procedure that starts exactly at `section`/`offset`.
    ///
    /// The match is exact in both fields: a nearest public symbol is only given a length when the
    /// compiler recorded a procedure that begins at the very same section offset. A procedure
    /// that merely covers the address is a different claim, so there is no range search here.
    pub fn function_at(&self, section: u16, offset: u32) -> Option<&ModuleFunction> {
        self.functions.iter().find(|function| function.section == section && function.offset == offset)
    }
}

/// Validates the substream signature and collects its procedure records.
pub fn parse(bytes: &[u8]) -> Result<ModuleSymbols, PdbError> {
    if bytes.len() < 4 {
        return Err(PdbError::new(
            PdbErrorKind::Truncated,
            format!("module symbol substream is {} bytes but its signature needs 4", bytes.len()),
        ));
    }
    let signature = word(bytes, 0).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "module symbol substream is truncated"))?;
    if signature != SIGNATURE {
        return Err(PdbError::new(
            PdbErrorKind::UnknownStreamConvention,
            format!(
                "module symbol substream begins with signature 0x{signature:08X} instead of 0x{SIGNATURE:08X}, so its records are not the C13 layout this reader knows"
            ),
        ));
    }
    let mut symbols = ModuleSymbols::default();
    let mut cursor = 4;
    while cursor < bytes.len() {
        let remainder = bytes.len() - cursor;
        if remainder < 4 {
            return Err(PdbError::new(
                PdbErrorKind::Truncated,
                format!("module symbol substream ends with {remainder} bytes that cannot hold a record header"),
            ));
        }
        let length = usize::from(u16::from_le_bytes([bytes[cursor], bytes[cursor + 1]]));
        let kind = u16::from_le_bytes([bytes[cursor + 2], bytes[cursor + 3]]);
        let total = length + 2;
        if length < 2 || total > remainder {
            return Err(PdbError::new(
                PdbErrorKind::OutOfRange,
                format!("module symbol record at offset {cursor} declares {length} body bytes with {remainder} left"),
            ));
        }
        if is_procedure(kind) {
            symbols.functions.push(read_procedure(bytes, cursor, length, kind)?);
        }
        else {
            symbols.other_records += 1;
        }
        cursor += total;
    }
    Ok(symbols)
}

fn is_procedure(kind: u16) -> bool {
    matches!(kind, S_LPROC32 | S_GPROC32 | S_LPROC32_ID | S_GPROC32_ID)
}

fn read_procedure(bytes: &[u8], start: usize, length: usize, kind: u16) -> Result<ModuleFunction, PdbError> {
    // The length covers the record kind, which occupies the first two body bytes.
    let payload = &bytes[start + 4..start + 2 + length];
    if payload.len() < PROC_NAME_OFFSET + 1 {
        return Err(PdbError::new(
            PdbErrorKind::OutOfRange,
            format!("procedure record at offset {start} carries {} payload bytes, too short for a name", payload.len()),
        ));
    }
    let byte_length =
        word(payload, PROC_LENGTH_OFFSET).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "procedure record is truncated"))?;
    let offset = word(payload, PROC_OFFSET_OFFSET).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "procedure record is truncated"))?;
    let section = half(payload, PROC_SECTION_OFFSET).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "procedure record is truncated"))?;
    let tail = &payload[PROC_NAME_OFFSET..];
    let name_end = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| PdbError::new(PdbErrorKind::UnsupportedSymbolFormat, format!("procedure name at offset {start} has no terminator")))?;
    if name_end == 0 {
        return Err(PdbError::new(PdbErrorKind::UnsupportedSymbolFormat, format!("procedure record at offset {start} has an empty name")));
    }
    if name_end > MAX_NAME_BYTES {
        return Err(PdbError::new(PdbErrorKind::UnsupportedSymbolFormat, format!("procedure name at offset {start} is {name_end} bytes")));
    }
    let name = std::str::from_utf8(&tail[..name_end]).map_err(|error| {
        PdbError::new(PdbErrorKind::UnsupportedSymbolFormat, format!("procedure name at offset {start} is not UTF-8: {error}"))
    })?;
    if section == 0 {
        return Err(PdbError::new(
            PdbErrorKind::OutOfRange,
            format!("procedure record at offset {start} names `{name}` in section 0, which no PE image has"),
        ));
    }
    Ok(ModuleFunction { name: name.to_owned(), section, offset, length: byte_length, kind })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdb::fixtures;

    fn fixture(kind: u16, section: u16, offset: u32, length: u32, name: &str) -> Vec<u8> {
        fixtures::module_symbol_stream(&[(kind, section, offset, length, name)])
    }

    #[test]
    fn collects_procedure_records_and_skips_other_kinds() {
        let bytes =
            fixtures::module_symbol_stream(&[(S_GPROC32, 1, 0x100, 0x40, "?Write@Kernel@@QEAAXXZ"), (S_LPROC32_ID, 2, 0x20, 0x18, "Helper")]);
        let symbols = parse(&bytes).expect("the synthetic substream is well formed");
        assert_eq!(symbols.functions.len(), 2);
        assert_eq!(symbols.functions[0].kind, S_GPROC32);
        assert_eq!(symbols.functions[0].section, 1);
        assert_eq!(symbols.functions[0].offset, 0x100);
        assert_eq!(symbols.functions[0].length, 0x40);
        assert_eq!(symbols.functions[0].name, "?Write@Kernel@@QEAAXXZ");
        assert_eq!(symbols.functions[1].length, 0x18);
        let hit = symbols.function_at(2, 0x20).expect("the second procedure starts at its own offset");
        assert_eq!(hit.name, "Helper");
        assert!(symbols.function_at(2, 0x24).is_none(), "an address inside the procedure is not its start");
    }

    #[test]
    fn reads_the_declared_length_and_name_of_one_procedure() {
        let bytes = fixture(S_LPROC32, 3, 0x4100, 0x35, "MiWalkEntireImage");
        let symbols = parse(&bytes).expect("one procedure record is valid");
        assert_eq!(
            symbols,
            ModuleSymbols {
                functions: vec![ModuleFunction {
                    name: "MiWalkEntireImage".to_string(),
                    section: 3,
                    offset: 0x4100,
                    length: 0x35,
                    kind: S_LPROC32
                }],
                other_records: 0
            }
        );
    }

    #[test]
    fn a_substream_with_a_foreign_signature_is_rejected() {
        let mut bytes = fixtures::module_symbol_stream(&[(S_GPROC32, 1, 0x100, 0x40, "Function")]);
        bytes[0] = 0x01;
        let error = parse(&bytes).expect_err("an unknown signature is not a symbol substream");
        assert_eq!(error.kind(), PdbErrorKind::UnknownStreamConvention);
        assert_eq!(error.code(), "unknown_stream_convention");
    }

    #[test]
    fn a_substream_shorter_than_the_signature_is_rejected() {
        let error = parse(&[0x02, 0xF1]).expect_err("two bytes cannot carry a signature");
        assert_eq!(error.kind(), PdbErrorKind::Truncated);
    }

    #[test]
    fn a_record_that_runs_past_the_substream_is_rejected() {
        let mut bytes = fixtures::module_symbol_stream(&[(S_GPROC32, 1, 0x100, 0x40, "Function")]);
        let length = bytes.len();
        bytes[4..6].copy_from_slice(&((length + 100) as u16).to_le_bytes());
        let error = parse(&bytes).expect_err("a record longer than the substream cannot be read");
        assert_eq!(error.kind(), PdbErrorKind::OutOfRange);
    }

    #[test]
    fn a_procedure_without_a_name_terminator_is_rejected() {
        let mut bytes = fixtures::module_symbol_stream(&[(S_GPROC32, 1, 0x100, 0x40, "Function")]);
        let length = bytes.len();
        bytes[length - 1] = b'n';
        let error = parse(&bytes).expect_err("an unterminated name cannot be trusted");
        assert_eq!(error.kind(), PdbErrorKind::UnsupportedSymbolFormat);
    }

    #[test]
    fn a_procedure_record_too_short_for_its_own_payload_is_rejected() {
        let mut bytes = Vec::new();
        bytes.extend(SIGNATURE.to_le_bytes());
        bytes.extend(2u16.to_le_bytes());
        bytes.extend(S_GPROC32.to_le_bytes());
        let error = parse(&bytes).expect_err("a bare kind cannot describe a procedure");
        assert_eq!(error.kind(), PdbErrorKind::OutOfRange);
    }
}
