//! DBI stream: the header plus the module list, section contributions and section map.
//!
//! The header names the streams that hold the symbol hash tables and the symbol records, and gives
//! the byte size of each substream that follows it. The substreams are written in a fixed order:
//! module information, section contributions, the section map, file information, type server maps,
//! the EC substream and the optional debug header. Only the first four carry data address lookup
//! needs: which object files built the image, where each object file's bytes landed, and how the
//! linker numbered the image sections. The type server maps, the EC substream and the optional
//! debug header are skipped by their declared sizes and never interpreted.
//!
//! A PDB module is one compiler object file, not one loaded image module, so the module list is
//! what the link step recorded, not the loader's module table. The module count comes from the
//! file information substream; the module records themselves do not carry it.

use super::{PdbError, PdbErrorKind, half, word};

const HEADER_SIZE: usize = 64;
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
const MODULE_BYTES_OFFSET: usize = 0x18;
const SECTION_CONTRIBUTION_BYTES_OFFSET: usize = 0x1C;
const SECTION_MAP_BYTES_OFFSET: usize = 0x20;
const FILE_INFO_BYTES_OFFSET: usize = 0x24;
const TYPE_SERVER_BYTES_OFFSET: usize = 0x28;
const OPTIONAL_DEBUG_BYTES_OFFSET: usize = 0x30;
const EC_BYTES_OFFSET: usize = 0x34;

/// Every module record begins with this fixed header, followed by its name and object name.
const MODULE_HEADER_SIZE: usize = 64;
/// Offsets inside a module record: the embedded section contribution, then its two strings.
const MODULE_SECTION_OFFSET: usize = 4;
const MODULE_CONTRIBUTION_OFFSET: usize = 8;
const MODULE_CONTRIBUTION_SIZE_OFFSET: usize = 12;
/// Section number a module record carries when the linker placed none of its bytes.
const NO_SECTION: u16 = 0xFFFF;

/// Section contribution substream markers. The value is `0xEFFE0000` plus the link date.
const SECTION_CONTRIBUTION_V60: u32 = 0xF12E_BA2D;
const SECTION_CONTRIBUTION_V2: u32 = 0xF131_51E4;
const SECTION_CONTRIBUTION_V60_BYTES: usize = 28;
const SECTION_CONTRIBUTION_V2_BYTES: usize = 32;

const SECTION_MAP_ENTRY_BYTES: usize = 20;
const MAX_MODULES: u32 = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DbiHeader {
    pub age: u32,
    /// Stream holding the global symbol hash table.
    pub global_stream: u16,
    /// Stream holding the public symbol hash table.
    pub public_stream: u16,
    /// Stream holding the symbol records the hash tables index into.
    pub symbol_record_stream: u16,
    /// Declared byte size of the module information substream.
    pub module_bytes: u32,
    /// Declared byte size of the section contribution substream.
    pub section_contribution_bytes: u32,
    /// Declared byte size of the section map substream.
    pub section_map_bytes: u32,
    /// Declared byte size of the file information substream.
    pub file_info_bytes: u32,
    pub type_server_bytes: u32,
    pub ec_bytes: u32,
    pub optional_debug_bytes: u32,
}

/// Where the linker placed a module's first contribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModulePlacement {
    /// 1-based section number in the image the PDB describes.
    pub section: u16,
    /// Byte offset from the start of that section.
    pub offset: u32,
    pub size: u32,
}

/// One compiler object file that contributed to the image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleInfo {
    pub name: String,
    pub object_name: String,
    /// `None` when the record carries the placeholder section number, which marks an object
    /// file whose bytes were merged elsewhere or discarded.
    pub placement: Option<ModulePlacement>,
}

/// One byte range a module placed in one image section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionContribution {
    /// Index into [`DebugInfo::modules`].
    pub module: u16,
    /// 1-based section number in the image the PDB describes.
    pub section: u16,
    /// Byte offset from the start of that section.
    pub offset: u32,
    pub size: u32,
}

/// One entry of the linker's section map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionMapEntry {
    /// 1-based section number in the image. Zero is the pseudo-section that holds absolute
    /// linker-defined symbols rather than image bytes.
    pub frame: u16,
    pub offset: u32,
    /// Bytes the linker recorded for this section, which can be smaller than the image's
    /// virtual size when the section is padded at load time.
    pub byte_length: u32,
}

/// What the DBI stream records about the image's build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugInfo {
    pub modules: Vec<ModuleInfo>,
    pub contributions: Vec<SectionContribution>,
    pub sections: Vec<SectionMapEntry>,
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
    let header = DbiHeader {
        age: word(bytes, AGE_OFFSET).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "DBI header is truncated"))?,
        global_stream: half(bytes, GLOBAL_STREAM_OFFSET).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "DBI header is truncated"))?,
        public_stream: half(bytes, PUBLIC_STREAM_OFFSET).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "DBI header is truncated"))?,
        symbol_record_stream: half(bytes, SYMBOL_RECORD_STREAM_OFFSET)
            .ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "DBI header is truncated"))?,
        module_bytes: word(bytes, MODULE_BYTES_OFFSET).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "DBI header is truncated"))?,
        section_contribution_bytes: word(bytes, SECTION_CONTRIBUTION_BYTES_OFFSET)
            .ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "DBI header is truncated"))?,
        section_map_bytes: word(bytes, SECTION_MAP_BYTES_OFFSET)
            .ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "DBI header is truncated"))?,
        file_info_bytes: word(bytes, FILE_INFO_BYTES_OFFSET)
            .ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "DBI header is truncated"))?,
        type_server_bytes: word(bytes, TYPE_SERVER_BYTES_OFFSET)
            .ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "DBI header is truncated"))?,
        ec_bytes: word(bytes, EC_BYTES_OFFSET).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "DBI header is truncated"))?,
        optional_debug_bytes: word(bytes, OPTIONAL_DEBUG_BYTES_OFFSET)
            .ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "DBI header is truncated"))?,
    };
    let declared = header.declared_substream_bytes();
    let needed = HEADER_SIZE as u64 + declared;
    if needed > bytes.len() as u64 {
        return Err(PdbError::new(
            PdbErrorKind::Truncated,
            format!("DBI header declares {declared} substream bytes, which need {needed} bytes but the stream holds {}", bytes.len()),
        ));
    }
    Ok(header)
}

impl DbiHeader {
    /// Total bytes the header claims the substreams occupy. Kept in 64 bits so a corrupt header
    /// cannot wrap the sum.
    fn declared_substream_bytes(&self) -> u64 {
        u64::from(self.module_bytes)
            + u64::from(self.section_contribution_bytes)
            + u64::from(self.section_map_bytes)
            + u64::from(self.file_info_bytes)
            + u64::from(self.type_server_bytes)
            + u64::from(self.ec_bytes)
            + u64::from(self.optional_debug_bytes)
    }
}

/// Validates the header and every substream it declares.
///
/// The module count comes from the file information substream, so that one is read before the
/// module records. A module count that the module records do not fill exactly is a failure:
/// either the two substreams describe different builds or this reader has the wrong count.
pub fn parse(bytes: &[u8]) -> Result<DebugInfo, PdbError> {
    let header = parse_header(bytes)?;
    let mut cursor = HEADER_SIZE;
    let modules_bytes = take_substream(bytes, &mut cursor, header.module_bytes, "module information")?;
    let contributions_bytes = take_substream(bytes, &mut cursor, header.section_contribution_bytes, "section contribution")?;
    let section_map_bytes = take_substream(bytes, &mut cursor, header.section_map_bytes, "section map")?;
    let file_info_bytes = take_substream(bytes, &mut cursor, header.file_info_bytes, "file information")?;
    skip_substream(bytes, &mut cursor, header.type_server_bytes, "type server")?;
    skip_substream(bytes, &mut cursor, header.ec_bytes, "EC")?;
    skip_substream(bytes, &mut cursor, header.optional_debug_bytes, "optional debug header")?;

    let (module_count, _source_file_count) = file_info_counts(file_info_bytes)?;
    let modules = parse_modules(modules_bytes, module_count)?;
    let contributions = parse_contributions(contributions_bytes)?;
    let sections = parse_section_map(section_map_bytes)?;
    for contribution in &contributions {
        if usize::from(contribution.module) >= modules.len() {
            return Err(PdbError::new(
                PdbErrorKind::OutOfRange,
                format!("a section contribution names module {} but the module list holds {}", contribution.module, modules.len()),
            ));
        }
    }
    Ok(DebugInfo { modules, contributions, sections })
}

/// Slices one substream out of the stream and moves the cursor past it.
fn take_substream<'a>(bytes: &'a [u8], cursor: &mut usize, size: u32, name: &str) -> Result<&'a [u8], PdbError> {
    let start = *cursor;
    let end = start
        .checked_add(size as usize)
        .ok_or_else(|| PdbError::new(PdbErrorKind::OutOfRange, format!("the {name} substream offset overflows")))?;
    let slice = bytes.get(start..end).ok_or_else(|| {
        PdbError::new(
            PdbErrorKind::Truncated,
            format!("the {name} substream needs bytes {start}..{end} but the DBI stream holds {}", bytes.len()),
        )
    })?;
    *cursor = end;
    Ok(slice)
}

/// Moves the cursor past a substream this reader keeps only for its size.
fn skip_substream(bytes: &[u8], cursor: &mut usize, size: u32, name: &str) -> Result<(), PdbError> {
    take_substream(bytes, cursor, size, name).map(|_| ())
}

/// Reads the module count and source file count that open the file information substream.
///
/// The two counts are followed by one `u16` per module, one more `u16` per module and one `u32`
/// per source file, so the substream has to be large enough for all three arrays. Names follow
/// them and are not read here.
fn file_info_counts(bytes: &[u8]) -> Result<(u32, u32), PdbError> {
    if bytes.is_empty() {
        return Ok((0, 0));
    }
    if bytes.len() < 4 {
        return Err(PdbError::new(
            PdbErrorKind::Truncated,
            format!("file information substream is {} bytes but its header needs 4", bytes.len()),
        ));
    }
    let module_count =
        u32::from(half(bytes, 0).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "file information substream is truncated"))?);
    let source_file_count =
        u32::from(half(bytes, 2).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "file information substream is truncated"))?);
    let needed = 4u64 + 4 * u64::from(module_count) + 4 * u64::from(source_file_count);
    if needed > bytes.len() as u64 {
        return Err(PdbError::new(
            PdbErrorKind::Truncated,
            format!(
                "file information substream declares {module_count} modules and {source_file_count} source files, which need {needed} bytes but it holds {}",
                bytes.len()
            ),
        ));
    }
    Ok((module_count, source_file_count))
}

fn parse_modules(bytes: &[u8], count: u32) -> Result<Vec<ModuleInfo>, PdbError> {
    if count > MAX_MODULES {
        return Err(PdbError::new(PdbErrorKind::UnknownStreamConvention, format!("file information declares {count} modules")));
    }
    let mut modules = Vec::with_capacity(count as usize);
    let mut cursor = 0usize;
    for _ in 0..count {
        let start = cursor;
        let header = bytes.get(start..start + MODULE_HEADER_SIZE).ok_or_else(|| {
            PdbError::new(
                PdbErrorKind::Truncated,
                format!("module substream ends before the header of module {} of {count} at offset {start}", modules.len()),
            )
        })?;
        let section = half(header, MODULE_SECTION_OFFSET)
            .ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, format!("module record at offset {start} is truncated")))?;
        cursor = start + MODULE_HEADER_SIZE;
        let name = take_string(bytes, &mut cursor, start)?;
        let object_name = take_string(bytes, &mut cursor, start)?;
        let aligned = start + ((cursor - start + 3) & !3);
        if aligned > bytes.len() {
            return Err(PdbError::new(
                PdbErrorKind::Truncated,
                format!("module substream ends inside the padding of module {} at offset {start}", modules.len()),
            ));
        }
        cursor = aligned;
        modules.push(ModuleInfo { name: name.to_owned(), object_name: object_name.to_owned(), placement: placement(header, start, section)? });
    }
    if cursor != bytes.len() {
        return Err(PdbError::new(
            PdbErrorKind::UnknownStreamConvention,
            format!(
                "the module substream is {} bytes but {count} module records end at {cursor}, so the module count and the records disagree",
                bytes.len()
            ),
        ));
    }
    Ok(modules)
}

fn placement(header: &[u8], start: usize, section: u16) -> Result<Option<ModulePlacement>, PdbError> {
    if section == NO_SECTION {
        return Ok(None);
    }
    if section == 0 {
        return Err(PdbError::new(PdbErrorKind::OutOfRange, format!("module record at offset {start} names section 0, which no image has")));
    }
    let offset = signed(header, MODULE_CONTRIBUTION_OFFSET)
        .ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, format!("module record at offset {start} is truncated")))?;
    let size = signed(header, MODULE_CONTRIBUTION_SIZE_OFFSET)
        .ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, format!("module record at offset {start} is truncated")))?;
    if offset < 0 || size < 0 {
        return Err(PdbError::new(
            PdbErrorKind::OutOfRange,
            format!("module record at offset {start} places {size} bytes at section {section} offset {offset}"),
        ));
    }
    Ok(Some(ModulePlacement { section, offset: offset as u32, size: size as u32 }))
}

fn parse_contributions(bytes: &[u8]) -> Result<Vec<SectionContribution>, PdbError> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if bytes.len() < 4 {
        return Err(PdbError::new(
            PdbErrorKind::Truncated,
            format!("section contribution substream is {} bytes but its version marker needs 4", bytes.len()),
        ));
    }
    let version = word(bytes, 0).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "section contribution substream is truncated"))?;
    let entry_bytes = match version {
        SECTION_CONTRIBUTION_V60 => SECTION_CONTRIBUTION_V60_BYTES,
        SECTION_CONTRIBUTION_V2 => SECTION_CONTRIBUTION_V2_BYTES,
        other => {
            return Err(PdbError::new(
                PdbErrorKind::UnknownStreamConvention,
                format!(
                    "section contribution substream begins with 0x{other:08X}, which is neither 0x{SECTION_CONTRIBUTION_V60:08X} nor 0x{SECTION_CONTRIBUTION_V2:08X}"
                ),
            ));
        }
    };
    let body = &bytes[4..];
    if !body.len().is_multiple_of(entry_bytes) {
        return Err(PdbError::new(
            PdbErrorKind::UnknownStreamConvention,
            format!(
                "section contribution substream holds {} bytes after its marker, which is not a whole number of {entry_bytes}-byte entries",
                body.len()
            ),
        ));
    }
    let mut contributions = Vec::with_capacity(body.len() / entry_bytes);
    for index in 0..body.len() / entry_bytes {
        let at = index * entry_bytes;
        let section = half(body, at).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "section contribution record is truncated"))?;
        let offset = signed(body, at + 4).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "section contribution record is truncated"))?;
        let size = signed(body, at + 8).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "section contribution record is truncated"))?;
        let module = half(body, at + 16).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "section contribution record is truncated"))?;
        if section == 0 {
            return Err(PdbError::new(PdbErrorKind::OutOfRange, format!("section contribution {index} names section 0, which no image has")));
        }
        if offset < 0 || size < 0 {
            return Err(PdbError::new(
                PdbErrorKind::OutOfRange,
                format!("section contribution {index} places {size} bytes at section {section} offset {offset}"),
            ));
        }
        contributions.push(SectionContribution { module, section, offset: offset as u32, size: size as u32 });
    }
    Ok(contributions)
}

fn parse_section_map(bytes: &[u8]) -> Result<Vec<SectionMapEntry>, PdbError> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if bytes.len() < 4 {
        return Err(PdbError::new(PdbErrorKind::Truncated, format!("section map substream is {} bytes but its header needs 4", bytes.len())));
    }
    let count = usize::from(half(bytes, 0).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "section map substream is truncated"))?);
    let end = 4usize
        .checked_add(count * SECTION_MAP_ENTRY_BYTES)
        .ok_or_else(|| PdbError::new(PdbErrorKind::OutOfRange, format!("section map declares {count} entries")))?;
    if end > bytes.len() {
        return Err(PdbError::new(
            PdbErrorKind::Truncated,
            format!("section map declares {count} entries, which need {end} bytes but the substream holds {}", bytes.len()),
        ));
    }
    let mut entries = Vec::with_capacity(count);
    for index in 0..count {
        let at = 4 + index * SECTION_MAP_ENTRY_BYTES;
        entries.push(SectionMapEntry {
            frame: half(bytes, at + 6).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "section map entry is truncated"))?,
            offset: word(bytes, at + 12).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "section map entry is truncated"))?,
            byte_length: word(bytes, at + 16).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "section map entry is truncated"))?,
        });
    }
    Ok(entries)
}

/// Reads a NUL-terminated module string and advances the cursor past its terminator.
fn take_string<'a>(bytes: &'a [u8], cursor: &mut usize, record_start: usize) -> Result<&'a str, PdbError> {
    let start = *cursor;
    let tail = bytes
        .get(start..)
        .ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, format!("module record at offset {record_start} is truncated")))?;
    let end = tail.iter().position(|byte| *byte == 0).ok_or_else(|| {
        PdbError::new(PdbErrorKind::Truncated, format!("module record at offset {record_start} has a string with no terminator"))
    })?;
    *cursor = start + end + 1;
    std::str::from_utf8(&tail[..end]).map_err(|error| {
        PdbError::new(PdbErrorKind::UnsupportedSymbolFormat, format!("module record at offset {record_start} has a non-UTF-8 string: {error}"))
    })
}

/// Reads a 32-bit field as the signed value the link tools store in it.
fn signed(bytes: &[u8], offset: usize) -> Option<i32> {
    word(bytes, offset).map(|value| value as i32)
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
        assert_eq!(header.module_bytes, 0);
    }

    #[test]
    fn reads_the_module_list_contributions_and_section_map() {
        let modules = [
            fixtures::FixtureModule { name: "ab.obj", object_name: "ab.obj", section: 1, offset: 0x10, size: 0x20 },
            fixtures::FixtureModule { name: "* Linker *", object_name: "", section: NO_SECTION, offset: 0, size: -1 },
        ];
        let contributions = [(0u16, 1u16, 0x10i32, 0x20i32), (1, 1, 0x30, 0x10)];
        let sections = [(1u16, 0u32, 0x100u32), (0, 0, u32::MAX)];
        let bytes = fixtures::dbi_stream_with_debug_info(&modules, SECTION_CONTRIBUTION_V60, &contributions, &sections);
        let info = parse(&bytes).expect("the synthetic DBI stream is valid");

        assert_eq!(info.modules.len(), 2);
        assert_eq!(info.modules[0].name, "ab.obj");
        assert_eq!(info.modules[0].object_name, "ab.obj");
        assert_eq!(info.modules[0].placement, Some(ModulePlacement { section: 1, offset: 0x10, size: 0x20 }));
        assert_eq!(info.modules[1].name, "* Linker *");
        assert_eq!(info.modules[1].object_name, "");
        assert_eq!(info.modules[1].placement, None, "the placeholder section number means no placement");

        assert_eq!(
            info.contributions,
            vec![
                SectionContribution { module: 0, section: 1, offset: 0x10, size: 0x20 },
                SectionContribution { module: 1, section: 1, offset: 0x30, size: 0x10 },
            ]
        );
        assert_eq!(
            info.sections,
            vec![SectionMapEntry { frame: 1, offset: 0, byte_length: 0x100 }, SectionMapEntry { frame: 0, offset: 0, byte_length: u32::MAX },]
        );
    }

    #[test]
    fn reads_the_section_contribution_version_two_layout() {
        let modules = [fixtures::FixtureModule { name: "only.obj", object_name: "only.obj", section: 2, offset: 0x40, size: 0x18 }];
        let contributions = [(0u16, 2u16, 0x40i32, 0x18i32)];
        let sections = [(2u16, 0u32, 0x80u32)];
        let bytes = fixtures::dbi_stream_with_debug_info(&modules, SECTION_CONTRIBUTION_V2, &contributions, &sections);
        let info = parse(&bytes).expect("the version two contribution layout is valid");
        assert_eq!(info.contributions, vec![SectionContribution { module: 0, section: 2, offset: 0x40, size: 0x18 }]);
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

    #[test]
    fn a_substream_size_past_the_stream_is_rejected() {
        let mut bytes = fixtures::dbi_stream(4, 5, 6);
        bytes[MODULE_BYTES_OFFSET..MODULE_BYTES_OFFSET + 4].copy_from_slice(&1024u32.to_le_bytes());
        let error = parse_header(&bytes).expect_err("the header claims a substream that is not there");
        assert_eq!(error.kind(), PdbErrorKind::Truncated);
        assert!(error.detail().contains("1024"), "the message names the declared size: {error}");
    }

    #[test]
    fn module_records_that_do_not_fill_the_substream_are_rejected() {
        let modules = [fixtures::FixtureModule { name: "ab.obj", object_name: "ab.obj", section: 1, offset: 0, size: 4 }];
        let bytes = fixtures::dbi_stream_with_debug_info(&modules, SECTION_CONTRIBUTION_V60, &[], &[]);
        let header = parse_header(&bytes).expect("the header is valid");
        let mut cursor = HEADER_SIZE;
        let modi = take_substream(&bytes, &mut cursor, header.module_bytes, "module").expect("the module substream is present");
        let error = parse_modules(&modi[..modi.len() - 4], 1).expect_err("a short module substream cannot hold its record");
        assert_eq!(error.kind(), PdbErrorKind::Truncated);

        let mut longer = modi.to_vec();
        longer.push(0);
        let error = parse_modules(&longer, 1).expect_err("trailing bytes mean the count and records disagree");
        assert_eq!(error.kind(), PdbErrorKind::UnknownStreamConvention);
    }

    #[test]
    fn a_contribution_that_names_a_missing_module_is_rejected() {
        let modules = [fixtures::FixtureModule { name: "only.obj", object_name: "only.obj", section: 1, offset: 0, size: 4 }];
        let contributions = [(7u16, 1u16, 0i32, 4i32)];
        let bytes = fixtures::dbi_stream_with_debug_info(&modules, SECTION_CONTRIBUTION_V60, &contributions, &[]);
        let error = parse(&bytes).expect_err("a contribution must belong to a listed module");
        assert_eq!(error.kind(), PdbErrorKind::OutOfRange);
        assert!(error.detail().contains('7'), "the message names the module index: {error}");
    }

    #[test]
    fn an_unknown_section_contribution_version_is_rejected() {
        let error = parse_contributions(&[0u8; 4]).expect_err("only the two known markers are parsed");
        assert_eq!(error.kind(), PdbErrorKind::UnknownStreamConvention);

        let mut bytes = vec![
            SECTION_CONTRIBUTION_V60 as u8,
            (SECTION_CONTRIBUTION_V60 >> 8) as u8,
            (SECTION_CONTRIBUTION_V60 >> 16) as u8,
            (SECTION_CONTRIBUTION_V60 >> 24) as u8,
        ];
        bytes.push(0);
        let error = parse_contributions(&bytes).expect_err("a partial entry means the substream does not match its layout");
        assert_eq!(error.kind(), PdbErrorKind::UnknownStreamConvention);
    }

    #[test]
    fn a_section_map_that_declares_more_entries_than_fit_is_rejected() {
        let bytes = [2u8, 0, 2, 0];
        let error = parse_section_map(&bytes).expect_err("two entries need 44 bytes and only 4 are present");
        assert_eq!(error.kind(), PdbErrorKind::Truncated);
    }
}
