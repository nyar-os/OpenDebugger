//! PDB reading without `dbghelp`.
//!
//! A kernel PDB is an MSF container of numbered streams. Function names come from the public
//! symbol records, which carry a section number and an offset inside that section. This module
//! reads the container, the PDB info stream, the DBI header fields that name the public symbol and
//! symbol record streams, the DBI module list, section contributions and section map, and the
//! per-module symbol streams that record each procedure's byte length. Type information, variables
//! and source lines are not read.
//!
//! Every unrecognized container shape, PDB version or stream convention is a structured error
//! carrying a stable code. No path returns an empty result to stand in for a format this code
//! does not understand.

use std::{fmt, path::Path};

use serde::Serialize;

mod dbi;
mod info;
mod lookup;
mod module;
mod msf;
mod publics;

#[cfg(test)]
mod conformance;
#[cfg(test)]
mod fixtures;

pub use dbi::{DbiHeader, DebugInfo, ModuleInfo, ModulePlacement, SectionContribution, SectionMapEntry};
pub use info::PdbInfo;
pub use lookup::{FunctionEntry, FunctionHit, FunctionIndex};
pub use module::{ModuleFunction, ModuleSymbols, S_GPROC32, S_GPROC32_ID, S_LPROC32, S_LPROC32_ID};
pub use msf::Msf;
pub use publics::{PublicSymbol, PublicSymbolTable, PublicsHeader};

/// Stream numbers fixed by the MSF 7.00 layout.
const OLD_DIRECTORY_STREAM: u32 = 0;
const INFO_STREAM: u32 = 1;
const TYPE_INFO_STREAM: u32 = 2;
const DBI_STREAM: u32 = 3;
const ID_INFO_STREAM: u32 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PdbErrorKind {
    /// The file is not an MSF container this reader understands.
    UnsupportedContainer,
    /// The PDB info stream declares a version this reader does not parse.
    UnsupportedPdbVersion,
    /// A stream numbering or header convention this reader does not recognize.
    UnknownStreamConvention,
    /// A symbol record shape or encoding this reader does not recognize.
    UnsupportedSymbolFormat,
    /// The file ends before a declared structure.
    Truncated,
    /// A block, stream or byte range lies outside its container.
    OutOfRange,
    /// The file could not be opened or read.
    Io,
}

impl PdbErrorKind {
    pub fn code(self) -> &'static str {
        match self {
            Self::UnsupportedContainer => "unsupported_container",
            Self::UnsupportedPdbVersion => "unsupported_pdb_version",
            Self::UnknownStreamConvention => "unknown_stream_convention",
            Self::UnsupportedSymbolFormat => "unsupported_symbol_format",
            Self::Truncated => "truncated",
            Self::OutOfRange => "out_of_range",
            Self::Io => "io",
        }
    }
}

#[derive(Debug)]
pub struct PdbError {
    kind: PdbErrorKind,
    detail: String,
}

impl PdbError {
    pub(crate) fn new(kind: PdbErrorKind, detail: impl fmt::Display) -> Self {
        Self { kind, detail: detail.to_string() }
    }

    pub(crate) fn io(path: &Path, source: std::io::Error) -> Self {
        Self::new(PdbErrorKind::Io, format!("{}: {source}", path.display()))
    }

    pub fn kind(&self) -> PdbErrorKind {
        self.kind
    }

    /// Stable machine-readable code, unchanged by message wording.
    pub fn code(&self) -> &'static str {
        self.kind.code()
    }

    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for PdbError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code(), self.detail)
    }
}

impl std::error::Error for PdbError {}

/// What a stream holds, as far as the container, info stream and DBI header can tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StreamRole {
    OldDirectory,
    PdbInfo,
    TypeInfo,
    DebugInfo,
    IdInfo,
    /// Global symbol hash table the DBI header points at.
    GlobalSymbols,
    PublicSymbols,
    SymbolRecords,
    Named,
    /// A directory slot that carries no stream.
    Nil,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamEntry {
    pub index: u32,
    /// Declared size, absent for a nil slot.
    pub size_bytes: Option<u32>,
    pub role: StreamRole,
    /// Name from the info stream map, present for named streams.
    pub name: Option<String>,
}

/// A PDB opened far enough to reach the public symbol records.
#[derive(Debug)]
pub struct PdbFile {
    msf: Msf,
    info: PdbInfo,
    dbi: DbiHeader,
}

impl PdbFile {
    pub fn open(path: &Path) -> Result<Self, PdbError> {
        let mut msf = Msf::open(path)?;
        let info_stream = msf.read_stream(INFO_STREAM).map_err(|error| match error.kind() {
            PdbErrorKind::OutOfRange => {
                PdbError::new(PdbErrorKind::UnsupportedContainer, format!("stream 1 must hold the PDB info stream but {error}"))
            }
            other => PdbError::new(other, error.detail()),
        })?;
        let info = info::parse(&info_stream)?;
        let dbi_stream = msf.read_stream(DBI_STREAM).map_err(|error| match error.kind() {
            PdbErrorKind::OutOfRange => {
                PdbError::new(PdbErrorKind::UnsupportedContainer, format!("stream 3 must hold the DBI stream but {error}"))
            }
            other => PdbError::new(other, error.detail()),
        })?;
        let dbi = dbi::parse_header(&dbi_stream)?;
        for (label, index) in [("public symbol", dbi.public_stream), ("symbol record", dbi.symbol_record_stream)] {
            if usize::from(index) >= msf.stream_count() {
                return Err(PdbError::new(
                    PdbErrorKind::OutOfRange,
                    format!("the DBI header points the {label} stream at {index} but the container holds {} streams", msf.stream_count()),
                ));
            }
        }
        for (name, index) in info.named_streams() {
            if usize::try_from(*index).map(|index| index >= msf.stream_count()).unwrap_or(true) {
                return Err(PdbError::new(
                    PdbErrorKind::OutOfRange,
                    format!("named stream `{name}` points at {index} but the container holds {} streams", msf.stream_count()),
                ));
            }
        }
        Ok(Self { msf, info, dbi })
    }

    pub fn info(&self) -> &PdbInfo {
        &self.info
    }

    pub fn dbi(&self) -> &DbiHeader {
        &self.dbi
    }

    pub fn block_size(&self) -> u32 {
        self.msf.block_size()
    }

    pub fn block_count(&self) -> u32 {
        self.msf.block_count()
    }

    pub fn directory_bytes(&self) -> u32 {
        self.msf.directory_bytes()
    }

    pub fn stream_count(&self) -> usize {
        self.msf.stream_count()
    }

    /// Reads a whole stream by its number, for callers that inspect a stream's own header.
    pub fn read_stream(&mut self, index: u32) -> Result<Vec<u8>, PdbError> {
        self.msf.read_stream(index)
    }

    /// Every directory slot with its size and the role this reader can assign to it.
    pub fn streams(&self) -> Vec<StreamEntry> {
        let named = self.info.named_streams();
        (0..self.msf.stream_count() as u32)
            .map(|index| {
                let size_bytes = self.msf.stream_size(index);
                let name = named.iter().find(|(_, stream)| *stream == index).map(|(name, _)| name.clone());
                let role = self.role(index, size_bytes.is_some(), name.as_deref());
                StreamEntry { index, size_bytes, role, name }
            })
            .collect()
    }

    /// Validates the public symbol stream and collects every `S_PUB32` record it indexes.
    pub fn public_symbols(&mut self) -> Result<PublicSymbolTable, PdbError> {
        let public_stream = self.read_stream(u32::from(self.dbi.public_stream))?;
        let records = self.read_stream(u32::from(self.dbi.symbol_record_stream))?;
        publics::load(&public_stream, &records)
    }

    /// Reads the module list, section contributions and section map the DBI stream declares.
    ///
    /// The module list is the link-time list of compiler object files, not the loader's module
    /// table. Each contribution places one object file's byte range in one image section.
    pub fn debug_info(&mut self) -> Result<DebugInfo, PdbError> {
        let stream = self.read_stream(DBI_STREAM)?;
        dbi::parse(&stream)
    }

    /// Reads the symbol records of one module and collects its procedure records.
    ///
    /// Only the byte size the module record declares is read, so a module that recorded no
    /// symbols costs nothing. A declared size that does not fit the stream, or a stream number
    /// the container does not hold, is a structured failure: the PDB and its own module list
    /// would then disagree.
    pub fn module_symbols(&mut self, module: &ModuleInfo) -> Result<ModuleSymbols, PdbError> {
        if module.symbol_bytes == 0 {
            return Ok(ModuleSymbols::default());
        }
        if module.symbol_stream == 0 {
            return Err(PdbError::new(
                PdbErrorKind::UnknownStreamConvention,
                format!(
                    "module `{}` declares {} symbol bytes but points at stream 0, which holds no symbols",
                    module.name, module.symbol_bytes
                ),
            ));
        }
        let stream = self.read_stream(u32::from(module.symbol_stream)).map_err(|error| match error.kind() {
            PdbErrorKind::OutOfRange => PdbError::new(
                PdbErrorKind::OutOfRange,
                format!("module `{}` points its symbols at stream {} but {error}", module.name, module.symbol_stream),
            ),
            other => PdbError::new(other, error.detail()),
        })?;
        let bytes = stream.get(..module.symbol_bytes as usize).ok_or_else(|| {
            PdbError::new(
                PdbErrorKind::Truncated,
                format!(
                    "module `{}` declares {} symbol bytes but stream {} holds {}",
                    module.name,
                    module.symbol_bytes,
                    module.symbol_stream,
                    stream.len()
                ),
            )
        })?;
        module::parse(bytes)
    }

    fn role(&self, index: u32, has_stream: bool, name: Option<&str>) -> StreamRole {
        if !has_stream {
            return StreamRole::Nil;
        }
        match index {
            OLD_DIRECTORY_STREAM => StreamRole::OldDirectory,
            INFO_STREAM => StreamRole::PdbInfo,
            TYPE_INFO_STREAM => StreamRole::TypeInfo,
            DBI_STREAM => StreamRole::DebugInfo,
            ID_INFO_STREAM => StreamRole::IdInfo,
            _ if index == u32::from(self.dbi.global_stream) => StreamRole::GlobalSymbols,
            _ if index == u32::from(self.dbi.public_stream) => StreamRole::PublicSymbols,
            _ if index == u32::from(self.dbi.symbol_record_stream) => StreamRole::SymbolRecords,
            _ if name.is_some() => StreamRole::Named,
            _ => StreamRole::Unknown,
        }
    }
}

pub(crate) fn word(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    bytes.get(offset..end).and_then(|slice| slice.try_into().ok()).map(u32::from_le_bytes)
}

pub(crate) fn half(bytes: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    bytes.get(offset..end).and_then(|slice| slice.try_into().ok()).map(u16::from_le_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_stream_roles_from_the_container_and_headers() {
        let named_index = 8;
        let info = fixtures::info_stream(20_000_404, &[("/names", named_index)]);
        let dbi = fixtures::dbi_stream(4, 5, 6);
        let bytes =
            fixtures::container(&[None, Some(info), None, Some(dbi), None, Some(vec![0; 32]), Some(vec![0; 64]), None, Some(vec![0; 16])]);
        let path = fixtures::write(&bytes, "stream-roles");
        let pdb = PdbFile::open(&path).expect("the synthetic container carries an info stream and a DBI header");
        std::fs::remove_file(&path).ok();

        let entries = pdb.streams();
        assert_eq!(entries.len(), 9);
        assert_eq!(entries[0].role, StreamRole::Nil);
        assert_eq!(entries[1].role, StreamRole::PdbInfo);
        assert_eq!(entries[3].role, StreamRole::DebugInfo);
        assert_eq!(entries[5].role, StreamRole::PublicSymbols);
        assert_eq!(entries[6].role, StreamRole::SymbolRecords);
        assert_eq!(entries[8].role, StreamRole::Named);
        assert_eq!(entries[8].name.as_deref(), Some("/names"));
        assert_eq!(entries[5].size_bytes, Some(32));
        assert_eq!(entries[0].size_bytes, None);
    }

    #[test]
    fn reads_the_debug_info_of_a_synthetic_container() {
        let info = fixtures::info_stream(20_000_404, &[]);
        let modules = [fixtures::FixtureModule {
            name: "unit.obj",
            object_name: "unit.obj",
            section: 1,
            offset: 0x20,
            size: 0x40,
            symbol_stream: 7,
            symbol_bytes: 0,
        }];
        let contributions = [(0u16, 1u16, 0x20i32, 0x40i32)];
        let sections = [(1u16, 0u32, 0x200u32)];
        let dbi = fixtures::dbi_stream_with_debug_info(&modules, 0xF12E_BA2D, &contributions, &sections);
        let bytes = fixtures::container(&[None, Some(info), None, Some(dbi), None, Some(vec![0; 32]), Some(vec![0; 64])]);
        let path = fixtures::write(&bytes, "debug-info");
        let mut pdb = PdbFile::open(&path).expect("the synthetic container carries a DBI stream with debug information");
        std::fs::remove_file(&path).ok();

        let debug_info = pdb.debug_info().expect("the DBI stream declares a parsable module list");
        assert_eq!(debug_info.modules.len(), 1);
        assert_eq!(debug_info.modules[0].name, "unit.obj");
        assert_eq!(debug_info.contributions, vec![SectionContribution { module: 0, section: 1, offset: 0x20, size: 0x40 }]);
        assert_eq!(debug_info.sections, vec![SectionMapEntry { frame: 1, offset: 0, byte_length: 0x200 }]);
    }

    #[test]
    fn an_unknown_pdb_version_is_a_structured_failure() {
        let info = fixtures::info_stream(20_140_508, &[]);
        let dbi = fixtures::dbi_stream(4, 3, 4);
        let bytes = fixtures::container(&[None, Some(info), None, Some(dbi), None]);
        let path = fixtures::write(&bytes, "unknown-version");
        let error = PdbFile::open(&path).expect_err("an unrecognized version must not produce a report");
        std::fs::remove_file(&path).ok();
        assert_eq!(error.kind(), PdbErrorKind::UnsupportedPdbVersion);
        assert_eq!(error.code(), "unsupported_pdb_version");
        assert!(error.to_string().contains("20140508"), "the message names the observed version: {error}");
    }

    #[test]
    fn a_dbi_stream_number_past_the_container_is_rejected() {
        let info = fixtures::info_stream(20_000_404, &[]);
        let dbi = fixtures::dbi_stream(4, 99, 4);
        let bytes = fixtures::container(&[None, Some(info), None, Some(dbi), None]);
        let path = fixtures::write(&bytes, "public-stream-past-container");
        let error = PdbFile::open(&path).expect_err("a stream number outside the container must fail");
        std::fs::remove_file(&path).ok();
        assert_eq!(error.kind(), PdbErrorKind::OutOfRange);
        assert_eq!(error.code(), "out_of_range");
    }

    #[test]
    fn guid_text_reorders_the_codeview_groups() {
        let mut guid = [0u8; 16];
        for (index, byte) in guid.iter_mut().enumerate() {
            *byte = 0xA0 + index as u8;
        }
        assert_eq!(info::guid_text(&guid), "A3A2A1A0A5A4A7A6A8A9AAABACADAEAF");
    }

    /// Lists the directory of a real PDB so the container and stream roles can be checked against
    /// real data rather than only against synthetic fixtures.
    #[test]
    #[ignore = "requires OPEN_DEBUGGER_REAL_PDB to point at a real Windows PDB"]
    fn lists_every_stream_of_a_real_kernel_pdb() {
        let path = std::env::var_os("OPEN_DEBUGGER_REAL_PDB").expect("set OPEN_DEBUGGER_REAL_PDB to a real PDB");
        let pdb = PdbFile::open(Path::new(&path)).expect("open the real PDB");
        println!(
            "container: {} blocks of {} bytes, {}-byte directory, {} streams",
            pdb.block_count(),
            pdb.block_size(),
            pdb.directory_bytes(),
            pdb.stream_count()
        );
        let info = pdb.info();
        println!(
            "info: version {}, signature 0x{:08X}, age {}, guid {}, {} named streams",
            info.version(),
            info.signature(),
            info.age(),
            info.guid_text(),
            info.named_streams().len()
        );
        let dbi = *pdb.dbi();
        println!(
            "dbi: age {}, global stream {}, public stream {}, symbol record stream {}",
            dbi.age, dbi.global_stream, dbi.public_stream, dbi.symbol_record_stream
        );

        let streams = pdb.streams();
        for entry in &streams {
            println!(
                "stream {:>4} {:>8} {:?} {}",
                entry.index,
                entry.size_bytes.map_or("nil".to_string(), |size| size.to_string()),
                entry.role,
                entry.name.as_deref().unwrap_or("")
            );
        }

        assert_eq!(streams.len(), pdb.stream_count());
        assert_eq!(streams.iter().filter(|entry| entry.role == StreamRole::GlobalSymbols).count(), 1);
        assert_eq!(streams.iter().filter(|entry| entry.role == StreamRole::PublicSymbols).count(), 1);
        assert_eq!(streams.iter().filter(|entry| entry.role == StreamRole::SymbolRecords).count(), 1);
        let public = streams.iter().find(|entry| entry.role == StreamRole::PublicSymbols).expect("public symbol stream");
        let records = streams.iter().find(|entry| entry.role == StreamRole::SymbolRecords).expect("symbol record stream");
        assert!(public.size_bytes.unwrap_or(0) > 0, "the public symbol stream carries the hash table");
        assert!(records.size_bytes.unwrap_or(0) > public.size_bytes.unwrap_or(0), "symbol records outgrow the index");
    }

    /// Reports the public symbol table a real PDB yields, so the record walk can be checked against
    /// real data.
    #[test]
    #[ignore = "requires OPEN_DEBUGGER_REAL_PDB to point at a real Windows PDB"]
    fn walks_public_symbols_of_a_real_kernel_pdb() {
        let path = std::env::var_os("OPEN_DEBUGGER_REAL_PDB").expect("set OPEN_DEBUGGER_REAL_PDB to a real PDB");
        let mut pdb = PdbFile::open(Path::new(&path)).expect("open the real PDB");
        let table = pdb.public_symbols().expect("the DBI header names a parsable public symbol stream");
        println!("publics header: {:?}", table.header);
        println!("{} public symbols", table.symbols.len());
        for symbol in table.symbols.iter().take(8) {
            println!("  section {:>3} offset 0x{:08X} flags 0x{:08X} {}", symbol.section, symbol.offset, symbol.flags, symbol.name);
        }

        assert!(table.symbols.len() > 40_000, "a kernel PDB carries tens of thousands of publics, got {}", table.symbols.len());
        assert!(
            table.symbols.iter().all(|symbol| symbol.section != 0 && !symbol.name.is_empty()),
            "every public record names a section and a symbol"
        );
    }

    /// Reads every module symbol stream of a real PDB, so the module record's stream number and
    /// declared byte size are checked against the container rather than against a fixture.
    #[test]
    #[ignore = "requires OPEN_DEBUGGER_REAL_PDB to point at a real Windows PDB"]
    fn reads_the_module_symbol_streams_of_a_real_kernel_pdb() {
        let path = std::env::var_os("OPEN_DEBUGGER_REAL_PDB").expect("set OPEN_DEBUGGER_REAL_PDB to a real PDB");
        let mut pdb = PdbFile::open(Path::new(&path)).expect("open the real PDB");
        let debug_info = pdb.debug_info().expect("read the DBI module list");
        let mut with_symbols = 0usize;
        let mut functions = 0usize;
        let mut other_records = 0usize;
        for module in &debug_info.modules {
            if module.symbol_bytes == 0 {
                continue;
            }
            with_symbols += 1;
            let symbols = pdb.module_symbols(module).unwrap_or_else(|error| {
                panic!("module `{}` stream {} declares {} bytes: {error}", module.name, module.symbol_stream, module.symbol_bytes)
            });
            functions += symbols.functions.len();
            other_records += symbols.other_records;
        }
        println!("{} modules, {with_symbols} with symbols, {functions} procedures, {other_records} other records", debug_info.modules.len());

        let first = debug_info.modules.iter().find(|module| module.symbol_bytes > 0).expect("some module records symbols");
        let sample = pdb.module_symbols(first).expect("the first module with symbols parses");
        for function in sample.functions.iter().take(4) {
            println!(
                "  {} section {} offset 0x{:X} length 0x{:X} kind 0x{:04X}",
                first.name, function.section, function.offset, function.length, function.kind
            );
        }

        assert!(with_symbols > 1, "a kernel PDB records symbols for many object files, got {with_symbols}");
        assert!(functions > with_symbols, "every object file with symbols carries at least one procedure, got {functions}");
        assert!(
            sample.functions.iter().any(|function| function.length > 0),
            "procedure records carry byte lengths, so at least one must be non-zero"
        );
    }
}
