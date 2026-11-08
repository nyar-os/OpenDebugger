//! The recorded frame table of one real dump, and the check that keeps the reader on it.
//!
//! A comparison against `dbghelp` can only run while the binding still exists. Before the reader
//! becomes the product path, the answers of that run are recorded here so the switch can be held to
//! evidence instead of to itself: `matches_the_recorded_frames_of_a_real_dump` resolves the same
//! dump again and requires every recorded frame to come back byte for byte.
//!
//! The record carries the dump's file name, byte count, modification time and an FNV-1a checksum,
//! plus each frame's address, module, section offset, name, displacement and whether a procedure
//! record supplied its length. It carries no machine path, user name or store location.

use std::{collections::BTreeMap, fs, io::Read, path::Path};

use serde::{Deserialize, Serialize};

use crate::{minidump::analyze_file, pdb::PdbFile, pe::SectionHeader, triage::KernelModule};

use super::{super::store, ProcedureLengths, locate};

/// Path of the recorded table inside the crate, so a checkout can run the check without arguments.
const FIXTURE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/real-dump-frames.json");

/// Where the recorded dump came from, in words that hold no host-specific detail.
const ACQUISITION: &str = "Kernel bugcheck triage dump collected from a Windows x64 host's minidump \
directory as `110426-11062-01.dmp`, analyzed with the `ntkrnlmp.pdb` published for that build under \
symbol store key `45B0BEEFE03C289F032E4EC96C7871741`";

/// The dump the frames were recorded from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DumpIdentity {
    /// File name only, so the record never carries a directory.
    pub file: String,
    pub bytes: u64,
    /// Modification time of the recorded file, which tells one collection from another.
    pub modified_unix_seconds: u64,
    /// FNV-1a over the whole file, independent of the file system and of the host.
    pub fnv1a64: String,
}

/// One frame as the reader answered it when the table was recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoldenFrame {
    pub address: String,
    pub module: String,
    /// Section of the public symbol that answered this address.
    pub section: u16,
    /// Byte offset of that public symbol inside the section.
    pub offset: u32,
    /// Where the name came from, or `None` when the frame stayed unnamed.
    pub name_source: Option<String>,
    pub function: Option<String>,
    pub displacement: u64,
    /// Length a procedure record supplied, or `None` when none starts at this offset.
    pub procedure_length: Option<u32>,
    pub named: bool,
}

/// The recorded dump identity, how it was collected, and one row per reported frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoldenTable {
    pub dump: DumpIdentity,
    pub acquisition: String,
    pub frames: Vec<GoldenFrame>,
}

/// Resolves one dump and returns the table that would be recorded for it.
fn observed(dump: &Path) -> GoldenTable {
    let report = analyze_file(dump).expect("analyze the recorded dump");
    assert!(report.symbols.engine, "the symbol store must accept the recorded dump: {:?}", report.symbols);
    let frames = report.stack.iter().chain(report.stack_guesses.iter()).collect::<Vec<_>>();
    let modules = module_table(&report);
    let addresses =
        frames.iter().map(|frame| parse_hex(&frame.address).expect("every frame carries a hexadecimal address")).collect::<Vec<_>>();
    let (resolved, diagnostics) = crate::symbols::function_names(&modules, &addresses);
    assert!(diagnostics.missing.is_empty(), "every frame module must resolve, else the table is partial: {:?}", diagnostics.missing);
    let store = store::symbol_store().expect("a symbol store is required to record the table");
    let details = provenance(&store, &modules, &addresses);

    let frames = frames
        .iter()
        .enumerate()
        .map(|(position, frame)| {
            let detail = details.get(position).and_then(|detail| detail.as_ref());
            let symbol = resolved.get(position).and_then(|symbol| symbol.as_ref());
            GoldenFrame {
                address: frame.address.clone(),
                module: frame.module.clone().unwrap_or_default(),
                section: detail.map(|detail| detail.section).unwrap_or(0),
                offset: detail.map(|detail| detail.offset).unwrap_or(0),
                name_source: symbol.map(|_| "public".to_string()),
                function: symbol.map(|symbol| symbol.function.clone()),
                displacement: symbol.map(|symbol| symbol.displacement).unwrap_or(0),
                procedure_length: detail.and_then(|detail| detail.procedure_length),
                named: symbol.is_some(),
            }
        })
        .collect();
    GoldenTable { dump: identity_of(dump), acquisition: ACQUISITION.to_string(), frames }
}

/// Where each frame's public symbol sits, and the length a procedure record added.
struct Detail {
    section: u16,
    offset: u32,
    procedure_length: Option<u32>,
}

/// Reads the public symbol that answers each address, one module at a time.
fn provenance(store: &Path, modules: &[KernelModule], addresses: &[u64]) -> Vec<Option<Detail>> {
    let mut details = std::iter::repeat_with(|| None).take(addresses.len()).collect::<Vec<Option<Detail>>>();
    for module in modules {
        let positions = addresses
            .iter()
            .enumerate()
            .filter_map(|(position, address)| {
                module.contains(*address).and_then(|offset| u32::try_from(offset).ok()).map(|rva| (position, rva))
            })
            .collect::<Vec<_>>();
        if positions.is_empty() {
            continue;
        }
        let mut missing = Vec::new();
        let Some(located) = locate(store, module, &mut missing)
        else {
            continue;
        };
        let Ok(mut file) = PdbFile::open(&located.pdb)
        else {
            continue;
        };
        let Ok(sections) = SectionHeader::read(&located.image)
        else {
            continue;
        };
        let Ok(table) = file.public_symbols()
        else {
            continue;
        };
        let Ok(index) = table.index(&sections)
        else {
            continue;
        };
        let Ok(debug_info) = file.debug_info()
        else {
            continue;
        };
        let mut lengths = ProcedureLengths { file: &mut file, debug_info: &debug_info, loaded: BTreeMap::new(), warned: Vec::new() };
        for (position, rva) in positions {
            let Some(hit) = index.find(rva)
            else {
                continue;
            };
            let procedure_length = lengths.at(hit.entry.section, hit.entry.offset);
            details[position] = Some(Detail { section: hit.entry.section, offset: hit.entry.offset, procedure_length });
        }
    }
    details
}

/// The module table of a report as the symbol reader takes it.
fn module_table(report: &crate::minidump::DumpReport) -> Vec<KernelModule> {
    report
        .modules
        .iter()
        .filter_map(|module| {
            let base = parse_hex(&module.base_address)?;
            Some(KernelModule { name: module.name.clone(), base, size: module.size_bytes, timestamp: module.timestamp })
        })
        .collect()
}

fn parse_hex(text: &str) -> Option<u64> {
    let digits = text.trim_start_matches("0x");
    u64::from_str_radix(digits, 16).ok()
}

/// File name, byte count, modification time and content checksum of the recorded dump.
fn identity_of(dump: &Path) -> DumpIdentity {
    let metadata = fs::metadata(dump).expect("read the recorded dump's metadata");
    let modified_unix_seconds = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default();
    DumpIdentity {
        file: dump.file_name().and_then(|name| name.to_str()).expect("the recorded dump has a file name").to_string(),
        bytes: metadata.len(),
        modified_unix_seconds,
        fnv1a64: fingerprint(dump),
    }
}

/// FNV-1a over the file, so two dumps with the same size still differ in the record.
fn fingerprint(dump: &Path) -> String {
    let mut file = fs::File::open(dump).expect("open the recorded dump");
    let mut hash: u64 = 0xCBF2_9CE4_8422_2325;
    let mut buffer = [0u8; 1 << 16];
    loop {
        let read = file.read(&mut buffer).expect("read the recorded dump");
        if read == 0 {
            break;
        }
        for byte in &buffer[..read] {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
        }
    }
    format!("0x{hash:016X}")
}

fn recorded() -> GoldenTable {
    let text = fs::read_to_string(FIXTURE_PATH).expect("the recorded frame table is part of the repository");
    serde_json::from_str(&text).expect("the recorded frame table parses")
}

/// Records the current answers for one real dump. Run only to create or refresh the table.
#[test]
#[ignore = "regenerates `fixtures/real-dump-frames.json` from `OPEN_DEBUGGER_REAL_DUMP` and a matching symbol store"]
fn records_the_frames_of_a_real_dump() {
    let dump = std::env::var("OPEN_DEBUGGER_REAL_DUMP").expect("set OPEN_DEBUGGER_REAL_DUMP to the dump to record");
    let table = observed(Path::new(&dump));
    let text = serde_json::to_string_pretty(&table).expect("serialize the recorded table");
    fs::write(FIXTURE_PATH, format!("{text}\n")).expect("write the recorded table");
    println!("recorded {} frames in {FIXTURE_PATH}", table.frames.len());
}

/// Requires the reader to answer the recorded dump exactly as the table recorded it.
#[test]
#[ignore = "requires OPEN_DEBUGGER_REAL_DUMP to be the recorded dump and a symbol store holding the matching image and PDB"]
fn matches_the_recorded_frames_of_a_real_dump() {
    let dump = std::env::var("OPEN_DEBUGGER_REAL_DUMP").expect("set OPEN_DEBUGGER_REAL_DUMP to the recorded dump");
    let recorded = recorded();
    let observed = observed(Path::new(&dump));
    assert_eq!(observed.dump.file, recorded.dump.file, "the recorded table belongs to another dump file");
    assert_eq!(
        observed.dump.bytes, recorded.dump.bytes,
        "the recorded table belongs to a dump of another size, record a new table for this dump"
    );
    assert_eq!(
        observed.dump.fnv1a64, recorded.dump.fnv1a64,
        "the dump content differs from the recorded one, record a new table for this dump"
    );
    assert_eq!(observed.frames.len(), recorded.frames.len(), "the reader no longer reports the recorded number of frames");
    for (index, (observed, recorded)) in observed.frames.iter().zip(&recorded.frames).enumerate() {
        assert_eq!(observed, recorded, "frame {index} differs from the recorded table");
    }
    println!("{} frames match the recorded table", observed.frames.len());
}

/// Keeps the recorded table readable without the dump, so a checkout still checks its shape.
#[test]
fn validates_the_recorded_frame_table() {
    let table = recorded();
    assert!(!table.frames.is_empty(), "the recorded table holds at least one frame");
    assert!(!table.acquisition.is_empty(), "the recorded table states how the dump was collected");
    assert!(table.dump.fnv1a64.starts_with("0x"), "the recorded dump carries a checksum");
    assert_eq!(table.dump.file.rsplit('.').next(), Some("dmp"), "the recorded identity is a dump file");
    for frame in &table.frames {
        assert_eq!(frame.named, frame.function.is_some(), "`{}` must agree on whether it is named", frame.address);
        assert_eq!(frame.name_source.as_deref(), frame.named.then_some("public"), "`{}` names its source", frame.address);
        assert!(!frame.address.starts_with("0x0x"), "`{}` is a hexadecimal address", frame.address);
        assert!(frame.named || frame.function.is_none(), "`{}` carries no name it did not record", frame.address);
        for text in [&frame.module, frame.function.as_deref().unwrap_or_default()] {
            assert!(!text.contains(['\\', '/', ':']), "the recorded table carries no paths, found `{text}`");
        }
    }
}
