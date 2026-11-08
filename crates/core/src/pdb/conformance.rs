//! Conformance checks for the PDB reader against real inputs.
//!
//! These checks take files from the environment so they run on a host that holds the corpus:
//! `OPEN_DEBUGGER_REAL_DUMP` (a kernel triage dump), `OPEN_DEBUGGER_REAL_IMAGE` (the matching
//! `ntoskrnl.exe`) and `OPEN_DEBUGGER_REAL_PDB` (the matching PDB).
//!
//! What a real dump answers through the symbol store is recorded once as a table and checked on
//! every replay, so the naming behavior is held to evidence rather than to the reader agreeing with
//! itself.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use crate::{minidump::analyze_file, pdb::PdbFile, pe::SectionHeader};

/// Requires the PDB's module list, contributions and section map to describe the real image.
///
/// The PDB's module list names compiler object files, so it is not comparable one-to-one with the
/// loader's module table. What must agree is the geometry: every object file's contribution lands
/// inside a section the image actually has and inside the byte range the dump records for that
/// module, and the section map covers exactly the image's section numbers.
#[test]
#[ignore = "requires OPEN_DEBUGGER_REAL_DUMP, OPEN_DEBUGGER_REAL_IMAGE and OPEN_DEBUGGER_REAL_PDB"]
fn matches_the_module_and_section_tables_of_a_real_image() {
    let dump = std::env::var("OPEN_DEBUGGER_REAL_DUMP").expect("set OPEN_DEBUGGER_REAL_DUMP to a real dump");
    let image = std::env::var("OPEN_DEBUGGER_REAL_IMAGE").expect("set OPEN_DEBUGGER_REAL_IMAGE to the matching image");
    let pdb = std::env::var("OPEN_DEBUGGER_REAL_PDB").expect("set OPEN_DEBUGGER_REAL_PDB to the matching PDB");

    let report = analyze_file(Path::new(&dump)).expect("analyze the real dump");
    let image_name = Path::new(&image).file_name().and_then(|name| name.to_str()).expect("the image path has a file name");
    let module = report
        .modules
        .iter()
        .find(|module| module.name.rsplit(['\\', '/']).next().is_some_and(|file| file.eq_ignore_ascii_case(image_name)))
        .unwrap_or_else(|| panic!("the dump's module table names no `{image_name}`"));
    let sections = SectionHeader::read(Path::new(&image)).expect("read the image sections");
    let mut pdb_file = PdbFile::open(Path::new(&pdb)).expect("open the real PDB");
    let debug_info = pdb_file.debug_info().expect("read the DBI module list, contributions and section map");

    let placed = debug_info.modules.iter().filter(|module| module.placement.is_some()).count();
    println!("image {image_name}: dump module base {}, size 0x{:X}, {} sections", module.base_address, module.size_bytes, sections.len());
    println!(
        "pdb: {} modules ({placed} placed), {} contributions, {} section map entries",
        debug_info.modules.len(),
        debug_info.contributions.len(),
        debug_info.sections.len()
    );
    for module in debug_info.modules.iter().take(4) {
        println!("  module {:?} object {:?} placement {:?}", module.name, module.object_name, module.placement);
    }

    assert!(!debug_info.modules.is_empty(), "a PDB for a linked image lists the object files that built it");
    assert!(debug_info.modules.iter().all(|module| !module.name.is_empty()), "every module record carries a name");
    assert!(placed > 0, "at least one module must have been placed in the image");
    assert!(!debug_info.contributions.is_empty(), "the link step records where each object file's bytes landed");

    let frames = debug_info.sections.iter().filter(|entry| entry.frame != 0).map(|entry| entry.frame).collect::<BTreeSet<_>>();
    let expected = (1..=u16::try_from(sections.len()).expect("an image has fewer than 65536 sections")).collect::<BTreeSet<_>>();
    assert_eq!(frames, expected, "the section map must cover every image section number");

    for entry in &debug_info.sections {
        if entry.frame == 0 {
            continue;
        }
        let section = &sections[usize::from(entry.frame) - 1];
        assert!(
            entry.offset <= section.virtual_size,
            "section {} maps to byte {} of a 0x{:X}-byte section",
            entry.frame,
            entry.offset,
            section.virtual_size
        );
        assert!(
            entry.byte_length <= section.virtual_size,
            "section {} records 0x{:X} bytes but the image section holds 0x{:X}",
            entry.frame,
            entry.byte_length,
            section.virtual_size
        );
    }

    let mut covered = BTreeMap::<u16, u32>::new();
    for (index, contribution) in debug_info.contributions.iter().enumerate() {
        assert!(
            usize::from(contribution.module) < debug_info.modules.len(),
            "contribution {index} names module {} but the module list holds {}",
            contribution.module,
            debug_info.modules.len()
        );
        let section = &sections[usize::from(contribution.section) - 1];
        let end = contribution
            .offset
            .checked_add(contribution.size)
            .unwrap_or_else(|| panic!("contribution {index} overflows: offset 0x{:X} size 0x{:X}", contribution.offset, contribution.size));
        assert!(
            end <= section.virtual_size,
            "contribution {index} ends at 0x{end:X} inside section {} whose image size is 0x{:X}",
            contribution.section,
            section.virtual_size
        );
        let rva_end = section.virtual_address.checked_add(end).unwrap_or_else(|| {
            panic!("contribution {index} leaves the 32-bit RVA space: address 0x{:X} end 0x{end:X}", section.virtual_address)
        });
        assert!(
            u64::from(rva_end) <= u64::from(module.size_bytes),
            "contribution {index} ends at RVA 0x{rva_end:X} but the dump records {} bytes for {image_name}",
            module.size_bytes
        );
        covered.entry(contribution.section).and_modify(|value| *value = (*value).max(end)).or_insert(end);
    }

    for (section, end) in &covered {
        let recorded = debug_info.sections.iter().find(|entry| entry.frame == *section).expect("every contributed section is mapped");
        assert!(
            *end <= recorded.byte_length,
            "section {section} contributions end at 0x{end:X} but the section map records 0x{:X}",
            recorded.byte_length
        );
    }
    println!("contributions cover {} of {} image sections", covered.len(), sections.len());
}
