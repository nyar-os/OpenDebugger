//! Conformance check for the public symbol reader against `dbghelp` on real inputs.
//!
//! This module exists only for tests. The product path in `pdb` never calls `dbghelp`: this check
//! runs both readers over the same addresses and reports where they agree, so the pure reader can
//! be trusted before it replaces the bound one. The two readers stay in separate code paths:
//! `symbols` binds `dbghelp` and this file only compares its answers with the PDB index.
//!
//! Inputs come from the environment so the check runs against files on the host:
//! `OPEN_DEBUGGER_REAL_DUMP` (a kernel triage dump), `OPEN_DEBUGGER_REAL_IMAGE` (the matching
//! `ntoskrnl.exe`) and `OPEN_DEBUGGER_REAL_PDB` (the matching PDB). The symbol store stays the one
//! `dbghelp` already uses, read from `OPEN_DEBUGGER_SYMBOL_STORE` or the Windows Kits directory.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::Instant,
};

use crate::{minidump::analyze_file, pdb::PdbFile, pe::SectionHeader, symbols};

/// Number of RVAs sampled from the PDB on top of every stack frame address.
const SAMPLE_COUNT: usize = 2000;
/// Rows of the per-address table printed before the rest is only counted.
const MAX_ROWS: usize = 40;

/// How the two readers disagree for one address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Verdict {
    /// Same symbol and same displacement.
    Match,
    /// Same symbol but a different displacement.
    Displacement,
    /// Different symbol names at the same address.
    Name,
    /// Only the PDB reader found a symbol.
    OnlyPdb,
    /// Only `dbghelp` found a symbol.
    OnlyDbghelp,
    /// Neither reader found a symbol.
    Neither,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Resolution {
    name: String,
    displacement: u32,
}

fn verdict(dbghelp: &Option<Resolution>, pdb: &Option<Resolution>) -> Verdict {
    match (dbghelp, pdb) {
        (Some(left), Some(right)) if left.name == right.name && left.displacement == right.displacement => Verdict::Match,
        (Some(left), Some(right)) if left.name == right.name => Verdict::Displacement,
        (Some(_), Some(_)) => Verdict::Name,
        (None, Some(_)) => Verdict::OnlyPdb,
        (Some(_), None) => Verdict::OnlyDbghelp,
        (None, None) => Verdict::Neither,
    }
}

/// One address where the two readers disagree.
struct Mismatch {
    address: u64,
    rva: u32,
    dbghelp: Option<Resolution>,
    pdb: Option<Resolution>,
    verdict: Verdict,
    /// Public symbols that share the entry RVA, which is how many aliases the arrow chooses from.
    aliases: usize,
}

fn parse_hex(text: &str) -> Option<u64> {
    let digits = text.trim_start_matches("0x");
    u64::from_str_radix(digits, 16).ok()
}

/// Deterministic sampler: the check must be repeatable, so it cannot depend on a random seed
/// outside the test.
struct Sampler(u32);

impl Sampler {
    fn next(&mut self) -> u32 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 17;
        self.0 ^= self.0 << 5;
        self.0
    }
}

#[test]
#[ignore = "requires OPEN_DEBUGGER_REAL_DUMP, OPEN_DEBUGGER_REAL_IMAGE and OPEN_DEBUGGER_REAL_PDB"]
fn compares_public_symbols_with_dbghelp_on_a_real_dump() {
    let dump = std::env::var("OPEN_DEBUGGER_REAL_DUMP").expect("set OPEN_DEBUGGER_REAL_DUMP to a real dump");
    let image = std::env::var("OPEN_DEBUGGER_REAL_IMAGE").expect("set OPEN_DEBUGGER_REAL_IMAGE to the matching image");
    let pdb = std::env::var("OPEN_DEBUGGER_REAL_PDB").expect("set OPEN_DEBUGGER_REAL_PDB to the matching PDB");

    let report = analyze_file(Path::new(&dump)).expect("analyze the real dump");
    assert!(report.symbols.engine, "`dbghelp` must be bound for a comparison, diagnostics: {:?}", report.symbols);

    // The PDB belongs to one module; use the module most stack frames land in.
    let mut counts = BTreeMap::new();
    for frame in report.stack.iter().chain(report.stack_guesses.iter()) {
        if let Some(name) = &frame.module {
            *counts.entry(name.clone()).or_insert(0usize) += 1;
        }
    }
    let (module_name, _) = counts.into_iter().max_by_key(|(_, count)| *count).expect("the stack names at least one module");
    let module = report.modules.iter().find(|module| module.name == module_name).expect("the module table carries the stack module");
    let module_base = parse_hex(&module.base_address).expect("the module base is hexadecimal");
    println!("module {module_name} base 0x{module_base:X} size 0x{:X}", module.size_bytes);

    // The clock starts before opening the file, so the total covers container, streams, records,
    // the index and every lookup: what a caller replaces with one `dbghelp` session.
    let started = Instant::now();
    let mut pdb_file = PdbFile::open(Path::new(&pdb)).expect("open the real PDB");
    let table = pdb_file.public_symbols().expect("read the public symbols");
    let sections = SectionHeader::read(Path::new(&image)).expect("read the image sections");
    let index = table.index(&sections).expect("resolve the public symbols to RVAs");
    let ours_elapsed = started.elapsed();
    println!(
        "publics header {:?}, image sections {}, {} public symbols, {} addressable, {} outside the image",
        table.header,
        sections.len(),
        table.symbols.len(),
        index.len(),
        index.unmapped()
    );

    // Every alias group, so a disagreement can show how many names the address had.
    let mut aliases = BTreeMap::new();
    for position in 0..index.len() {
        let rva = index.symbol_rva(position).expect("every position is inside the index");
        *aliases.entry(rva).or_insert(0usize) += 1;
    }

    // One address per known frame plus a deterministic sample spread over the whole symbol list.
    let mut addresses = Vec::new();
    for frame in report.stack.iter().chain(report.stack_guesses.iter()) {
        if frame.module.as_deref() != Some(module_name.as_str()) {
            continue;
        }
        let Some(offset) = frame.offset_in_module.as_deref().and_then(parse_hex)
        else {
            continue;
        };
        addresses.push((module_base + offset, u32::try_from(offset).expect("a kernel module is smaller than 4 GiB")));
    }
    let mut sampler = Sampler(0x1234_5678);
    for _ in 0..SAMPLE_COUNT {
        let pick = sampler.next() as usize % index.len();
        let symbol_rva = index.symbol_rva(pick).expect("the picked symbol is inside the index");
        let displacement = sampler.next() % 64;
        addresses.push((module_base + u64::from(symbol_rva + displacement), symbol_rva + displacement));
    }
    let frame_count = addresses.len() - SAMPLE_COUNT;

    let absolute = addresses.iter().map(|(address, _)| *address).collect::<Vec<_>>();
    let module_entry =
        || crate::triage::KernelModule { name: module.name.clone(), base: module_base, size: module.size_bytes, timestamp: module.timestamp };

    let raw_started = Instant::now();
    let dbghelp_raw = symbols::function_names_raw(&[module_entry()], &absolute).0;
    let raw_elapsed = raw_started.elapsed();
    let normalized_started = Instant::now();
    let dbghelp_normalized = symbols::function_names(&[module_entry()], &absolute).0;
    let normalized_elapsed = normalized_started.elapsed();

    let ours = addresses
        .iter()
        .map(|(_, rva)| index.find(*rva).map(|hit| Resolution { name: hit.entry.name.clone(), displacement: hit.displacement }))
        .collect::<Vec<_>>();

    let (raw_totals, raw_mismatches) =
        report_comparison("source spelling (primary gate)", &resolve(dbghelp_raw), &ours, &addresses, frame_count, &aliases);
    let (normalized_totals, _) =
        report_comparison("undecorated (product path)", &resolve(dbghelp_normalized), &ours, &addresses, frame_count, &aliases);
    print_mismatches(&raw_mismatches, &raw_totals);

    println!(
        "\npdb reader: {ours_elapsed:?} for {} symbols and {} addresses, dbghelp source spelling: {raw_elapsed:?}, dbghelp undecorated: {normalized_elapsed:?}",
        table.symbols.len(),
        addresses.len()
    );
    let compared = addresses.len() - raw_totals.get(&Verdict::Neither).copied().unwrap_or(0);
    let matched = raw_totals.get(&Verdict::Match).copied().unwrap_or(0);
    let rate = if compared == 0 { 0.0 } else { matched as f64 / compared as f64 };
    println!("source-spelling consistency: {matched}/{compared} = {:.4}%", rate * 100.0);
    let normalized_compared = addresses.len() - normalized_totals.get(&Verdict::Neither).copied().unwrap_or(0);
    let normalized_matched = normalized_totals.get(&Verdict::Match).copied().unwrap_or(0);
    println!(
        "undecorated consistency: {normalized_matched}/{normalized_compared} = {:.4}% (informational, undecoration is out of S1 scope)",
        100.0 * normalized_matched as f64 / normalized_compared.max(1) as f64
    );

    assert!(rate >= 0.99, "source-spelling consistency {:.4}% is below the 99% gate, verdicts: {:?}", rate * 100.0, raw_totals);
}

fn resolve(symbols: Vec<Option<symbols::ResolvedSymbol>>) -> Vec<Option<Resolution>> {
    symbols
        .into_iter()
        .map(|resolved| {
            resolved.map(|symbol| Resolution { name: symbol.function, displacement: u32::try_from(symbol.displacement).unwrap_or(u32::MAX) })
        })
        .collect()
}

fn report_comparison(
    label: &str,
    dbghelp: &[Option<Resolution>],
    ours: &[Option<Resolution>],
    addresses: &[(u64, u32)],
    frame_count: usize,
    aliases: &BTreeMap<u32, usize>,
) -> (BTreeMap<Verdict, usize>, Vec<Mismatch>) {
    let mut totals = BTreeMap::new();
    let mut mismatches = Vec::new();
    for ((address, rva), (left, right)) in addresses.iter().zip(dbghelp.iter().zip(ours.iter())) {
        let verdict = verdict(left, right);
        *totals.entry(verdict).or_insert(0usize) += 1;
        if verdict == Verdict::Match || verdict == Verdict::Neither {
            continue;
        }
        let entry_rva = right.as_ref().map_or(*rva, |resolution| rva.saturating_sub(resolution.displacement));
        let aliases = aliases.get(&entry_rva).copied().unwrap_or(0);
        mismatches.push(Mismatch { address: *address, rva: *rva, dbghelp: left.clone(), pdb: right.clone(), verdict, aliases });
    }
    println!("\n{label}: {frame_count} frame addresses, then {SAMPLE_COUNT} sampled RVAs");
    (totals, mismatches)
}

/// Prints the per-address disagreement table and the category counts.
///
/// The categories are what a percentage hides: a wrong displacement, a different alias at the same
/// address, and coverage on either side are separate defects with separate fixes.
fn print_mismatches(mismatches: &[Mismatch], totals: &BTreeMap<Verdict, usize>) {
    println!("\n{:<18} {:<10} {:<40} {:<40} {:<10} {:>7}", "address", "rva", "dbghelp", "pdb", "verdict", "aliases");
    for mismatch in mismatches.iter().take(MAX_ROWS) {
        let left =
            mismatch.dbghelp.as_ref().map_or("-".to_string(), |resolution| format!("{}+0x{:X}", resolution.name, resolution.displacement));
        let right = mismatch.pdb.as_ref().map_or("-".to_string(), |resolution| format!("{}+0x{:X}", resolution.name, resolution.displacement));
        println!(
            "0x{:016X} 0x{:08X} {:<40} {:<40} {:<10} {:>7}",
            mismatch.address,
            mismatch.rva,
            truncate(&left, 40),
            truncate(&right, 40),
            format!("{:?}", mismatch.verdict),
            mismatch.aliases
        );
    }
    if let Some(rest) = mismatches.len().checked_sub(MAX_ROWS).filter(|rest| *rest > 0) {
        println!("… {rest} more rows");
    }
    for (verdict, count) in totals {
        println!("  {verdict:?}: {count}");
    }
}

fn truncate(text: &str, width: usize) -> String {
    if text.len() <= width { text.to_string() } else { format!("{}…", &text[..width - 1]) }
}

/// Checks the DBI module list, section contributions and section map against the image and the
/// module table the dump carries.
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

/// Asks `dbghelp` to undecorate names, so the in-tree undecorator can be checked against it.
///
/// Only tests call this. The product path reads names from the PDB alone, so this binding must
/// disappear with the rest of `dbghelp` once the runtime switch lands.
#[cfg(windows)]
fn undecorate_with_oracle(names: &[&str]) -> Vec<Option<String>> {
    use std::{ffi::c_void, os::windows::ffi::OsStrExt};

    type UnDecorateSymbolName = unsafe extern "system" fn(*const u8, *mut u8, u32, u32) -> u32;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LoadLibraryW(name: *const u16) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    }

    let library = std::ffi::OsStr::new("dbghelp.dll").encode_wide().chain(Some(0)).collect::<Vec<_>>();
    // SAFETY: the wide string is NUL terminated and lives for the call.
    let module = unsafe { LoadLibraryW(library.as_ptr()) };
    if module.is_null() {
        return vec![None; names.len()];
    }
    let address = unsafe { GetProcAddress(module, c"UnDecorateSymbolName".as_ptr().cast::<u8>()) };
    if address.is_null() {
        return vec![None; names.len()];
    }
    // SAFETY: `dbghelp` exports `UnDecorateSymbolName` with this documented signature.
    let undecorate: UnDecorateSymbolName = unsafe { std::mem::transmute(address) };
    names
        .iter()
        .map(|name| {
            let mut output = [0u8; 16_384];
            // SAFETY: input is NUL terminated by the caller's `CString` and the output buffer is sized.
            let written = unsafe { undecorate(name.as_ptr(), output.as_mut_ptr().cast::<u8>(), output.len() as u32, 0) };
            if written == 0 {
                return None;
            }
            // The documented return is the character count, but a failed call can leave the buffer
            // untouched, so the terminator is what decides the text actually produced.
            let end = output.iter().take(written as usize).position(|byte| *byte == 0).unwrap_or(written as usize);
            Some(String::from_utf8_lossy(&output[..end]).into_owned())
        })
        .collect()
}

/// Compares the in-tree undecorator with `dbghelp` over every decorated public symbol of a real PDB.
///
/// Undecoration is a rendering rule, not an address lookup, so the whole name list is compared
/// instead of the sampled addresses. A name the in-tree parser declines keeps its stored spelling,
/// which is a coverage gap rather than a wrong answer, so the report separates the two.
#[cfg(windows)]
#[test]
#[ignore = "requires OPEN_DEBUGGER_REAL_PDB"]
fn compares_the_undecorator_with_dbghelp_on_a_real_pdb() {
    use std::ffi::CString;

    let pdb = std::env::var("OPEN_DEBUGGER_REAL_PDB").expect("set OPEN_DEBUGGER_REAL_PDB to the matching PDB");
    let mut pdb_file = PdbFile::open(Path::new(&pdb)).expect("open the real PDB");
    let table = pdb_file.public_symbols().expect("read the public symbols");

    let names = table
        .symbols
        .iter()
        .map(|symbol| symbol.name.as_str())
        .filter(|name| name.starts_with('?'))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    println!("{} public symbols, {} distinct decorated names", table.symbols.len(), names.len());

    let mut same = 0usize;
    let mut literals = Vec::new();
    let mut declined = Vec::new();
    let mut wrong = Vec::new();
    for chunk in names.chunks(512) {
        let owned = chunk.iter().map(|name| CString::new(name.as_str()).expect("names are NUL free")).collect::<Vec<_>>();
        let borrowed = owned.iter().map(|name| name.to_str().expect("names are ASCII")).collect::<Vec<_>>();
        let oracle = undecorate_with_oracle(&borrowed);
        for (name, expected) in chunk.iter().zip(oracle) {
            let ours = crate::pdb::undecorate(name);
            match (ours, expected) {
                (Some(ours), Some(expected)) if ours == expected => same += 1,
                // `dbghelp` renders a literal with a mangled scope prefix it cannot read, so the
                // placeholder is the answer on both sides and only the prefix differs.
                (Some(ours), Some(expected)) if ours == "`string'" && expected.contains("`string'") => literals.push(name.clone()),
                (None, _) => declined.push(name.clone()),
                (Some(ours), expected) => wrong.push((name.clone(), ours, expected.unwrap_or_else(|| "<none>".to_string()))),
            }
        }
    }

    println!(
        "identical: {same}\nliteral placeholder: {}\ndeclined: {}\nsome answer dbghelp does not give: {}",
        literals.len(),
        declined.len(),
        wrong.len()
    );
    let named = wrong.iter().filter(|row| row.1.split('(').next() == row.2.split('(').next()).count();
    println!("  of those, the function name itself agrees and only the signature differs: {named}");
    let mut shapes = BTreeMap::<String, Vec<&(String, String, String)>>::new();
    for row in &wrong {
        shapes.entry(shape(&row.0)).or_default().push(row);
    }
    println!("\n{:<12} {:>6}  example", "shape", "count");
    for (shape, rows) in &shapes {
        let example = rows.first().expect("a shape holds at least one name");
        println!("{shape:<12} {:>6}  {}", rows.len(), truncate(&example.0, 40));
    }
    println!();
    for row in wrong.iter().take(MAX_ROWS) {
        println!("{}\n  ours:    {}\n  dbghelp: {}", row.0, row.1, row.2);
    }
    let mut gaps = BTreeMap::<String, Vec<&String>>::new();
    for name in &declined {
        gaps.entry(shape(name)).or_default().push(name);
    }
    println!("\n{:<12} {:>6}  declined example", "shape", "count");
    for (shape, rows) in &gaps {
        let name = rows.first().expect("a shape holds at least one name");
        let owned = CString::new(name.as_str()).expect("names are NUL free");
        let can_be =
            undecorate_with_oracle(&[owned.to_str().expect("names are ASCII")]).pop().flatten().unwrap_or_else(|| "<none>".to_string());
        println!("{shape:<12} {:>6}  {}\n{:<20}  {}", rows.len(), truncate(name, 60), "", truncate(&can_be, 160));
    }
}

/// The bytes that follow the symbol's scope chain, which is what selects the record grammar.
fn shape(name: &str) -> String {
    let tail = name.rfind("@@").map(|at| &name[at + 2..]).unwrap_or(name);
    tail.chars().take(4).collect()
}

/// Compares the PDB reader with the runtime in use, over every frame of a real dump.
///
/// The report is produced by the bound engine today, so its frames are the behavior being
/// replaced. Each frame is resolved a second time through the PDB reader, and every difference is
/// printed by name: a frame that gains a name is a behavior change, not a non-regression, and a
/// frame that loses one would be a regression that has to be understood before the switch.
#[test]
#[ignore = "requires OPEN_DEBUGGER_REAL_DUMP and a symbol store holding the matching image and PDB"]
fn compares_the_pdb_reader_with_the_current_runtime_on_a_real_dump() {
    let dump = std::env::var("OPEN_DEBUGGER_REAL_DUMP").expect("set OPEN_DEBUGGER_REAL_DUMP to a real dump");
    let report = analyze_file(Path::new(&dump)).expect("analyze the real dump");
    assert!(report.symbols.engine, "the current runtime must resolve names for a comparison, diagnostics: {:?}", report.symbols);

    let frames = report.stack.iter().chain(report.stack_guesses.iter()).collect::<Vec<_>>();
    let addresses = frames.iter().filter_map(|frame| parse_hex(&frame.address)).collect::<Vec<_>>();
    assert_eq!(addresses.len(), frames.len(), "every reported frame carries a hexadecimal address");

    let modules = report
        .modules
        .iter()
        .filter_map(|module| {
            let base = parse_hex(&module.base_address)?;
            Some(crate::triage::KernelModule { name: module.name.clone(), base, size: module.size_bytes, timestamp: module.timestamp })
        })
        .collect::<Vec<_>>();
    let (resolved, diagnostics) = symbols::function_names_from_pdb(&modules, &addresses);
    println!("pdb reader diagnostics: store {:?}, engine {}, {} missing", diagnostics.store, diagnostics.engine, diagnostics.missing.len());
    for missing in &diagnostics.missing {
        println!("  missing {}: {}", missing.module, missing.reason);
    }
    for warning in &diagnostics.warnings {
        println!("  warning: {warning}");
    }

    let mut identical = 0usize;
    let mut unnamed = 0usize;
    let mut gained = Vec::new();
    let mut lost = Vec::new();
    let mut different = Vec::new();
    for (index, frame) in frames.iter().enumerate() {
        let ours = resolved.get(index).and_then(|symbol| symbol.as_ref());
        let label = format!("{} {}", frame.address, frame.module.as_deref().unwrap_or("<unattributed>"));
        match (frame.function.as_deref(), ours) {
            (None, None) => unnamed += 1,
            (Some(_), None) => lost.push((label, frame.offset_in_module.clone(), frame.function.clone())),
            (None, Some(symbol)) => gained.push((label, frame.offset_in_module.clone(), symbol.function.clone(), symbol.displacement)),
            (Some(today), Some(symbol)) => {
                let displacement = format!("0x{:X}", symbol.displacement);
                if today == symbol.function && frame.function_offset.as_deref() == Some(displacement.as_str()) {
                    identical += 1;
                }
                else {
                    different.push((label, today.to_string(), frame.function_offset.clone(), symbol.function.clone(), displacement));
                }
            }
        }
    }

    println!(
        "\nframes {}: identical {identical}, unnamed by both {unnamed}, newly named {}, lost {}, differing {}",
        frames.len(),
        gained.len(),
        lost.len(),
        different.len()
    );
    println!("\nframes that gain a name under the PDB reader (a behavior change):");
    for (label, offset, function, displacement) in &gained {
        println!("  {label} at {} -> {} +0x{:X}", offset.as_deref().unwrap_or("<no offset>"), function, displacement);
    }
    println!("\nframes that would lose a name:");
    for (label, offset, today) in &lost {
        println!("  {label} at {} -> was {:?}", offset.as_deref().unwrap_or("<no offset>"), today.as_deref().unwrap_or("<none>"));
    }
    println!("\nframes named differently:");
    for (label, today, today_offset, function, displacement) in &different {
        println!("  {label}\n    dbghelp: {today} +{}\n    pdb:     {function} +{displacement}", today_offset.as_deref().unwrap_or("<none>"));
    }

    assert_eq!(diagnostics.missing.len(), 0, "every frame module must resolve, else the comparison is partial");
}
