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

use std::{collections::BTreeMap, path::Path, time::Instant};

use crate::{
    minidump::analyze_file,
    pdb::PdbFile,
    pe::SectionHeader,
    symbols,
};

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
    let module_entry = || crate::triage::KernelModule {
        name: module.name.clone(),
        base: module_base,
        size: module.size_bytes,
        timestamp: module.timestamp,
    };

    let raw_started = Instant::now();
    let dbghelp_raw = symbols::function_names_raw(&[module_entry()], &absolute).0;
    let raw_elapsed = raw_started.elapsed();
    let normalized_started = Instant::now();
    let dbghelp_normalized = symbols::function_names(&[module_entry()], &absolute).0;
    let normalized_elapsed = normalized_started.elapsed();

    let ours = addresses
        .iter()
        .map(|(_, rva)| {
            index.find(*rva).map(|hit| Resolution { name: hit.entry.name.clone(), displacement: hit.displacement })
        })
        .collect::<Vec<_>>();

    let (raw_totals, raw_mismatches) = report_comparison("source spelling (primary gate)", &resolve(dbghelp_raw), &ours, &addresses, frame_count, &aliases);
    let (normalized_totals, _) = report_comparison(
        "undecorated (product path)",
        &resolve(dbghelp_normalized),
        &ours,
        &addresses,
        frame_count,
        &aliases,
    );
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

    assert!(
        rate >= 0.99,
        "source-spelling consistency {:.4}% is below the 99% gate, verdicts: {:?}",
        rate * 100.0,
        raw_totals
    );
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
        let left = mismatch.dbghelp.as_ref().map_or("-".to_string(), |resolution| format!("{}+0x{:X}", resolution.name, resolution.displacement));
        let right = mismatch.pdb.as_ref().map_or("-".to_string(), |resolution| format!("{}+0x{:X}", resolution.name, resolution.displacement));
        println!(
            "0x{:016X} 0x{:08X} {:<40} {:<40} {:<10} {:>7}",
            mismatch.address,
            mismatch.rva,
            truncate(&left),
            truncate(&right),
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

fn truncate(text: &str) -> String {
    const WIDTH: usize = 40;
    if text.len() <= WIDTH { text.to_string() } else { format!("{}…", &text[..WIDTH - 1]) }
}
