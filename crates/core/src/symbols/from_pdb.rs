//! Function names for `MODULE+offset` frames, read out of the PDB with no host library.
//!
//! A frame needs a name and, to stay honest about how far into a function the address sits, the
//! byte length of that function. A public symbol record carries the name but no length, so the
//! length comes from the module symbol stream that contributed the section: each procedure record
//! there states its own byte length.
//!
//! Three rules bound the work and the claims:
//!
//! * Only modules whose section contribution covers the public symbol are opened, and each module
//!   stream is read at most once. A kernel PDB names over two thousand modules, and a frame
//!   touches only the few that contributed its section.
//! * A frame names code, so only a public symbol flagged as code or a function names it. A string
//!   literal that happens to sit before the address is storage, not the function being executed.
//! * The procedure match is exact in both section and offset. A procedure that merely covers the
//!   address is a different claim, so no length is borrowed from a neighbouring record: with no
//!   record starting at the public symbol's own offset the frame keeps the name and displacement it
//!   had before this reader existed.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use crate::{
    pdb::{self, DebugInfo, FunctionIndex, ModuleSymbols, PdbFile},
    pe::SectionHeader,
    triage::KernelModule,
};

use super::{MissingSymbol, ResolvedSymbol, SymbolDiagnostics, store, unique_modules};

/// The recorded frame table of a real dump, which holds the reader to evidence across the switch.
#[cfg(test)]
mod golden;

/// Resolves `addresses` against the module table, reading each module's PDB from the store.
pub(super) fn function_names(modules: &[KernelModule], addresses: &[u64]) -> (Vec<Option<ResolvedSymbol>>, SymbolDiagnostics) {
    let mut symbols = std::iter::repeat_with(|| None).take(addresses.len()).collect::<Vec<Option<ResolvedSymbol>>>();
    let Some(store) = store::symbol_store()
    else {
        return (symbols, SymbolDiagnostics {
            warnings: vec![
                "function names need a local symbol store: set `OPEN_DEBUGGER_SYMBOL_STORE` to a directory laid out like the debugger symbol cache, because a triage dump carries no module images and no PDB paths".to_string(),
            ],
            ..SymbolDiagnostics::default()
        });
    };
    let mut missing = Vec::new();
    let mut warnings = Vec::new();
    for index in unique_modules(modules, addresses) {
        let module = &modules[index];
        let Some(located) = locate(&store, module, &mut missing)
        else {
            continue;
        };
        let mut file = match PdbFile::open(&located.pdb) {
            Ok(file) => file,
            Err(error) => {
                missing.push(unusable(module, &store, &located, format!("the PDB the image names could not be read: {error}")));
                continue;
            }
        };
        let sections = match SectionHeader::read(&located.image) {
            Ok(sections) => sections,
            Err(error) => {
                missing.push(unusable(module, &store, &located, format!("the image section table could not be read: {error}")));
                continue;
            }
        };
        let table = match file.public_symbols() {
            Ok(table) => table,
            Err(error) => {
                missing.push(unusable(module, &store, &located, format!("the PDB holds no usable public symbols: {error}")));
                continue;
            }
        };
        let index_table = match table.index(&sections) {
            Ok(index_table) => index_table,
            Err(error) => {
                missing.push(unusable(module, &store, &located, format!("the public symbols do not resolve against the image: {error}")));
                continue;
            }
        };
        let debug_info = match file.debug_info() {
            Ok(debug_info) => debug_info,
            Err(error) => {
                missing.push(unusable(module, &store, &located, format!("the PDB module list could not be read: {error}")));
                continue;
            }
        };
        name_frames(module, &index_table, &mut file, &debug_info, addresses, &mut symbols, &mut warnings);
    }
    (symbols, SymbolDiagnostics { store: Some(store.to_string_lossy().into_owned()), engine: true, missing, warnings })
}

/// The image and PDB one module resolves to, with the identity the image records.
struct Located {
    image: PathBuf,
    pdb: PathBuf,
    code_view: store::CodeView,
}

/// Finds the image and PDB the store holds for one module, recording a missing-input report when
/// either is absent.
fn locate(store: &Path, module: &KernelModule, missing: &mut Vec<MissingSymbol>) -> Option<Located> {
    let expected_image = store::expected_image(store, module);
    let Some(image) = store::find_image(store, module)
    else {
        missing.push(MissingSymbol {
            module: module.name.clone(),
            timestamp: module.timestamp,
            size: module.size,
            reason: "the module image is missing from the symbol store".to_string(),
            image_path: Some(expected_image.to_string_lossy().into_owned()),
            pdb_name: None,
            pdb_key: None,
            pdb_path: None,
            fetch_command: Some(store::fetch_command(&expected_image, store)),
        });
        return None;
    };
    let Some(code_view) = store::code_view(&image)
    else {
        missing.push(MissingSymbol {
            module: module.name.clone(),
            timestamp: module.timestamp,
            size: module.size,
            reason: "the module image carries no CodeView record, so the PDB name and age are unknown".to_string(),
            image_path: Some(image.to_string_lossy().into_owned()),
            pdb_name: None,
            pdb_key: None,
            pdb_path: None,
            fetch_command: Some(store::fetch_command(&image, store)),
        });
        return None;
    };
    let expected_pdb = store::expected_pdb(store, &code_view);
    let Some(pdb) = store::find_pdb(store, &code_view)
    else {
        missing.push(MissingSymbol {
            module: module.name.clone(),
            timestamp: module.timestamp,
            size: module.size,
            reason: "the PDB named by the module image is missing from the symbol store".to_string(),
            image_path: Some(image.to_string_lossy().into_owned()),
            pdb_name: Some(code_view.pdb_name.clone()),
            pdb_key: Some(code_view.key.clone()),
            pdb_path: Some(expected_pdb.to_string_lossy().into_owned()),
            fetch_command: Some(store::fetch_command(&image, store)),
        });
        return None;
    };
    Some(Located { image, pdb, code_view })
}

/// Reports a module whose files exist but whose contents this reader could not use.
fn unusable(module: &KernelModule, store: &Path, located: &Located, reason: String) -> MissingSymbol {
    MissingSymbol {
        module: module.name.clone(),
        timestamp: module.timestamp,
        size: module.size,
        reason,
        image_path: Some(located.image.to_string_lossy().into_owned()),
        pdb_name: Some(located.code_view.pdb_name.clone()),
        pdb_key: Some(located.code_view.key.clone()),
        pdb_path: Some(store::expected_pdb(store, &located.code_view).to_string_lossy().into_owned()),
        fetch_command: Some(store::fetch_command(&located.image, store)),
    }
}

/// Public symbol flags that mark code: bit 0 is code, bit 1 is a function.
const SYMBOL_CODE: u32 = 3;

/// Names every address that falls inside `module`.
fn name_frames(
    module: &KernelModule,
    index: &FunctionIndex,
    file: &mut PdbFile,
    debug_info: &DebugInfo,
    addresses: &[u64],
    symbols: &mut [Option<ResolvedSymbol>],
    warnings: &mut Vec<String>,
) {
    let mut lengths = ProcedureLengths { file, debug_info, loaded: BTreeMap::new(), warned: Vec::new() };
    for (position, rva) in module_addresses(module, addresses) {
        let Some(hit) = index.find(rva)
        else {
            continue;
        };
        // A frame names code, so only a public symbol the compiler flagged as code or a function
        // names it. A string literal and other non-code publics leave the frame as it was.
        if hit.entry.flags & SYMBOL_CODE == 0 {
            continue;
        }
        // Only a procedure record that starts at this exact section offset states the byte length,
        // and without one the gate below is vacuous. The frame then keeps the name and displacement
        // the previous reader reported instead of a length guessed from a neighbouring record.
        let size = lengths.at(hit.entry.section, hit.entry.offset).unwrap_or(0);
        if size == 0 || hit.displacement < size {
            let function = pdb::undecorate(&hit.entry.name).unwrap_or_else(|| hit.entry.name.clone());
            symbols[position] = Some(ResolvedSymbol { function, displacement: u64::from(hit.displacement) });
        }
    }
    warnings.append(&mut lengths.warned);
}

/// Addresses of this module with their index into the caller's address list and their RVA.
fn module_addresses(module: &KernelModule, addresses: &[u64]) -> Vec<(usize, u32)> {
    addresses
        .iter()
        .enumerate()
        .filter_map(|(position, address)| module.contains(*address).and_then(|offset| u32::try_from(offset).ok()).map(|rva| (position, rva)))
        .collect()
}

/// Byte lengths of procedures, looked up by section and offset across the modules that contributed
/// that section.
///
/// A module stream is read the first time one of its contributions is asked about and kept, so a
/// section shared by several modules costs one read per module rather than one per frame.
struct ProcedureLengths<'a> {
    file: &'a mut PdbFile,
    debug_info: &'a DebugInfo,
    loaded: BTreeMap<usize, Option<ModuleSymbols>>,
    warned: Vec<String>,
}

impl ProcedureLengths<'_> {
    /// Length the compiler recorded for the procedure starting at `section`/`offset`.
    ///
    /// `None` means no contributing module records a procedure at that exact offset. The caller
    /// treats the length as unknown rather than absent, so the frame keeps the behaviour of the
    /// previous reader instead of gaining or losing a name.
    fn at(&mut self, section: u16, offset: u32) -> Option<u32> {
        for module_index in contributing_modules(self.debug_info, section, offset) {
            if !self.loaded.contains_key(&module_index) {
                let parsed = match self.debug_info.modules.get(module_index) {
                    Some(module) => self.load_module(module),
                    None => None,
                };
                self.loaded.insert(module_index, parsed);
            }
            let Some(Some(symbols)) = self.loaded.get(&module_index)
            else {
                continue;
            };
            if let Some(function) = symbols.function_at(section, offset) {
                return Some(function.length);
            }
        }
        None
    }

    fn load_module(&mut self, module: &pdb::ModuleInfo) -> Option<ModuleSymbols> {
        match self.file.module_symbols(module) {
            Ok(symbols) => Some(symbols),
            Err(error) => {
                self.warned
                    .push(format!("module `{}` symbol stream could not be read, so its procedures have no byte length: {error}", module.name));
                None
            }
        }
    }
}

/// Modules whose section contribution covers the byte at `section`/`offset`.
fn contributing_modules(debug_info: &DebugInfo, section: u16, offset: u32) -> Vec<usize> {
    let mut modules = Vec::new();
    for contribution in &debug_info.contributions {
        if contribution.section != section {
            continue;
        }
        let end = contribution.offset.saturating_add(contribution.size);
        if offset < contribution.offset || offset >= end {
            continue;
        }
        let index = usize::from(contribution.module);
        if !modules.contains(&index) {
            modules.push(index);
        }
    }
    modules
}
