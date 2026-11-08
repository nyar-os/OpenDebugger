//! Function names for `MODULE+offset` frames.
//!
//! A triage dump carries no module images, so naming a frame needs two inputs beyond the dump: the
//! module binary, which carries the CodeView record that names its PDB, and that PDB. This module
//! finds both in a local symbol store laid out like the debugger `sym` directory, and `store` reads
//! the image identity the store keys on.
//!
//! When an image or PDB is missing the frame keeps its `MODULE+offset` form and the diagnostics
//! name the module, the expected store keys, and the command that prefetches the missing files.

use serde::{Deserialize, Serialize};

use crate::triage::KernelModule;

#[cfg(windows)]
mod dbghelp;
/// The portable reader. Only tests drive it until it replaces the binding above.
#[cfg(all(test, windows))]
mod from_pdb;
mod store;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SymbolDiagnostics {
    /// Symbol store used for this analysis, when one was found.
    pub store: Option<String>,
    /// True when the symbol source accepted the store.
    pub engine: bool,
    /// Modules whose image or PDB could not be used, with the prefetch command for each.
    pub missing: Vec<MissingSymbol>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MissingSymbol {
    pub module: String,
    pub timestamp: u32,
    pub size: u32,
    /// Why the module could not be named.
    pub reason: String,
    /// Store path for the image, or the path the image must occupy.
    pub image_path: Option<String>,
    pub pdb_name: Option<String>,
    /// `<GUID><age>` key used by the symbol store directory.
    pub pdb_key: Option<String>,
    pub pdb_path: Option<String>,
    /// Command that fetches the image and PDB on a machine with Debugging Tools.
    pub fetch_command: Option<String>,
}

pub(crate) struct ResolvedSymbol {
    pub function: String,
    pub displacement: u64,
}

/// Resolves `addresses` against the module table.
///
/// Returns one entry per address, in the same order, plus diagnostics describing missing inputs.
pub(crate) fn function_names(modules: &[KernelModule], addresses: &[u64]) -> (Vec<Option<ResolvedSymbol>>, SymbolDiagnostics) {
    #[cfg(windows)]
    {
        dbghelp::function_names(modules, addresses)
    }
    #[cfg(not(windows))]
    {
        let _ = (modules, addresses);
        (
            Vec::new(),
            SymbolDiagnostics {
                warnings: vec!["function names need `dbghelp`, which is only bound on Windows, so frames stay at `MODULE+offset`".to_string()],
                ..SymbolDiagnostics::default()
            },
        )
    }
}

/// Resolves `addresses` exactly as the PDB spells the names, without undecoration.
///
/// Only the conformance check uses this, so the pure PDB reader can be compared with the same
/// spelling `dbghelp` reads from the file rather than with its normalized output.
#[cfg(all(test, windows))]
pub(crate) fn function_names_raw(modules: &[KernelModule], addresses: &[u64]) -> (Vec<Option<ResolvedSymbol>>, SymbolDiagnostics) {
    dbghelp::function_names_raw(modules, addresses)
}

/// Resolves `addresses` through the PDB reader alone, with no `dbghelp` binding.
///
/// Only the conformance check calls this, so the portable reader can be compared with the bound
/// engine over the same addresses before it becomes the product path.
#[cfg(all(test, windows))]
pub(crate) fn function_names_from_pdb(modules: &[KernelModule], addresses: &[u64]) -> (Vec<Option<ResolvedSymbol>>, SymbolDiagnostics) {
    from_pdb::function_names(modules, addresses)
}

/// The modules at least one address falls into, in order of first appearance.
fn unique_modules(modules: &[KernelModule], addresses: &[u64]) -> Vec<usize> {
    let mut indexes = Vec::new();
    for address in addresses {
        if let Some(index) = modules.iter().position(|module| module.contains(*address).is_some())
            && !indexes.contains(&index)
        {
            indexes.push(index);
        }
    }
    indexes
}
