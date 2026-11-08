//! Function names for `MODULE+offset` frames.
//!
//! A triage dump carries no module images, so naming a frame needs two inputs beyond the dump: the
//! module binary, which carries the CodeView record that names its PDB, and that PDB. This module
//! finds both in a local symbol store laid out like the debugger `sym` directory, and `store` reads
//! the image identity the store keys on.
//!
//! Names and displacements come from the PDB's public symbols and procedure lengths from its
//! module symbol streams, so naming a frame needs no host library. When an image or PDB is missing
//! the frame keeps its `MODULE+offset` form and the diagnostics name the module, the expected store
//! keys, and the command that prefetches the missing files.

use serde::{Deserialize, Serialize};

use crate::triage::KernelModule;

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
