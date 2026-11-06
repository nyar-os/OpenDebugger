//! Function names for `MODULE+offset` frames, bound to `dbghelp.dll` at runtime.
//!
//! A triage dump carries no module images, so naming a frame needs two inputs beyond the dump:
//! the module binary, which carries the CodeView record that names its PDB, and that PDB. This
//! module looks both up in a local symbol store laid out like the debugger `sym` directory and
//! asks `dbghelp` which function contains each stack address.
//!
//! When an image or PDB is missing the frame keeps its `MODULE+offset` form and the diagnostics
//! name the module, the expected store keys, and the command that prefetches the missing files.

use serde::{Deserialize, Serialize};

use crate::triage::KernelModule;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SymbolDiagnostics {
    /// Symbol store used for this analysis, when one was found.
    pub store: Option<String>,
    /// True when `dbghelp` was bound and accepted the store.
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
        windows::function_names(modules, addresses)
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
    windows::function_names_raw(modules, addresses)
}

#[cfg(windows)]
mod windows {
    use std::{
        ffi::c_void,
        io::{Read, Seek, SeekFrom},
        path::{Path, PathBuf},
        sync::Mutex,
    };

    use super::{KernelModule, MissingSymbol, ResolvedSymbol, SymbolDiagnostics};

    const SYMOPT_UNDNAME: u32 = 0x0000_0002;
    const SYMOPT_NO_PROMPTS: u32 = 0x0008_0000;
    const PROCESS_HANDLE: usize = 0x4F44_4247;
    const MAX_SYM_NAME: u32 = 256;

    /// `SYMBOL_INFOW` ends with a one-character name array and reports 88 bytes on x64.
    ///
    /// Reading the buffer `dbghelp` fills shows the field order used here: a 64-bit `ModBase`,
    /// `NameLen` at 76, `MaxNameLen` at 80 and the name at 84. A smaller `SizeOfStruct` is
    /// rejected with `ERROR_INVALID_PARAMETER`, so 88 is what makes `SymFromAddrW` return a name.
    const SYMBOL_INFO_SIZE: u32 = 88;

    /// PE32+ optional header magic and the offsets this module reads inside it.
    const PE32_PLUS: u16 = 0x20B;
    const DATA_DIRECTORY_OFFSET: usize = 0x70;
    const DEBUG_DIRECTORY_INDEX: usize = 6;
    const DEBUG_ENTRY_SIZE: usize = 28;
    const SECTION_HEADER_SIZE: usize = 40;
    const CODEVIEW_ENTRY: u32 = 2;
    const MAX_PDB_PATH_BYTES: usize = 260;
    /// Bounds on the header region a real PE32+ image can occupy.
    const MAX_OPTIONAL_HEADER: usize = 0x1000;
    const MAX_SECTIONS: usize = 96;

    static SERIALIZE: Mutex<()> = Mutex::new(());

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LoadLibraryW(name: *const u16) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    }

    type SymInitialize = unsafe extern "system" fn(usize, *const u16, i32) -> i32;
    type SymSetOptions = unsafe extern "system" fn(u32) -> u32;
    type SymLoadModuleEx = unsafe extern "system" fn(usize, *mut c_void, *const u16, *const u16, u64, u32, *mut c_void, u32) -> u64;
    type SymFromAddr = unsafe extern "system" fn(usize, u64, *mut u64, *mut SymbolInfoW) -> i32;
    type SymCleanup = unsafe extern "system" fn(usize) -> i32;

    struct Engine {
        _library: *mut c_void,
        store: PathBuf,
        initialize: SymInitialize,
        set_options: SymSetOptions,
        load_module: SymLoadModuleEx,
        from_addr: SymFromAddr,
        cleanup: SymCleanup,
    }

    /// Mirrors `SYMBOL_INFOW`; the trailing array is oversized so `dbghelp` can fill the name.
    #[repr(C)]
    #[allow(dead_code)]
    struct SymbolInfoW {
        size_of_struct: u32,
        type_index: u32,
        reserved: [u64; 2],
        index: u32,
        size: u32,
        mod_base: u64,
        flags: u32,
        padding: u32,
        value: u64,
        address: u64,
        register_field: u32,
        scope: u32,
        tag: u32,
        name_len: u32,
        max_name_len: u32,
        name: [u16; MAX_SYM_NAME as usize],
    }

    /// The identity a module image records for its PDB.
    ///
    /// `pdb_name` and the `<GUID><age>` key together are the exact PDB a frame needs, which is
    /// what a missing-symbol report has to print. The GUID is the 16 raw CodeView bytes in
    /// stored order, uppercase, followed by the decimal age, matching the symbol store directory.
    struct CodeView {
        pdb_name: String,
        key: String,
    }

    pub(super) fn function_names(modules: &[KernelModule], addresses: &[u64]) -> (Vec<Option<ResolvedSymbol>>, SymbolDiagnostics) {
        function_names_with(modules, addresses, true)
    }

    /// Resolves names without `SYMOPT_UNDNAME`, so a comparison sees the spelling a PDB stores.
    ///
    /// This exists for the conformance check that compares the pure PDB reader with `dbghelp`.
    #[cfg(test)]
    pub(super) fn function_names_raw(modules: &[KernelModule], addresses: &[u64]) -> (Vec<Option<ResolvedSymbol>>, SymbolDiagnostics) {
        function_names_with(modules, addresses, false)
    }

    fn function_names_with(modules: &[KernelModule], addresses: &[u64], undname: bool) -> (Vec<Option<ResolvedSymbol>>, SymbolDiagnostics) {
        let symbols = std::iter::repeat_with(|| None).take(addresses.len()).collect::<Vec<Option<ResolvedSymbol>>>();
        let _serialized = SERIALIZE.lock().unwrap_or_else(|poison| poison.into_inner());

        let Some(store) = symbol_store()
        else {
            return (symbols, SymbolDiagnostics {
                store: None,
                engine: false,
                missing: unnamed_modules(modules, addresses, "no symbol store is configured, so this module cannot be named"),
                warnings: vec![
                    "function names need a local symbol store: set `OPEN_DEBUGGER_SYMBOL_STORE` to a directory laid out like the debugger symbol cache, because a triage dump carries no module images and no PDB paths".to_string(),
                ],
            });
        };
        let Some(engine) = Engine::open(&store)
        else {
            return (
                symbols,
                SymbolDiagnostics {
                    store: Some(store.to_string_lossy().into_owned()),
                    engine: false,
                    missing: unnamed_modules(modules, addresses, "`dbghelp.dll` could not be bound, so this module cannot be named"),
                    warnings: vec!["`dbghelp.dll` could not be bound, so frames stay at `MODULE+offset`".to_string()],
                },
            );
        };
        if !engine.initialize(undname) {
            return (
                symbols,
                SymbolDiagnostics {
                    store: Some(store.to_string_lossy().into_owned()),
                    engine: false,
                    missing: unnamed_modules(modules, addresses, "`dbghelp` rejected the symbol store, so this module cannot be named"),
                    warnings: vec!["`dbghelp` rejected the symbol store, so frames stay at `MODULE+offset`".to_string()],
                },
            );
        }
        engine.resolve(modules, addresses)
    }

    fn unnamed_modules(modules: &[KernelModule], addresses: &[u64], reason: &str) -> Vec<MissingSymbol> {
        unique_modules(modules, addresses)
            .into_iter()
            .map(|index| MissingSymbol {
                module: modules[index].name.clone(),
                timestamp: modules[index].timestamp,
                size: modules[index].size,
                reason: reason.to_string(),
                image_path: None,
                pdb_name: None,
                pdb_key: None,
                pdb_path: None,
                fetch_command: None,
            })
            .collect()
    }

    fn symbol_store() -> Option<PathBuf> {
        if let Some(value) = std::env::var_os("OPEN_DEBUGGER_SYMBOL_STORE") {
            let path = PathBuf::from(value);
            if path.is_dir() {
                return Some(path);
            }
        }
        let program_files = std::env::var_os("ProgramFiles(x86)").or_else(|| std::env::var_os("ProgramFiles"))?;
        let candidate = Path::new(&program_files).join("Windows Kits").join("10").join("Debuggers").join("x64").join("sym");
        candidate.is_dir().then_some(candidate)
    }

    impl Engine {
        fn open(store: &Path) -> Option<Self> {
            let debugger_dir = store.parent()?;
            let library_path = debugger_dir.join("dbghelp.dll");
            let library_name = if library_path.is_file() { library_path.to_string_lossy().into_owned() } else { "dbghelp.dll".to_string() };
            // SAFETY: the name is null-terminated UTF-16 and the result is checked for null.
            let library = unsafe { LoadLibraryW(wide(&library_name).as_ptr()) };
            if library.is_null() {
                return None;
            }
            Some(Self {
                _library: library,
                store: store.to_path_buf(),
                initialize: unsafe { symbol::<SymInitialize>(library, b"SymInitializeW\0") }?,
                set_options: unsafe { symbol::<SymSetOptions>(library, b"SymSetOptions\0") }?,
                load_module: unsafe { symbol::<SymLoadModuleEx>(library, b"SymLoadModuleExW\0") }?,
                from_addr: unsafe { symbol::<SymFromAddr>(library, b"SymFromAddrW\0") }?,
                cleanup: unsafe { symbol::<SymCleanup>(library, b"SymCleanup\0") }?,
            })
        }

        fn initialize(&self, undname: bool) -> bool {
            // SAFETY: `dbghelp` accepts any non-zero unique handle value and a null-terminated path.
            unsafe {
                let options = if undname { SYMOPT_UNDNAME | SYMOPT_NO_PROMPTS } else { SYMOPT_NO_PROMPTS };
                (self.set_options)(options);
                (self.initialize)(PROCESS_HANDLE, wide(&self.store.to_string_lossy()).as_ptr(), 0) != 0
            }
        }

        fn resolve(&self, modules: &[KernelModule], addresses: &[u64]) -> (Vec<Option<ResolvedSymbol>>, SymbolDiagnostics) {
            let mut symbols = std::iter::repeat_with(|| None).take(addresses.len()).collect::<Vec<Option<ResolvedSymbol>>>();
            let mut missing: Vec<MissingSymbol> = Vec::new();
            let mut warnings = Vec::new();
            let mut failed_loads: Vec<String> = Vec::new();
            for index in unique_modules(modules, addresses) {
                let module = &modules[index];
                let expected_image = self.store.join(&module.name).join(image_key(module)).join(&module.name);
                let Some(image) = self.image(module)
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
                        fetch_command: Some(fetch_command(&expected_image, &self.store)),
                    });
                    continue;
                };
                let Some(code_view) = code_view(&image)
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
                        fetch_command: Some(fetch_command(&image, &self.store)),
                    });
                    continue;
                };
                let expected_pdb = self.store.join(&code_view.pdb_name).join(&code_view.key).join(&code_view.pdb_name);
                if store_entry(&self.store, &code_view.pdb_name, &code_view.key, &code_view.pdb_name).is_none() {
                    missing.push(MissingSymbol {
                        module: module.name.clone(),
                        timestamp: module.timestamp,
                        size: module.size,
                        reason: "the PDB named by the module image is missing from the symbol store".to_string(),
                        image_path: Some(image.to_string_lossy().into_owned()),
                        pdb_name: Some(code_view.pdb_name.clone()),
                        pdb_key: Some(code_view.key.clone()),
                        pdb_path: Some(expected_pdb.to_string_lossy().into_owned()),
                        fetch_command: Some(fetch_command(&image, &self.store)),
                    });
                    continue;
                }
                // SAFETY: the image path, module name and base/size all come from the dump module table.
                let loaded = unsafe {
                    (self.load_module)(
                        PROCESS_HANDLE,
                        std::ptr::null_mut(),
                        wide(&image.to_string_lossy()).as_ptr(),
                        wide(&module.name).as_ptr(),
                        module.base,
                        module.size,
                        std::ptr::null_mut(),
                        0,
                    )
                };
                if loaded == 0 {
                    failed_loads.push(module.name.clone());
                    missing.push(MissingSymbol {
                        module: module.name.clone(),
                        timestamp: module.timestamp,
                        size: module.size,
                        reason: "`dbghelp` did not load the module image and its PDB".to_string(),
                        image_path: Some(image.to_string_lossy().into_owned()),
                        pdb_name: Some(code_view.pdb_name.clone()),
                        pdb_key: Some(code_view.key.clone()),
                        pdb_path: Some(expected_pdb.to_string_lossy().into_owned()),
                        fetch_command: Some(fetch_command(&image, &self.store)),
                    });
                }
            }
            if !failed_loads.is_empty() {
                warnings
                    .push(format!("`dbghelp` did not load symbols for {}, so those frames stay at `MODULE+offset`", failed_loads.join(", ")));
            }

            for (address, symbol) in addresses.iter().zip(symbols.iter_mut()) {
                let mut info = SymbolInfoW {
                    size_of_struct: SYMBOL_INFO_SIZE,
                    type_index: 0,
                    reserved: [0; 2],
                    index: 0,
                    size: 0,
                    mod_base: 0,
                    flags: 0,
                    padding: 0,
                    value: 0,
                    address: 0,
                    register_field: 0,
                    scope: 0,
                    tag: 0,
                    name_len: 0,
                    max_name_len: MAX_SYM_NAME,
                    name: [0; MAX_SYM_NAME as usize],
                };
                let mut displacement = 0u64;
                // SAFETY: `info` is a live buffer large enough for `SYMBOL_INFOW` plus the name capacity.
                let found = unsafe { (self.from_addr)(PROCESS_HANDLE, *address, &mut displacement, &mut info) };
                if found == 0 || info.name_len == 0 {
                    continue;
                }
                let length = (info.name_len as usize).min(info.name.len());
                let function = String::from_utf16_lossy(&info.name[..length]);
                // A nearest-symbol match outside the symbol's own byte range is not a function
                // name for this address. Symbols without a recorded size keep their name.
                let inside = info.size == 0 || displacement < u64::from(info.size);
                if !function.is_empty() && inside {
                    *symbol = Some(ResolvedSymbol { function, displacement });
                }
            }
            (symbols, SymbolDiagnostics { store: Some(self.store.to_string_lossy().into_owned()), engine: true, missing, warnings })
        }

        /// `<store>\<name>\<timestamp><size>\<name>` is the layout a debugger symbol cache uses.
        fn image(&self, module: &KernelModule) -> Option<PathBuf> {
            let directory = child(&self.store, &module.name)?;
            let entry = child(&directory, &image_key(module))?;
            let image = child(&entry, &module.name)?;
            image.is_file().then_some(image)
        }
    }

    impl Drop for Engine {
        fn drop(&mut self) {
            // SAFETY: the handle was initialized by `SymInitialize` and is used serially.
            unsafe {
                (self.cleanup)(PROCESS_HANDLE);
            }
        }
    }

    fn image_key(module: &KernelModule) -> String {
        format!("{:08X}{:x}", module.timestamp, module.size)
    }

    fn fetch_command(image: &Path, store: &Path) -> String {
        format!("symchk /r \"{}\" /s srv*\"{}\"*https://msdl.microsoft.com/download/symbols", image.display(), store.display())
    }

    /// Finds a directory or file under `base`, ignoring case so a dump name and a store name
    /// that differ only in case still meet.
    fn child(base: &Path, name: &str) -> Option<PathBuf> {
        std::fs::read_dir(base)
            .ok()?
            .flatten()
            .find_map(|entry| entry.file_name().to_string_lossy().eq_ignore_ascii_case(name).then(|| entry.path()))
    }

    fn store_entry(store: &Path, directory: &str, key: &str, file: &str) -> Option<PathBuf> {
        let directory = child(store, directory)?;
        let key = child(&directory, key)?;
        let file = child(&key, file)?;
        file.is_file().then_some(file)
    }

    /// Reads the RSDS CodeView record of a PE image.
    ///
    /// Only the headers, the section table, the debug directory entry and the RSDS record are
    /// read, so an eleven megabyte image costs a few kilobytes instead of a full copy. Returns
    /// `None` for anything this module does not understand: a missing DOS or PE header, a non
    /// PE32+ optional header, an absent debug directory, or a CodeView record without the `RSDS`
    /// signature. The PDB name is taken from the file part of the recorded path, because the
    /// build machine path does not exist on the analysis host.
    fn code_view(image: &Path) -> Option<CodeView> {
        let mut file = std::fs::File::open(image).ok()?;
        let dos = read_at(&mut file, 0, 0x40)?;
        let pe = u64::from(read_u32(&dos, 0x3C)?);
        let coff = read_at(&mut file, pe, 24)?;
        if coff.get(0..4)? != b"PE\0\0".as_slice() {
            return None;
        }
        let sections = usize::from(read_u16(&coff, 6)?);
        let optional_size = usize::from(read_u16(&coff, 20)?);
        if !(2..=MAX_OPTIONAL_HEADER).contains(&optional_size) || !(1..=MAX_SECTIONS).contains(&sections) {
            return None;
        }
        let optional = read_at(&mut file, pe + 24, optional_size)?;
        if read_u16(&optional, 0)? != PE32_PLUS {
            return None;
        }
        let directory = DATA_DIRECTORY_OFFSET + DEBUG_DIRECTORY_INDEX * 8;
        let debug_rva = read_u32(&optional, directory)?;
        let debug_size = read_u32(&optional, directory + 4)?;
        if debug_rva == 0 || debug_size < DEBUG_ENTRY_SIZE as u32 {
            return None;
        }
        let section_table = read_at(&mut file, pe + 24 + optional_size as u64, sections * SECTION_HEADER_SIZE)?;
        let start = section_offset(&section_table, sections, debug_rva)?;
        for index in 0..usize::try_from(debug_size / DEBUG_ENTRY_SIZE as u32).ok()? {
            let entry = read_at(&mut file, (start + index * DEBUG_ENTRY_SIZE) as u64, DEBUG_ENTRY_SIZE)?;
            if read_u32(&entry, 12)? != CODEVIEW_ENTRY {
                continue;
            }
            let size = read_u32(&entry, 16)?;
            let pointer = read_u32(&entry, 24)?;
            let data =
                if pointer == 0 { section_offset(&section_table, sections, read_u32(&entry, 20)?)? } else { usize::try_from(pointer).ok()? };
            if size < 24 || read_at(&mut file, data as u64, 4)? != b"RSDS".as_slice() {
                continue;
            }
            let record = read_at(&mut file, data as u64 + 4, 20)?;
            let guid = record.get(0..16)?;
            let age = read_u32(&record, 16)?;
            let name_offset = data as u64 + 24;
            let length = usize::try_from(file.metadata().ok()?.len().checked_sub(name_offset)?).ok()?.min(MAX_PDB_PATH_BYTES + 1);
            let name = read_at(&mut file, name_offset, length)?;
            let terminator = name.iter().position(|byte| *byte == 0)?;
            let path = std::str::from_utf8(name.get(..terminator)?).ok()?;
            let pdb_name = Path::new(path).file_name()?.to_string_lossy().into_owned();
            let key = store_key(guid, age);
            return Some(CodeView { pdb_name, key });
        }
        None
    }

    /// Reads exactly `length` bytes at `offset`, so a malformed header cannot make the caller
    /// believe it owns more data than the file holds.
    fn read_at(file: &mut std::fs::File, offset: u64, length: usize) -> Option<Vec<u8>> {
        let mut buffer = vec![0u8; length];
        file.seek(SeekFrom::Start(offset)).ok()?;
        file.read_exact(&mut buffer).ok()?;
        Some(buffer)
    }

    /// Builds the `<GUID><age>` symbol store key from the raw CodeView GUID.
    ///
    /// CodeView stores the first three GUID groups little-endian, while the store key is the
    /// canonical textual GUID. Reading the bytes in raw order produces a key that does not exist
    /// on disk, so each group is decoded before it is printed.
    fn store_key(guid: &[u8], age: u32) -> String {
        let first = u32::from_le_bytes([guid[0], guid[1], guid[2], guid[3]]);
        let second = u16::from_le_bytes([guid[4], guid[5]]);
        let third = u16::from_le_bytes([guid[6], guid[7]]);
        let tail = guid[8..16].iter().map(|byte| format!("{byte:02X}")).collect::<String>();
        format!("{first:08X}{second:04X}{third:04X}{tail}{age}")
    }

    fn section_offset(section_table: &[u8], count: usize, rva: u32) -> Option<usize> {
        for index in 0..count {
            let section = index * SECTION_HEADER_SIZE;
            let virtual_size = read_u32(section_table, section + 8)?;
            let virtual_address = read_u32(section_table, section + 12)?;
            let raw_size = read_u32(section_table, section + 16)?;
            let raw_offset = read_u32(section_table, section + 20)?;
            let span = virtual_size.max(raw_size);
            if rva >= virtual_address && rva - virtual_address < span {
                let delta = usize::try_from(rva - virtual_address).ok()?;
                return usize::try_from(raw_offset).ok()?.checked_add(delta);
            }
        }
        None
    }

    fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
        Some(u16::from_le_bytes(bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?))
    }

    fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
        Some(u32::from_le_bytes(bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?))
    }

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

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    unsafe fn symbol<T: Copy>(library: *mut c_void, name: &[u8]) -> Option<T> {
        // SAFETY: `name` is a null-terminated ASCII procedure name and `library` is loaded.
        let address = unsafe { GetProcAddress(library, name.as_ptr()) };
        if address.is_null() {
            return None;
        }
        Some(unsafe { std::mem::transmute_copy::<*mut c_void, T>(&address) })
    }

    #[cfg(test)]
    mod tests {
        use std::io::Write;

        use super::*;

        const PE: usize = 0x40;
        const OPTIONAL: usize = PE + 24;
        const SECTION_TABLE: usize = OPTIONAL + 0xF0;
        const SECTION_RAW: usize = 0x200;
        const DEBUG_ENTRY: usize = 0x200;
        const CODEVIEW: usize = 0x220;
        const PDB_NAME: &[u8] = b"C:\\build\\ntkrnlmp.pdb\0";

        /// Minimal PE32+ image with one section, one debug directory entry and an RSDS record.
        fn synthetic_image() -> Vec<u8> {
            let mut bytes = vec![0u8; CODEVIEW + 24 + PDB_NAME.len()];
            bytes[0x3C..0x40].copy_from_slice(&(PE as u32).to_le_bytes());
            bytes[PE..PE + 4].copy_from_slice(b"PE\0\0");
            bytes[PE + 6..PE + 8].copy_from_slice(&1u16.to_le_bytes());
            bytes[PE + 20..PE + 22].copy_from_slice(&0xF0u16.to_le_bytes());
            bytes[OPTIONAL..OPTIONAL + 2].copy_from_slice(&PE32_PLUS.to_le_bytes());
            let directory = OPTIONAL + DATA_DIRECTORY_OFFSET + DEBUG_DIRECTORY_INDEX * 8;
            bytes[directory..directory + 4].copy_from_slice(&0x1000u32.to_le_bytes());
            bytes[directory + 4..directory + 8].copy_from_slice(&(DEBUG_ENTRY_SIZE as u32).to_le_bytes());
            bytes[SECTION_TABLE + 8..SECTION_TABLE + 12].copy_from_slice(&0x200u32.to_le_bytes());
            bytes[SECTION_TABLE + 12..SECTION_TABLE + 16].copy_from_slice(&0x1000u32.to_le_bytes());
            bytes[SECTION_TABLE + 16..SECTION_TABLE + 20].copy_from_slice(&0x200u32.to_le_bytes());
            bytes[SECTION_TABLE + 20..SECTION_TABLE + 24].copy_from_slice(&(SECTION_RAW as u32).to_le_bytes());
            bytes[DEBUG_ENTRY + 12..DEBUG_ENTRY + 16].copy_from_slice(&CODEVIEW_ENTRY.to_le_bytes());
            bytes[DEBUG_ENTRY + 16..DEBUG_ENTRY + 20].copy_from_slice(&(24u32 + PDB_NAME.len() as u32).to_le_bytes());
            bytes[DEBUG_ENTRY + 20..DEBUG_ENTRY + 24].copy_from_slice(&((CODEVIEW - SECTION_RAW) as u32 + 0x1000).to_le_bytes());
            bytes[DEBUG_ENTRY + 24..DEBUG_ENTRY + 28].copy_from_slice(&(CODEVIEW as u32).to_le_bytes());
            bytes[CODEVIEW..CODEVIEW + 4].copy_from_slice(b"RSDS");
            for (index, byte) in bytes[CODEVIEW + 4..CODEVIEW + 20].iter_mut().enumerate() {
                *byte = 0xA0 + index as u8;
            }
            bytes[CODEVIEW + 20..CODEVIEW + 24].copy_from_slice(&1u32.to_le_bytes());
            bytes[CODEVIEW + 24..CODEVIEW + 24 + PDB_NAME.len()].copy_from_slice(PDB_NAME);
            bytes
        }

        fn write_image(bytes: &[u8], tag: &str) -> PathBuf {
            let path = std::env::temp_dir().join(format!("open-debugger-{tag}-{}.bin", std::process::id()));
            std::fs::File::create(&path).and_then(|mut file| file.write_all(bytes)).expect("write synthetic image");
            path
        }

        #[test]
        fn code_view_reads_the_pdb_identity_from_rsds() {
            let path = write_image(&synthetic_image(), "rsds");
            let view = code_view(&path).expect("synthetic image carries an RSDS record");
            std::fs::remove_file(&path).ok();
            assert_eq!(view.pdb_name, "ntkrnlmp.pdb");
            assert_eq!(view.key, "A3A2A1A0A5A4A7A6A8A9AAABACADAEAF1");
        }

        #[test]
        fn code_view_rejects_unknown_codeview_signatures() {
            let mut image = synthetic_image();
            image[CODEVIEW..CODEVIEW + 4].copy_from_slice(b"NB10");
            let path = write_image(&image, "nb10");
            assert!(code_view(&path).is_none(), "only RSDS is understood, so an unknown record must not invent a key");
            std::fs::remove_file(&path).ok();
        }
    }
}
