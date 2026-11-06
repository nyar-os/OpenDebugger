//! Function names for `MODULE+offset` frames, bound to `dbghelp.dll` at runtime.
//!
//! A triage dump carries no module images, so naming a frame needs two inputs beyond the dump:
//! the module binary, which carries the CodeView record that names its PDB, and that PDB. This
//! module looks both up in a local symbol store laid out like the debugger `sym` directory and
//! asks `dbghelp` which function contains each stack address. When an image or PDB is missing the
//! frame keeps its `MODULE+offset` form and the report says what is missing.

use crate::triage::KernelModule;

pub(crate) struct ResolvedSymbol {
    pub function: String,
    pub displacement: u64,
}

/// Resolves `addresses` against the module table.
///
/// Returns one entry per address, in the same order, plus warnings describing any missing input.
pub(crate) fn function_names(modules: &[KernelModule], addresses: &[u64]) -> (Vec<Option<ResolvedSymbol>>, Vec<String>) {
    #[cfg(windows)]
    {
        windows::function_names(modules, addresses)
    }
    #[cfg(not(windows))]
    {
        let _ = (modules, addresses);
        (Vec::new(), Vec::new())
    }
}

#[cfg(windows)]
mod windows {
    use std::{
        ffi::c_void,
        path::{Path, PathBuf},
        sync::Mutex,
    };

    use super::{KernelModule, ResolvedSymbol};

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

    pub(super) fn function_names(modules: &[KernelModule], addresses: &[u64]) -> (Vec<Option<ResolvedSymbol>>, Vec<String>) {
        let symbols = std::iter::repeat_with(|| None).take(addresses.len()).collect::<Vec<Option<ResolvedSymbol>>>();
        let _serialized = SERIALIZE.lock().unwrap_or_else(|poison| poison.into_inner());

        let Some(store) = symbol_store()
        else {
            return (symbols, vec![
                "function names need a local symbol store: set `OPEN_DEBUGGER_SYMBOL_STORE` to a directory laid out like the debugger symbol cache, because a triage dump carries no module images and no PDB paths".to_string(),
            ]);
        };
        let Some(engine) = Engine::open(&store)
        else {
            return (symbols, vec!["`dbghelp.dll` could not be bound, so frames stay at `MODULE+offset`".to_string()]);
        };
        if !engine.initialize() {
            return (symbols, vec!["`dbghelp` rejected the symbol store, so frames stay at `MODULE+offset`".to_string()]);
        }
        engine.resolve(modules, addresses)
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

        fn initialize(&self) -> bool {
            // SAFETY: `dbghelp` accepts any non-zero unique handle value and a null-terminated path.
            unsafe {
                (self.set_options)(SYMOPT_UNDNAME | SYMOPT_NO_PROMPTS);
                (self.initialize)(PROCESS_HANDLE, wide(&self.store.to_string_lossy()).as_ptr(), 0) != 0
            }
        }

        fn resolve(&self, modules: &[KernelModule], addresses: &[u64]) -> (Vec<Option<ResolvedSymbol>>, Vec<String>) {
            let mut symbols = std::iter::repeat_with(|| None).take(addresses.len()).collect::<Vec<Option<ResolvedSymbol>>>();
            let mut warnings = Vec::new();
            let mut missing_images: Vec<String> = Vec::new();
            let mut failed_loads: Vec<String> = Vec::new();
            for index in unique_modules(modules, addresses) {
                let module = &modules[index];
                let Some(image) = self.image(module)
                else {
                    missing_images.push(module.name.clone());
                    continue;
                };
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
                }
            }
            if !missing_images.is_empty() {
                warnings.push(format!(
                    "the symbol store has no image at the recorded timestamp and size for {}, so those frames stay at `MODULE+offset`",
                    missing_images.join(", ")
                ));
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
            (symbols, warnings)
        }

        /// `<store>\<name>\<timestamp><size>\<name>` is the layout a debugger symbol cache uses.
        fn image(&self, module: &KernelModule) -> Option<PathBuf> {
            let store = &self.store;
            let key = format!("{:08X}{:x}", module.timestamp, module.size);
            let entries = std::fs::read_dir(store.join(&module.name)).ok()?;
            entries.flatten().find_map(|entry| {
                if !entry.file_name().to_string_lossy().eq_ignore_ascii_case(&key) {
                    return None;
                }
                let image = entry.path().join(&module.name);
                image.is_file().then_some(image)
            })
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
}
