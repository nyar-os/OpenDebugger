//! The local symbol store: where a module image and its PDB live, and what identity they carry.
//!
//! The store is laid out like the debugger `sym` directory. An image sits at
//! `<store>\<module>\<timestamp><size>\<module>`, and the PDB an image names sits at
//! `<store>\<pdb>\<GUID><age>\<pdb>`. Nothing here needs a host library: the layout is directories
//! and the identity is a CodeView record inside the image.
//!
//! A dump names modules by base, size and timestamp, so the directory key is built from those two
//! fields. Case is ignored when a directory or file is looked up, because a dump name and a store
//! name can differ in case and still describe the same module.

use std::{
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use crate::triage::KernelModule;

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

/// The identity a module image records for its PDB.
///
/// `pdb_name` and the `<GUID><age>` key together are the exact PDB a frame needs, which is what a
/// missing-symbol report has to print. The GUID is the 16 raw CodeView bytes in stored order,
/// uppercase, followed by the decimal age, matching the symbol store directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CodeView {
    pub pdb_name: String,
    pub key: String,
}

/// Finds the symbol store for this host.
///
/// `OPEN_DEBUGGER_SYMBOL_STORE` wins when it names a directory, so a store can live anywhere. The
/// fallback is the Windows Kits store, which is where the debugger keeps symbols when it has
/// already downloaded them.
pub(crate) fn symbol_store() -> Option<PathBuf> {
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

/// `<timestamp><size>` is the directory an image occupies inside its module directory.
pub(crate) fn image_key(module: &KernelModule) -> String {
    format!("{:08X}{:x}", module.timestamp, module.size)
}

/// Path the image must occupy for this module, whether or not it exists.
pub(crate) fn expected_image(store: &Path, module: &KernelModule) -> PathBuf {
    store.join(&module.name).join(image_key(module)).join(&module.name)
}

/// `<store>\<name>\<timestamp><size>\<name>` is the layout a debugger symbol cache uses.
pub(crate) fn find_image(store: &Path, module: &KernelModule) -> Option<PathBuf> {
    let directory = child(store, &module.name)?;
    let entry = child(&directory, &image_key(module))?;
    let image = child(&entry, &module.name)?;
    image.is_file().then_some(image)
}

/// Path the PDB must occupy, derived from the identity the image records.
pub(crate) fn expected_pdb(store: &Path, code_view: &CodeView) -> PathBuf {
    store.join(&code_view.pdb_name).join(&code_view.key).join(&code_view.pdb_name)
}

/// Finds the PDB an image names, ignoring case on every directory level.
pub(crate) fn find_pdb(store: &Path, code_view: &CodeView) -> Option<PathBuf> {
    let directory = child(store, &code_view.pdb_name)?;
    let key = child(&directory, &code_view.key)?;
    let file = child(&key, &code_view.pdb_name)?;
    file.is_file().then_some(file)
}

pub(crate) fn fetch_command(image: &Path, store: &Path) -> String {
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

/// Reads the RSDS CodeView record of a PE image.
///
/// Only the headers, the section table, the debug directory entry and the RSDS record are
/// read, so an eleven megabyte image costs a few kilobytes instead of a full copy. Returns
/// `None` for anything this module does not understand: a missing DOS or PE header, a non
/// PE32+ optional header, an absent debug directory, or a CodeView record without the `RSDS`
/// signature. The PDB name is taken from the file part of the recorded path, because the
/// build machine path does not exist on the analysis host.
pub(crate) fn code_view(image: &Path) -> Option<CodeView> {
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

    #[test]
    fn the_image_key_joins_the_dump_timestamp_and_size() {
        let module = KernelModule { name: "ntoskrnl.exe".to_string(), base: 0xFFFF_F000_0000_0000, size: 0x10_0000, timestamp: 0x4A5B_6C7D };
        assert_eq!(image_key(&module), "4A5B6C7D100000");
    }
}
