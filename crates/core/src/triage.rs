//! Kernel triage dump layout: faulting context, crash stack block, and the module table.
//!
//! A triage dump does not carry page tables, so a generic virtual-to-physical walk is not
//! possible. What it does carry is a header describing the blocks that were captured. Those
//! blocks are located through the descriptor area that follows the 64-bit dump header, and
//! every descriptor is validated against the faulting context before it is used.

use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::PathBuf,
};

use crate::{
    input::{Input, read_u32, read_u64},
    minidump::{StackFrame, StackFrameSource, StackReference},
};

/// Size of `DUMP_HEADER64`; the triage descriptor area starts right after it.
const TRIAGE_OFFSET: u64 = 0x2000;
const CONTEXT_OFFSET_FIELD: u64 = TRIAGE_OFFSET + 0x0C;
const DESCRIPTOR_END: u64 = TRIAGE_OFFSET + 0x180;
const CONTEXT_RSP: u64 = 0x98;
const CONTEXT_RIP: u64 = 0xF8;

const KERNEL_BASE_MIN: u64 = 0xFFFF_8000_0000_0000;
const PAGE_SIZE: u64 = 0x1000;
const MODULE_RECORD_STRIDE: u64 = 0x90;
const RECORD_NAME: u64 = 0x00;
const RECORD_BASE: u64 = 0x38;
const RECORD_SIZE: u64 = 0x48;
const RECORD_TIMESTAMP: u64 = 0x88;
const MAX_MODULES: u32 = 4096;
const MAX_MODULE_NAME_CHARS: u32 = 260;
const MAX_MODULE_SIZE: u32 = 0x4000_0000;
const MAX_STACK_BYTES: u32 = 0x0040_0000;
const MIN_MODULE_RECORDS: usize = 8;

pub(crate) struct KernelModule {
    pub name: String,
    pub base: u64,
    pub size: u32,
    pub timestamp: u32,
}

impl KernelModule {
    fn contains(&self, address: u64) -> Option<u64> {
        let span = u64::from(self.size);
        if address >= self.base && address < self.base + span { Some(address - self.base) } else { None }
    }
}

pub(crate) struct StackBlock {
    pub va: u64,
    pub file_offset: u64,
    pub size: u32,
}

pub(crate) struct Triage {
    pub context_rip: u64,
    pub pfn_database_base: Option<u64>,
    pub stack_block: Option<StackBlock>,
    pub modules: Vec<KernelModule>,
    pub warnings: Vec<String>,
}

/// Reads the triage header and returns the mapped stack block plus the loaded module table.
pub(crate) fn parse(input: &Input) -> Option<Triage> {
    let context_offset = u64::from(read_u32(input, CONTEXT_OFFSET_FIELD)?);
    if context_offset >= input.len() {
        return None;
    }
    let context_rsp = read_u64(input, context_offset + CONTEXT_RSP)?;
    let context_rip = read_u64(input, context_offset + CONTEXT_RIP)?;
    if context_rsp < KERNEL_BASE_MIN || context_rip < KERNEL_BASE_MIN {
        return None;
    }

    let mut warnings = Vec::new();
    let stack_block = locate_stack_block(input, context_rsp, &mut warnings);
    let modules = locate_module_table(input, &mut warnings).unwrap_or_default();
    let pfn_database_base = read_u64(input, 0x18).filter(|value| *value >= KERNEL_BASE_MIN);

    Some(Triage { context_rip, pfn_database_base, stack_block, modules, warnings })
}

/// Finds the descriptor whose recorded virtual address equals `CONTEXT.Rsp`.
///
/// A descriptor is a pair of `u32` file offset / size immediately followed by the `u64`
/// virtual address it maps to. Patching the offset, size and address of that descriptor in a
/// copy of the dump and re-reading `rsp` in a debugger confirmed each field.
fn locate_stack_block(input: &Input, rsp: u64, warnings: &mut Vec<String>) -> Option<StackBlock> {
    let mut position = TRIAGE_OFFSET;
    while position + 8 <= DESCRIPTOR_END {
        if read_u64(input, position) == Some(rsp) && position >= TRIAGE_OFFSET + 0x20 {
            let file_offset = u64::from(read_u32(input, position - 0x20)?);
            let size = read_u32(input, position - 0x1C)?;
            if (0x200..=MAX_STACK_BYTES).contains(&size) && file_offset.saturating_add(u64::from(size)) <= input.len() {
                return Some(StackBlock { va: rsp, file_offset, size });
            }
            warnings.push("the crash stack descriptor has an unusable offset or size".to_string());
        }
        position += 4;
    }
    warnings.push("no triage memory block maps the faulting stack pointer".to_string());
    None
}

/// Finds a descriptor that expands into a self-consistent module record table.
fn locate_module_table(input: &Input, warnings: &mut Vec<String>) -> Option<Vec<KernelModule>> {
    let mut found: Option<Vec<KernelModule>> = None;
    let mut position = TRIAGE_OFFSET;
    while position + 8 <= DESCRIPTOR_END {
        let file_offset = u64::from(read_u32(input, position)?);
        let count = read_u32(input, position + 4)?;
        if (1..=MAX_MODULES).contains(&count)
            && file_offset.saturating_add(u64::from(count) * MODULE_RECORD_STRIDE) <= input.len()
            && let Some(modules) = parse_module_records(input, file_offset, count)
            && found.as_ref().is_none_or(|best| modules.len() > best.len())
        {
            found = Some(modules);
        }
        position += 4;
    }
    if found.is_none() {
        warnings.push("no triage descriptor expands into a valid kernel module table".to_string());
    }
    found
}

fn parse_module_records(input: &Input, table_offset: u64, count: u32) -> Option<Vec<KernelModule>> {
    let mut modules = Vec::with_capacity(count as usize);
    for index in 0..u64::from(count) {
        let record = table_offset + index * MODULE_RECORD_STRIDE;
        let name_offset = read_u64(input, record + RECORD_NAME)?;
        let name = read_module_name(input, name_offset)?;
        let base = read_u64(input, record + RECORD_BASE)?;
        let size = read_u32(input, record + RECORD_SIZE)?;
        if base < KERNEL_BASE_MIN || base % PAGE_SIZE != 0 || size == 0 || size > MAX_MODULE_SIZE || u64::from(size) % PAGE_SIZE != 0 {
            return None;
        }
        let timestamp = read_u32(input, record + RECORD_TIMESTAMP)?;
        modules.push(KernelModule { name, base, size, timestamp });
    }
    (modules.len() >= MIN_MODULE_RECORDS).then_some(modules)
}

fn read_module_name(input: &Input, offset: u64) -> Option<String> {
    let chars = read_u32(input, offset)?;
    if chars == 0 || chars > MAX_MODULE_NAME_CHARS {
        return None;
    }
    let bytes = input.read(offset + 4, chars * 2)?;
    let (chunks, _) = bytes.as_chunks::<2>();
    if chunks.iter().any(|unit| !unit[0].is_ascii_graphic() && unit[0] != b' ') {
        return None;
    }
    let units: Vec<u16> = chunks.iter().map(|chunk| u16::from_le_bytes(*chunk)).collect();
    let text = String::from_utf16_lossy(&units);
    (!text.is_empty()).then_some(text)
}

/// Builds `MODULE+offset` frames from the faulting context and the crash stack block.
///
/// Return addresses are verified against the matching module image when one is available on
/// disk: the bytes immediately before the address must encode a call. A triage dump carries no
/// unwind metadata, so frames are not produced by a real stack unwind; unverified stack words
/// inside a module range are kept and marked as scanned rather than dropped silently.
///
/// The second value lists stack words that equal a loaded module's base address. Those are
/// image references passed as arguments, which is evidence a driver was being handled, not proof
/// that it caused the bugcheck.
pub(crate) fn stack_frames(input: &Input, triage: &mut Triage) -> (Vec<StackFrame>, Vec<StackReference>) {
    let mut frames = vec![describe_frame(triage.context_rip, &triage.modules, StackFrameSource::Context)];
    let mut references = Vec::new();
    let Some(block) = &triage.stack_block
    else {
        return (frames, references);
    };
    let block_offset = block.file_offset;
    let block_size = block.size;
    let Some(data) = input.read(block_offset, block_size)
    else {
        return (frames, references);
    };

    let mut images: Vec<Option<ModuleImage>> = Vec::new();
    images.resize_with(triage.modules.len(), || None);
    let mut skipped = 0u32;
    let mut unavailable = Vec::new();

    let words = data.len() / 8;
    for index in 0..words {
        let Some(chunk) = data.get(index * 8..index * 8 + 8)
        else {
            break;
        };
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(chunk);
        let address = u64::from_le_bytes(bytes);
        let Some((module_index, offset)) = resolve_module(&triage.modules, address)
        else {
            continue;
        };
        if offset == 0 {
            // A module base on the stack is an argument, not a call site.
            let reference = StackReference { address: format!("0x{address:016X}"), module: triage.modules[module_index].name.clone() };
            if !references.iter().any(|existing| existing.address == reference.address && existing.module == reference.module) {
                references.push(reference);
            }
            continue;
        }
        if let Some(image) = module_image(&triage.modules[module_index], &mut images[module_index]) {
            if !image.is_call_target(offset as u32) {
                skipped += 1;
                continue;
            }
            frames.push(frame(address, &triage.modules[module_index], offset, StackFrameSource::CallSite));
        }
        else {
            if !unavailable.contains(&module_index) {
                unavailable.push(module_index);
            }
            frames.push(frame(address, &triage.modules[module_index], offset, StackFrameSource::Scan));
        }
    }

    if skipped > 0 {
        triage
            .warnings
            .push(format!("{skipped} stack words resolved inside loaded modules but are not call sites, so they were not reported as frames"));
    }
    if !unavailable.is_empty() {
        let names = unavailable.iter().map(|index| triage.modules[*index].name.clone()).collect::<Vec<_>>();
        triage.warnings.push(format!(
            "module images for {} are not available on disk with a matching timestamp, so their stack words are unverified",
            names.join(", ")
        ));
    }
    (frames, references)
}

fn describe_frame(address: u64, modules: &[KernelModule], source: StackFrameSource) -> StackFrame {
    match resolve_module(modules, address) {
        Some((index, offset)) => frame(address, &modules[index], offset, source),
        None => StackFrame { address: format!("0x{address:016X}"), module: None, offset_in_module: None, source },
    }
}

fn frame(address: u64, module: &KernelModule, offset: u64, source: StackFrameSource) -> StackFrame {
    StackFrame {
        address: format!("0x{address:016X}"),
        module: Some(module.name.clone()),
        offset_in_module: Some(format!("0x{offset:X}")),
        source,
    }
}

fn resolve_module(modules: &[KernelModule], address: u64) -> Option<(usize, u64)> {
    modules.iter().enumerate().find_map(|(index, module)| module.contains(address).map(|offset| (index, offset)))
}

fn module_image<'a>(module: &KernelModule, cache: &'a mut Option<ModuleImage>) -> Option<&'a mut ModuleImage> {
    if cache.is_none() {
        *cache = ModuleImage::open(module);
    }
    cache.as_mut()
}

/// A module image on disk, used only to tell a return address from an ordinary stack word.
struct ModuleImage {
    file: File,
    sections: Vec<PeSection>,
}

struct PeSection {
    virtual_address: u32,
    virtual_size: u32,
    raw_offset: u32,
    raw_size: u32,
}

impl ModuleImage {
    fn open(module: &KernelModule) -> Option<Self> {
        let path = image_path(&module.name)?;
        let mut file = File::open(&path).ok()?;
        let header = read_prefix(&mut file, 0)?;
        if header.get(0..2) != Some(b"MZ") {
            return None;
        }
        let pe_offset = u32::from_le_bytes(header.get(0x3C..0x40)?.try_into().ok()?) as usize;
        let timestamp = u32::from_le_bytes(header.get(pe_offset + 8..pe_offset + 12)?.try_into().ok()?);
        if timestamp != module.timestamp {
            return None;
        }
        let section_count = u16::from_le_bytes(header.get(pe_offset + 6..pe_offset + 8)?.try_into().ok()?) as usize;
        let optional_size = u16::from_le_bytes(header.get(pe_offset + 20..pe_offset + 22)?.try_into().ok()?) as usize;
        let table = pe_offset + 24 + optional_size;
        let mut sections = Vec::with_capacity(section_count);
        for index in 0..section_count {
            let entry = table + index * 40;
            let raw = header.get(entry..entry + 40)?;
            sections.push(PeSection {
                virtual_size: u32::from_le_bytes(raw.get(8..12)?.try_into().ok()?),
                virtual_address: u32::from_le_bytes(raw.get(12..16)?.try_into().ok()?),
                raw_size: u32::from_le_bytes(raw.get(16..20)?.try_into().ok()?),
                raw_offset: u32::from_le_bytes(raw.get(20..24)?.try_into().ok()?),
            });
        }
        Some(Self { file, sections })
    }

    /// True when the bytes ending at `rva` encode a direct call or a RIP-relative call.
    fn is_call_target(&mut self, rva: u32) -> bool {
        let before = match self.bytes_before(rva, 8) {
            Some(bytes) => bytes,
            None => return false,
        };
        before[3] == 0xE8 || (before[2] == 0xFF && before[3] == 0x15)
    }

    fn bytes_before(&mut self, rva: u32, count: u64) -> Option<Vec<u8>> {
        let offset = self.rva_to_offset(rva)?;
        let start = offset.checked_sub(count)?;
        read_at(&mut self.file, start, count as usize)
    }

    fn rva_to_offset(&self, rva: u32) -> Option<u64> {
        self.sections.iter().find_map(|section| {
            let span = section.virtual_size.max(section.raw_size);
            if rva < section.virtual_address || u64::from(rva) >= u64::from(section.virtual_address) + u64::from(span) {
                return None;
            }
            Some(u64::from(section.raw_offset) + u64::from(rva - section.virtual_address))
        })
    }
}

/// Reads exactly `size` bytes starting at `offset`, or `None` when the file is shorter.
fn read_at(file: &mut File, offset: u64, size: usize) -> Option<Vec<u8>> {
    file.seek(SeekFrom::Start(offset)).ok()?;
    let mut buffer = vec![0u8; size];
    file.read_exact(&mut buffer).ok()?;
    Some(buffer)
}

fn read_prefix(file: &mut File, offset: u64) -> Option<Vec<u8>> {
    read_at(file, offset, 0x1000)
}

pub(crate) fn image_path(name: &str) -> Option<PathBuf> {
    if !name.chars().all(|character| character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')) {
        return None;
    }
    let root = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("C:\\Windows"));
    let candidates = [root.join("System32").join(name), root.join("System32").join("drivers").join(name)];
    candidates.into_iter().find(|path| path.is_file())
}

/// The PFN database entry for `pfn` is `PfnDataBase + pfn * sizeof(MMPFN)`; `MMPFN` is 0x30 bytes on x64.
pub(crate) fn pfn_database_entry(base: u64, pfn: u64) -> u64 {
    base + pfn * 0x30
}
