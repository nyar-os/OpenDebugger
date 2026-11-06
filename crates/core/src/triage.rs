//! Kernel triage dump layout: faulting context, crash stack block, and the module table.
//!
//! A triage dump does not carry page tables, so a generic virtual-to-physical walk is not
//! possible. What it does carry is a record of the virtual ranges that were captured: the
//! descriptor area after the 64-bit header locates the faulting stack block, and a table of
//! `(virtual address, file offset, size)` records maps the remaining captured ranges. Every
//! descriptor and record is validated before it is used.

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
const CONTEXT_RBP: u64 = 0xA0;
const CONTEXT_RIP: u64 = 0xF8;
const MAX_FRAME_POINTER_LINKS: usize = 64;
const MAX_STACK_GUESSES: usize = 64;

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
const BLOCK_RECORD_STRIDE: u64 = 0x10;
const MAX_BLOCK_RECORDS: u32 = 8192;
const MAX_BLOCK_SIZE: u32 = 0x0040_0000;
const MIN_BLOCK_RECORDS: usize = 4;

pub(crate) struct KernelModule {
    pub name: String,
    pub base: u64,
    pub size: u32,
    pub timestamp: u32,
}

impl KernelModule {
    pub(crate) fn contains(&self, address: u64) -> Option<u64> {
        let span = u64::from(self.size);
        if address >= self.base && address < self.base + span { Some(address - self.base) } else { None }
    }
}

pub(crate) struct StackBlock {
    pub va: u64,
    pub file_offset: u64,
    pub size: u32,
}

/// A virtual address range that this dump stores at a known file offset.
pub(crate) struct TriageBlock {
    pub va: u64,
    pub file_offset: u64,
    pub size: u32,
}

impl TriageBlock {
    pub(crate) fn contains(&self, address: u64) -> bool {
        address >= self.va && address - self.va < u64::from(self.size)
    }
}

pub(crate) struct Triage {
    pub context_rip: u64,
    pub context_rsp: u64,
    pub context_rbp: Option<u64>,
    pub pfn_database_base: Option<u64>,
    pub stack_block: Option<StackBlock>,
    pub modules: Vec<KernelModule>,
    /// Captured virtual ranges, used to tell whether an address has content in this dump.
    pub blocks: Vec<TriageBlock>,
    pub warnings: Vec<String>,
}

impl Triage {
    /// Reads `size` bytes at `address` from the captured range that contains it.
    pub(crate) fn read(&self, input: &Input, address: u64, size: u32) -> Option<Vec<u8>> {
        let block = self.blocks.iter().find(|block| block.contains(address))?;
        let delta = address - block.va;
        if delta + u64::from(size) > u64::from(block.size) {
            return None;
        }
        input.read(block.file_offset + delta, size)
    }
}

/// Reads the triage header and returns the mapped stack block plus the loaded module table.
pub(crate) fn parse(input: &Input) -> Option<Triage> {
    let context_offset = u64::from(read_u32(input, CONTEXT_OFFSET_FIELD)?);
    if context_offset >= input.len() {
        return None;
    }
    let context_rsp = read_u64(input, context_offset + CONTEXT_RSP)?;
    let context_rbp = read_u64(input, context_offset + CONTEXT_RBP).filter(|value| *value >= KERNEL_BASE_MIN);
    let context_rip = read_u64(input, context_offset + CONTEXT_RIP)?;
    if context_rsp < KERNEL_BASE_MIN || context_rip < KERNEL_BASE_MIN {
        return None;
    }

    let mut warnings = Vec::new();
    let stack_block = locate_stack_block(input, context_rsp, &mut warnings);
    let modules = locate_module_table(input, &mut warnings).unwrap_or_default();
    let mut blocks = locate_block_table(input, &mut warnings);
    if let Some(stack) = stack_block.as_ref()
        && !blocks.iter().any(|block| block.contains(stack.va))
    {
        blocks.push(TriageBlock { va: stack.va, file_offset: stack.file_offset, size: stack.size });
    }
    let pfn_database_base = read_u64(input, 0x18).filter(|value| *value >= KERNEL_BASE_MIN);

    Some(Triage { context_rip, context_rsp, context_rbp, pfn_database_base, stack_block, modules, blocks, warnings })
}

/// Finds the descriptor that expands into the table of captured virtual ranges.
///
/// Each record is a `u64` virtual address followed by a `u32` file offset and a `u32` byte
/// count, and consecutive records tile the file. Reading the same virtual addresses through
/// a debugger returns the bytes at the recorded offsets, which confirms the layout.
fn locate_block_table(input: &Input, warnings: &mut Vec<String>) -> Vec<TriageBlock> {
    let mut best: Vec<TriageBlock> = Vec::new();
    let mut position = TRIAGE_OFFSET;
    while position + 8 <= DESCRIPTOR_END {
        let Some(file_offset) = read_u32(input, position)
        else {
            break;
        };
        let Some(count) = read_u32(input, position + 4)
        else {
            break;
        };
        let in_bounds = u64::from(file_offset).saturating_add(u64::from(count) * BLOCK_RECORD_STRIDE) <= input.len();
        if (1..=MAX_BLOCK_RECORDS).contains(&count)
            && in_bounds
            && let Some(blocks) = parse_block_records(input, u64::from(file_offset), count)
            && blocks.len() > best.len()
        {
            best = blocks;
        }
        position += 4;
    }
    if best.is_empty() {
        warnings.push("no triage descriptor expands into a captured memory block table".to_string());
    }
    best
}

fn parse_block_records(input: &Input, table_offset: u64, count: u32) -> Option<Vec<TriageBlock>> {
    let mut blocks: Vec<TriageBlock> = Vec::with_capacity(count as usize);
    for index in 0..u64::from(count) {
        let record = table_offset + index * BLOCK_RECORD_STRIDE;
        let va = read_u64(input, record)?;
        let file_offset = u64::from(read_u32(input, record + 8)?);
        let size = read_u32(input, record + 0x0C)?;
        if va < KERNEL_BASE_MIN || size == 0 || size > MAX_BLOCK_SIZE || file_offset.saturating_add(u64::from(size)) > input.len() {
            return None;
        }
        if let Some(previous) = blocks.last()
            && previous.file_offset + u64::from(previous.size) != file_offset
        {
            return None;
        }
        blocks.push(TriageBlock { va, file_offset, size });
    }
    (blocks.len() >= MIN_BLOCK_RECORDS).then_some(blocks)
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
/// disk: the bytes immediately before the address must encode a call. When the crashing thread
/// kept a frame-pointer chain inside the captured stack block, that chain contributes additional
/// frames. A triage dump carries no unwind metadata, so this is not a real stack unwind.
///
/// Trusted frames and guesses are returned in separate vectors. A guess is a stack word that
/// resolves into a loaded module but cannot be verified, because the image is missing or the
/// frame-pointer link itself cannot be checked. Guesses never appear in the trusted sequence.
///
/// The third value lists stack words that equal a loaded module's base address. Those are
/// image references passed as arguments, which is evidence a driver was being handled, not proof
/// that it caused the bugcheck. The fourth value reports the symbol store state, naming every
/// module whose image or PDB is missing and the command that prefetches it.
pub(crate) fn stack_frames(
    input: &Input,
    triage: &mut Triage,
) -> (Vec<StackFrame>, Vec<StackFrame>, Vec<StackReference>, crate::symbols::SymbolDiagnostics) {
    let mut trusted: Vec<(u64, u64, StackFrame)> =
        vec![(triage.context_rsp, triage.context_rip, describe_frame(triage.context_rip, &triage.modules, StackFrameSource::Context))];
    let mut guesses: Vec<(u64, u64, StackFrame)> = Vec::new();
    let mut references = Vec::new();
    let stack = triage.stack_block.as_ref().map(|block| (block.va, block.file_offset, block.size));
    let data = stack.and_then(|(_, offset, size)| input.read(offset, size));
    let mut images: Vec<Option<ModuleImage>> = Vec::new();
    images.resize_with(triage.modules.len(), || None);
    let mut skipped = 0u32;
    let mut unavailable = Vec::new();
    let mut chained_slots: Vec<u64> = Vec::new();
    let mut dropped_guesses = 0u32;

    if let (Some((block_va, _, _)), Some(data), Some(rbp)) = (stack, data.as_deref(), triage.context_rbp) {
        for (slot, address) in frame_pointer_slots(triage.context_rsp, rbp, block_va, data) {
            let Some((verified, slot, stack_frame)) =
                classify_stack_word(slot, address, &triage.modules, &mut images, &mut references, &mut unavailable, &mut skipped)
            else {
                chained_slots.push(slot);
                continue;
            };
            if verified {
                trusted.push((slot, address, StackFrame { source: StackFrameSource::FramePointer, ..stack_frame }));
                chained_slots.push(slot);
            }
            else if guesses.len() < MAX_STACK_GUESSES {
                guesses.push((slot, address, stack_frame));
                chained_slots.push(slot);
            }
            else {
                dropped_guesses += 1;
            }
        }
    }

    if let (Some((block_va, _, _)), Some(data)) = (stack, data.as_deref()) {
        let words = data.len() / 8;
        for index in 0..words {
            let Some(chunk) = data.get(index * 8..index * 8 + 8)
            else {
                break;
            };
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(chunk);
            let address = u64::from_le_bytes(bytes);
            let slot = block_va + (index * 8) as u64;
            if chained_slots.contains(&slot) {
                continue;
            }
            let Some((verified, slot, stack_frame)) =
                classify_stack_word(slot, address, &triage.modules, &mut images, &mut references, &mut unavailable, &mut skipped)
            else {
                continue;
            };
            if verified {
                trusted.push((slot, address, stack_frame));
            }
            else if guesses.len() < MAX_STACK_GUESSES {
                guesses.push((slot, address, stack_frame));
            }
            else {
                dropped_guesses += 1;
            }
        }
    }

    trusted.sort_by_key(|(slot, _, _)| *slot);
    guesses.sort_by_key(|(slot, _, _)| *slot);

    let mut frames: Vec<StackFrame> = trusted.into_iter().map(|(_, _, frame)| frame).collect();
    let separate_guesses: Vec<StackFrame> = guesses.into_iter().map(|(_, _, frame)| frame).collect();
    let mut addresses: Vec<u64> = frames.iter().filter_map(frame_address).collect();
    addresses.extend(separate_guesses.iter().filter_map(frame_address));

    if skipped > 0 {
        triage
            .warnings
            .push(format!("{skipped} stack words resolved inside loaded modules but are not call sites, so they were not reported as frames"));
    }
    if let Some(rbp) = triage.context_rbp
        && !chained_slots.is_empty()
    {
        let links = chained_slots.len();
        triage.warnings.push(format!(
            "the frame-pointer chain at 0x{rbp:016X} contributed {links} stack slots, each checked against the module image before it was reported"
        ));
    }
    if dropped_guesses > 0 {
        triage.warnings.push(format!("{dropped_guesses} unverified stack words were dropped after the {MAX_STACK_GUESSES}-guess report limit"));
    }
    if !unavailable.is_empty() {
        let names = unavailable.iter().map(|index| triage.modules[*index].name.clone()).collect::<Vec<_>>();
        triage.warnings.push(format!(
            "module images for {} are not available on disk with a matching timestamp, so their stack words are reported as guesses",
            names.join(", ")
        ));
    }
    let (symbols, diagnostics) = crate::symbols::function_names(&triage.modules, &addresses);
    triage.warnings.extend(diagnostics.warnings.iter().cloned());
    let trusted_count = frames.len();
    for (index, frame) in frames.iter_mut().enumerate() {
        apply_symbol(frame, symbols.get(index).and_then(|symbol| symbol.as_ref()));
    }
    let mut separate_guesses = separate_guesses;
    for (offset, frame) in separate_guesses.iter_mut().enumerate() {
        apply_symbol(frame, symbols.get(trusted_count + offset).and_then(|symbol| symbol.as_ref()));
    }
    (frames, separate_guesses, references, diagnostics)
}

/// Resolves one stack word into a frame.
///
/// Returns `None` for non-module words and for module base references, which are recorded in
/// `references` instead. The boolean is true when the word was verified as a call target.
fn classify_stack_word(
    slot: u64,
    address: u64,
    modules: &[KernelModule],
    images: &mut [Option<ModuleImage>],
    references: &mut Vec<StackReference>,
    unavailable: &mut Vec<usize>,
    skipped: &mut u32,
) -> Option<(bool, u64, StackFrame)> {
    let (module_index, offset) = resolve_module(modules, address)?;
    if offset == 0 {
        // A module base on the stack is an argument, not a call site.
        let reference = StackReference { address: format!("0x{address:016X}"), module: modules[module_index].name.clone() };
        if !references.iter().any(|existing| existing.address == reference.address && existing.module == reference.module) {
            references.push(reference);
        }
        return None;
    }
    if let Some(image) = module_image(&modules[module_index], &mut images[module_index]) {
        if !image.is_call_target(offset as u32) {
            *skipped += 1;
            return None;
        }
        return Some((true, slot, frame(address, &modules[module_index], offset, StackFrameSource::CallSite)));
    }
    if !unavailable.contains(&module_index) {
        unavailable.push(module_index);
    }
    Some((false, slot, frame(address, &modules[module_index], offset, StackFrameSource::Scan)))
}

fn apply_symbol(frame: &mut StackFrame, symbol: Option<&crate::symbols::ResolvedSymbol>) {
    if let Some(symbol) = symbol {
        frame.function = Some(symbol.function.clone());
        frame.function_offset = Some(format!("0x{:X}", symbol.displacement));
    }
}

fn frame_address(frame: &StackFrame) -> Option<u64> {
    frame.address.strip_prefix("0x").and_then(|value| u64::from_str_radix(value, 16).ok())
}

/// Walks a frame-pointer chain inside the captured stack block.
///
/// A link is accepted only when the saved frame pointer grows monotonically, stays inside the
/// captured block, and the return slot holds a kernel address. The returned slots are
/// `(stack address of the return slot, return address)` pairs, which callers still have to
/// verify against the module image.
fn frame_pointer_slots(rsp: u64, rbp: u64, block_va: u64, data: &[u8]) -> Vec<(u64, u64)> {
    let mut slots = Vec::new();
    if rbp < rsp || rbp < block_va {
        return slots;
    }
    let end = block_va.saturating_add(data.len() as u64);
    let mut link = rbp;
    for _ in 0..MAX_FRAME_POINTER_LINKS {
        let Some(offset) = link.checked_sub(block_va).map(|value| value as usize)
        else {
            break;
        };
        let Some(window) = data.get(offset..offset.saturating_add(16))
        else {
            break;
        };
        let mut next_bytes = [0u8; 8];
        next_bytes.copy_from_slice(&window[0..8]);
        let mut return_bytes = [0u8; 8];
        return_bytes.copy_from_slice(&window[8..16]);
        let next = u64::from_le_bytes(next_bytes);
        let return_address = u64::from_le_bytes(return_bytes);
        if return_address < KERNEL_BASE_MIN {
            break;
        }
        slots.push((link + 8, return_address));
        if next <= link || next >= end || next < link + 16 {
            break;
        }
        link = next;
    }
    slots
}

fn describe_frame(address: u64, modules: &[KernelModule], source: StackFrameSource) -> StackFrame {
    match resolve_module(modules, address) {
        Some((index, offset)) => frame(address, &modules[index], offset, source),
        None => StackFrame {
            address: format!("0x{address:016X}"),
            module: None,
            offset_in_module: None,
            function: None,
            function_offset: None,
            source,
        },
    }
}

fn frame(address: u64, module: &KernelModule, offset: u64, source: StackFrameSource) -> StackFrame {
    StackFrame {
        address: format!("0x{address:016X}"),
        module: Some(module.name.clone()),
        offset_in_module: Some(format!("0x{offset:X}")),
        function: None,
        function_offset: None,
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

#[cfg(test)]
mod tests {
    use super::*;

    const KERNEL: u64 = 0xFFFF_8000_0000_0000;
    const BLOCK: u64 = 0xFFFF_9000_0000_0000;

    #[test]
    fn frame_pointer_chain_follows_monotonic_links_only() {
        let mut data = vec![0u8; 0x100];
        let links = [(0x10, 0x20, KERNEL + 0x10), (0x20, 0x30, KERNEL + 0x20), (0x30, 0x00, KERNEL + 0x30)];
        for (offset, next, return_address) in links {
            data[offset..offset + 8].copy_from_slice(&(BLOCK + next as u64).to_le_bytes());
            data[offset + 8..offset + 16].copy_from_slice(&return_address.to_le_bytes());
        }
        let slots = frame_pointer_slots(BLOCK, BLOCK + 0x10, BLOCK, &data);
        assert_eq!(slots, vec![(BLOCK + 0x18, KERNEL + 0x10), (BLOCK + 0x28, KERNEL + 0x20), (BLOCK + 0x38, KERNEL + 0x30)]);
        assert!(frame_pointer_slots(BLOCK, BLOCK - 0x8, BLOCK, &data).is_empty(), "a frame pointer below the stack pointer is rejected");
        assert!(frame_pointer_slots(BLOCK, BLOCK + 0x200, BLOCK, &data).is_empty(), "a frame pointer outside the captured block is rejected");
    }
}
