//! Synthetic PDB containers for tests.
//!
//! A real kernel PDB is proprietary-format data that a test cannot fabricate reliably, but the
//! container layout is small enough to build: a superblock, a directory block map, the stream
//! directory with sizes and block lists, and one block per stream chunk.

use std::path::PathBuf;

const MAGIC: &[u8] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0";
const BLOCK: usize = 512;

/// Builds an MSF 7.00 container with one stream per entry, `None` for a nil slot.
pub(crate) fn container(streams: &[Option<Vec<u8>>]) -> Vec<u8> {
    let counts = streams.iter().map(|stream| stream.as_ref().map_or(0, |bytes| bytes.len().div_ceil(BLOCK))).collect::<Vec<_>>();
    let directory_bytes = 4 + 4 * streams.len() + 4 * counts.iter().sum::<usize>();
    let directory_blocks = directory_bytes.div_ceil(BLOCK);
    let data_start = 2 + directory_blocks;

    let mut lists = Vec::with_capacity(streams.len());
    let mut next_block = data_start as u32;
    for count in &counts {
        let mut list = Vec::with_capacity(*count);
        for _ in 0..*count {
            list.push(next_block);
            next_block += 1;
        }
        lists.push(list);
    }
    let block_count = next_block as usize;
    let mut data = vec![0u8; block_count * BLOCK];

    let mut header = vec![0u8; BLOCK];
    header[..MAGIC.len()].copy_from_slice(MAGIC);
    header[0x20..0x24].copy_from_slice(&(BLOCK as u32).to_le_bytes());
    header[0x28..0x2C].copy_from_slice(&(block_count as u32).to_le_bytes());
    header[0x2C..0x30].copy_from_slice(&(directory_bytes as u32).to_le_bytes());
    header[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());
    data[..BLOCK].copy_from_slice(&header);

    let mut map = vec![0u8; BLOCK];
    for (index, block) in (2..2 + directory_blocks).enumerate() {
        map[index * 4..index * 4 + 4].copy_from_slice(&(block as u32).to_le_bytes());
    }
    data[BLOCK..BLOCK * 2].copy_from_slice(&map);

    let mut directory = Vec::with_capacity(directory_bytes);
    directory.extend((streams.len() as u32).to_le_bytes());
    for stream in streams {
        let size = stream.as_ref().map_or(u32::MAX, |bytes| bytes.len() as u32);
        directory.extend(size.to_le_bytes());
    }
    for list in &lists {
        for block in list {
            directory.extend(block.to_le_bytes());
        }
    }
    let directory_start = 2 * BLOCK;
    data[directory_start..directory_start + directory.len()].copy_from_slice(&directory);

    for (stream, list) in streams.iter().zip(&lists) {
        let Some(bytes) = stream
        else {
            continue;
        };
        for (chunk, block) in bytes.chunks(BLOCK).zip(list) {
            let start = *block as usize * BLOCK;
            data[start..start + chunk.len()].copy_from_slice(chunk);
        }
    }
    data
}

/// Builds a VC70 PDB info stream with the given named streams.
///
/// The named stream map is written the way a real kernel PDB stores it: an entry count, a bucket
/// capacity, a sparse presence bitmap, a sparse deletion bitmap, one `(name offset, stream
/// number)` pair per entry, then `niMac` and the producer feature stamp.
pub(crate) fn info_stream(version: u32, named: &[(&str, u32)]) -> Vec<u8> {
    let mut names = Vec::new();
    let mut entries = Vec::new();
    for (name, index) in named {
        entries.push((names.len() as u32, *index));
        names.extend(name.as_bytes());
        names.push(0);
    }
    let capacity = bucket_capacity(entries.len());
    let mut bytes = Vec::new();
    bytes.extend(version.to_le_bytes());
    bytes.extend(0x1234_5678u32.to_le_bytes());
    bytes.extend(1u32.to_le_bytes());
    for index in 0..16 {
        bytes.push(0xC0 + index as u8);
    }
    bytes.extend((names.len() as u32).to_le_bytes());
    bytes.extend(&names);
    bytes.extend((entries.len() as u32).to_le_bytes());
    bytes.extend(capacity.to_le_bytes());
    // Every entry occupies its own bucket, so the presence bitmap is a run of low bits.
    let words = capacity.div_ceil(32);
    bytes.extend(words.to_le_bytes());
    for word in 0..words {
        let mut bits = 0u32;
        for bit in 0..32 {
            let bucket = word * 32 + bit;
            if (bucket as usize) < entries.len() {
                bits |= 1 << bit;
            }
        }
        bytes.extend(bits.to_le_bytes());
    }
    // Nothing was deleted.
    bytes.extend(0u32.to_le_bytes());
    for (offset, index) in entries {
        bytes.extend(offset.to_le_bytes());
        bytes.extend(index.to_le_bytes());
    }
    bytes.extend(0u32.to_le_bytes());
    bytes.extend(0u32.to_le_bytes());
    bytes
}

/// Chooses a bucket capacity that is at least the entry count and never zero.
fn bucket_capacity(entries: usize) -> u32 {
    (entries.max(1) as u32).next_power_of_two()
}

/// Builds a DBI stream holding only a valid 64-byte header.
pub(crate) fn dbi_stream(global_stream: u16, public_stream: u16, symbol_record_stream: u16) -> Vec<u8> {
    let mut bytes = vec![0u8; 64];
    bytes[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
    bytes[4..8].copy_from_slice(&19_990_903u32.to_le_bytes());
    bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
    bytes[0x0C..0x0E].copy_from_slice(&global_stream.to_le_bytes());
    bytes[0x10..0x12].copy_from_slice(&public_stream.to_le_bytes());
    bytes[0x14..0x16].copy_from_slice(&symbol_record_stream.to_le_bytes());
    bytes
}

/// One module record for a synthetic DBI stream.
pub(crate) struct FixtureModule<'a> {
    pub name: &'a str,
    pub object_name: &'a str,
    pub section: u16,
    pub offset: i32,
    pub size: i32,
}

/// Builds one module record: the 64-byte header, the two strings and the alignment padding.
pub(crate) fn module_record(module: &FixtureModule<'_>) -> Vec<u8> {
    let mut record = vec![0u8; 64];
    record[4..6].copy_from_slice(&module.section.to_le_bytes());
    record[8..12].copy_from_slice(&module.offset.to_le_bytes());
    record[12..16].copy_from_slice(&module.size.to_le_bytes());
    record.extend(module.name.as_bytes());
    record.push(0);
    record.extend(module.object_name.as_bytes());
    record.push(0);
    while !record.len().is_multiple_of(4) {
        record.push(0);
    }
    record
}

/// Builds a DBI stream with a module list, section contributions and a section map.
///
/// `contributions` entries are `(module, section, offset, size)` and `sections` entries are
/// `(frame, offset, byte length)`. The header points the global, public and symbol record streams
/// at streams 4, 5 and 6, the numbers the other fixtures use.
pub(crate) fn dbi_stream_with_debug_info(
    modules: &[FixtureModule<'_>],
    section_contribution_version: u32,
    contributions: &[(u16, u16, i32, i32)],
    sections: &[(u16, u32, u32)],
) -> Vec<u8> {
    let modi = modules.iter().flat_map(module_record).collect::<Vec<u8>>();

    let entry_bytes = if section_contribution_version == 0xF131_51E4 { 32 } else { 28 };
    let mut contributions_bytes = Vec::with_capacity(4 + contributions.len() * entry_bytes);
    contributions_bytes.extend(section_contribution_version.to_le_bytes());
    for (module, section, offset, size) in contributions {
        contributions_bytes.extend(section.to_le_bytes());
        contributions_bytes.extend([0u8; 2]);
        contributions_bytes.extend(offset.to_le_bytes());
        contributions_bytes.extend(size.to_le_bytes());
        contributions_bytes.extend([0u8; 4]);
        contributions_bytes.extend(module.to_le_bytes());
        contributions_bytes.extend([0u8; 2]);
        contributions_bytes.extend([0u8; 8]);
        if entry_bytes == 32 {
            contributions_bytes.extend([0u8; 4]);
        }
    }

    let mut section_map = Vec::with_capacity(4 + sections.len() * 20);
    section_map.extend((sections.len() as u16).to_le_bytes());
    section_map.extend((sections.len() as u16).to_le_bytes());
    for (frame, offset, byte_length) in sections {
        section_map.extend([0u8; 6]);
        section_map.extend(frame.to_le_bytes());
        section_map.extend([0xFFu8; 2]);
        section_map.extend([0xFFu8, 0xFF]);
        section_map.extend(offset.to_le_bytes());
        section_map.extend(byte_length.to_le_bytes());
    }

    let mut file_info = Vec::with_capacity(4 + modules.len() * 4);
    file_info.extend((modules.len() as u16).to_le_bytes());
    file_info.extend(0u16.to_le_bytes());
    file_info.extend(vec![0u8; modules.len() * 4]);

    let mut bytes = dbi_stream(4, 5, 6);
    bytes[0x18..0x1C].copy_from_slice(&(modi.len() as u32).to_le_bytes());
    bytes[0x1C..0x20].copy_from_slice(&(contributions_bytes.len() as u32).to_le_bytes());
    bytes[0x20..0x24].copy_from_slice(&(section_map.len() as u32).to_le_bytes());
    bytes[0x24..0x28].copy_from_slice(&(file_info.len() as u32).to_le_bytes());
    bytes.extend(modi);
    bytes.extend(contributions_bytes);
    bytes.extend(section_map);
    bytes.extend(file_info);
    bytes
}

/// Writes fixture bytes to a uniquely named temporary file.
pub(crate) fn write(bytes: &[u8], tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("open-debugger-pdb-{tag}-{}.pdb", std::process::id()));
    std::fs::write(&path, bytes).expect("write synthetic PDB");
    path
}
