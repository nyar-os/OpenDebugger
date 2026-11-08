//! MSF container: superblock, stream directory and per-stream block maps.
//!
//! A PDB file is a set of numbered streams stored in fixed-size blocks. The superblock names
//! the block size and the block that holds the directory block map, the directory lists every
//! stream size and the blocks backing it, and a stream is read by concatenating its blocks up
//! to its declared size. Nothing here interprets stream contents.

use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use super::{PdbError, PdbErrorKind, word};

/// The 32-byte superblock signature of MSF 7.00.
const MAGIC: &[u8] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0";
const SUPERBLOCK_SIZE: usize = 56;
const BLOCK_SIZE_OFFSET: usize = 0x20;
const BLOCK_COUNT_OFFSET: usize = 0x28;
const DIRECTORY_BYTES_OFFSET: usize = 0x2C;
const BLOCK_MAP_OFFSET: usize = 0x34;

const MIN_BLOCK_SIZE: u32 = 512;
const MAX_BLOCK_SIZE: u32 = 16_384;
const MAX_STREAMS: u32 = 1 << 20;
const MAX_DIRECTORY_BYTES: u32 = 64 << 20;

/// Stream sizes use this value for a slot that carries no stream.
const NIL_STREAM: u32 = u32::MAX;

/// An opened MSF container. Every stream read seeks to the blocks that back it.
pub struct Msf {
    path: PathBuf,
    file: File,
    length: u64,
    block_size: u32,
    block_count: u32,
    directory_bytes: u32,
    streams: Vec<Option<Stream>>,
}

struct Stream {
    size: u32,
    blocks: Vec<u32>,
}

impl std::fmt::Debug for Msf {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Msf")
            .field("path", &self.path)
            .field("block_size", &self.block_size)
            .field("block_count", &self.block_count)
            .field("directory_bytes", &self.directory_bytes)
            .field("streams", &self.streams.len())
            .finish()
    }
}

impl Msf {
    pub fn open(path: &Path) -> Result<Self, PdbError> {
        let mut file = File::open(path).map_err(|source| PdbError::io(path, source))?;
        let length = file.metadata().map_err(|source| PdbError::io(path, source))?.len();
        let superblock = read_range(&mut file, length, path, 0, SUPERBLOCK_SIZE, "MSF superblock")?;
        if superblock.get(..MAGIC.len()) != Some(MAGIC) {
            return Err(PdbError::new(
                PdbErrorKind::UnsupportedContainer,
                "the file does not start with the `Microsoft C/C++ MSF 7.00` superblock",
            ));
        }
        let block_size = superblock_word(&superblock, BLOCK_SIZE_OFFSET)?;
        if !block_size.is_power_of_two() || !(MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE).contains(&block_size) {
            return Err(PdbError::new(
                PdbErrorKind::UnsupportedContainer,
                format!(
                    "MSF declares a block size of {block_size}, outside the supported {MIN_BLOCK_SIZE}..={MAX_BLOCK_SIZE} power-of-two range"
                ),
            ));
        }
        let block_count = superblock_word(&superblock, BLOCK_COUNT_OFFSET)?;
        let directory_bytes = superblock_word(&superblock, DIRECTORY_BYTES_OFFSET)?;
        let block_map = superblock_word(&superblock, BLOCK_MAP_OFFSET)?;
        if block_count == 0 || directory_bytes == 0 {
            return Err(PdbError::new(
                PdbErrorKind::UnsupportedContainer,
                format!("MSF declares {block_count} blocks and a {directory_bytes} byte stream directory"),
            ));
        }
        if directory_bytes > MAX_DIRECTORY_BYTES {
            return Err(PdbError::new(
                PdbErrorKind::UnsupportedContainer,
                format!("MSF declares a {directory_bytes} byte stream directory, above the supported {MAX_DIRECTORY_BYTES}"),
            ));
        }
        if block_map >= block_count {
            return Err(PdbError::new(
                PdbErrorKind::OutOfRange,
                format!("MSF directory block map is in block {block_map} but the container declares {block_count} blocks"),
            ));
        }
        let occupied = u64::from(block_count) * u64::from(block_size);
        if occupied > length {
            return Err(PdbError::new(
                PdbErrorKind::Truncated,
                format!("MSF declares {block_count} blocks of {block_size} bytes, which needs {occupied} bytes but the file holds {length}"),
            ));
        }

        let map_entries = usize::try_from(directory_bytes.div_ceil(block_size))
            .map_err(|_| PdbError::new(PdbErrorKind::OutOfRange, format!("MSF directory needs {directory_bytes} bytes")))?;
        let map_size =
            map_entries.checked_mul(4).ok_or_else(|| PdbError::new(PdbErrorKind::OutOfRange, "MSF directory block map size overflows"))?;
        if map_size > block_size as usize {
            return Err(PdbError::new(
                PdbErrorKind::UnsupportedContainer,
                format!("MSF directory needs {map_entries} block map entries, which do not fit in a single {block_size} byte block"),
            ));
        }
        let map_offset = u64::from(block_map) * u64::from(block_size);
        let map_bytes = read_range(&mut file, length, path, map_offset, map_size, "MSF directory block map")?;
        let mut directory_blocks = Vec::with_capacity(map_entries);
        for index in 0..map_entries {
            let block =
                word(&map_bytes, index * 4).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "MSF directory block map is truncated"))?;
            if block >= block_count {
                return Err(PdbError::new(
                    PdbErrorKind::OutOfRange,
                    format!("MSF directory block map points at block {block} but the container declares {block_count} blocks"),
                ));
            }
            directory_blocks.push(block);
        }
        let directory = read_blocks(&mut file, length, path, &directory_blocks, directory_bytes, block_size, "MSF stream directory")?;

        let stream_count = word(&directory, 0).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "MSF stream directory is empty"))?;
        if stream_count == 0 || stream_count > MAX_STREAMS {
            return Err(PdbError::new(
                PdbErrorKind::UnsupportedContainer,
                format!("MSF stream directory declares {stream_count} streams, outside the supported 1..={MAX_STREAMS}"),
            ));
        }
        let sizes_start = 4;
        let sizes_end = sizes_start + 4 * stream_count as usize;
        if sizes_end > directory.len() {
            return Err(PdbError::new(PdbErrorKind::Truncated, format!("MSF stream directory is too short for {stream_count} stream sizes")));
        }
        let streams = parse_streams(&directory, stream_count, sizes_start, sizes_end, block_size, block_count)?;

        Ok(Self { path: path.to_path_buf(), file, length, block_size, block_count, directory_bytes, streams })
    }

    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    pub fn block_count(&self) -> u32 {
        self.block_count
    }

    pub fn directory_bytes(&self) -> u32 {
        self.directory_bytes
    }

    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

    /// Declared size of a stream, or `None` when the slot holds no stream.
    pub fn stream_size(&self, index: u32) -> Option<u32> {
        self.streams.get(index as usize).and_then(Option::as_ref).map(|stream| stream.size)
    }

    /// Reads a whole stream into memory.
    ///
    /// The symbol record stream is the largest stream this reader takes in one piece. Byte
    /// ranges of other streams are read through the same block map when a caller needs them.
    pub fn read_stream(&mut self, index: u32) -> Result<Vec<u8>, PdbError> {
        let Some(stream) = self.streams.get(index as usize).and_then(Option::as_ref)
        else {
            return Err(PdbError::new(
                PdbErrorKind::OutOfRange,
                format!("stream {index} is absent from a container with {} streams", self.streams.len()),
            ));
        };
        let size = usize::try_from(stream.size)
            .map_err(|_| PdbError::new(PdbErrorKind::OutOfRange, format!("stream {index} declares {} bytes", stream.size)))?;
        let mut buffer = Vec::with_capacity(size);
        let mut remaining = size;
        for block in &stream.blocks {
            if remaining == 0 {
                break;
            }
            let chunk = remaining.min(self.block_size as usize);
            let offset = u64::from(*block) * u64::from(self.block_size);
            buffer.extend(read_range(&mut self.file, self.length, &self.path, offset, chunk, "stream block")?);
            remaining -= chunk;
        }
        if remaining != 0 {
            return Err(PdbError::new(
                PdbErrorKind::Truncated,
                format!("stream {index} declares {size} bytes but its block map supplies fewer"),
            ));
        }
        Ok(buffer)
    }
}

fn superblock_word(bytes: &[u8], offset: usize) -> Result<u32, PdbError> {
    word(bytes, offset).ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "the MSF superblock is shorter than its 56-byte header"))
}

/// Parses the size array and the block lists that follow it in the stream directory.
fn parse_streams(
    directory: &[u8],
    stream_count: u32,
    sizes_start: usize,
    sizes_end: usize,
    block_size: u32,
    block_count: u32,
) -> Result<Vec<Option<Stream>>, PdbError> {
    let mut streams = Vec::with_capacity(stream_count as usize);
    let mut offset = sizes_end;
    for index in 0..stream_count as usize {
        let size = word(directory, sizes_start + index * 4)
            .ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "MSF stream directory is truncated"))?;
        if size == NIL_STREAM {
            streams.push(None);
            continue;
        }
        let needed = usize::try_from(size.div_ceil(block_size))
            .map_err(|_| PdbError::new(PdbErrorKind::OutOfRange, format!("stream {index} declares {size} bytes")))?;
        let blocks_end =
            offset.checked_add(needed * 4).ok_or_else(|| PdbError::new(PdbErrorKind::OutOfRange, "MSF stream block list overflows"))?;
        if blocks_end > directory.len() {
            return Err(PdbError::new(
                PdbErrorKind::Truncated,
                format!("MSF stream directory is too short for the block list of stream {index}"),
            ));
        }
        let mut blocks = Vec::with_capacity(needed);
        for entry in 0..needed {
            let block = word(directory, offset + entry * 4)
                .ok_or_else(|| PdbError::new(PdbErrorKind::Truncated, "MSF stream block list is truncated"))?;
            if block >= block_count {
                return Err(PdbError::new(
                    PdbErrorKind::OutOfRange,
                    format!("stream {index} points at block {block} but the container declares {block_count} blocks"),
                ));
            }
            blocks.push(block);
        }
        offset = blocks_end;
        streams.push(Some(Stream { size, blocks }));
    }
    Ok(streams)
}

fn read_blocks(
    file: &mut File,
    length: u64,
    path: &Path,
    blocks: &[u32],
    bytes: u32,
    block_size: u32,
    context: &str,
) -> Result<Vec<u8>, PdbError> {
    let mut buffer = Vec::with_capacity(bytes as usize);
    let mut remaining = bytes as usize;
    for block in blocks {
        if remaining == 0 {
            break;
        }
        let chunk = remaining.min(block_size as usize);
        let offset = u64::from(*block) * u64::from(block_size);
        buffer.extend(read_range(file, length, path, offset, chunk, context)?);
        remaining -= chunk;
    }
    if remaining != 0 {
        return Err(PdbError::new(PdbErrorKind::Truncated, format!("{context} declares {bytes} bytes but its block map supplies fewer")));
    }
    Ok(buffer)
}

fn read_range(file: &mut File, length: u64, path: &Path, offset: u64, size: usize, context: &str) -> Result<Vec<u8>, PdbError> {
    if size == 0 {
        return Ok(Vec::new());
    }
    let end = offset
        .checked_add(size as u64)
        .ok_or_else(|| PdbError::new(PdbErrorKind::OutOfRange, format!("{context} offset {offset} overflows")))?;
    if end > length {
        return Err(PdbError::new(
            PdbErrorKind::Truncated,
            format!("{context} needs bytes {offset}..{end} but {} holds {length} bytes", path.display()),
        ));
    }
    file.seek(SeekFrom::Start(offset)).map_err(|source| PdbError::io(path, source))?;
    let mut buffer = vec![0u8; size];
    file.read_exact(&mut buffer).map_err(|source| PdbError::io(path, source))?;
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdb::fixtures;

    #[test]
    fn reads_each_stream_through_its_block_map() {
        let long = (0..700u32).map(|value| value as u8).collect::<Vec<u8>>();
        let short = vec![9u8; 100];
        let bytes = fixtures::container(&[None, Some(long.clone()), Some(short.clone())]);
        let path = fixtures::write(&bytes, "msf-streams");
        let mut msf = Msf::open(&path).expect("the synthetic container is valid");
        assert_eq!(msf.block_size(), 512);
        assert_eq!(msf.stream_count(), 3);
        assert_eq!(msf.stream_size(0), None);
        assert_eq!(msf.stream_size(1), Some(700));
        assert_eq!(msf.read_stream(1).unwrap(), long, "a stream spanning two blocks is reassembled in order");
        assert_eq!(msf.read_stream(2).unwrap(), short);
        assert_eq!(msf.read_stream(9).unwrap_err().kind(), PdbErrorKind::OutOfRange);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn an_empty_stream_is_readable_and_a_nil_stream_is_absent() {
        let bytes = fixtures::container(&[Some(Vec::new()), None]);
        let path = fixtures::write(&bytes, "msf-empty");
        let mut msf = Msf::open(&path).expect("the synthetic container is valid");
        assert_eq!(msf.stream_size(0), Some(0));
        assert!(msf.read_stream(0).unwrap().is_empty());
        assert_eq!(msf.stream_size(1), None);
        assert_eq!(msf.read_stream(1).unwrap_err().kind(), PdbErrorKind::OutOfRange);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn rejects_a_foreign_superblock() {
        let mut bytes = fixtures::container(&[None]);
        bytes[..4].copy_from_slice(b"MDMP");
        let path = fixtures::write(&bytes, "msf-foreign");
        let error = Msf::open(&path).expect_err("a dump header is not an MSF container");
        std::fs::remove_file(&path).ok();
        assert_eq!(error.kind(), PdbErrorKind::UnsupportedContainer);
    }

    #[test]
    fn rejects_a_directory_block_past_the_container() {
        let mut bytes = fixtures::container(&[None, Some(vec![7u8; 8])]);
        bytes[512..516].copy_from_slice(&999u32.to_le_bytes());
        let path = fixtures::write(&bytes, "msf-directory-block");
        let error = Msf::open(&path).expect_err("a directory block outside the container must fail");
        std::fs::remove_file(&path).ok();
        assert_eq!(error.kind(), PdbErrorKind::OutOfRange);
    }

    #[test]
    fn rejects_a_block_size_outside_the_supported_range() {
        let mut bytes = fixtures::container(&[None]);
        bytes[0x20..0x24].copy_from_slice(&300u32.to_le_bytes());
        let path = fixtures::write(&bytes, "msf-block-size");
        let error = Msf::open(&path).expect_err("a non-power-of-two block size must fail");
        std::fs::remove_file(&path).ok();
        assert_eq!(error.kind(), PdbErrorKind::UnsupportedContainer);
    }

    #[test]
    fn rejects_a_file_shorter_than_its_block_count() {
        let mut bytes = fixtures::container(&[None, Some(vec![5u8; 600])]);
        bytes.truncate(bytes.len() - 512);
        let path = fixtures::write(&bytes, "msf-short");
        let error = Msf::open(&path).expect_err("a container shorter than its block count must fail");
        std::fs::remove_file(&path).ok();
        assert_eq!(error.kind(), PdbErrorKind::Truncated);
    }
}
