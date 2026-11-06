//! Random-access reads over a dump without loading the whole file.

use std::{
    cell::RefCell,
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

use crate::error::{Error, Result};

/// A dump opened from disk. Every read seeks and transfers only the requested range.
pub(crate) struct FileReader {
    file: File,
    len: u64,
    bytes_read: u64,
}

impl FileReader {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        let file = File::open(path).map_err(|source| Error::io(path.display().to_string(), source))?;
        let len = file.metadata().map_err(|source| Error::io(path.display().to_string(), source))?.len();
        Ok(Self { file, len, bytes_read: 0 })
    }

    fn read(&mut self, offset: u64, size: u32) -> Option<Vec<u8>> {
        let end = offset.checked_add(u64::from(size))?;
        if end > self.len {
            return None;
        }
        self.file.seek(SeekFrom::Start(offset)).ok()?;
        let mut buffer = vec![0u8; size as usize];
        self.file.read_exact(&mut buffer).ok()?;
        self.bytes_read += u64::from(size);
        Some(buffer)
    }
}

/// Either in-memory dump bytes or a file-backed reader.
pub(crate) enum Input<'a> {
    Bytes(&'a [u8]),
    File(&'a RefCell<FileReader>),
}

impl Input<'_> {
    pub(crate) fn len(&self) -> u64 {
        match self {
            Self::Bytes(bytes) => bytes.len() as u64,
            Self::File(reader) => reader.borrow().len,
        }
    }

    pub(crate) fn read(&self, offset: u64, size: u32) -> Option<Vec<u8>> {
        match self {
            Self::Bytes(bytes) => {
                let start = usize::try_from(offset).ok()?;
                let end = start.checked_add(size as usize)?;
                bytes.get(start..end).map(<[u8]>::to_vec)
            }
            Self::File(reader) => reader.borrow_mut().read(offset, size),
        }
    }

    /// Total bytes transferred so far. Used by tests to prove ranges are read on demand.
    #[cfg(test)]
    pub(crate) fn bytes_read(&self) -> u64 {
        match self {
            Self::Bytes(_) => 0,
            Self::File(reader) => reader.borrow().bytes_read,
        }
    }
}

pub(crate) fn read_u8(input: &Input, offset: u64) -> Option<u8> {
    input.read(offset, 1).map(|data| data[0])
}

pub(crate) fn read_u16(input: &Input, offset: u64) -> Option<u16> {
    let data = input.read(offset, 2)?;
    Some(u16::from_le_bytes([data[0], data[1]]))
}

pub(crate) fn read_u32(input: &Input, offset: u64) -> Option<u32> {
    let data = input.read(offset, 4)?;
    Some(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
}

pub(crate) fn read_u64(input: &Input, offset: u64) -> Option<u64> {
    let data = input.read(offset, 8)?;
    Some(u64::from_le_bytes([data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]]))
}
