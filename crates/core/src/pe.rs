//! PE image section headers, read from an image file.
//!
//! Public symbols in a PDB are section-relative: an `S_PUB32` record carries a 1-based section
//! number and an offset. Turning that into an RVA needs the section table of the image the PDB
//! describes. This module reads only the DOS header, the COFF header and the section headers;
//! it does not load, map or relocate anything.

use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

use crate::error::{Error, Result};

const DOS_HEADER_SIZE: usize = 0x40;
const DOS_SIGNATURE: u16 = 0x5A4D;
const PE_SIGNATURE_OFFSET: usize = 0x3C;
const COFF_HEADER_SIZE: usize = 24;
const PE_SIGNATURE: &[u8; 4] = b"PE\0\0";
/// The COFF header is read from the PE signature, so its field offsets include the four signature
/// bytes: machine at 4, section count at 6 and optional header size at 20.
const SECTION_COUNT_OFFSET: usize = 6;
const OPTIONAL_HEADER_SIZE_OFFSET: usize = 20;
const SECTION_HEADER_SIZE: usize = 40;
const SECTION_VIRTUAL_SIZE_OFFSET: usize = 8;
const SECTION_VIRTUAL_ADDRESS_OFFSET: usize = 12;
const MAX_SECTIONS: usize = 96;
const MAX_OPTIONAL_HEADER: usize = 0x1000;

/// The VA range a PE section covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionHeader {
    pub virtual_address: u32,
    pub virtual_size: u32,
}

impl SectionHeader {
    /// Parses the section headers out of a PE image on disk.
    ///
    /// Only the header region is transferred, so a kernel image with megabytes of code is read in
    /// the same handful of bytes as a small driver.
    pub fn read(path: &Path) -> Result<Vec<Self>> {
        let mut file = File::open(path).map_err(|source| Error::io(path.display().to_string(), source))?;
        let dos = read_range(&mut file, path, 0, DOS_HEADER_SIZE)?;
        if u16::from_le_bytes([dos[0], dos[1]]) != DOS_SIGNATURE {
            return Err(Error::message(format!("{} does not begin with an `MZ` signature", path.display())));
        }
        let pe_offset = usize::from(u16::from_le_bytes([dos[PE_SIGNATURE_OFFSET], dos[PE_SIGNATURE_OFFSET + 1]]));
        let coff = read_range(&mut file, path, pe_offset as u64, COFF_HEADER_SIZE)?;
        if &coff[0..4] != PE_SIGNATURE {
            return Err(Error::message(format!("{} has no `PE` signature at offset {pe_offset}", path.display())));
        }
        let section_count = usize::from(u16::from_le_bytes([coff[SECTION_COUNT_OFFSET], coff[SECTION_COUNT_OFFSET + 1]]));
        let optional_size = usize::from(u16::from_le_bytes([coff[OPTIONAL_HEADER_SIZE_OFFSET], coff[OPTIONAL_HEADER_SIZE_OFFSET + 1]]));
        if section_count == 0 || section_count > MAX_SECTIONS {
            return Err(Error::message(format!("{} declares {section_count} sections", path.display())));
        }
        if optional_size == 0 || optional_size > MAX_OPTIONAL_HEADER {
            return Err(Error::message(format!("{} declares a {optional_size}-byte optional header", path.display())));
        }
        let table_offset = (pe_offset + COFF_HEADER_SIZE + optional_size) as u64;
        let table = read_range(&mut file, path, table_offset, section_count * SECTION_HEADER_SIZE)?;
        let mut sections = Vec::with_capacity(section_count);
        for index in 0..section_count {
            let base = index * SECTION_HEADER_SIZE;
            let virtual_size = u32::from_le_bytes(field(&table, base + SECTION_VIRTUAL_SIZE_OFFSET));
            let virtual_address = u32::from_le_bytes(field(&table, base + SECTION_VIRTUAL_ADDRESS_OFFSET));
            let end = u64::from(virtual_address) + u64::from(virtual_size);
            if end > u64::from(u32::MAX) {
                return Err(Error::message(format!("{} section {index} ends past the 32-bit RVA space", path.display())));
            }
            sections.push(Self { virtual_address, virtual_size });
        }
        Ok(sections)
    }
}

fn read_range(file: &mut File, path: &Path, offset: u64, size: usize) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(offset)).map_err(|source| Error::io(path.display().to_string(), source))?;
    let mut bytes = vec![0u8; size];
    file.read_exact(&mut bytes).map_err(|source| Error::io(path.display().to_string(), source))?;
    Ok(bytes)
}

fn field(bytes: &[u8], offset: usize) -> [u8; 4] {
    [bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image_with_sections(section_count: u16) -> Vec<u8> {
        let pe_offset = 0x80usize;
        let mut bytes = vec![0u8; pe_offset + COFF_HEADER_SIZE + MAX_OPTIONAL_HEADER + MAX_SECTIONS * SECTION_HEADER_SIZE];
        bytes[0] = DOS_SIGNATURE as u8;
        bytes[1] = (DOS_SIGNATURE >> 8) as u8;
        bytes[PE_SIGNATURE_OFFSET..PE_SIGNATURE_OFFSET + 4].copy_from_slice(&(pe_offset as u32).to_le_bytes());
        bytes[pe_offset..pe_offset + 4].copy_from_slice(PE_SIGNATURE);
        bytes[pe_offset + SECTION_COUNT_OFFSET..pe_offset + SECTION_COUNT_OFFSET + 2].copy_from_slice(&section_count.to_le_bytes());
        bytes[pe_offset + OPTIONAL_HEADER_SIZE_OFFSET..pe_offset + OPTIONAL_HEADER_SIZE_OFFSET + 2].copy_from_slice(&0xF0u16.to_le_bytes());
        bytes
    }

    fn write(bytes: &[u8], tag: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("open-debugger-pe-{tag}-{}.bin", std::process::id()));
        std::fs::write(&path, bytes).expect("write the synthetic image");
        path
    }

    #[test]
    fn reads_the_section_table() {
        let mut bytes = image_with_sections(2);
        let table = 0x80 + COFF_HEADER_SIZE + 0xF0;
        bytes[table + SECTION_VIRTUAL_SIZE_OFFSET..table + SECTION_VIRTUAL_SIZE_OFFSET + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[table + SECTION_VIRTUAL_ADDRESS_OFFSET..table + SECTION_VIRTUAL_ADDRESS_OFFSET + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        let second = table + SECTION_HEADER_SIZE;
        bytes[second + SECTION_VIRTUAL_SIZE_OFFSET..second + SECTION_VIRTUAL_SIZE_OFFSET + 4].copy_from_slice(&0x2000u32.to_le_bytes());
        bytes[second + SECTION_VIRTUAL_ADDRESS_OFFSET..second + SECTION_VIRTUAL_ADDRESS_OFFSET + 4].copy_from_slice(&0x4000u32.to_le_bytes());
        let path = write(&bytes, "sections");
        let sections = SectionHeader::read(&path).expect("the synthetic image is well formed");
        assert_eq!(sections.len(), 2);
        assert_eq!(sections[0], SectionHeader { virtual_address: 0x1000, virtual_size: 0x1000 });
        assert_eq!(sections[1], SectionHeader { virtual_address: 0x4000, virtual_size: 0x2000 });
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rejects_an_image_without_an_mz_signature() {
        let mut bytes = image_with_sections(1);
        bytes[0] = 0;
        let path = write(&bytes, "no-mz");
        let error = SectionHeader::read(&path).expect_err("a file that is not an image cannot supply sections");
        assert!(error.to_string().contains("`MZ`"), "{error}");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rejects_a_section_count_outside_the_supported_bound() {
        let bytes = image_with_sections(0);
        let path = write(&bytes, "no-sections");
        let error = SectionHeader::read(&path).expect_err("an image without sections cannot map a symbol");
        assert!(error.to_string().contains("0 sections"), "{error}");
        let _ = std::fs::remove_file(path);
    }
}
