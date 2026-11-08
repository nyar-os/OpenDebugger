//! Address lookup over the public symbols of one PDB.
//!
//! The PDB stores symbols by section and offset, so an RVA only becomes a name once the section
//! table of the matching image is known. This module joins the two and answers the only question
//! a stack frame asks: which public symbol covers this address, and how far into it is the address.
//!
//! `S_PUB32` carries no size. The answer is therefore the nearest public symbol at or before the
//! address, which is the rule a debugger applies to public symbols. An address before the first
//! public symbol has no answer. A public symbol can name a section the image does not declare:
//! linker-defined constants live in a pseudo-section and carry absolute values, so they cannot
//! answer a stack address and are counted instead of guessed at. A table where nothing maps is a
//! failure, because then the PDB and the image do not describe the same module.

use super::{PdbError, PdbErrorKind, PublicSymbol};
use crate::pe::SectionHeader;

/// A public symbol resolved to the RVA space of its image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionEntry {
    pub name: String,
    pub rva: u32,
    pub section: u16,
    /// Byte offset from the start of `section`, which is how a procedure record names the same
    /// function and how its length is found.
    pub offset: u32,
    /// `S_PUB32` flags: 1 code, 2 function, 4 data, 8 thunk, 16 absolute.
    pub flags: u32,
}

/// A hit for one address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionHit<'a> {
    pub entry: &'a FunctionEntry,
    /// Bytes from the entry start to the queried address.
    pub displacement: u32,
}

/// Public symbols sorted by RVA, ready for lookup.
#[derive(Debug, Clone, Default)]
pub struct FunctionIndex {
    entries: Vec<FunctionEntry>,
    unmapped: usize,
}

impl FunctionIndex {
    /// Resolves every public symbol against the image section table.
    ///
    /// A public symbol can name a section the image does not declare: linker-defined constants
    /// live in a pseudo-section and carry absolute values, so they have no RVA and can never
    /// answer a stack address. Those are counted in `unmapped` rather than guessed at. If every
    /// symbol is unmapped, the PDB and the image do not describe the same module and the build
    /// fails instead of returning an empty table.
    pub fn build(symbols: &[PublicSymbol], sections: &[SectionHeader]) -> Result<Self, PdbError> {
        let mut entries = Vec::with_capacity(symbols.len());
        let mut unmapped = 0usize;
        for symbol in symbols {
            let Some(section) = usize::from(symbol.section).checked_sub(1).and_then(|index| sections.get(index))
            else {
                unmapped += 1;
                continue;
            };
            let Some(rva) = section.virtual_address.checked_add(symbol.offset)
            else {
                return Err(PdbError::new(
                    PdbErrorKind::OutOfRange,
                    format!("`{}` at section {} offset 0x{:X} is past the 32-bit RVA space", symbol.name, symbol.section, symbol.offset),
                ));
            };
            entries.push(FunctionEntry { name: symbol.name.clone(), rva, section: symbol.section, offset: symbol.offset, flags: symbol.flags });
        }
        if entries.is_empty() {
            return Err(PdbError::new(
                PdbErrorKind::UnknownStreamConvention,
                format!("no public symbol of {unmapped} maps into the {} sections of this image", sections.len()),
            ));
        }
        entries.sort_by(|left, right| left.rva.cmp(&right.rva).then_with(|| left.name.cmp(&right.name)));
        Ok(Self { entries, unmapped })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Public symbols that name a section the image does not declare and therefore carry no RVA.
    pub fn unmapped(&self) -> usize {
        self.unmapped
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// RVA of the entry at `position` in sorted order. Used to sample the table deterministically.
    pub fn symbol_rva(&self, position: usize) -> Option<u32> {
        self.entries.get(position).map(|entry| entry.rva)
    }

    /// Returns the nearest public symbol at or before `rva`.
    ///
    /// Several publics can share one RVA: folded functions, shared constants and aliases. A
    /// debugger answers such an address with the ordinally lowest name of the group, which is what
    /// the comparison against the bound reader on a real kernel PDB shows, so the index sorts each
    /// group by name and takes the first entry.
    pub fn find(&self, rva: u32) -> Option<FunctionHit<'_>> {
        let end = self.entries.partition_point(|entry| entry.rva <= rva);
        if end == 0 {
            return None;
        }
        let mut start = end - 1;
        while start > 0 && self.entries[start - 1].rva == self.entries[start].rva {
            start -= 1;
        }
        let entry = &self.entries[start];
        Some(FunctionHit { entry, displacement: rva - entry.rva })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(virtual_address: u32, virtual_size: u32) -> SectionHeader {
        SectionHeader { virtual_address, virtual_size }
    }

    fn symbol(name: &str, section: u16, offset: u32) -> PublicSymbol {
        PublicSymbol { name: name.to_string(), section, offset, flags: 0 }
    }

    #[test]
    fn resolves_section_offsets_to_rvas_and_finds_the_covering_symbol() {
        let sections = [section(0x1000, 0x2000), section(0x4000, 0x1000)];
        let symbols = [symbol("First", 1, 0x10), symbol("Second", 1, 0x210), symbol("Third", 2, 0x30)];
        let index = FunctionIndex::build(&symbols, &sections).expect("every section exists in the image");
        assert_eq!(index.len(), 3);

        let hit = index.find(0x1015).expect("the first symbol covers the section start");
        assert_eq!(hit.entry.name, "First");
        assert_eq!(hit.displacement, 0x5);

        let hit = index.find(0x1212).expect("the middle symbol covers its own range");
        assert_eq!(hit.entry.name, "Second");
        assert_eq!(hit.displacement, 0x2);

        let hit = index.find(0x4032).expect("section two resolves through its own base");
        assert_eq!(hit.entry.name, "Third");
        assert_eq!(hit.displacement, 0x2);

        assert!(index.find(0x100F).is_none(), "an address before the first symbol has no answer");
    }

    #[test]
    fn the_first_name_wins_when_several_publics_share_one_rva() {
        let sections = [section(0x1000, 0x1000)];
        let symbols = [symbol("Folded", 1, 0x20), symbol("Alias", 1, 0x20), symbol("Later", 1, 0x40)];
        let index = FunctionIndex::build(&symbols, &sections).expect("all symbols map into the image");
        let hit = index.find(0x1020).expect("the shared address has a symbol");
        assert_eq!(hit.entry.name, "Alias", "the ordinal name decides which alias answers, not the record order");
    }

    #[test]
    fn a_symbol_in_a_section_the_image_does_not_declare_carries_no_rva() {
        let sections = [section(0x1000, 0x1000)];
        let symbols = [symbol("Mapped", 1, 0x10), symbol("Absolute", 3, 0x7FFF_FFFF)];
        let index = FunctionIndex::build(&symbols, &sections).expect("one of the symbols maps into the image");
        assert_eq!(index.len(), 1);
        assert_eq!(index.unmapped(), 1);
        assert_eq!(index.find(0x1010).expect("the mapped symbol is addressable").entry.name, "Mapped");
    }

    #[test]
    fn an_index_where_no_symbol_maps_into_the_image_fails_the_build() {
        let sections = [section(0x1000, 0x1000)];
        let symbols = [symbol("Stray", 2, 0)];
        let error = FunctionIndex::build(&symbols, &sections).expect_err("a table that maps nothing cannot answer any address");
        assert_eq!(error.kind(), PdbErrorKind::UnknownStreamConvention);
    }

    #[test]
    fn an_offset_past_the_rva_space_fails_the_build() {
        let sections = [section(0xFFFF_0000, 0x1_0000)];
        let symbols = [symbol("Wrapped", 1, 0x2_0000)];
        let error = FunctionIndex::build(&symbols, &sections).expect_err("an RVA cannot wrap");
        assert_eq!(error.kind(), PdbErrorKind::OutOfRange);
    }
}
