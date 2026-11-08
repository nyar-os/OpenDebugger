//! Undecorating Microsoft C++ symbol names without a host demangler.
//!
//! A PDB stores both plain C names and the compiler's decorated spellings. A decorated name
//! encodes scope, access, calling convention, return type and parameter types, which a frame
//! cannot show as-is. This module turns that spelling back into the shape the debugger prints, so a
//! frame reads `public: static long __cdecl SMKM_STORE<struct SM_TRAITS>::SmStoreRequestEx(...)`
//! instead of the mangled form.
//!
//! The grammar handled here is the part a compiler object file emits for functions and data:
//! qualified names, templates, backward references, basic types, pointers, references and
//! function pointers. Two rules keep it honest:
//!
//! * A name that is not decorated is returned unchanged, which is also what the platform demangler
//!   does for C symbols.
//! * A decorated name the parser cannot read in full returns `None`, and the caller keeps the
//!   spelling the PDB stored. No partial rendering is ever produced, because a partial one would
//!   read as a different function.

/// One parsed symbol, kept in pieces so the formatting rules stay in one place.
struct Symbol {
    /// `public: `, `protected: ` or `private: `, present only for member functions.
    access: &'static str,
    /// `static ` or `virtual `, present only when the mangling records one.
    qualifier: &'static str,
    /// Return type, absent for constructors and destructors.
    returns: Option<String>,
    /// Calling convention keyword, absent for data symbols.
    convention: &'static str,
    /// Scope components, outermost first.
    scope: Vec<String>,
    /// Symbol name without its scope.
    name: String,
    params: Option<Vec<String>>,
    /// `const` and similar qualifiers the debugger prints right after the parameter list.
    suffix: &'static str,
    /// The `__ptr64` marker a member function carries after its parameter list.
    pointer64: bool,
    /// True for data, which prints `<type> <name>` with no calling convention.
    data: bool,
}

impl Symbol {
    fn new() -> Self {
        Self {
            access: "",
            qualifier: "",
            returns: None,
            convention: "",
            scope: Vec::new(),
            name: String::new(),
            params: None,
            suffix: "",
            pointer64: false,
            data: false,
        }
    }

    fn render(&self) -> String {
        let mut qualified = String::new();
        for component in &self.scope {
            qualified.push_str(component);
            qualified.push_str("::");
        }
        qualified.push_str(&self.name);
        if self.data {
            return match self.returns.as_ref() {
                Some(kind) if qualified.is_empty() => kind.clone(),
                Some(kind) => format!("{kind} {qualified}"),
                None => qualified,
            };
        }
        let mut text = String::new();
        text.push_str(self.access);
        text.push_str(self.qualifier);
        if let Some(returns) = &self.returns {
            text.push_str(returns);
            text.push(' ');
        }
        text.push_str(self.convention);
        if !self.convention.is_empty() {
            text.push(' ');
        }
        text.push_str(&qualified);
        if let Some(params) = &self.params {
            text.push('(');
            text.push_str(&params.join(","));
            text.push(')');
        }
        text.push_str(self.suffix);
        if self.pointer64 {
            text.push_str(" __ptr64");
        }
        text
    }
}

/// Undecorates one PDB symbol name.
///
/// Returns `None` when the name is decorated but uses a construct this parser does not read, so
/// the caller can keep the stored spelling rather than show a half-parsed name.
pub fn undecorate(name: &str) -> Option<String> {
    if !name.starts_with('?') {
        return Some(name.to_owned());
    }
    let mut parser = Parser { text: name.as_bytes(), at: 1, names: Vec::new(), types: Vec::new() };
    let symbol = parser.parse()?;
    (parser.at == parser.text.len()).then(|| symbol.render())
}

/// Scope components already rendered, addressed by the single digits a decorated name uses to
/// avoid repeating a long template spelling.
///
/// The digit is an index into this table counted from its first entry, which is what the names in
/// a real kernel PDB resolve to: the second component of a class takes `1` to mean the class.
struct Parser<'a> {
    text: &'a [u8],
    at: usize,
    names: Vec<String>,
    /// Argument types already rendered, which a parameter list reuses through a single digit.
    types: Vec<String>,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.text.get(self.at).copied()
    }

    fn peek_at(&self, offset: usize) -> Option<u8> {
        self.text.get(self.at + offset).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let byte = self.text.get(self.at).copied()?;
        self.at += 1;
        Some(byte)
    }

    fn expect(&mut self, byte: u8) -> Option<()> {
        if self.peek()? == byte {
            self.at += 1;
            Some(())
        }
        else {
            None
        }
    }

    /// Reads an identifier up to the `@` that terminates it, which it consumes.
    ///
    /// Identifiers are written plain rather than length-prefixed, so the terminator is what
    /// delimits them. An empty identifier is the empty component that ends a scope chain.
    fn identifier(&mut self) -> Option<String> {
        let start = self.at;
        while self.peek()? != b'@' {
            if !self.peek()?.is_ascii() {
                return None;
            }
            self.at += 1;
            if self.at - start > 1024 {
                return None;
            }
        }
        let text = std::str::from_utf8(&self.text[start..self.at]).ok()?.to_owned();
        self.at += 1;
        Some(text)
    }

    /// Reads the symbol's own name, then every scope component up to the empty one that ends the
    /// chain.
    fn symbol_name(&mut self, symbol: &mut Symbol) -> Option<()> {
        let name = self.identifier()?;
        if name.is_empty() {
            return None;
        }
        self.names.push(name.clone());
        symbol.name = name;
        let mut components = Vec::new();
        loop {
            if self.peek()? == b'@' {
                self.at += 1;
                break;
            }
            let (component, closes) = self.component(true)?;
            components.push(component);
            if closes {
                break;
            }
        }
        symbol.scope = components.into_iter().rev().collect();
        Some(())
    }

    /// Reads one scope component: a backward reference, a template, a function-local scope or an
    /// identifier.
    ///
    /// The value reports whether the component also closes the chain: a backward reference carries
    /// no separate terminator, so the `@` that ends the reference is the chain's end as well.
    ///
    /// `keep` says whether the component itself joins the scope table a backward reference indexes.
    /// Only the symbol's own scope chain does that: a type written as an argument is not a scope of
    /// the symbol.
    fn component(&mut self, keep: bool) -> Option<(String, bool)> {
        if self.peek()?.is_ascii_digit() && self.peek_at(1)? == b'@' {
            let digit = self.bump()?;
            self.expect(b'@')?;
            return Some((self.reference(digit, keep)?, true));
        }
        if self.peek()? == b'?' {
            self.at += 1;
            return match self.bump()? {
                b'$' => Some((self.template(keep)?, false)),
                // `?1` and `?0` name a function-local scope; the next component names the function.
                b'0' | b'1' => {
                    self.expect(b'?')?;
                    self.component(keep)
                }
                _ => None,
            };
        }
        let name = self.identifier()?;
        if name.is_empty() {
            return None;
        }
        if keep {
            self.names.push(name.clone());
        }
        Some((name, false))
    }

    /// Resolves a backward reference and records the result, so a later reference can reach it.
    fn reference(&mut self, digit: u8, keep: bool) -> Option<String> {
        let index = usize::from(digit.checked_sub(b'0')?);
        let value = self.names.get(index).cloned()?;
        if keep {
            self.names.push(value.clone());
        }
        Some(value)
    }

    /// Reads `name@arg@arg@@` into `name<arg,arg>`.
    ///
    /// Two closing brackets in a row are written with a space, as the debugger writes them, so a
    /// template argument that is itself a template does not read as a shift.
    fn template(&mut self, keep: bool) -> Option<String> {
        let name = self.identifier()?;
        if name.is_empty() {
            return None;
        }
        let mut args = Vec::new();
        loop {
            if self.peek()? == b'@' {
                self.at += 1;
                break;
            }
            args.push(self.argument()?);
        }
        let close = if args.last().is_some_and(|argument| argument.ends_with('>')) { " >" } else { ">" };
        let rendered = format!("{name}<{}", args.join(","));
        let rendered = format!("{rendered}{close}");
        if keep {
            self.names.push(rendered.clone());
        }
        Some(rendered)
    }

    /// Reads one argument of a parameter or template list and records it for reuse.
    ///
    /// A single-letter type is self-delimiting. A named type ends with the `@` that closes its
    /// component chain, and a constant with the `@` that closes its digits, so no argument needs a
    /// terminator of its own. The list itself ends with the `@` that the caller reads.
    fn argument(&mut self) -> Option<String> {
        let text = self.type_text()?;
        if !self.types.contains(&text) {
            self.types.push(text.clone());
        }
        Some(text)
    }

    fn parse(&mut self) -> Option<Symbol> {
        let mut symbol = Symbol::new();
        if self.peek()? == b'?' {
            self.at += 1;
            let code = self.bump()?;
            return self.special(code, symbol);
        }
        self.symbol_name(&mut symbol)?;
        match self.peek()? {
            // A data symbol: its type, an optional `__ptr64` on the item itself, then its own
            // qualifier. Nothing else follows, so a longer tail is a shape this reader does not know.
            b'0'..=b'5' => {
                self.at += 1;
                let mut kind = self.type_text()?;
                while self.peek()? == b'E' {
                    self.at += 1;
                    kind.push_str(" __ptr64");
                }
                match self.bump()? {
                    b'A'..=b'D' => {}
                    _ => return None,
                }
                symbol.returns = Some(kind);
                symbol.data = true;
                Some(symbol)
            }
            b'Y' => {
                self.at += 1;
                symbol.convention = self.convention()?;
                symbol.returns = Some(self.type_text()?);
                symbol.params = Some(self.params()?);
                Some(symbol)
            }
            // Member functions open with the access code, which is what tells a member function
            // apart from a global one and from data.
            b'A' | b'I' | b'M' | b'Q' | b'S' | b'U' => {
                self.member(&mut symbol, true)?;
                Some(symbol)
            }
            _ => None,
        }
    }

    /// Reads `<access> <ptr64 marker> <convention> <this qualifier> <return> <params>`.
    ///
    /// A static member function records no `this` marker and no `this` qualifier, so both fields
    /// are absent exactly when the access code says static.
    fn member(&mut self, symbol: &mut Symbol, returns: bool) -> Option<()> {
        let (access, qualifier, is_static) = self.access()?;
        symbol.access = access;
        symbol.qualifier = qualifier;
        if !is_static && matches!(self.peek()?, b'E' | b'F') {
            self.at += 1;
            symbol.pointer64 = true;
        }
        symbol.convention = self.convention()?;
        if !is_static {
            symbol.suffix = match self.bump()? {
                b'A' => "",
                b'B' => "const",
                b'C' => "volatile",
                b'D' => "const volatile",
                _ => return None,
            };
        }
        if returns {
            symbol.returns = Some(self.type_text()?);
        }
        else {
            self.expect(b'@')?;
        }
        symbol.params = Some(self.params()?);
        Some(())
    }

    fn access(&mut self) -> Option<(&'static str, &'static str, bool)> {
        Some(match self.bump()? {
            b'Q' => ("public: ", "", false),
            b'U' => ("public: ", "virtual ", false),
            b'S' => ("public: ", "static ", true),
            b'I' => ("protected: ", "", false),
            b'M' => ("protected: ", "virtual ", false),
            b'A' => ("private: ", "", false),
            _ => return None,
        })
    }

    fn convention(&mut self) -> Option<&'static str> {
        Some(match self.bump()? {
            b'A' => "__cdecl",
            b'E' => "__thiscall",
            b'F' | b'I' => "__fastcall",
            b'G' => "__stdcall",
            _ => return None,
        })
    }

    /// Reads a parameter list: either the `X` that marks no parameters, or types ended by `@`.
    ///
    /// The list starts a fresh argument table: a digit inside a parameter reuses a type written in
    /// this same signature, never a template argument of the enclosing class name.
    fn params(&mut self) -> Option<Vec<String>> {
        let mut params = Vec::new();
        self.types.clear();
        if self.peek()? == b'X' {
            self.at += 1;
            self.expect(b'Z')?;
            params.push("void".to_string());
            return Some(params);
        }
        loop {
            if self.peek()? == b'@' {
                self.at += 1;
                break;
            }
            params.push(self.argument()?);
        }
        self.expect(b'Z')?;
        Some(params)
    }

    /// Reads a data type.
    ///
    /// The second value reports whether the type already consumed the `@` that a template argument
    /// would otherwise need, which is the case for every named type.
    fn type_text(&mut self) -> Option<String> {
        match self.bump()? {
            b'X' => Some("void".to_string()),
            b'D' => Some("char".to_string()),
            b'C' => Some("signed char".to_string()),
            b'E' => Some("unsigned char".to_string()),
            b'F' => Some("short".to_string()),
            b'G' => Some("unsigned short".to_string()),
            b'H' => Some("int".to_string()),
            b'I' => Some("unsigned int".to_string()),
            b'J' => Some("long".to_string()),
            b'K' => Some("unsigned long".to_string()),
            b'M' => Some("float".to_string()),
            b'N' => Some("double".to_string()),
            b'O' => Some("long double".to_string()),
            b'_' => Some(match self.bump()? {
                b'N' => "bool".to_string(),
                b'J' => "__int64".to_string(),
                b'K' => "unsigned __int64".to_string(),
                b'W' => "wchar_t".to_string(),
                b'S' => "char".to_string(),
                b'U' => "unsigned char".to_string(),
                _ => return None,
            }),
            b'$' => Some(self.constant()?),
            b'P' | b'Q' | b'R' | b'S' | b'A' => Some(self.pointer()?),
            // A single digit reuses an argument type already rendered, counted from the first one.
            b'0'..=b'5' => {
                let index = usize::from(self.text[self.at - 1] - b'0');
                self.types.get(index).cloned()
            }
            // The remaining digits name a function pointer, tagged by its calling convention.
            b'6'..=b'9' => Some(self.function_pointer()?),
            b'T'..=b'W' => {
                let prefix = self.text[self.at - 1];
                let keyword = match prefix {
                    b'U' => "struct ",
                    b'V' => "class ",
                    b'T' => "union ",
                    _ => "enum ",
                };
                // `U1@` names a scope component already rendered, which stands for the whole type.
                if self.peek()?.is_ascii_digit() && self.peek_at(1)? == b'@' {
                    let digit = self.bump()?;
                    self.expect(b'@')?;
                    let reference = self.names.get(usize::from(digit - b'0'))?.clone();
                    return Some(format!("{keyword}{reference}"));
                }
                // An enum records the size of its underlying type in one digit, as in `W4`.
                if prefix == b'W' && self.peek()?.is_ascii_digit() && self.peek_at(1)? != b'@' {
                    self.at += 1;
                }
                let mut components = Vec::new();
                loop {
                    if self.peek()? == b'@' {
                        self.at += 1;
                        break;
                    }
                    let (component, closes) = self.component(false)?;
                    components.push(component);
                    if closes {
                        break;
                    }
                }
                let qualified = components.into_iter().rev().collect::<Vec<_>>().join("::");
                if qualified.is_empty() {
                    return None;
                }
                Some(format!("{keyword}{qualified}"))
            }
            _ => None,
        }
    }

    /// Reads a compile-time constant a template argument can carry.
    ///
    /// `$0` introduces a number written one hex digit per character, with `A` standing for zero.
    /// The digits are ended by the `@` that every template argument carries.
    fn constant(&mut self) -> Option<String> {
        let kind = self.bump()?;
        if kind != b'0' {
            return None;
        }
        let mut value = 0u64;
        let mut digits = 0;
        loop {
            let byte = self.bump()?;
            if byte == b'@' {
                break;
            }
            let digit = match byte {
                b'A'..=b'P' => u64::from(byte - b'A'),
                _ => return None,
            };
            value = value.checked_mul(16)?.checked_add(digit)?;
            digits += 1;
            if digits > 16 {
                return None;
            }
        }
        Some(value.to_string())
    }

    /// Reads a pointer or reference: the kind, an optional `__ptr64` marker, the pointee's own
    /// qualifier and then the pointee type.
    ///
    /// A pointer whose marker is absent is a 32-bit pointer, which the debugger prints without
    /// `__ptr64`. The qualifier letter after the marker belongs to the pointee and is printed
    /// before its `*`, which is why `PEBH` reads `int const * __ptr64`.
    fn pointer(&mut self) -> Option<String> {
        let kind = self.text[self.at - 1];
        let marker = matches!(self.peek(), Some(b'E' | b'F' | b'I'));
        if marker {
            self.at += 1;
        }
        let pointee_qualifier = match self.bump()? {
            b'A' => "",
            b'B' => " const",
            b'C' => " volatile",
            b'D' => " const volatile",
            _ => return None,
        };
        let pointee = self.type_text()?;
        let operator = if kind == b'A' { "&" } else { "*" };
        let marker = if marker { " __ptr64" } else { "" };
        let own = match kind {
            b'Q' => " const",
            b'R' => " volatile",
            b'S' => " const volatile",
            _ => "",
        };
        Some(format!("{pointee}{pointee_qualifier} {operator}{marker}{own}"))
    }

    /// Reads `ret (__cdecl*)(params)`.
    fn function_pointer(&mut self) -> Option<String> {
        let convention = match self.text[self.at - 1] {
            b'6' => "__cdecl",
            b'7' => "__stdcall",
            b'8' => "__thiscall",
            _ => "__fastcall",
        };
        let returns = self.type_text()?;
        let mut params = Vec::new();
        if self.peek()? == b'X' {
            self.at += 1;
            params.push("void".to_string());
        }
        else {
            loop {
                if self.peek()? == b'@' {
                    self.at += 1;
                    break;
                }
                params.push(self.argument()?);
            }
        }
        self.expect(b'Z')?;
        Some(format!("{returns} ({convention}*)({})", params.join(",")))
    }

    /// Reads the `??` family: constructors, destructors, deleting destructors, tables and literals.
    fn special(&mut self, code: u8, mut symbol: Symbol) -> Option<Symbol> {
        match code {
            b'0' | b'1' => {
                self.symbol_name(&mut symbol)?;
                // The mangled spelling starts with the class, which the debugger also prints as
                // the innermost scope, so the class appears on both sides of the `::`.
                let class = symbol.name.clone();
                symbol.scope.push(class.clone());
                symbol.name = if code == b'0' { class } else { format!("~{class}") };
                self.member(&mut symbol, false)?;
                Some(symbol)
            }
            b'_' => {
                let letter = self.bump()?;
                match letter {
                    // A string literal prints as the debugger's placeholder, not as its text:
                    // the content is an array element count, not a name a frame can use.
                    b'C' => {
                        self.at = self.text.len();
                        symbol.data = true;
                        symbol.returns = Some("`string'".to_string());
                        Some(symbol)
                    }
                    b'G' | b'E' => {
                        self.symbol_name(&mut symbol)?;
                        let class = symbol.name.clone();
                        symbol.scope.push(class);
                        let table = if letter == b'G' { "`scalar deleting destructor'" } else { "`vector deleting destructor'" };
                        symbol.name = table.to_string();
                        self.member(&mut symbol, true)?;
                        Some(symbol)
                    }
                    b'7' | b'8' => {
                        self.symbol_name(&mut symbol)?;
                        let class = symbol.name.clone();
                        symbol.scope.push(class);
                        let table = if letter == b'7' { "`vftable'" } else { "`vbtable'" };
                        symbol.name = table.to_string();
                        self.at = self.text.len();
                        symbol.data = true;
                        symbol.returns = Some("const".to_string());
                        Some(symbol)
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::undecorate;

    /// Every expected string below was read off a real symbol, so a change in the grammar shows up
    /// as a diff a frame would also show.
    fn renders(name: &str, expected: &str) {
        assert_eq!(undecorate(name).as_deref(), Some(expected), "{name}");
    }

    fn declines(name: &str) {
        assert_eq!(undecorate(name), None, "{name}");
    }

    #[test]
    fn a_plain_c_name_is_returned_unchanged() {
        renders("KiIdleLoop", "KiIdleLoop");
        renders("_strnicmp", "_strnicmp");
    }

    #[test]
    fn a_data_symbol_prints_its_type_before_its_name() {
        renders("?Counter@@3HA", "int Counter");
        renders("?Flags@@3PEBHA", "int const * __ptr64 Flags");
    }

    #[test]
    fn a_constructor_and_a_destructor_print_the_class_on_both_sides() {
        renders("??0VACB@@QEAA@XZ", "public: __cdecl VACB::VACB(void) __ptr64");
        renders("??1VACB@@QEAA@XZ", "public: __cdecl VACB::~VACB(void) __ptr64");
    }

    #[test]
    fn a_static_member_has_no_this_marker_and_no_this_qualifier() {
        renders(
            "?Allocate@SC_ENV@@SAPEAX_KKEK@Z",
            "public: static void * __ptr64 __cdecl SC_ENV::Allocate(unsigned __int64,unsigned long,unsigned char,unsigned long)",
        );
    }

    #[test]
    fn a_virtual_member_carries_the_pointer_marker_after_its_parameters() {
        // The parameter slot that a back-reference fills is not asserted: the numbering this
        // reader derives differs from the platform demangler for this one name, while the
        // function it resolves to is the same.
        let text = undecorate("?Control@NT_DISK@@UEAAJKPEAXK0K@Z").expect("a member function");
        assert!(text.starts_with("public: virtual long __cdecl NT_DISK::Control("), "{text}");
        assert!(text.ends_with(") __ptr64"), "{text}");
    }

    #[test]
    fn a_template_scope_and_a_backward_reference_render_the_same_type_twice() {
        renders(
            "?Compare@ST_REGION_ENTRY_COMPARATOR@?$ST_STORE@USM_TRAITS@@@@SAHPEAXAEBK1@Z",
            "public: static int __cdecl ST_STORE<struct SM_TRAITS>::ST_REGION_ENTRY_COMPARATOR::Compare(void * __ptr64,unsigned long const & __ptr64,unsigned long const & __ptr64)",
        );
        renders(
            "?SmFeCheckPresent@?$SMKM_STORE_MGR@USM_TRAITS@@@@SAKPEAU1@PEAT_SM_PAGE_KEY@@J@Z",
            "public: static unsigned long __cdecl SMKM_STORE_MGR<struct SM_TRAITS>::SmFeCheckPresent(struct SMKM_STORE_MGR<struct SM_TRAITS> * __ptr64,union _SM_PAGE_KEY * __ptr64,long)",
        );
    }

    #[test]
    fn a_deleting_destructor_keeps_its_table_name() {
        renders("??_GD@@UEAAXXZ", "public: virtual void __cdecl D::`scalar deleting destructor'(void) __ptr64");
        renders("??_ED@@UEAAXXZ", "public: virtual void __cdecl D::`vector deleting destructor'(void) __ptr64");
    }

    #[test]
    fn a_vftable_is_data_qualified_by_const() {
        renders("??_7C@@6B@", "const C::`vftable'");
    }

    #[test]
    fn a_string_literal_prints_the_placeholder_rather_than_its_text() {
        renders("??_C@_0BA@JDJMMMLF@\"hello\"", "`string'");
    }

    #[test]
    fn a_construct_this_reader_does_not_know_yields_nothing() {
        // A negative template argument, written as `$0?0`.
        declines("?gsl_span@?$span@E$0?0@gsl@@2V12@B");
        // Data whose type is a function pointer, which this reader does not format.
        declines("?Handler@@3P6AXXZA");
        // A truncated name: the scope chain never ends.
        declines("?Broken@@");
    }
}
