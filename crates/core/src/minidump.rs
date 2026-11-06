use std::{fs, path::Path};

use serde::Serialize;

use crate::{
    bugcheck::{lookup_bugcheck, parameter_labels, parameter_notes},
    error::{Error, Result},
};

const MINIDUMP_SIGNATURE: u32 = 0x504D_444D;
const PAGE_SIGNATURE: u32 = 0x4547_4150;
const DUMP64_SIGNATURE: u32 = 0x3436_5544;
const DUMP32_SIGNATURE: u32 = 0x504D_5544;

const STREAM_THREAD_LIST: u32 = 3;
const STREAM_MODULE_LIST: u32 = 4;
const STREAM_EXCEPTION: u32 = 6;
const STREAM_SYSTEM_INFO: u32 = 7;
const STREAM_MISC_INFO: u32 = 15;

const MAX_STREAMS: u32 = 256;
const MAX_MODULES: u32 = 65_536;
const MAX_STRING_BYTES: u32 = 32_768;

/// Windows `DUMP_TYPE` values stored in the 64-bit kernel dump header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DumpType {
    Full,
    Summary,
    Header,
    Triage,
    BitmapFull,
    BitmapKernel,
    Automatic,
    Unknown,
}

impl DumpType {
    fn from_header(value: u32) -> Self {
        match value {
            1 => Self::Full,
            2 => Self::Summary,
            3 => Self::Header,
            4 => Self::Triage,
            5 => Self::BitmapFull,
            6 => Self::BitmapKernel,
            7 => Self::Automatic,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DumpFormat {
    #[serde(rename = "minidump")]
    MiniDump,
    #[serde(rename = "kernel-dump-64")]
    KernelDump64,
    #[serde(rename = "kernel-dump-32")]
    KernelDump32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemInfo {
    pub architecture: String,
    pub os_version: String,
    pub build_number: u32,
    pub processor_count: u8,
    pub product_type: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModuleInfo {
    pub name: String,
    pub base_address: String,
    pub size_bytes: u32,
    pub timestamp: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreadInfo {
    pub thread_id: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExceptionInfo {
    pub thread_id: u32,
    pub code: String,
    pub code_value: u32,
    pub address: String,
    pub parameters: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BugcheckSummary {
    pub code: u32,
    pub code_hex: String,
    pub known: bool,
    pub name: Option<&'static str>,
    pub summary: Option<&'static str>,
    pub common_causes: Vec<&'static str>,
    pub parameters: Vec<String>,
    pub parameter_labels: Vec<&'static str>,
    pub parameter_notes: Vec<Option<&'static str>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DumpReport {
    pub format: DumpFormat,
    /// Header-declared dump kind; minidumps do not declare one.
    pub dump_type: Option<DumpType>,
    pub size_bytes: u64,
    /// ISO-8601 UTC time recorded when the dump was generated, when the header carries one.
    pub captured_at: Option<String>,
    pub system: Option<SystemInfo>,
    pub bugcheck: Option<BugcheckSummary>,
    pub exception: Option<ExceptionInfo>,
    pub modules: Vec<ModuleInfo>,
    pub threads: Vec<ThreadInfo>,
    pub process_id: Option<u32>,
    pub warnings: Vec<String>,
}

impl DumpReport {
    fn new(format: DumpFormat, size_bytes: u64) -> Self {
        Self {
            format,
            dump_type: None,
            size_bytes,
            captured_at: None,
            system: None,
            bugcheck: None,
            exception: None,
            modules: Vec::new(),
            threads: Vec::new(),
            process_id: None,
            warnings: Vec::new(),
        }
    }
}

/// Reads a dump file and returns the parsed report.
pub fn analyze_file(path: &Path) -> Result<DumpReport> {
    let bytes = fs::read(path).map_err(|source| Error::io(path.display().to_string(), source))?;
    analyze_bytes(&bytes)
}

/// Parses dump bytes. Supports Windows minidumps (`MDMP`) and kernel dump headers (`PAGE`).
pub fn analyze_bytes(bytes: &[u8]) -> Result<DumpReport> {
    let signature = read_u32(bytes, 0).ok_or_else(|| Error::message("file is too small to contain a dump header"))?;
    match signature {
        MINIDUMP_SIGNATURE => parse_minidump(bytes),
        PAGE_SIGNATURE => parse_kernel_dump(bytes),
        other => Err(Error::message(format!("unrecognized dump signature 0x{other:08X}; expected a Windows minidump or kernel dump"))),
    }
}

fn parse_minidump(bytes: &[u8]) -> Result<DumpReport> {
    let stream_count = read_u32(bytes, 8).ok_or_else(|| Error::message("truncated minidump header"))?;
    let directory_rva = read_u32(bytes, 12).ok_or_else(|| Error::message("truncated minidump header"))?;
    if stream_count > MAX_STREAMS {
        return Err(Error::message(format!("minidump declares {stream_count} streams, which exceeds the supported limit")));
    }

    let mut report = DumpReport::new(DumpFormat::MiniDump, bytes.len() as u64);
    report.captured_at = read_u32(bytes, 20).filter(|value| *value > 0).and_then(|value| iso8601_from_unix_ms(i64::from(value) * 1000));

    for index in 0..stream_count {
        let entry_rva = directory_rva as usize + index as usize * 12;
        if entry_rva.checked_add(12).is_none_or(|end| end > bytes.len()) {
            report.warnings.push(format!("stream directory entry {index} is out of bounds"));
            break;
        }
        let stream_type = read_u32(bytes, entry_rva as u32).unwrap_or_default();
        let data_size = read_u32(bytes, entry_rva as u32 + 4).unwrap_or_default();
        let data_rva = read_u32(bytes, entry_rva as u32 + 8).unwrap_or_default();
        if data_size == 0 {
            continue;
        }
        match stream_type {
            STREAM_SYSTEM_INFO => match parse_system_info(bytes, data_rva) {
                Some(system) => report.system = Some(system),
                None => report.warnings.push("system info stream is malformed".to_string()),
            },
            STREAM_MODULE_LIST => match parse_module_list(bytes, data_rva) {
                Some(modules) => report.modules = modules,
                None => report.warnings.push("module list stream is malformed".to_string()),
            },
            STREAM_THREAD_LIST => match parse_thread_list(bytes, data_rva) {
                Some(threads) => report.threads = threads,
                None => report.warnings.push("thread list stream is malformed".to_string()),
            },
            STREAM_EXCEPTION => match parse_exception(bytes, data_rva) {
                Some(exception) => report.exception = Some(exception),
                None => report.warnings.push("exception stream is malformed".to_string()),
            },
            STREAM_MISC_INFO => report.process_id = parse_process_id(bytes, data_rva),
            _ => {}
        }
    }

    if report.modules.is_empty() {
        report.warnings.push("no module list was found in the minidump".to_string());
    }
    if report.bugcheck.is_none() {
        report.warnings.push("minidumps do not carry a bugcheck code; pass the code to `bugcheck` or use a kernel dump".to_string());
    }
    Ok(report)
}

fn parse_system_info(bytes: &[u8], rva: u32) -> Option<SystemInfo> {
    let architecture = read_u16(bytes, rva)?;
    let processor_count = read_u8(bytes, rva + 6)?;
    let product_type = read_u8(bytes, rva + 7)?;
    let build = read_u32(bytes, rva + 16)?;
    let platform_id = read_u32(bytes, rva + 20)?;
    if platform_id != 2 {
        return None;
    }
    Some(SystemInfo {
        architecture: architecture_name(architecture).to_string(),
        os_version: windows_release(build).to_string(),
        build_number: build,
        processor_count,
        product_type: product_type_name(product_type).to_string(),
    })
}

fn parse_module_list(bytes: &[u8], rva: u32) -> Option<Vec<ModuleInfo>> {
    let count = read_u32(bytes, rva)?;
    if count > MAX_MODULES {
        return None;
    }
    let mut modules = Vec::with_capacity(count.min(4096) as usize);
    for index in 0..count {
        let base = rva as usize + 4 + index as usize * 108;
        let base_address = read_u64(bytes, base as u32)?;
        let size_bytes = read_u32(bytes, base as u32 + 8)?;
        let timestamp = read_u32(bytes, base as u32 + 16)?;
        let name_rva = read_u32(bytes, base as u32 + 20)?;
        let name = read_utf16_string(bytes, name_rva).unwrap_or_default();
        modules.push(ModuleInfo { name, base_address: hex64(base_address), size_bytes, timestamp });
    }
    Some(modules)
}

fn parse_thread_list(bytes: &[u8], rva: u32) -> Option<Vec<ThreadInfo>> {
    let count = read_u32(bytes, rva)?;
    if count > 65_536 {
        return None;
    }
    let mut threads = Vec::with_capacity(count.min(4096) as usize);
    for index in 0..count {
        let offset = rva as usize + 4 + index as usize * 48;
        let thread_id = read_u32(bytes, offset as u32)?;
        threads.push(ThreadInfo { thread_id });
    }
    Some(threads)
}

fn parse_exception(bytes: &[u8], rva: u32) -> Option<ExceptionInfo> {
    let thread_id = read_u32(bytes, rva)?;
    let code = read_u32(bytes, rva + 8)?;
    let address = read_u64(bytes, rva + 24)?;
    let parameter_count = read_u32(bytes, rva + 32)?.min(15) as usize;
    let mut parameters = Vec::with_capacity(parameter_count);
    for index in 0..parameter_count {
        parameters.push(hex64(read_u64(bytes, rva + 40 + index as u32 * 8)?));
    }
    Some(ExceptionInfo { thread_id, code: format!("0x{code:08X}"), code_value: code, address: hex64(address), parameters })
}

fn parse_process_id(bytes: &[u8], rva: u32) -> Option<u32> {
    let flags = read_u32(bytes, rva + 4)?;
    if flags & 0x1 == 0 {
        return None;
    }
    read_u32(bytes, rva + 8)
}

fn parse_kernel_dump(bytes: &[u8]) -> Result<DumpReport> {
    let valid_dump = read_u32(bytes, 4).ok_or_else(|| Error::message("truncated kernel dump header"))?;
    let (format, bugcheck_offset, parameter_offset, machine_offset, processor_offset) = match valid_dump {
        DUMP64_SIGNATURE => (DumpFormat::KernelDump64, 0x38, 0x40, 0x30, 0x34),
        DUMP32_SIGNATURE => (DumpFormat::KernelDump32, 0x28, 0x2C, 0x20, 0x24),
        other => {
            return Err(Error::message(format!("unrecognized kernel dump marker 0x{other:08X}; expected DU64 or DUMP")));
        }
    };

    let build = read_u32(bytes, 12).ok_or_else(|| Error::message("truncated kernel dump header"))?;
    let machine = read_u32(bytes, machine_offset).ok_or_else(|| Error::message("truncated kernel dump header"))?;
    let processors = read_u32(bytes, processor_offset).ok_or_else(|| Error::message("truncated kernel dump header"))?;
    let bugcheck_code = read_u32(bytes, bugcheck_offset).ok_or_else(|| Error::message("truncated kernel dump header"))?;

    let is_64 = matches!(format, DumpFormat::KernelDump64);
    let mut report = DumpReport::new(format, bytes.len() as u64);
    if is_64 {
        // `DUMP_TYPE` and the capture time sit behind the memory descriptors of the 64-bit header.
        report.dump_type = read_u32(bytes, 0xF98).map(DumpType::from_header);
        report.captured_at = read_u64(bytes, 0xFA8).and_then(filetime_to_iso8601);
    }
    report.system = Some(SystemInfo {
        architecture: machine_name(machine).to_string(),
        os_version: windows_release(build).to_string(),
        build_number: build,
        processor_count: processors.min(255) as u8,
        product_type: "unknown".to_string(),
    });

    if bugcheck_code == 0 {
        report.warnings.push("kernel dump header contains no bugcheck code".to_string());
    }
    else {
        let values = (0..4)
            .map(|index| {
                let offset = parameter_offset + index * if is_64 { 8 } else { 4 };
                if is_64 { read_u64(bytes, offset).unwrap_or_default() } else { read_u32(bytes, offset).unwrap_or_default() as u64 }
            })
            .collect::<Vec<_>>();
        let info = lookup_bugcheck(bugcheck_code);
        report.bugcheck = Some(BugcheckSummary {
            code: bugcheck_code,
            code_hex: format!("0x{bugcheck_code:08X}"),
            known: info.known,
            name: info.name,
            summary: info.summary,
            common_causes: info.common_causes,
            parameter_labels: parameter_labels(bugcheck_code).to_vec(),
            parameter_notes: parameter_notes(bugcheck_code, &values),
            parameters: values.iter().map(|value| hex64(*value)).collect(),
        });
    }

    report.warnings.push(
        "not_implemented: module-list: kernel triage dumps carry module names only inside mapped memory, and this parser does not translate virtual addresses, so module and `MODULE+offset` attribution is unavailable"
            .to_string(),
    );
    report.warnings.push(
        "not_implemented: thread-list: kernel triage dumps store only the faulting context, so per-thread enumeration is unavailable"
            .to_string(),
    );
    report.warnings.push(
        "not_implemented: stack-unwind: recovering a module+offset stack needs the Windows debug engine, which this build does not bind"
            .to_string(),
    );
    report
        .warnings
        .push("dependency_blocked: symbol-resolve: symbol names need the Windows debug engine and a configured symbol path".to_string());
    Ok(report)
}

/// Maps a Windows build number to its marketed release name.
fn windows_release(build: u32) -> &'static str {
    match build {
        7600..=7601 => "Windows 7",
        9200 => "Windows 8",
        9600 => "Windows 8.1",
        10_240..=21_999 => "Windows 10",
        22_000..=u32::MAX => "Windows 11",
        _ => "Windows",
    }
}

fn architecture_name(value: u16) -> &'static str {
    match value {
        0 => "x86",
        5 => "arm",
        6 => "ia64",
        9 => "x64",
        12 => "arm64",
        _ => "unknown",
    }
}

fn machine_name(value: u32) -> &'static str {
    match value {
        0x014C => "x86",
        0x01C4 => "arm",
        0x8664 => "x64",
        0xAA64 => "arm64",
        _ => "unknown",
    }
}

fn product_type_name(value: u8) -> &'static str {
    match value {
        1 => "workstation",
        2 => "domain-controller",
        3 => "server",
        _ => "unknown",
    }
}

/// Converts a Windows `FILETIME` (100 ns ticks since 1601-01-01) to ISO-8601 UTC.
fn filetime_to_iso8601(filetime: u64) -> Option<String> {
    if filetime == 0 {
        return None;
    }
    let unix_ms = i128::from(filetime) / 10_000 - 11_644_473_600_000;
    iso8601_from_unix_ms(i64::try_from(unix_ms).ok()?)
}

fn iso8601_from_unix_ms(milliseconds: i64) -> Option<String> {
    // Reject times outside 1970-01-01 .. 9999-12-31 so garbage headers do not print as a date.
    if !(0..=253_402_300_799_999).contains(&milliseconds) {
        return None;
    }
    let seconds = milliseconds / 1000;
    let millis = milliseconds % 1000;
    let days = seconds / 86_400;
    let seconds_of_day = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3600;
    let minute = (seconds_of_day % 3600) / 60;
    let second = seconds_of_day % 60;
    Some(format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z"))
}

/// Gregorian calendar conversion for days since 1970-01-01 (Howard Hinnant's civil algorithm).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 { shifted } else { shifted - 146_096 } / 146_097;
    let day_of_era = (shifted - era * 146_097) as u32;
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = i64::from(year_of_era) + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_position = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_position + 2) / 5 + 1;
    let month = if month_position < 10 { month_position + 3 } else { month_position - 9 };
    (if month <= 2 { year + 1 } else { year }, month, day)
}

fn read_utf16_string(bytes: &[u8], rva: u32) -> Option<String> {
    let byte_length = read_u32(bytes, rva)?;
    if byte_length > MAX_STRING_BYTES || byte_length % 2 != 0 {
        return None;
    }
    let start = rva as usize + 4;
    let end = start.checked_add(byte_length as usize)?;
    let data = bytes.get(start..end)?;
    let (chunks, _) = data.as_chunks::<2>();
    let units: Vec<u16> = chunks.iter().map(|chunk| u16::from_le_bytes(*chunk)).collect();
    Some(String::from_utf16_lossy(&units))
}

fn read_u8(bytes: &[u8], offset: u32) -> Option<u8> {
    bytes.get(offset as usize).copied()
}

fn read_u16(bytes: &[u8], offset: u32) -> Option<u16> {
    let data = bytes.get(offset as usize..offset as usize + 2)?;
    Some(u16::from_le_bytes([data[0], data[1]]))
}

fn read_u32(bytes: &[u8], offset: u32) -> Option<u32> {
    let data = bytes.get(offset as usize..offset as usize + 4)?;
    Some(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
}

fn read_u64(bytes: &[u8], offset: u32) -> Option<u64> {
    let data = bytes.get(offset as usize..offset as usize + 8)?;
    Some(u64::from_le_bytes([data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]]))
}

fn hex64(value: u64) -> String {
    format!("0x{value:016X}")
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        bytes: Vec<u8>,
    }

    impl Fixture {
        fn push_u8(&mut self, value: u8) {
            self.bytes.push(value);
        }

        fn push_u16(&mut self, value: u16) {
            self.bytes.extend_from_slice(&value.to_le_bytes());
        }

        fn push_u32(&mut self, value: u32) {
            self.bytes.extend_from_slice(&value.to_le_bytes());
        }

        fn push_u64(&mut self, value: u64) {
            self.bytes.extend_from_slice(&value.to_le_bytes());
        }

        fn put_u32(&mut self, offset: usize, value: u32) {
            self.bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
    }

    fn build_minidump() -> Vec<u8> {
        let stream_count = 5u32;
        let directory_rva = 32usize;
        let data_base = directory_rva + stream_count as usize * 12;

        let system_rva = data_base;
        let system_size = 56usize;
        let module_list_rva = system_rva + system_size;
        let module_list_size = 4 + 108;
        let module_name_rva = module_list_rva + module_list_size;
        let module_name = "ntoskrnl.exe";
        let module_name_size = 4 + module_name.len() * 2;
        let thread_list_rva = module_name_rva + module_name_size;
        let thread_list_size = 4 + 48 * 2;
        let exception_rva = thread_list_rva + thread_list_size;
        let exception_size = 168usize;
        let misc_rva = exception_rva + exception_size;
        let misc_size = 24usize;

        let mut fixture = Fixture { bytes: Vec::new() };
        fixture.push_u32(MINIDUMP_SIGNATURE);
        fixture.push_u32(0xA793);
        fixture.push_u32(stream_count);
        fixture.push_u32(directory_rva as u32);
        fixture.push_u32(0);
        fixture.push_u32(0);
        fixture.push_u64(0);

        fixture.push_u32(STREAM_SYSTEM_INFO);
        fixture.push_u32(system_size as u32);
        fixture.push_u32(system_rva as u32);
        fixture.push_u32(STREAM_MODULE_LIST);
        fixture.push_u32(module_list_size as u32);
        fixture.push_u32(module_list_rva as u32);
        fixture.push_u32(STREAM_THREAD_LIST);
        fixture.push_u32(thread_list_size as u32);
        fixture.push_u32(thread_list_rva as u32);
        fixture.push_u32(STREAM_EXCEPTION);
        fixture.push_u32(exception_size as u32);
        fixture.push_u32(exception_rva as u32);
        fixture.push_u32(STREAM_MISC_INFO);
        fixture.push_u32(misc_size as u32);
        fixture.push_u32(misc_rva as u32);

        fixture.push_u16(9);
        fixture.push_u16(6);
        fixture.push_u16(0x5E03);
        fixture.push_u8(8);
        fixture.push_u8(1);
        fixture.push_u32(10);
        fixture.push_u32(0);
        fixture.push_u32(19045);
        fixture.push_u32(2);
        fixture.push_u32(0);
        fixture.push_u16(0x100);
        fixture.push_u16(0);
        for _ in 0..6 {
            fixture.push_u32(0);
        }

        fixture.push_u32(1);
        fixture.push_u64(0x0000_0001_4000_0000);
        fixture.push_u32(0x1000);
        fixture.push_u32(0);
        fixture.push_u32(0x5F00_0000);
        fixture.push_u32(module_name_rva as u32);
        for _ in 0..13 {
            fixture.push_u32(0);
        }
        fixture.push_u32(0);
        fixture.push_u32(0);
        fixture.push_u32(0);
        fixture.push_u32(0);
        fixture.push_u64(0);
        fixture.push_u64(0);

        fixture.push_u32((module_name.len() * 2) as u32);
        for byte in module_name.as_bytes() {
            fixture.push_u8(*byte);
            fixture.push_u8(0);
        }

        fixture.push_u32(2);
        for thread_id in [100u32, 200u32] {
            fixture.push_u32(thread_id);
            for _ in 0..11 {
                fixture.push_u32(0);
            }
        }

        fixture.push_u32(100);
        fixture.push_u32(0);
        fixture.push_u32(0x8000_0003);
        fixture.push_u32(0);
        fixture.push_u64(0);
        fixture.push_u64(0x0000_7FF9_1234_5678);
        fixture.push_u32(1);
        fixture.push_u32(0);
        fixture.push_u64(0x1234);
        for _ in 0..14 {
            fixture.push_u64(0);
        }
        fixture.push_u32(0);
        fixture.push_u32(0);

        fixture.push_u32(24);
        fixture.push_u32(0x1);
        fixture.push_u32(4321);
        fixture.push_u32(0);
        fixture.push_u32(0);
        fixture.push_u32(0);

        assert_eq!(
            fixture.bytes.len(),
            data_base + system_size + module_list_size + module_name_size + thread_list_size + exception_size + misc_size
        );
        fixture.put_u32(0, MINIDUMP_SIGNATURE);
        fixture.put_u32(20, 1_700_000_000);
        fixture.bytes
    }

    #[test]
    fn parses_synthetic_minidump() {
        let report = analyze_bytes(&build_minidump()).expect("minidump should parse");
        assert_eq!(report.format, DumpFormat::MiniDump);
        assert_eq!(report.dump_type, None);
        assert_eq!(report.captured_at.as_deref(), Some("2023-11-14T22:13:20.000Z"));
        let system = report.system.expect("system info");
        assert_eq!(system.architecture, "x64");
        assert_eq!(system.os_version, "Windows 10");
        assert_eq!(system.build_number, 19045);
        assert_eq!(system.processor_count, 8);
        assert_eq!(report.modules.len(), 1);
        assert_eq!(report.modules[0].name, "ntoskrnl.exe");
        assert_eq!(report.modules[0].base_address, "0x0000000140000000");
        assert_eq!(report.threads.len(), 2);
        assert_eq!(report.threads[1].thread_id, 200);
        let exception = report.exception.expect("exception");
        assert_eq!(exception.code, "0x80000003");
        assert_eq!(exception.address, "0x00007FF912345678");
        assert_eq!(exception.parameters, vec!["0x0000000000001234".to_string()]);
        assert_eq!(report.process_id, Some(4321));
    }

    #[test]
    fn parses_synthetic_kernel_dump_header() {
        let mut bytes = vec![0u8; 0x2000];
        bytes[0..4].copy_from_slice(b"PAGE");
        bytes[4..8].copy_from_slice(b"DU64");
        bytes[8..12].copy_from_slice(&15u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&26100u32.to_le_bytes());
        bytes[0x30..0x34].copy_from_slice(&0x8664u32.to_le_bytes());
        bytes[0x34..0x38].copy_from_slice(&16u32.to_le_bytes());
        bytes[0x38..0x3C].copy_from_slice(&0x4Eu32.to_le_bytes());
        bytes[0x40..0x48].copy_from_slice(&7u64.to_le_bytes());
        bytes[0x48..0x50].copy_from_slice(&0x00DC_E80Du64.to_le_bytes());
        bytes[0x50..0x58].copy_from_slice(&1u64.to_le_bytes());
        bytes[0xF98..0xF9C].copy_from_slice(&4u32.to_le_bytes());
        // Capture time observed in a real Windows triage dump: 2026-11-04T01:09:31.038Z.
        bytes[0xFA8..0xFB0].copy_from_slice(&0x01DD_6BF9_2574_4641u64.to_le_bytes());

        let report = analyze_bytes(&bytes).expect("kernel header should parse");
        assert_eq!(report.format, DumpFormat::KernelDump64);
        assert_eq!(report.dump_type, Some(DumpType::Triage));
        assert_eq!(report.captured_at.as_deref(), Some("2026-11-04T01:09:31.038Z"));
        let system = report.system.expect("system info");
        assert_eq!(system.architecture, "x64");
        assert_eq!(system.os_version, "Windows 11");
        assert_eq!(system.build_number, 26100);
        assert_eq!(system.processor_count, 16);
        let bugcheck = report.bugcheck.expect("bugcheck");
        assert_eq!(bugcheck.code, 0x4E);
        assert_eq!(bugcheck.name, Some("PFN_LIST_CORRUPT"));
        assert_eq!(bugcheck.parameters[0], "0x0000000000000007");
        assert_eq!(bugcheck.parameter_labels[0], "subtype");
        assert_eq!(bugcheck.parameter_notes[0], Some("A driver has unlocked a page more times than it locked it"));
        assert!(report.warnings.iter().any(|warning| warning.starts_with("not_implemented: module-list")));
        assert!(report.warnings.iter().any(|warning| warning.starts_with("dependency_blocked: symbol-resolve")));
    }

    #[test]
    fn rejects_malformed_capture_time() {
        assert_eq!(filetime_to_iso8601(0), None);
        assert_eq!(filetime_to_iso8601(u64::MAX), None);
    }

    #[test]
    fn rejects_unknown_signature() {
        let error = analyze_bytes(&[0u8; 32]).expect_err("zero signature must be rejected");
        assert!(error.to_string().contains("unrecognized dump signature"));
    }

    #[test]
    fn rejects_truncated_file() {
        let error = analyze_bytes(b"MD").expect_err("short file must be rejected");
        assert!(error.to_string().contains("too small"));
    }

    #[test]
    fn rejects_kernel_marker_mismatch() {
        let mut bytes = vec![0u8; 0x2000];
        bytes[0..4].copy_from_slice(b"PAGE");
        bytes[4..8].copy_from_slice(b"XXXX");
        assert!(analyze_bytes(&bytes).is_err());
    }
}
