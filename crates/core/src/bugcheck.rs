use serde::Serialize;

use crate::error::{Error, Result};

/// A bugcheck (blue screen) code entry from the built-in table.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BugcheckInfo {
    pub code: u32,
    pub code_hex: String,
    pub known: bool,
    pub name: Option<&'static str>,
    pub summary: Option<&'static str>,
    pub common_causes: Vec<&'static str>,
    pub parameter_labels: Vec<&'static str>,
}

struct Entry {
    code: u32,
    name: &'static str,
    summary: &'static str,
    causes: &'static [&'static str],
}

const ENTRIES: &[Entry] = &[
    Entry {
        code: 0x0000_000A,
        name: "IRQL_NOT_LESS_OR_EQUAL",
        summary: "A kernel-mode driver accessed pageable or invalid memory while running at an elevated IRQL.",
        causes: &[
            "A driver dereferenced an invalid pointer",
            "A driver touched pageable memory at DISPATCH_LEVEL or above",
            "Faulty memory or a failing device",
        ],
    },
    Entry {
        code: 0x0000_001A,
        name: "KMODE_EXCEPTION_NOT_HANDLED",
        summary: "A kernel-mode exception reached the top of the kernel stack without being handled.",
        causes: &[
            "A third-party driver raised an exception it did not handle",
            "Corrupted data or stack passed between drivers",
            "Incompatible filter or antivirus driver",
        ],
    },
    Entry {
        code: 0x0000_001E,
        name: "KMODE_EXCEPTION_NOT_HANDLED",
        summary: "A kernel-mode exception reached the top of the kernel stack without being handled.",
        causes: &[
            "A third-party driver raised an exception it did not handle",
            "Corrupted data or stack passed between drivers",
            "Incompatible filter or antivirus driver",
        ],
    },
    Entry {
        code: 0x0000_0019,
        name: "BAD_POOL_HEADER",
        summary: "The kernel pool header of an allocation was corrupted.",
        causes: &[
            "A driver overran a pooled allocation",
            "A driver freed the same allocation twice",
            "Driver Verifier detects the same condition with more detail",
        ],
    },
    Entry {
        code: 0x0000_002E,
        name: "DATA_BUS_ERROR",
        summary: "A parity error was detected on the memory bus.",
        causes: &["Failing RAM modules", "Memory slots or the memory controller", "Overclocked or unstable memory timings"],
    },
    Entry {
        code: 0x0000_003B,
        name: "SYSTEM_SERVICE_EXCEPTION",
        summary: "An exception happened while executing a routine that transitions from user mode to kernel mode.",
        causes: &[
            "A driver passed corrupted arguments to a kernel service",
            "Stack or object corruption caused by another driver",
            "Antivirus or filter drivers intercepting system calls",
        ],
    },
    Entry {
        code: 0x0000_004E,
        name: "PFN_LIST_CORRUPT",
        summary: "The page frame number (PFN) list was corrupted, so the memory manager stopped the system.",
        causes: &[
            "A driver unlocked a page more times than it locked it",
            "A driver corrupted the PFN database",
            "Failing memory that returns inconsistent page data",
        ],
    },
    Entry {
        code: 0x0000_0050,
        name: "PAGE_FAULT_IN_NONPAGED_AREA",
        summary: "Invalid memory was referenced while the system was running with page faults disabled for the region.",
        causes: &["A driver dereferenced a stale or invalid pointer", "A driver accessed freed pool memory", "Failing RAM or storage hardware"],
    },
    Entry {
        code: 0x0000_007E,
        name: "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
        summary: "A system thread raised an exception that no handler processed.",
        causes: &["An incompatible driver", "A driver that does not match the OS version", "Corrupted system files or failing hardware"],
    },
    Entry {
        code: 0x0000_007F,
        name: "UNEXPECTED_KERNEL_MODE_TRAP",
        summary: "The processor raised a trap that the kernel does not allow to be recovered.",
        causes: &[
            "A divide error or bad stack pointer in a driver",
            "Failing hardware or overclocking",
            "A driver that corrupts processor state",
        ],
    },
    Entry {
        code: 0x0000_009F,
        name: "DRIVER_POWER_STATE_FAILURE",
        summary: "A driver did not complete a power state transition in time.",
        causes: &[
            "A driver blocked while handling an IRP_MJ_POWER request",
            "A device that does not support the requested sleep state",
            "A filter driver holding a power IRP too long",
        ],
    },
    Entry {
        code: 0x0000_00BE,
        name: "ATTEMPTED_WRITE_TO_READONLY_MEMORY",
        summary: "A driver tried to write to a read-only section of memory.",
        causes: &[
            "A driver wrote through a pointer into read-only code or data",
            "A driver used a wrong pointer after a failed allocation",
            "Driver Verifier can repeat the same fault deterministically",
        ],
    },
    Entry {
        code: 0x0000_00C2,
        name: "BAD_POOL_CALLER",
        summary: "A driver called a pool routine with invalid arguments or from an invalid context.",
        causes: &[
            "Freeing an allocation from the wrong pool type",
            "Double free or use after free",
            "Calling a pool routine at an invalid IRQL",
        ],
    },
    Entry {
        code: 0x0000_00C4,
        name: "DRIVER_VERIFIER_DETECTED_VIOLATION",
        summary: "Driver Verifier detected a violation in a driver under test.",
        causes: &[
            "Memory corruptions, leaks or illegal IRQL usage",
            "A driver that does not follow kernel API contracts",
            "A third-party driver not compatible with the verifier checks",
        ],
    },
    Entry {
        code: 0x0000_00C5,
        name: "DRIVER_CORRUPTED_EXPOOL",
        summary: "A driver corrupted an executive pool allocation that the kernel later touched.",
        causes: &[
            "A driver overran or underran a pool allocation",
            "Use after free of an executive pool block",
            "Memory corruption by another driver",
        ],
    },
    Entry {
        code: 0x0000_00FC,
        name: "ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY",
        summary: "An attempt was made to execute code from a page that is marked non-executable.",
        causes: &[
            "A driver jumped to a data address",
            "Corrupted function pointer or vtable",
            "Self-modifying code without the proper page permissions",
        ],
    },
    Entry {
        code: 0x0000_0101,
        name: "CLOCK_WATCHDOG_TIMEOUT",
        summary: "A processor did not respond to an inter-processor interrupt within the watchdog period.",
        causes: &[
            "A driver holding a spinlock or running at high IRQL too long",
            "A virtualized or overclocked CPU",
            "Hardware or firmware instability",
        ],
    },
    Entry {
        code: 0x0000_0109,
        name: "CRITICAL_STRUCTURE_CORRUPTION",
        summary: "A critical kernel structure was modified by code that is not allowed to do so.",
        causes: &[
            "A driver patching kernel code or data structures",
            "An incompatible security or virtualization product",
            "A compromised or unsigned driver",
        ],
    },
    Entry {
        code: 0x0000_0124,
        name: "WHEA_UNCORRECTABLE_ERROR",
        summary: "Windows Hardware Error Architecture reported an uncorrectable hardware error.",
        causes: &["Failing processor, memory or PCIe device", "Overheating or unstable power delivery", "Outdated firmware or microcode"],
    },
    Entry {
        code: 0x0000_0133,
        name: "DPC_WATCHDOG_VIOLATION",
        summary: "A deferred procedure call or interrupt service routine ran longer than the watchdog allows.",
        causes: &[
            "A driver holding a DPC or spinlock too long",
            "A storage or network driver with a stalled interrupt path",
            "A driver deadlocking at DISPATCH_LEVEL",
        ],
    },
    Entry {
        code: 0x0000_0139,
        name: "KERNEL_SECURITY_CHECK_FAILURE",
        summary: "The kernel detected corruption of a critical security-related structure.",
        causes: &[
            "A driver corrupting a stack buffer or object header",
            "An invalid or stale handle passed to a kernel API",
            "An incompatible driver on the current build",
        ],
    },
    Entry {
        code: 0x0000_00EF,
        name: "CRITICAL_PROCESS_DIED",
        summary: "A process that Windows requires for normal operation terminated unexpectedly.",
        causes: &[
            "A critical system process crashed",
            "System file corruption or failing storage",
            "Malware or a security product terminating the process",
        ],
    },
    Entry {
        code: 0x0000_DEAD_DEAD,
        name: "MANUALLY_INITIATED_CRASH1",
        summary: "Crash was initiated manually or by a debugger command.",
        causes: &[
            "A debugger requested a forced crash dump",
            "The keyboard-initiated crash hotkey was used",
            "A test harness deliberately triggered the bugcheck",
        ],
    },
];

/// Labels for the four bugcheck parameters, in argument order. Codes without documented
/// labels return an empty slice instead of invented names.
pub fn parameter_labels(code: u32) -> &'static [&'static str] {
    match code {
        0x0000_004E => &["subtype", "page frame number", "current share count", "reserved"],
        _ => &[],
    }
}

/// Explains a parameter value when the code documents concrete subtypes. Values without a
/// documented meaning return `None` rather than a guessed description.
pub fn parameter_notes(code: u32, parameters: &[u64]) -> Vec<Option<&'static str>> {
    parameters
        .iter()
        .enumerate()
        .map(|(index, value)| match (code, index, *value) {
            (0x0000_004E, 0, 0x7) => Some("A driver has unlocked a page more times than it locked it"),
            _ => None,
        })
        .collect()
}

/// Looks up a bugcheck code in the built-in table. Unknown codes return a result with `known = false`.
pub fn lookup_bugcheck(code: u32) -> BugcheckInfo {
    let entry = ENTRIES.iter().find(|entry| entry.code == code);
    BugcheckInfo {
        code,
        code_hex: format!("0x{code:08X}"),
        known: entry.is_some(),
        name: entry.map(|entry| entry.name),
        summary: entry.map(|entry| entry.summary),
        common_causes: entry.map(|entry| entry.causes.to_vec()).unwrap_or_default(),
        parameter_labels: parameter_labels(code).to_vec(),
    }
}

/// Parses a user supplied bugcheck code. Windows convention is hexadecimal, with or without `0x`.
pub fn parse_code(input: &str) -> Result<u32> {
    let text = input.trim();
    if text.is_empty() {
        return Err(Error::message("bugcheck code is empty"));
    }
    let digits = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")).unwrap_or(text);
    if digits.is_empty() {
        return Err(Error::message(format!("invalid bugcheck code: {input}")));
    }
    u32::from_str_radix(digits, 16).map_err(|_| Error::message(format!("invalid bugcheck code: {input}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_code_has_name_and_causes() {
        let info = lookup_bugcheck(0x1A);
        assert!(info.known);
        assert_eq!(info.name, Some("KMODE_EXCEPTION_NOT_HANDLED"));
        assert_eq!(info.code_hex, "0x0000001A");
        assert!(!info.common_causes.is_empty());
    }

    #[test]
    fn unknown_code_is_reported_as_unknown() {
        let info = lookup_bugcheck(0x1234_5678);
        assert!(!info.known);
        assert!(info.name.is_none());
        assert!(info.common_causes.is_empty());
        assert!(info.parameter_labels.is_empty());
    }

    #[test]
    fn pfn_list_corrupt_explains_its_parameters() {
        let info = lookup_bugcheck(0x4E);
        assert!(info.known);
        assert_eq!(info.name, Some("PFN_LIST_CORRUPT"));
        assert_eq!(info.parameter_labels, vec!["subtype", "page frame number", "current share count", "reserved"]);

        let parameters = [7, 0x00DC_E80D, 1, 0];
        let notes = parameter_notes(0x4E, &parameters);
        assert_eq!(
            notes[0],
            Some("A driver has unlocked a page more times than it locked it"),
            "arg 1 subtype 7 is documented by the debugger output"
        );
        assert!(notes[1..].iter().all(Option::is_none));
    }

    #[test]
    fn parses_hex_with_and_without_prefix() {
        assert_eq!(parse_code("0x1A").unwrap(), 0x1A);
        assert_eq!(parse_code("1a").unwrap(), 0x1A);
        assert_eq!(parse_code(" 0X133 ").unwrap(), 0x133);
        assert_eq!(parse_code("DEADDEAD").unwrap(), 0xDEAD_DEAD);
    }

    #[test]
    fn rejects_invalid_input() {
        assert!(parse_code("").is_err());
        assert!(parse_code("0x").is_err());
        assert!(parse_code("nonsense").is_err());
        assert!(parse_code("0x1G").is_err());
    }
}
