use serde::Serialize;

use crate::error::CapabilityState;

pub const CAP_DUMP_PARSE: &str = "dump-parse";
pub const CAP_KERNEL_DUMP: &str = "kernel-dump";
pub const CAP_BUGCHECK: &str = "bugcheck-lookup";
pub const CAP_MODULE_LIST: &str = "module-list";
pub const CAP_KERNEL_MODULE_LIST: &str = "kernel-module-list";
pub const CAP_REPORT_WRITE: &str = "report-write";
pub const CAP_SYMBOL_RESOLVE: &str = "symbol-resolve";
pub const CAP_STACK_UNWIND: &str = "stack-unwind";
pub const CAP_LIVE_ATTACH: &str = "live-attach";
pub const CAP_GUI: &str = "gui";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Platform {
    Windows,
    Macos,
    Linux,
    Other,
}

impl Platform {
    pub fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        }
        else if cfg!(target_os = "macos") {
            Self::Macos
        }
        else if cfg!(target_os = "linux") {
            Self::Linux
        }
        else {
            Self::Other
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityEntry {
    pub capability: &'static str,
    pub available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<CapabilityState>,
    pub detail: &'static str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Capabilities {
    pub platform: Platform,
    pub architecture: &'static str,
    pub entries: Vec<CapabilityEntry>,
}

fn available(capability: &'static str, detail: &'static str) -> CapabilityEntry {
    CapabilityEntry { capability, available: true, code: None, detail }
}

fn blocked(capability: &'static str, state: CapabilityState, detail: &'static str) -> CapabilityEntry {
    CapabilityEntry { capability, available: false, code: Some(state), detail }
}

/// Reports which OpenDebugger capabilities are usable on the current platform.
pub fn capabilities() -> Capabilities {
    let windows = cfg!(windows);
    let windows_only = if windows { CapabilityState::NotImplemented } else { CapabilityState::UnsupportedPlatform };
    let windows_only_detail = if windows { "not implemented yet on Windows" } else { "this capability is implemented for Windows only" };
    let kernel_module_detail = if windows {
        "kernel module enumeration needs virtual-to-physical address translation, which is not implemented"
    }
    else {
        "kernel module enumeration is implemented for Windows only"
    };
    let symbol_detail = if windows {
        "requires binding the Windows debug engine and a configured symbol path"
    }
    else {
        "the Windows debug engine is available on Windows only"
    };
    let stack_detail =
        if windows { "requires binding the Windows debug engine" } else { "the Windows debug engine is available on Windows only" };

    let mut entries = vec![
        available(CAP_DUMP_PARSE, "minidump (MDMP) container parsing is available on every build target"),
        available(
            CAP_KERNEL_DUMP,
            "kernel dump header parsing follows the documented `DUMP_HEADER64` layout and is verified against a real Windows triage dump",
        ),
        available(CAP_BUGCHECK, "built-in bugcheck code table"),
        available(CAP_MODULE_LIST, "module records are read from the minidump module list stream only"),
        blocked(CAP_KERNEL_MODULE_LIST, windows_only, kernel_module_detail),
        available(CAP_REPORT_WRITE, "report documents are written to a caller-supplied file path"),
        blocked(CAP_SYMBOL_RESOLVE, windows_only, symbol_detail),
        blocked(CAP_STACK_UNWIND, windows_only, stack_detail),
        blocked(CAP_LIVE_ATTACH, windows_only, windows_only_detail),
    ];

    entries.push(if windows {
        available(CAP_GUI, "WebView2 GUI host is available on Windows")
    }
    else {
        blocked(CAP_GUI, CapabilityState::UnsupportedPlatform, "the GUI host is shipped for win32-x64 only")
    });

    Capabilities { platform: Platform::current(), architecture: architecture_name(), entries }
}

fn architecture_name() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        "x86" => "x86",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_vocabulary_uses_the_shared_codes() {
        assert_eq!(CapabilityState::UnsupportedPlatform.code(), "unsupported_platform");
        assert_eq!(CapabilityState::NotImplemented.code(), "not_implemented");
        assert_eq!(CapabilityState::DependencyBlocked.code(), "dependency_blocked");
    }

    #[test]
    fn portable_capabilities_are_available_everywhere() {
        let report = capabilities();
        for capability in [CAP_DUMP_PARSE, CAP_KERNEL_DUMP, CAP_BUGCHECK, CAP_MODULE_LIST, CAP_REPORT_WRITE] {
            let entry = report.entries.iter().find(|entry| entry.capability == capability).expect("capability entry");
            assert!(entry.available, "{capability} should be portable");
            assert!(entry.code.is_none());
        }
    }

    #[test]
    fn kernel_module_list_is_not_claimed_as_available() {
        let report = capabilities();
        let entry = report.entries.iter().find(|entry| entry.capability == CAP_KERNEL_MODULE_LIST).expect("entry");
        assert!(!entry.available, "kernel module enumeration is not implemented");
        let expected = if cfg!(windows) { CapabilityState::NotImplemented } else { CapabilityState::UnsupportedPlatform };
        assert_eq!(entry.code, Some(expected));
    }

    #[test]
    fn windows_only_capabilities_report_a_structured_code_off_windows() {
        let report = capabilities();
        let entry = report.entries.iter().find(|entry| entry.capability == CAP_SYMBOL_RESOLVE).expect("entry");
        if cfg!(windows) {
            assert_eq!(entry.code, Some(CapabilityState::NotImplemented));
        }
        else {
            assert_eq!(entry.code, Some(CapabilityState::UnsupportedPlatform));
        }
        assert!(!entry.available);
    }
}
