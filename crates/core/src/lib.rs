//! OpenDebugger domain: Windows crash dump analysis without GUI or platform bindings.
//!
//! The crate owns dump container parsing, the built-in bugcheck table and capability reporting.
//! Symbol resolution, stack unwinding and live debugging are Windows-only capabilities that are
//! reported as `not_implemented` until a real engine is wired.

pub mod bugcheck;
pub mod error;
pub mod minidump;
pub mod platform;
pub mod report;

pub use bugcheck::{BugcheckInfo, lookup_bugcheck, parse_code};
pub use error::{CapabilityState, Error, Result};
pub use minidump::{BugcheckSummary, DumpFormat, DumpReport, ExceptionInfo, ModuleInfo, SystemInfo, ThreadInfo, analyze_bytes, analyze_file};
pub use platform::{Capabilities, CapabilityEntry, Platform, capabilities};
pub use report::{REPORT_SCHEMA, ReportWrite, encode_report, write_report};
