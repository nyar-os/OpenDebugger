//! OpenDebugger domain: Windows crash dump analysis without GUI or platform bindings.
//!
//! The crate owns dump container parsing, the built-in bugcheck table, kernel triage block and
//! module-table reads, and capability reporting. Symbol resolution and stack unwinding through
//! unwind metadata still require a Windows debug engine, which this crate does not bind.

pub mod bugcheck;
pub mod error;
mod input;
pub mod minidump;
pub mod platform;
pub mod report;
mod triage;

pub use bugcheck::{BugcheckInfo, lookup_bugcheck, parse_code};
pub use error::{CapabilityState, Error, Result};
pub use minidump::{
    BugcheckSummary, DumpFormat, DumpReport, ExceptionInfo, ModuleInfo, PhysicalPage, StackFrame, StackFrameSource, StackReference, SystemInfo,
    ThreadInfo, analyze_bytes, analyze_file,
};
pub use platform::{Capabilities, CapabilityEntry, Platform, capabilities};
pub use report::{REPORT_SCHEMA, ReportWrite, encode_report, write_report};
