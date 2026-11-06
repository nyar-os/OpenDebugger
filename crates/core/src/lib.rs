//! OpenDebugger domain: Windows crash dump analysis without GUI or platform bindings.
//!
//! The crate owns dump container parsing, the built-in bugcheck table, kernel triage block and
//! module-table reads, `dbghelp`-bound function names for resolved frames, and capability
//! reporting. Stack unwinding through unwind metadata is not attempted: a triage dump carries
//! none, so frames come from the faulting context and verified call sites.

pub mod bugcheck;
pub mod correlation;
pub mod error;
mod input;
pub mod minidump;
pub mod pdb;
pub mod platform;
pub mod report;
mod symbols;
mod triage;

pub use bugcheck::{BugcheckInfo, lookup_bugcheck, parse_code};
pub use correlation::{CrashGroup, CrashObservation, CrashOccurrence, aggregate, observe};
pub use error::{CapabilityState, Error, Result};
pub use minidump::{
    BugcheckSummary, DumpFormat, DumpReport, ExceptionInfo, ModuleInfo, PhysicalPage, StackFrame, StackFrameSource, StackReference, SystemInfo,
    ThreadInfo, analyze_bytes, analyze_file,
};
pub use platform::{Capabilities, CapabilityEntry, Platform, capabilities};
pub use report::{REPORT_SCHEMA, ReportWrite, encode_report, write_report};
