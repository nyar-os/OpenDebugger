//! Report encoding and the file-write capability.
//!
//! The CLI and the GUI both produce reports through this module so that the write is validated
//! and audited at the capability boundary instead of happening ad hoc in the TypeScript layer.

use std::{fs, path::Path};

use serde::Serialize;

use crate::{Error, Result, minidump::DumpReport};

/// Contract namespace for the emitted report document.
pub const REPORT_SCHEMA: &str = "open-debugger.report/v0";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportWrite {
    pub path: String,
    pub bytes: usize,
    pub dry_run: bool,
}

#[derive(Serialize)]
struct ReportDocument<'a> {
    schema: &'static str,
    report: &'a DumpReport,
}

/// Serialize a dump report as the stable report document written to disk.
pub fn encode_report(report: &DumpReport) -> Result<String> {
    let document = ReportDocument { schema: REPORT_SCHEMA, report };
    let mut text = serde_json::to_string_pretty(&document).map_err(|error| Error::message(format!("encode report: {error}")))?;
    text.push('\n');
    Ok(text)
}

/// Write the report document, or only validate it when `dry_run` is true.
pub fn write_report(path: &Path, report: &DumpReport, dry_run: bool) -> Result<ReportWrite> {
    let text = encode_report(report)?;
    let target = path.to_string_lossy().to_string();
    if target.trim().is_empty() {
        return Err(Error::message("report path is empty"));
    }
    if path.is_dir() {
        return Err(Error::message(format!("{target}: report path is a directory")));
    }
    if !dry_run {
        fs::write(path, text.as_bytes()).map_err(|source| Error::io(&target, source))?;
    }
    Ok(ReportWrite { path: target, bytes: text.len(), dry_run })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::minidump::{DumpFormat, DumpReport};

    fn sample() -> DumpReport {
        DumpReport {
            format: DumpFormat::MiniDump,
            dump_type: None,
            size_bytes: 576,
            captured_at: None,
            system: None,
            bugcheck: None,
            exception: None,
            modules: Vec::new(),
            threads: Vec::new(),
            stack: Vec::new(),
            stack_module_bases: Vec::new(),
            physical_page: None,
            process_id: None,
            warnings: vec!["synthetic".into()],
        }
    }

    #[test]
    fn report_document_carries_its_schema() {
        let text = encode_report(&sample()).unwrap();
        assert!(text.contains("\"schema\": \"open-debugger.report/v0\""));
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn dry_run_does_not_touch_the_filesystem() {
        let dir = std::env::temp_dir().join(format!("open-debugger-report-{}", std::process::id()));
        let target = dir.join("report.json");
        let write = write_report(&target, &sample(), true).unwrap();
        assert!(write.dry_run);
        assert_eq!(write.bytes, encode_report(&sample()).unwrap().len());
        assert!(!target.exists());
    }

    #[test]
    fn directory_targets_are_rejected() {
        let error = write_report(&std::env::temp_dir(), &sample(), false).unwrap_err();
        assert!(error.to_string().contains("is a directory"));
    }
}
