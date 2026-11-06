//! Groups crashes from one machine by bugcheck code and by the module the trusted stack points at.
//!
//! One dump answers "what happened in this crash". Repeated crashes need a different question:
//! whether the same bugcheck keeps coming back through the same driver. This module answers it
//! from facts the analyzer already produces, without inventing an attribution: a group is keyed
//! by the bugcheck code plus the first non-platform module that owns a trusted frame, falling
//! back to a module base seen on the stack, which is how a driver appears in a kernel-only stack.
//!
//! Verified against synthetic observations only. A real multi-dump corpus is not available on
//! the analysis host, so group counts from a single machine remain unverified.

use serde::Serialize;

use crate::minidump::DumpReport;

/// Modules that belong to Windows itself. A frame in one of them says nothing about a driver.
const PLATFORM_MODULES: &[&str] = &["ntoskrnl.exe", "ntkrnlmp.exe", "ntkrnlpa.exe", "hal.dll"];

/// What one dump contributes to the grouping.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CrashObservation {
    pub path: String,
    pub captured_at: Option<String>,
    pub bugcheck: Option<u32>,
    pub bugcheck_name: Option<String>,
    /// Modules outside the platform set, in the order the dump exposed them.
    pub trigger_modules: Vec<String>,
}

/// One dump inside a [`CrashGroup`].
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CrashOccurrence {
    pub path: String,
    pub captured_at: Option<String>,
}

/// Crashes that share a bugcheck code and a trigger module.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CrashGroup {
    pub bugcheck: Option<u32>,
    pub bugcheck_hex: Option<String>,
    pub bugcheck_name: Option<String>,
    /// Module the group is keyed by, absent when no trusted frame or stack word names one.
    pub module: Option<String>,
    /// Every non-platform module seen across the grouped dumps.
    pub modules: Vec<String>,
    pub count: usize,
    pub dumps: Vec<CrashOccurrence>,
}

/// Extracts the grouping facts from a parsed report.
pub fn observe(path: &str, report: &DumpReport) -> CrashObservation {
    let mut trigger_modules = Vec::new();
    for frame in &report.stack {
        push_trigger(&mut trigger_modules, frame.module.as_deref());
    }
    for reference in &report.stack_module_bases {
        push_trigger(&mut trigger_modules, Some(reference.module.as_str()));
    }
    CrashObservation {
        path: path.to_string(),
        captured_at: report.captured_at.clone(),
        bugcheck: report.bugcheck.as_ref().map(|bugcheck| bugcheck.code),
        bugcheck_name: report.bugcheck.as_ref().and_then(|bugcheck| bugcheck.name).map(str::to_string),
        trigger_modules,
    }
}

/// Groups observations by bugcheck code and first trigger module, largest group first.
pub fn aggregate(observations: &[CrashObservation]) -> Vec<CrashGroup> {
    let mut groups: Vec<CrashGroup> = Vec::new();
    for observation in observations {
        let module = observation.trigger_modules.first().cloned();
        let existing = groups.iter().position(|group| group.bugcheck == observation.bugcheck && group.module == module);
        let index = match existing {
            Some(index) => index,
            None => {
                groups.push(CrashGroup {
                    bugcheck: observation.bugcheck,
                    bugcheck_hex: observation.bugcheck.map(|code| format!("0x{code:08X}")),
                    bugcheck_name: observation.bugcheck_name.clone(),
                    module,
                    modules: Vec::new(),
                    count: 0,
                    dumps: Vec::new(),
                });
                groups.len() - 1
            }
        };
        let group = &mut groups[index];
        group.count += 1;
        for trigger in &observation.trigger_modules {
            if !group.modules.contains(trigger) {
                group.modules.push(trigger.clone());
            }
        }
        group.dumps.push(CrashOccurrence { path: observation.path.clone(), captured_at: observation.captured_at.clone() });
    }
    groups.sort_by(|left, right| right.count.cmp(&left.count).then(left.bugcheck.cmp(&right.bugcheck)).then(left.module.cmp(&right.module)));
    groups
}

fn push_trigger(modules: &mut Vec<String>, module: Option<&str>) {
    let Some(module) = module
    else {
        return;
    };
    if module.is_empty() || PLATFORM_MODULES.iter().any(|platform| platform.eq_ignore_ascii_case(module)) {
        return;
    }
    if !modules.iter().any(|existing| existing.eq_ignore_ascii_case(module)) {
        modules.push(module.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::minidump::{DumpFormat, StackFrame, StackFrameSource, StackReference};

    fn observation(path: &str, bugcheck: Option<u32>, modules: &[&str]) -> CrashObservation {
        CrashObservation {
            path: path.to_string(),
            captured_at: None,
            bugcheck,
            bugcheck_name: None,
            trigger_modules: modules.iter().map(|module| module.to_string()).collect(),
        }
    }

    #[test]
    fn groups_by_bugcheck_and_first_trigger_module() {
        let observations = [
            observation("a.dmp", Some(0x4E), &["hidusb.sys"]),
            observation("b.dmp", Some(0x4E), &["hidusb.sys"]),
            observation("c.dmp", Some(0x4E), &["usbxhci.sys"]),
            observation("d.dmp", Some(0xD1), &["hidusb.sys"]),
        ];
        let groups = aggregate(&observations);
        assert_eq!(groups.len(), 3);
        assert_eq!(groups[0].count, 2, "the busiest group sorts first");
        assert_eq!(groups[0].bugcheck, Some(0x4E));
        assert_eq!(groups[0].module.as_deref(), Some("hidusb.sys"));
        assert_eq!(groups[0].bugcheck_hex.as_deref(), Some("0x0000004E"));
        assert_eq!(groups[0].dumps.iter().map(|dump| dump.path.as_str()).collect::<Vec<_>>(), vec!["a.dmp", "b.dmp"]);
    }

    #[test]
    fn a_group_keeps_every_trigger_module_across_its_dumps() {
        let observations =
            [observation("a.dmp", Some(0x4E), &["hidusb.sys"]), observation("b.dmp", Some(0x4E), &["hidusb.sys", "usbxhci.sys"])];
        let groups = aggregate(&observations);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].modules, vec!["hidusb.sys", "usbxhci.sys"]);
    }

    #[test]
    fn a_dump_without_a_trigger_module_is_not_folded_into_a_driver_group() {
        let observations = [observation("a.dmp", Some(0x4E), &["hidusb.sys"]), observation("b.dmp", Some(0x4E), &[])];
        let groups = aggregate(&observations);
        assert_eq!(groups.len(), 2);
        assert!(groups.iter().any(|group| group.module.as_deref() == Some("hidusb.sys")));
        assert!(groups.iter().any(|group| group.module.is_none()));
    }

    #[test]
    fn observe_skips_platform_frames_and_keeps_stack_bases() {
        let mut report = DumpReport::new(DumpFormat::KernelDump64, 0x2000);
        report.stack.push(StackFrame {
            address: "0xFFFFF807B64B85D0".to_string(),
            module: Some("ntoskrnl.exe".to_string()),
            offset_in_module: Some("0x4B85D0".to_string()),
            function: None,
            function_offset: None,
            source: StackFrameSource::Context,
        });
        report.stack.push(StackFrame {
            address: "0xFFFFF807B6601234".to_string(),
            module: Some("hidusb.sys".to_string()),
            offset_in_module: Some("0x1234".to_string()),
            function: None,
            function_offset: None,
            source: StackFrameSource::CallSite,
        });
        report.stack_module_bases.push(StackReference { address: "0xFFFFF8078B660000".to_string(), module: "usbxhci.sys".to_string() });

        let observed = observe("dump.dmp", &report);
        assert_eq!(observed.trigger_modules, vec!["hidusb.sys", "usbxhci.sys"], "the kernel frame is not a trigger module");
    }
}
