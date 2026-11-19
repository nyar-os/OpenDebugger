//! Groups crashes from one machine by failure code and by the module the evidence points at.
//!
//! One dump answers "what happened in this crash". Repeated crashes need a different question:
//! whether the same failure keeps coming back through the same module. This module answers it
//! from facts the analyzer already produces, without inventing an attribution. A kernel dump
//! groups by the bugcheck code plus the first non-platform module that owns a trusted frame,
//! falling back to a module base seen on the stack, which is how a driver appears in a
//! kernel-only stack. A user-mode dump carries neither, so it groups by the exception code plus
//! the module that owns the exception address.
//!
//! The kernel path is verified against synthetic observations; the user-mode grouping was added
//! after a real CrashDumps corpus showed every application dump would otherwise collapse into
//! one ownerless group.

use serde::Serialize;

use crate::minidump::{DumpReport, module_ranges, parse_hex64};

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
    /// Exception code of a user-mode crash, absent when the dump carries a bugcheck instead.
    pub exception: Option<u32>,
    /// Module that owns the exception address, when the module table names one.
    pub faulting_module: Option<String>,
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

/// Crashes that share a bugcheck or exception code and a trigger module.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CrashGroup {
    pub bugcheck: Option<u32>,
    pub bugcheck_hex: Option<String>,
    pub bugcheck_name: Option<String>,
    /// Exception code the group is keyed by, present when no bugcheck is.
    pub exception: Option<u32>,
    pub exception_hex: Option<String>,
    /// Module the group is keyed by, absent when no trusted frame, stack word or exception
    /// address names one.
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
    let faulting_module = report.exception.as_ref().and_then(|exception| {
        let value = parse_hex64(&exception.address)?;
        module_ranges(&report.modules).into_iter().find(|(base, end, _)| value >= *base && value < *end).map(|(_, _, name)| name.to_string())
    });
    CrashObservation {
        path: path.to_string(),
        captured_at: report.captured_at.clone(),
        bugcheck: report.bugcheck.as_ref().map(|bugcheck| bugcheck.code),
        bugcheck_name: report.bugcheck.as_ref().and_then(|bugcheck| bugcheck.name).map(str::to_string),
        exception: report.exception.as_ref().map(|exception| exception.code_value),
        faulting_module,
        trigger_modules,
    }
}

/// Groups observations by bugcheck or exception code and trigger module, largest group first.
pub fn aggregate(observations: &[CrashObservation]) -> Vec<CrashGroup> {
    let mut groups: Vec<CrashGroup> = Vec::new();
    for observation in observations {
        let module = observation.trigger_modules.first().cloned().or_else(|| observation.faulting_module.clone());
        let existing = groups.iter().position(|group| group.bugcheck == observation.bugcheck && group.exception == observation.exception && group.module == module);
        let index = match existing {
            Some(index) => index,
            None => {
                groups.push(CrashGroup {
                    bugcheck: observation.bugcheck,
                    bugcheck_hex: observation.bugcheck.map(|code| format!("0x{code:08X}")),
                    bugcheck_name: observation.bugcheck_name.clone(),
                    exception: observation.exception,
                    exception_hex: observation.exception.map(|code| format!("0x{code:08X}")),
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
    groups.sort_by(|left, right| {
        right.count.cmp(&left.count).then(left.bugcheck.cmp(&right.bugcheck)).then(left.exception.cmp(&right.exception)).then(left.module.cmp(&right.module))
    });
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
            exception: None,
            faulting_module: None,
            trigger_modules: modules.iter().map(|module| module.to_string()).collect(),
        }
    }

    fn user_observation(path: &str, exception: u32, faulting: Option<&str>) -> CrashObservation {
        CrashObservation {
            path: path.to_string(),
            captured_at: None,
            bugcheck: None,
            bugcheck_name: None,
            exception: Some(exception),
            faulting_module: faulting.map(str::to_string),
            trigger_modules: Vec::new(),
        }
    }

    #[test]
    fn user_mode_crashes_group_by_exception_and_faulting_module() {
        let observations = [
            user_observation("a.dmp", 0xC0000005, Some("nvwgf2umx.dll")),
            user_observation("b.dmp", 0xC0000005, Some("nvwgf2umx.dll")),
            user_observation("c.dmp", 0xC0000005, Some("libgallium.dll")),
            user_observation("d.dmp", 0xC00000FD, Some("nvwgf2umx.dll")),
            user_observation("e.dmp", 0xC0000005, None),
        ];
        let groups = aggregate(&observations);
        assert_eq!(groups.len(), 4, "code and faulting module together key the group, and an ownerless dump stands apart");
        assert_eq!(groups[0].count, 2);
        assert_eq!(groups[0].exception_hex.as_deref(), Some("0xC0000005"));
        assert_eq!(groups[0].module.as_deref(), Some("nvwgf2umx.dll"));
        assert!(groups.iter().all(|group| group.bugcheck.is_none()), "a user-mode group carries no bugcheck");
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
