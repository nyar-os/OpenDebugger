//! Batch crash investigation over a directory of real dumps.
//!
//! Analyzes every `.dmp` under one directory, prints a one-line verdict per dump with the
//! phase timings of the exact run, then groups the corpus by bugcheck/exception and trigger
//! module so repeated crashes become visible.
//!
//! ```text
//! cargo run --release -p open-debugger-core --example crash_batch -- --dir "C:\Users\me\AppData\Local\CrashDumps"
//! ```
//!
//! Flags: `--dir <path>` selects the dump directory, `--json <path>` writes every report as a
//! JSON array, `--store <path>` points the symbol store at a directory laid out like the
//! debugger symbol cache before any PDB lookup runs.

use std::{path::PathBuf, time::Instant};

use open_debugger_core::{DumpReport, aggregate, analyze_file, encode_report, observe};

fn main() {
    let mut args = std::env::args().skip(1).peekable();
    let mut dir: Option<PathBuf> = None;
    let mut json: Option<PathBuf> = None;
    while let Some(arg) = args.next() {
        let value = match args.peek() {
            Some(next) if !next.starts_with("--") => args.next(),
            _ => None,
        };
        match arg.as_str() {
            "--dir" => dir = value.map(PathBuf::from),
            "--json" => json = value.map(PathBuf::from),
            "--store" => {
                if let Some(store) = value {
                    // SAFETY: single-threaded argument parsing before any analysis starts.
                    unsafe { std::env::set_var("OPEN_DEBUGGER_SYMBOL_STORE", store) };
                }
            }
            other => eprintln!("unknown flag: {other}"),
        }
    }

    let dir = dir.unwrap_or_else(|| {
        let mut path = std::env::temp_dir();
        path.pop();
        path.join("CrashDumps")
    });

    let mut dumps: Vec<PathBuf> = Vec::new();
    let mut pending = vec![dir.clone()];
    while let Some(root) = pending.pop() {
        let Ok(read) = boost_fs::read_dir(&root) else { continue };
        for entry in read.flatten() {
            let path = entry.path();
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                pending.push(path);
            }
            else if meta.is_file() && path.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("dmp")) {
                dumps.push(path);
            }
        }
    }
    dumps.sort();

    println!("dumps under {}: {}", dir.display(), dumps.len());
    let mut reports = Vec::new();
    let mut observations = Vec::new();
    let batch = Instant::now();
    for path in &dumps {
        let started = Instant::now();
        match analyze_file(path) {
            Ok(report) => {
                print_verdict(path, &report);
                observations.push(observe(&path.display().to_string(), &report));
                reports.push((path.clone(), report));
            }
            Err(error) => println!("FAIL {}  {error}", path.display()),
        }
        let _ = started;
    }
    println!("\nbatch: {} dumps in {:.1} ms", dumps.len(), batch.elapsed().as_secs_f64() * 1000.0);

    println!("\n== groups ==");
    for group in aggregate(&observations) {
        let key = group
            .bugcheck_name
            .clone()
            .or_else(|| group.bugcheck_hex.clone())
            .or_else(|| group.exception_hex.clone())
            .unwrap_or_else(|| "no code".to_string());
        println!("{}  module={}  count={}", key, group.module.as_deref().unwrap_or("-"), group.count);
        for occurrence in &group.dumps {
            println!("  {}  {}", occurrence.captured_at.as_deref().unwrap_or("-"), occurrence.path);
        }
    }

    if let Some(path) = json {
        let items: Vec<serde_json::Value> = reports
            .iter()
            .map(|(file, report)| {
                let mut value: serde_json::Value = serde_json::from_str(&encode_report(report).expect("the encoder emits valid JSON")).expect("valid JSON");
                value["dumpPath"] = serde_json::Value::String(file.display().to_string());
                value
            })
            .collect();
        boost_fs::write(&path, serde_json::to_string_pretty(&items).expect("serialize").as_bytes()).expect("write json");
        println!("\nwrote {} reports to {}", items.len(), path.display());
    }
}

fn print_verdict(path: &std::path::Path, report: &DumpReport) {
    let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("?");
    let kind = match report.bugcheck.as_ref() {
        Some(bugcheck) => format!("bugcheck {} {}", bugcheck.code_hex, bugcheck.name.unwrap_or("?")),
        None => match report.exception.as_ref() {
            Some(exception) => format!("exception {} at {}", exception.code, exception.address),
            None => "no exception record".to_string(),
        },
    };
    let failing = report
        .exception
        .as_ref()
        .and_then(|exception| report.modules.iter().find(|module| in_module(module, &exception.address)))
        .map(|module| module.name.clone())
        .or_else(|| report.stack.first().and_then(|frame| frame.module.clone()));
    println!(
        "{name}  {:>9} B  {}  captured={}  module={}  threads={}  modules={}  t: hdr {:.1} mods {:.1} blocks {:.1} stack {:.1} sym {:.1} total {:.1} ms",
        report.size_bytes,
        kind,
        report.captured_at.as_deref().unwrap_or("-"),
        failing.unwrap_or_else(|| "-".to_string()),
        report.threads.len(),
        report.modules.len(),
        report.timings.header,
        report.timings.module_table,
        report.timings.block_table,
        report.timings.stack,
        report.timings.symbols,
        report.timings.total
    );
    // The scanned chain is unverified, so it is shown as references, never as a stack.
    let mut seen = Vec::new();
    for guess in &report.stack_guesses {
        let Some(module) = guess.module.as_ref().map(|name| name.rsplit(['\\', '/']).next().unwrap_or(name.as_str())) else { continue };
        if seen.iter().any(|first: &String| first == module) {
            continue;
        }
        seen.push(module.to_string());
        if seen.len() == 6 {
            break;
        }
    }
    if !seen.is_empty() {
        println!("  refs: {}", seen.join(" "));
    }
    for warning in report.warnings.iter().take(3) {
        println!("  warn: {warning}");
    }
}

fn in_module(module: &open_debugger_core::ModuleInfo, address: &str) -> bool {
    let parse = |text: &str| u64::from_str_radix(text.trim_start_matches("0x"), 16).ok();
    let (Some(value), Some(base)) = (parse(address), parse(&module.base_address)) else { return false };
    value >= base && value < base + u64::from(module.size_bytes)
}
