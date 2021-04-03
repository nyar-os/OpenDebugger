//! Node-API surface for `@wae/open-debugger` via the WAE facade.
//!
//! This crate is platform-agnostic: the GUI host, window and event pump all
//! forward to `wae::webview`, which selects a backend per compile target and
//! reports missing capabilities as structured [`wae::webview::WebViewError`]
//! values. There is no `cfg` branch here and no platform-specific message.
//!
//! Every exported capability is recorded through [`audit::run`], including the
//! GUI IPC path.

mod audit;

use std::{
    cell::RefCell,
    path::{Path, PathBuf},
};

use open_debugger_core::{
    BugcheckInfo, CapabilityState, DumpReport, Error as CoreError, analyze_file, capabilities, lookup_bugcheck, parse_code, write_report,
};
use serde_json::{Value, json};
use wae::{
    CallContext, Env, Error, JsValue, Result,
    audit::{Actor, ActorKind, Mode, Query},
    function, optional_string_prop, register_module, sys,
    webview::{IpcHandler, IpcOutcome, OpenOptions, WebViewHost},
};

const APP_TITLE: &str = "OpenDebugger";

thread_local! {
    static GUI: RefCell<Option<GuiState>> = const { RefCell::new(None) };
}

struct GuiState {
    host: WebViewHost,
}

struct DumpIpcHandler;

impl IpcHandler for DumpIpcHandler {
    fn on_ipc(&mut self, message: &str) -> IpcOutcome {
        let Ok(value) = serde_json::from_str::<Value>(message)
        else {
            return IpcOutcome::Ignored;
        };
        let ty = value.get("type").and_then(|value| value.as_str()).unwrap_or("");
        let id = value.get("id").cloned().unwrap_or(Value::Null);
        match ty {
            "close" => IpcOutcome::CloseWindow,
            "capabilities" => match serde_json::to_value(capabilities()) {
                Ok(report) => IpcOutcome::ReplyToPage(json!({ "type": "capabilitiesResult", "id": id, "capabilities": report }).to_string()),
                Err(error) => {
                    IpcOutcome::ReplyToPage(json!({ "type": "capabilitiesError", "id": id, "message": error.to_string() }).to_string())
                }
            },
            "analyze" => {
                let path = value.get("path").and_then(Value::as_str).unwrap_or("").to_string();
                match audited_analyze(path) {
                    Ok(report) => {
                        let reply =
                            json!({ "type": "analyzeResult", "id": id, "report": serde_json::to_value(&report).unwrap_or(Value::Null) });
                        IpcOutcome::ReplyToPage(reply.to_string())
                    }
                    Err(error) => {
                        IpcOutcome::ReplyToPage(json!({ "type": "analyzeError", "id": id, "message": error.to_string() }).to_string())
                    }
                }
            }
            "bugcheck" => {
                let code = match code_from_value(value.get("code")) {
                    Ok(code) => audited_lookup(code),
                    Err(error) => Err(core_error(error)),
                };
                match code {
                    Ok(info) => {
                        let reply = json!({ "type": "bugcheckResult", "id": id, "info": serde_json::to_value(&info).unwrap_or(Value::Null) });
                        IpcOutcome::ReplyToPage(reply.to_string())
                    }
                    Err(error) => {
                        IpcOutcome::ReplyToPage(json!({ "type": "bugcheckError", "id": id, "message": error.to_string() }).to_string())
                    }
                }
            }
            _ => IpcOutcome::Ignored,
        }
    }
}

fn core_error(error: CoreError) -> Error {
    Error::new(error.to_string())
}

fn webview_error(error: wae::webview::WebViewError) -> CoreError {
    if matches!(error, wae::webview::WebViewError::Unsupported { .. }) {
        return CoreError::capability(CapabilityState::UnsupportedPlatform, error);
    }
    CoreError::message(error.to_string())
}

fn audited_analyze(path: String) -> Result<DumpReport> {
    let params = json!({ "path": path });
    audit::run("analyze-dump", Mode::DryRun, params, || {
        let report = analyze_file(Path::new(&path))?;
        let count = report.modules.len() as u64;
        let summary = format!("{:?}, {} modules, {} threads", report.format, report.modules.len(), report.threads.len());
        Ok((report, audit::Summary::new(count, summary)))
    })
    .map_err(core_error)
}

fn audited_lookup(code: u32) -> Result<BugcheckInfo> {
    let params = json!({ "code": format!("0x{code:08X}") });
    audit::run("bugcheck-lookup", Mode::DryRun, params, || {
        let info = lookup_bugcheck(code);
        let summary =
            if info.known { format!("{} {}", info.code_hex, info.name.unwrap_or_default()) } else { format!("{} unknown", info.code_hex) };
        Ok((info, audit::Summary::new(1, summary)))
    })
    .map_err(core_error)
}

fn json_to_js(env: Env, value: &Value) -> Result<JsValue> {
    match value {
        Value::Null => env.null(),
        Value::Bool(flag) => env.boolean(*flag),
        Value::Number(number) => match number.as_i64() {
            Some(int) => env.int64(int),
            None => env.double(number.as_f64().unwrap_or(0.0)),
        },
        Value::String(text) => env.string(text),
        Value::Array(items) => {
            let array = env.array_with_length(items.len())?;
            for (index, item) in items.iter().enumerate() {
                array.set_element(index as u32, json_to_js(env, item)?)?;
            }
            Ok(array)
        }
        Value::Object(map) => {
            let object = env.object()?;
            for (key, item) in map {
                object.set_named(key, json_to_js(env, item)?)?;
            }
            Ok(object)
        }
    }
}

fn value_to_js(env: Env, value: impl serde::Serialize) -> Result<JsValue> {
    let value = serde_json::to_value(value).map_err(|error| Error::new(error.to_string()))?;
    json_to_js(env, &value)
}

fn required_path(arg: Option<JsValue>) -> Result<String> {
    let Some(value) = arg
    else {
        return Err(Error::new("analyzeDump expects an options object with `path`"));
    };
    if value.is_undefined()? {
        return Err(Error::new("analyzeDump expects an options object with `path`"));
    }
    let path = optional_string_prop(value, "path")?.ok_or_else(|| Error::new("analyzeDump requires `path`"))?;
    if path.trim().is_empty() {
        return Err(Error::new("analyzeDump requires a non-empty `path`"));
    }
    Ok(path)
}

fn code_from_value(value: Option<&Value>) -> std::result::Result<u32, CoreError> {
    let Some(value) = value
    else {
        return Err(CoreError::message("bugcheck requires `code`"));
    };
    match value {
        Value::Number(number) => {
            let raw = number.as_i64().ok_or_else(|| CoreError::message("bugcheck `code` must be an integer or hex string"))?;
            u32::try_from(raw).map_err(|_| CoreError::message("bugcheck `code` is outside the 32-bit range"))
        }
        Value::String(text) => parse_code(text),
        _ => Err(CoreError::message("bugcheck `code` must be an integer or hex string")),
    }
}

fn code_from_js(arg: Option<JsValue>) -> Result<u32> {
    let Some(value) = arg
    else {
        return Err(Error::new("lookupBugcheck expects an options object with `code`"));
    };
    if value.is_undefined()? {
        return Err(Error::new("lookupBugcheck expects an options object with `code`"));
    }
    let code = value.get_named("code").map_err(|_| Error::new("lookupBugcheck requires `code`"))?;
    if code.type_of()? == sys::napi_number {
        let raw = code.as_i64()?;
        return u32::try_from(raw).map_err(|_| Error::new("bugcheck `code` is outside the 32-bit range"));
    }
    if code.type_of()? == sys::napi_string {
        return parse_code(&code.as_string()?).map_err(core_error);
    }
    Err(Error::new("bugcheck `code` must be an integer or hex string"))
}

fn resolve_gui_dir() -> Result<PathBuf> {
    if let Ok(value) = std::env::var("OPEN_DEBUGGER_GUI") {
        let path = PathBuf::from(value);
        if path.is_dir() {
            return Ok(path);
        }
        if path.is_file()
            && let Some(parent) = path.parent()
        {
            return Ok(parent.to_path_buf());
        }
    }

    let manifest_relative =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("..").join("packages").join("open-debugger").join("dist").join("gui");
    if manifest_relative.join("index.html").is_file() {
        return Ok(manifest_relative);
    }

    if let Ok(cwd) = std::env::current_dir() {
        let candidates = [cwd.join("packages").join("open-debugger").join("dist").join("gui"), cwd.join("dist").join("gui"), cwd.join("gui")];
        for candidate in candidates {
            if candidate.join("index.html").is_file() {
                return Ok(candidate);
            }
        }
    }

    Err(Error::new("dist/gui folder not found, pass contentDir to openGui() or set OPEN_DEBUGGER_GUI"))
}

fn actor_from_js(arg: Option<JsValue>) -> Result<Actor> {
    let mut actor = Actor::from_env();
    let Some(value) = arg
    else {
        return Ok(actor);
    };
    if value.is_undefined()? {
        return Ok(actor);
    }
    if let Some(kind) = optional_string_prop(value, "actorKind")? {
        actor.kind = if kind.eq_ignore_ascii_case("agent") { ActorKind::Agent } else { ActorKind::User };
    }
    if let Some(id) = optional_string_prop(value, "actorId")?
        && !id.trim().is_empty()
    {
        actor.id = id;
    }
    if let Some(source) = optional_string_prop(value, "actorSource")?
        && !source.trim().is_empty()
    {
        actor.source = source;
    }
    Ok(actor)
}

fn optional_string_prop_of(arg: Option<JsValue>, name: &str) -> Result<Option<String>> {
    match arg {
        Some(value) if !value.is_undefined()? => optional_string_prop(value, name),
        _ => Ok(None),
    }
}

fn required_string_prop(arg: Option<JsValue>, name: &str, caller: &str) -> Result<String> {
    let Some(value) = arg
    else {
        return Err(Error::new(format!("{caller} expects an options object with `{name}`")));
    };
    if value.is_undefined()? {
        return Err(Error::new(format!("{caller} expects an options object with `{name}`")));
    }
    let text = optional_string_prop(value, name)?.ok_or_else(|| Error::new(format!("{caller} requires `{name}`")))?;
    if text.trim().is_empty() {
        return Err(Error::new(format!("{caller} requires a non-empty `{name}`")));
    }
    Ok(text)
}

fn bool_prop(arg: JsValue, name: &str) -> Result<bool> {
    match arg.get_named(name) {
        Ok(value) if value.type_of()? == sys::napi_boolean => value.as_bool(),
        _ => Ok(false),
    }
}

fn audited_write_report(path: String, report: &DumpReport, dry_run: bool) -> Result<open_debugger_core::ReportWrite> {
    let mode = if dry_run { Mode::DryRun } else { Mode::Execute };
    let params = json!({ "path": path.clone(), "modules": report.modules.len(), "dryRun": dry_run });
    audit::run("report-write", mode, params, || {
        let write = write_report(Path::new(&path), report, dry_run)?;
        let summary = format!(
            "{} {} ({} bytes, {} modules)",
            if dry_run { "would write" } else { "wrote" },
            write.path,
            write.bytes,
            report.modules.len()
        );
        Ok((write, audit::Summary::new(report.modules.len() as u64, summary)))
    })
    .map_err(core_error)
}

#[function(js_name = "analyzeDump")]
fn analyze_dump(ctx: CallContext) -> Result<JsValue> {
    let path = required_path(ctx.args().first().copied())?;
    let report = audited_analyze(path)?;
    value_to_js(ctx.env(), &report)
}

#[function(js_name = "lookupBugcheck")]
fn lookup_bugcheck_js(ctx: CallContext) -> Result<JsValue> {
    let code = code_from_js(ctx.args().first().copied())?;
    let info = audited_lookup(code)?;
    value_to_js(ctx.env(), &info)
}

#[function(js_name = "writeReport")]
fn write_report_js(ctx: CallContext) -> Result<JsValue> {
    let arg = ctx.args().first().copied();
    let path = required_string_prop(arg, "path", "writeReport")?;
    let dump_source = required_string_prop(arg, "dumpPath", "writeReport")?;
    let dry_run = match arg {
        Some(value) if !value.is_undefined()? => bool_prop(value, "dryRun")?,
        _ => false,
    };
    let report = audited_analyze(dump_source)?;
    let write = audited_write_report(path, &report, dry_run)?;
    let payload = json!({ "path": write.path, "bytes": write.bytes, "dryRun": write.dry_run, "report": report });
    json_to_js(ctx.env(), &payload)
}

#[function]
fn version(ctx: CallContext) -> Result<JsValue> {
    let version = env!("CARGO_PKG_VERSION");
    audit::run("version", Mode::DryRun, Value::Null, || Ok(((), audit::Summary::new(0, format!("version {version}"))))).map_err(core_error)?;
    ctx.env().string(version)
}

#[function(js_name = "capabilities")]
fn capabilities_js(ctx: CallContext) -> Result<JsValue> {
    let report = audit::run("capabilities", Mode::DryRun, Value::Null, || {
        let report = capabilities();
        let count = report.entries.len() as u64;
        let summary = format!("platform {:?}, {} capabilities", report.platform, count);
        Ok((report, audit::Summary::new(count, summary)))
    })
    .map_err(core_error)?;
    value_to_js(ctx.env(), &report)
}

#[function(js_name = "openGui")]
fn open_gui(ctx: CallContext) -> Result<JsValue> {
    let mut title = APP_TITLE.to_string();
    let mut content_dir: Option<String> = None;
    let mut url: Option<String> = None;
    let mut width = 1180;
    let mut height = 760;

    if let Ok(arg) = ctx.arg(0)
        && !arg.is_undefined()?
    {
        if let Some(value) = optional_string_prop(arg, "title")? {
            title = value;
        }
        content_dir = optional_string_prop(arg, "contentDir")?;
        url = optional_string_prop(arg, "url")?;
        if let Ok(value) = arg.get_named("width")
            && value.type_of()? == sys::napi_number
        {
            width = value.as_i64()? as i32;
        }
        if let Ok(value) = arg.get_named("height")
            && value.type_of()? == sys::napi_number
        {
            height = value.as_i64()? as i32;
        }
    }

    let params = json!({ "title": title.clone(), "contentDir": content_dir.clone(), "url": url.clone() });
    let host = audit::run("gui-open", Mode::Execute, params, || {
        let already_open = GUI.with(|slot| slot.borrow().as_ref().map(|state| state.host.is_alive()).unwrap_or(false));
        if already_open {
            return Err(CoreError::message("a debugger window is already open"));
        }
        let options = if let Some(dir) = content_dir.clone() {
            OpenOptions::from_content_dir(dir, title.clone())
        }
        else if let Some(url) = url.clone() {
            OpenOptions::from_url(url, title.clone())
        }
        else {
            let dir = resolve_gui_dir().map_err(|error| CoreError::message(error.to_string()))?;
            OpenOptions::from_content_dir(dir.display().to_string(), title.clone())
        };
        let mut options = options;
        options.width = width;
        options.height = height;
        let host = WebViewHost::open(options, Box::new(DumpIpcHandler)).map_err(webview_error)?;
        let summary = format!("window opened with {} backend", host.backend_name());
        Ok((host, audit::Summary::new(1, summary)))
    })
    .map_err(core_error)?;

    GUI.with(|slot| {
        *slot.borrow_mut() = Some(GuiState { host });
    });
    ctx.env().undefined()
}

#[function(js_name = "pumpEvents")]
fn pump_events(ctx: CallContext) -> Result<JsValue> {
    let alive = audit::run("gui-pump", Mode::Execute, Value::Null, || {
        let alive = GUI.with(|slot| {
            let mut guard = slot.borrow_mut();
            match guard.as_mut() {
                Some(state) => {
                    let ok = state.host.pump();
                    if !ok {
                        *guard = None;
                    }
                    ok
                }
                None => false,
            }
        });
        Ok((alive, audit::Summary::new(1, if alive { "window alive" } else { "window closed" })))
    })
    .map_err(core_error)?;
    ctx.env().boolean(alive)
}

#[function(js_name = "closeGui")]
fn close_gui(ctx: CallContext) -> Result<JsValue> {
    audit::run("gui-close", Mode::Execute, Value::Null, || {
        let closed = GUI.with(|slot| {
            let mut guard = slot.borrow_mut();
            if let Some(mut state) = guard.take() {
                let _ = state.host.close();
                true
            }
            else {
                false
            }
        });
        Ok(((), audit::Summary::new(1, if closed { "window closed" } else { "no window" })))
    })
    .map_err(core_error)?;
    ctx.env().undefined()
}

#[function(js_name = "isGuiOpen")]
fn is_gui_open(ctx: CallContext) -> Result<JsValue> {
    let open = audit::run("gui-status", Mode::DryRun, Value::Null, || {
        let open = GUI.with(|slot| slot.borrow().as_ref().map(|state| state.host.is_alive()).unwrap_or(false));
        Ok((open, audit::Summary::new(1, if open { "open" } else { "closed" })))
    })
    .map_err(core_error)?;
    ctx.env().boolean(open)
}

#[function(js_name = "configureAudit")]
fn configure_audit_js(ctx: CallContext) -> Result<JsValue> {
    let arg = ctx.arg(0).ok();
    let actor = actor_from_js(arg)?;
    let session = optional_string_prop_of(arg, "session")?;
    let host = optional_string_prop_of(arg, "host")?;
    audit::configure(actor, session, host);
    ctx.env().undefined()
}

#[function(js_name = "auditQuery")]
fn audit_query_js(ctx: CallContext) -> Result<JsValue> {
    let filter = query_from_js(ctx.arg(0).ok())?;
    let entries = audit::run("audit-query", Mode::DryRun, Value::Null, || {
        let entries = audit::query(&filter).map_err(|error| CoreError::message(error.to_string()))?;
        Ok((entries, audit::Summary::new(0, "audit history queried")))
    })
    .map_err(core_error)?;
    value_to_js(ctx.env(), &entries)
}

fn query_from_js(arg: Option<JsValue>) -> Result<Query> {
    let Some(value) = arg
    else {
        return Ok(Query::default());
    };
    if value.is_undefined()? {
        return Ok(Query::default());
    }
    Ok(Query {
        actor_kind: optional_string_prop(value, "actorKind")?
            .map(|kind| if kind.eq_ignore_ascii_case("agent") { ActorKind::Agent } else { ActorKind::User }),
        actor_id: optional_string_prop(value, "actorId")?,
        from_ms: optional_number_prop(value, "fromMs")?,
        to_ms: optional_number_prop(value, "toMs")?,
        capability: optional_string_prop(value, "capability")?,
        limit: optional_number_prop(value, "limit")?.map(|limit| limit as usize),
    })
}

fn optional_number_prop(value: JsValue, name: &str) -> Result<Option<u64>> {
    match value.get_named(name) {
        Ok(inner) if !inner.is_undefined()? && inner.type_of()? == sys::napi_number => Ok(Some(inner.as_i64()?.max(0) as u64)),
        _ => Ok(None),
    }
}

register_module![
    analyze_dump,
    lookup_bugcheck_js,
    write_report_js,
    version,
    capabilities_js,
    open_gui,
    pump_events,
    close_gui,
    is_gui_open,
    configure_audit_js,
    audit_query_js
];
