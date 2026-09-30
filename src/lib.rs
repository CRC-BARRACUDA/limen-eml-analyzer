use std::collections::HashMap;
use std::sync::OnceLock;

use limen_sdk_rust::ui::{button, file, label, menu_item, notice, row, separator, step, table, window};
use limen_sdk_rust::{export_module, json, rpc, Catalog, Handler, Host, RpcError, Value};
use base64::{Engine as _, engine::general_purpose::STANDARD};

mod headers;
mod ioc;
mod links;
mod parser;
mod scoring;

fn catalog() -> &'static Catalog {
    static C: OnceLock<Catalog> = OnceLock::new();
    C.get_or_init(|| {
        Catalog::new(&[
            ("en", include_str!("../locales/en.toml")),
            ("uk", include_str!("../locales/uk.toml")),
        ])
    })
}

/// Reduce the name an attachment gives itself to a bare file name.
///
/// `Content-Disposition: filename=` is written by whoever sent the message, so
/// it is hostile input: it can carry directory components
/// (`../../.config/autostart/x.desktop`), separators of either platform, or
/// control characters that hide the real extension. Keep the last component
/// only, and never hand back something empty for the save dialog to start from.
fn safe_name(declared: &str) -> String {
    let base = declared.rsplit(['/', '\\']).next().unwrap_or("");
    let cleaned: String = base
        .chars()
        .filter(|c| !c.is_control() && !matches!(c, ':' | '*' | '?' | '"' | '<' | '>' | '|'))
        .collect();
    match cleaned.trim() {
        "" | "." | ".." => "dump.bin".to_string(),
        name => name.to_string(),
    }
}

#[derive(Default)]
struct EmlAnalyzer {
    last_scan: Value,
    last_attachments: HashMap<String, Value>,
}

impl Handler for EmlAnalyzer {
    fn capabilities(&self) -> Vec<String> {
        vec!["eml.triage".into()]
    }

    fn invoke(&mut self, _cap: &str, method: &str, params: Value, host: &Host) -> Result<Value, RpcError> {
        let lang = host.locale();
        let has_osint = host.has_capability("osint.reputation");
        // Optional companion, discovered per call rather than remembered: a
        // report module installed while this tab is open should make the button
        // appear on the next draw.
        let has_report = host.has_capability("report.build");

        match method {
            "ui" => Ok(self.idle_view(&lang)),
            "scan" => Ok(self.scan(&params, &lang)),
            "dashboard" => Ok(self.render_dashboard(has_osint, has_report, &lang)),
            "make_report" => Ok(self.make_report(host, &lang)),
            "view_iocs" => Ok(self.view_iocs(has_osint, &lang)),
            "view_atts" => Ok(self.view_atts(has_osint, &lang)),
            "check_reputation" => Ok(self.check_reputation(&params, host, &lang)),
            "save_file" => Ok(self.save_file(&params, host, &lang)),
            "extract_strings" => Ok(self.run_strings(&params, &lang)),
            other => Err(RpcError::new(rpc::METHOD_NOT_FOUND, format!("No method {}", other))),
        }
    }
}

/// One line of a report's summary, as `name: value`.
///
/// The name is taken as it is written for the screen, where several of these
/// carry their own colon — `From:`. Left in, the line reads `From:: someone`,
/// and a reader that splits it at the first colon shows a value beginning with
/// the second.
fn figure(name: &str, value: &str) -> String {
    format!("{}: {value}", name.trim_end().trim_end_matches(':').trim_end())
}

impl EmlAnalyzer {
    fn idle_view(&self, lang: &str) -> Value {
        let t = |k: &str| catalog().tr(lang, k);
        window(
            t("ui.title"),
            vec![
                file("file_path").label(t("ui.path")).browse(t("ui.browse")),
                button(t("ui.scan"), "eml.triage", "scan").primary(),
            ],
        )
    }

    /// Something went wrong before there was anything to look at — an empty
    /// path, a file that would not parse.
    ///
    /// It carries the file picker, not just the message. An error screen with
    /// nothing on it is a dead end: the analyst has read the sentence, and the
    /// only way back to the thing they came to do is to close the tab and open
    /// it again.
    fn error_view(&self, lang: &str, message: impl Into<String>) -> Value {
        let t = |k: &str| catalog().tr(lang, k);
        window(
            t("ui.error"),
            vec![
                label(message.into()).strong(),
                separator(),
                file("file_path").label(t("ui.path")).browse(t("ui.browse")),
                button(t("ui.scan"), "eml.triage", "scan").primary(),
            ],
        )
    }

    /// Shown when a view that needs a parsed message is reached before there is
    /// one. `last_scan` stays `Null` until `scan` succeeds, and any method can
    /// be invoked at any time — a tab restored on start-up, `limen-cli run
    /// eml.triage dashboard`. This used to be an `unwrap()`, and a panic cannot
    /// unwind out of the `extern "C"` entry point: it aborted the host process,
    /// taking every other tab down with it.
    fn no_scan_view(&self, lang: &str) -> Value {
        let t = |k: &str| catalog().tr(lang, k);
        window(
            t("ui.title"),
            vec![
                label(t("errors.no_scan")).strong(),
                separator(),
                file("file_path").label(t("ui.path")).browse(t("ui.browse")),
                button(t("ui.scan"), "eml.triage", "scan").primary(),
            ],
        )
    }

    /// An error on something opened *from* a scan — a row's strings, a
    /// reputation lookup. The message, and the way back to the report it came
    /// from, which is where the analyst was.
    fn dead_end(&self, lang: &str, message: impl Into<String>) -> Value {
        let t = |k: &str| catalog().tr(lang, k);
        window(
            t("ui.error"),
            vec![
                label(message.into()).strong(),
                separator(),
                button(t("ui.back"), "eml.triage", "dashboard"),
            ],
        )
    }

    fn scan(&mut self, params: &Value, lang: &str) -> Value {
        let t = |k: &str| catalog().tr(lang, k);
        let path = params.get("file_path").and_then(Value::as_str).unwrap_or("");
        
        if path.is_empty() {
            return self.error_view(lang, t("errors.empty"));
        }

        match parser::parse(path) {
            Ok(data) => {
                self.last_scan = data.clone();
                self.last_attachments.clear();
                if let Some(atts) = data.get("attachments").and_then(Value::as_array) {
                    for (i, att) in atts.iter().enumerate() {
                        self.last_attachments.insert(i.to_string(), att.clone());
                    }
                }
                self.render_simple_summary(lang)
            },
            Err(e) => self.error_view(lang, e),
        }
    }

    fn render_simple_summary(&self, lang: &str) -> Value {
        let t = |k: &str| catalog().tr(lang, k);
        
        let Some(scoring) = self.last_scan.get("scoring") else {
            return self.no_scan_view(lang);
        };
        let score = scoring.get("score").and_then(Value::as_u64).unwrap_or(0);
        
        let (verdict_text, verdict_state) = match score {
            0..=30 => (t("ui.simple_safe"), "done"),
            31..=60 => (t("ui.simple_warn"), "warning"),
            _ => (t("ui.simple_danger"), "error"),
        };

        let mut widgets = vec![
            separator(),
            label(format!("{}: {}/100", t("ui.score"), score)).heading(),
            step(verdict_text, verdict_state).heading(),
            separator(),
        ];

        if score > 30 {
            widgets.push(label(t("ui.cert_msg")).strong());
            widgets.push(label(t("ui.cert_contacts")).mono());
            widgets.push(label(t("ui.cert_pgp")).mono().weak());
            widgets.push(separator());
        }

        widgets.push(button(t("ui.details"), "eml.triage", "dashboard").primary());
        
        window(t("ui.title"), widgets)
    }

    fn render_dashboard(&self, has_osint: bool, has_report: bool, lang: &str) -> Value {
        let t = |k: &str| catalog().tr(lang, k);
        
        let Some(scoring) = self.last_scan.get("scoring") else {
            return self.no_scan_view(lang);
        };
        let score = scoring.get("score").and_then(Value::as_u64).unwrap_or(0);
        let triggers = scoring.get("triggers").and_then(Value::as_array).unwrap_or(&vec![]).clone();
        
        let (r_label, r_icon) = match score {
            0..=30 => (t("ui.score_low"), "done"),
            31..=60 => (t("ui.score_med"), "warning"),
            _ => (t("ui.score_high"), "error"),
        };

        let Some(headers) = self.last_scan.get("headers") else {
            return self.no_scan_view(lang);
        };
        let subj = headers.get("subject").and_then(Value::as_str).unwrap_or("");
        let from = headers.get("from").and_then(Value::as_str).unwrap_or("");
        
        let get_st = |k: &str| if headers.get(k).and_then(Value::as_bool).unwrap_or(false) { "done" } else { "error" };

        let mut widgets = vec![
            label(t("ui.summary")).heading(),
            step(format!("{}: {}/100 - {}", t("ui.score"), score, r_label), r_icon),
            separator(),
            label(t("ui.triggers")).heading(),
        ];

        if triggers.is_empty() {
            widgets.push(label(t("ui.no_triggers")).weak());
        } else {
            for tr in triggers {
                let key = tr.get("key").and_then(Value::as_str).unwrap_or("");
                let pts = tr.get("pts").and_then(Value::as_u64).unwrap_or(0);
                let state = if pts >= 50 { "error" } else { "warning" };
                widgets.push(step(format!("+{} | {}", pts, t(key)), state));
            }
        }

        widgets.push(separator());
        widgets.push(label(t("headers.title")).heading());
        widgets.push(row(vec![label(t("headers.subject")).strong(), label(subj.to_string())]));
        widgets.push(row(vec![label(t("headers.from")).strong(), label(from.to_string())]));

        if headers.get("spoofed").and_then(Value::as_bool).unwrap_or(false) {
            widgets.push(step(t("headers.spoofed"), "error"));
        }

        widgets.push(step(t("headers.spf"), get_st("spf_pass")));
        widgets.push(step(t("headers.dkim"), get_st("dkim_pass")));
        widgets.push(step(t("headers.dmarc"), get_st("dmarc_pass")));

        let eml_hash = self.last_scan.get("eml_hash").and_then(Value::as_str).unwrap_or("");
        if !eml_hash.is_empty() {
            widgets.push(separator());
            widgets.push(label(format!("EML MD5: {}", eml_hash)).mono().weak());
            if has_osint {
                widgets.push(button(t("menu.check_eml"), "osint.reputation", "check_hash").args(json!({ "hash": eml_hash })));
            }
        }

        widgets.push(separator());
        let mut actions = vec![
            button(t("ui.view_iocs"), "eml.triage", "view_iocs"),
            button(t("ui.view_atts"), "eml.triage", "view_atts"),
        ];
        // Only while a report provider is loaded — a button that calls a
        // capability nobody provides is one that answers with an error.
        if has_report {
            actions.push(button(t("ui.report"), "eml.triage", "make_report"));
        }
        widgets.push(row(actions));

        window(t("ui.title"), widgets)
    }

    /// Hand the analysis to whatever report provider is installed.
    fn make_report(&self, host: &Host, lang: &str) -> Value {
        let t = |k: &str| catalog().tr(lang, k);
        let Some(spec) = self.report_spec(lang) else {
            return self.error_view(lang, t("errors.no_scan"));
        };
        match host.call("report.build", "build", spec) {
            // The provider's own screen — its preview, with the buttons that
            // write the file.
            Ok(v) if v.get("widgets").is_some() => v,
            Ok(_) => window(t("ui.title"), vec![label(t("report.written")).strong()]),
            Err(e) => window(
                t("ui.title"),
                vec![label(t("report.failed")).strong(), label(format!("{e}")).weak()],
            ),
        }
    }

    /// The last analysis as a report spec, or `None` if nothing was analysed.
    ///
    /// Separate from the call that sends it so it can be read in a test: what
    /// goes into a report is the part worth pinning down, and the sending is a
    /// line of plumbing.
    ///
    /// The document is the message as this module read it — the verdict and
    /// what produced it, who it claims to be from and whether that was
    /// authenticated, every attachment with its hash, and every indicator. It
    /// is the thing attached to a ticket, so nothing is left for the reader to
    /// go back to the tool for.
    fn report_spec(&self, lang: &str) -> Option<Value> {
        let t = |k: &str| catalog().tr(lang, k);
        let scoring = self.last_scan.get("scoring")?;
        let headers = self.last_scan.get("headers")?;
        let score = scoring.get("score").and_then(Value::as_u64).unwrap_or(0);
        let verdict = match score {
            0..=30 => t("ui.score_low"),
            31..=60 => t("ui.score_med"),
            _ => t("ui.score_high"),
        };
        let field = |k: &str| headers.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        let flag = |k: &str| {
            if headers.get(k).and_then(Value::as_bool).unwrap_or(false) {
                t("report.pass")
            } else {
                t("report.fail")
            }
        };
        let hash = self
            .last_scan
            .get("eml_hash")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();

        // What identifies the message itself, and what was decided about it.
        let mut sections = vec![json!({
            "heading": t("headers.title"),
            "columns": [t("report.field"), t("report.value")],
            "rows": [
                [t("headers.subject"), field("subject")],
                [t("headers.from"), field("from")],
                [t("report.reply_to"), field("reply_to")],
                [t("report.to"), field("to")],
                [t("headers.spf"), flag("spf_pass")],
                [t("headers.dkim"), flag("dkim_pass")],
                [t("headers.dmarc"), flag("dmarc_pass")],
                [t("report.hash"), hash.clone()],
            ],
        })];

        // Why it scored what it scored, worst first — the order somebody reads
        // a verdict in.
        let mut triggers: Vec<(u64, String)> = scoring
            .get("triggers")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .map(|tr| {
                        (
                            tr.get("pts").and_then(Value::as_u64).unwrap_or(0),
                            t(tr.get("key").and_then(Value::as_str).unwrap_or("")),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        triggers.sort_by_key(|(pts, _)| std::cmp::Reverse(*pts));
        if !triggers.is_empty() {
            sections.push(json!({
                "heading": t("ui.triggers"),
                "columns": [t("report.points"), t("report.reason")],
                "rows": triggers.iter()
                    .map(|(pts, why)| vec![format!("+{pts}"), why.clone()])
                    .collect::<Vec<_>>(),
            }));
        }

        let atts = self.last_scan.get("attachments").and_then(Value::as_array);
        if let Some(atts) = atts.filter(|a| !a.is_empty()) {
            sections.push(json!({
                "heading": t("atts.title"),
                "columns": [t("atts.filename"), t("atts.size"), t("atts.hash"), t("atts.note")],
                "rows": atts.iter().map(|a| vec![
                    a.get("filename").and_then(Value::as_str).unwrap_or("").to_string(),
                    a.get("size").and_then(Value::as_u64).unwrap_or(0).to_string(),
                    a.get("hash").and_then(Value::as_str).unwrap_or("").to_string(),
                    self.note_text(a.get("note"), lang),
                ]).collect::<Vec<_>>(),
            }));
        }

        if let Some(iocs) = self.last_scan.get("iocs").and_then(Value::as_array) {
            if !iocs.is_empty() {
                sections.push(json!({
                    "heading": t("iocs.title"),
                    "columns": [t("iocs.indicator")],
                    "rows": iocs.iter()
                        .filter_map(Value::as_str)
                        .map(|i| vec![i.to_string()])
                        .collect::<Vec<_>>(),
                }));
            }
        }

        let attachments = self.last_scan.get("attachments").and_then(Value::as_array).map_or(0, Vec::len);
        let indicators = self.last_scan.get("iocs").and_then(Value::as_array).map_or(0, Vec::len);
        Some(json!({
            "title": t("report.title"),
            "subtitle": field("subject"),
            // Filed under the message's own hash: two copies of one phishing
            // run have the same subject and different files, and the hash is
            // what a ticket refers to.
            "file_name": format!("eml_{}", hash.chars().take(12).collect::<String>()),
            "format": "view",
            // `name: value`, with exactly one colon: several of these labels
            // are the dashboard's, where they are written with their own — and
            // "From:: someone" is what a second one looks like once the report
            // splits the line to lay it out.
            "summary": [
                figure(&t("ui.score"), &format!("{score}/100 — {verdict}")),
                figure(&t("atts.title"), &attachments.to_string()),
                figure(&t("iocs.title"), &indicators.to_string()),
                figure(&t("headers.from"), &field("from")),
            ],
            "charts": [],
            "sections": sections,
        }))
    }

    fn view_iocs(&self, has_osint: bool, lang: &str) -> Value {
        let t = |k: &str| catalog().tr(lang, k);
        let mut widgets = vec![
            row(vec![button(t("ui.back"), "eml.triage", "dashboard")]),
            separator(),
            label(t("iocs.title")).heading(), 
            separator()
        ];
        
        if let Some(iocs) = self.last_scan.get("iocs").and_then(Value::as_array) {
            if iocs.is_empty() {
                widgets.push(label(t("iocs.empty")).weak());
            } else {
                let cols = vec![t("iocs.indicator")];
                let mut rows = Vec::new();
                let mut row_ids = Vec::new();
                
                for (i, ioc) in iocs.iter().enumerate() {
                    let val = ioc.as_str().unwrap_or("");
                    rows.push(vec![val.to_string()]);
                    row_ids.push(i.to_string());
                }
                
                let mut tbl = table(cols, rows).row_ids(row_ids);
                if has_osint {
                    tbl = tbl.row_menu(vec![menu_item(t("menu.reputation"), "osint.reputation", "check_hash")]);
                }
                widgets.push(tbl);
            }
        }
        window(t("iocs.title"), widgets)
    }

    /// An attachment's note, as the analyst reads it.
    ///
    /// The parser has no locale, so it names a key and — where it found a name
    /// inside the file — passes it along. `{}` in the translation is where that
    /// name goes.
    fn note_text(&self, note: Option<&Value>, lang: &str) -> String {
        match note {
            Some(n) if n.is_object() => {
                let text = catalog().tr(lang, n.get("key").and_then(Value::as_str).unwrap_or(""));
                match n.get("arg").and_then(Value::as_str) {
                    Some(arg) => text.replace("{}", arg),
                    None => text,
                }
            }
            // A scan taken before this build, still held in the tab's state.
            Some(Value::String(s)) => s.clone(),
            _ => String::new(),
        }
    }

    fn view_atts(&self, has_osint: bool, lang: &str) -> Value {
        let t = |k: &str| catalog().tr(lang, k);
        let mut widgets = vec![
            row(vec![button(t("ui.back"), "eml.triage", "dashboard")]),
            separator(),
            label(t("atts.title")).heading(), 
            separator()
        ];
        
        let cols = vec![t("atts.filename"), t("atts.size"), t("atts.hash"), t("atts.note")];
        let mut rows = Vec::new();
        let mut row_ids = Vec::new();

        if let Some(atts) = self.last_scan.get("attachments").and_then(Value::as_array) {
            for (i, att) in atts.iter().enumerate() {
                rows.push(vec![
                    att.get("filename").and_then(Value::as_str).unwrap_or("").to_string(),
                    att.get("size").and_then(Value::as_u64).unwrap_or(0).to_string(),
                    att.get("hash").and_then(Value::as_str).unwrap_or("").to_string(),
                    self.note_text(att.get("note"), lang),
                ]);
                row_ids.push(i.to_string());
            }
        }

        let mut menu = vec![
            menu_item(t("menu.save"), "eml.triage", "save_file"),
            menu_item(t("menu.strings"), "eml.triage", "extract_strings").open_in_tab()
        ];
        if has_osint { menu.push(menu_item(t("menu.reputation"), "eml.triage", "check_reputation")); }

        widgets.push(table(cols, rows).row_ids(row_ids).row_menu(menu));
        window(t("atts.title"), widgets)
    }

    fn run_strings(&self, params: &Value, lang: &str) -> Value {
        let t = |k: &str| catalog().tr(lang, k);
        let id = params.get("id").and_then(Value::as_str).unwrap_or("");

        if let Some(att) = self.last_attachments.get(id) {
            let b64 = att.get("body_b64").and_then(Value::as_str).unwrap_or("");
            match STANDARD.decode(b64) {
                Ok(bytes) => {
                    let mut widgets = vec![label(t("ui.strings")).heading(), separator()];
                    let extracted = parser::extract_strings(&bytes);
                    let joined = extracted.into_iter().take(1000).collect::<Vec<String>>().join("\n");
                    widgets.push(label(joined).mono()); 
                    window(t("ui.output"), widgets)
                },
                Err(e) => self.dead_end(lang, format!("{} {}", t("errors.decode"), e)),
            }
        } else {
            self.dead_end(lang, t("errors.not_found"))
        }
    }

    fn check_reputation(&self, params: &Value, host: &Host, lang: &str) -> Value {
        let t = |k: &str| catalog().tr(lang, k);
        let id = params.get("id").and_then(Value::as_str).unwrap_or("");
        
        let hash = if let Some(att) = self.last_attachments.get(id) {
            att.get("hash").and_then(Value::as_str).unwrap_or("")
        } else if let Some(iocs) = self.last_scan.get("iocs").and_then(Value::as_array) {
            if let Ok(idx) = id.parse::<usize>() {
                if let Some(ioc) = iocs.get(idx).and_then(Value::as_str) {
                    let parts: Vec<&str> = ioc.split(": ").collect();
                    if parts.len() > 1 { parts[1] } else { ioc }
                } else { "" }
            } else { "" }
        } else { "" };

        if hash.is_empty() {
            return self.dead_end(lang, t("errors.not_found"));
        }
        
        match host.call("osint.reputation", "check_hash", json!({ "hash": hash })) {
            // The provider answers with a screen of its own — show it as it is.
            Ok(res) if res.get("widgets").is_some() => res,
            // ...or with nothing, which used to render as an empty window: the
            // analyst clicked "Check OSINT" and the screen went blank, which
            // reads as "clean" when it means "no answer".
            Ok(res) if res.is_null() => notice(
                self.view_atts(true, lang),
                "warning",
                t("errors.osint_empty"),
            ),
            // Anything else is data without a screen: show it rather than drop it.
            Ok(res) => window(
                t("menu.reputation"),
                vec![label(res.to_string()).mono()],
            ),
            Err(e) => self.dead_end(lang, format!("OSINT: {e}")),
        }
    }

    fn save_file(&self, params: &Value, host: &Host, lang: &str) -> Value {
        let t = |k: &str| catalog().tr(lang, k);
        let id = params.get("id").and_then(Value::as_str).unwrap_or("");
        
        let has_osint = host.has_capability("osint.reputation");
        let current_view = self.view_atts(has_osint, lang);
        
        let Some(att) = self.last_attachments.get(id) else {
            return notice(current_view, "error", t("errors.not_found"));
        };

        // Decode before asking where to put it — no reason to raise a dialog
        // for bytes that cannot be written.
        let b64 = att.get("body_b64").and_then(Value::as_str).unwrap_or("");
        let bytes = match STANDARD.decode(b64) {
            Ok(bytes) => bytes,
            Err(e) => {
                return notice(current_view, "error", format!("{} {}", t("errors.decode"), e));
            }
        };

        // The attachment does not choose where it lands. Its declared name is
        // only a suggestion for the dialog; the path written is the one the
        // user picked, which is what `filesystem = ["<user-selected>"]` in
        // limen.toml promises. `None` means they cancelled.
        let declared = att.get("filename").and_then(Value::as_str).unwrap_or("dump.bin");
        let Some(dest) = host.save_file(&safe_name(declared)) else {
            return notice(current_view, "warning", t("errors.fs_cancelled"));
        };

        match std::fs::write(&dest, bytes) {
            Ok(_) => notice(current_view, "ok", format!("{} {}", t("errors.fs_success"), dest)),
            Err(e) => notice(current_view, "error", format!("{} {}", t("errors.fs_error"), e)),
        }
    }
}

export_module!(EmlAnalyzer);


#[cfg(test)]
mod tests;
