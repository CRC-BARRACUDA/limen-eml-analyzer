use std::collections::HashMap;
use std::sync::OnceLock;

use limen_sdk_rust::ui::{button, file, label, menu_item, notice, row, separator, step, table, window};
use limen_sdk_rust::{export_module, json, rpc, Catalog, Handler, Host, RpcError, Value};
use base64::{Engine as _, engine::general_purpose::STANDARD};

mod headers;
mod ioc;
mod parser;
mod scoring;

fn catalog() -> &'static Catalog {
    static C: OnceLock<Catalog> = OnceLock::new();
    C.get_or_init(|| {
        Catalog::new(&[
            ("en", include_str!("locales/en.toml")),
            ("uk", include_str!("locales/uk.toml")),
        ])
    })
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

        match method {
            "ui" => Ok(self.idle_view(&lang)),
            "scan" => Ok(self.scan(&params, &lang)),
            "dashboard" => Ok(self.render_dashboard(has_osint, &lang)),
            "view_iocs" => Ok(self.view_iocs(has_osint, &lang)),
            "view_atts" => Ok(self.view_atts(has_osint, &lang)),
            "check_reputation" => Ok(self.check_reputation(&params, host, &lang)),
            "save_file" => Ok(self.save_file(&params, host, &lang)),
            "extract_strings" => Ok(self.run_strings(&params, &lang)),
            other => Err(RpcError::new(rpc::METHOD_NOT_FOUND, format!("No method {}", other))),
        }
    }
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

    fn scan(&mut self, params: &Value, lang: &str) -> Value {
        let t = |k: &str| catalog().tr(lang, k);
        let path = params.get("file_path").and_then(Value::as_str).unwrap_or("");
        
        if path.is_empty() {
            return window("Error", vec![label(t("errors.empty")).strong()]);
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
            Err(e) => window("Error", vec![label(e).strong()]),
        }
    }

    fn render_simple_summary(&self, lang: &str) -> Value {
        let t = |k: &str| catalog().tr(lang, k);
        
        let scoring = self.last_scan.get("scoring").unwrap();
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

    fn render_dashboard(&self, has_osint: bool, lang: &str) -> Value {
        let t = |k: &str| catalog().tr(lang, k);
        
        let scoring = self.last_scan.get("scoring").unwrap();
        let score = scoring.get("score").and_then(Value::as_u64).unwrap_or(0);
        let triggers = scoring.get("triggers").and_then(Value::as_array).unwrap_or(&vec![]).clone();
        
        let (r_label, r_icon) = match score {
            0..=30 => (t("ui.score_low"), "done"),
            31..=60 => (t("ui.score_med"), "warning"),
            _ => (t("ui.score_high"), "error"),
        };

        let headers = self.last_scan.get("headers").unwrap();
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
        widgets.push(row(vec![
            button(t("ui.view_iocs"), "eml.triage", "view_iocs"),
            button(t("ui.view_atts"), "eml.triage", "view_atts"),
        ]));

        window(t("ui.title"), widgets)
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
                let cols = vec!["Indicator".to_string()];
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

    fn view_atts(&self, has_osint: bool, lang: &str) -> Value {
        let t = |k: &str| catalog().tr(lang, k);
        let mut widgets = vec![
            row(vec![button(t("ui.back"), "eml.triage", "dashboard")]),
            separator(),
            label(t("atts.title")).heading(), 
            separator()
        ];
        
        let cols = vec![t("atts.filename").into(), t("atts.size").into(), t("atts.hash").into(), t("atts.note").into()];
        let mut rows = Vec::new();
        let mut row_ids = Vec::new();

        if let Some(atts) = self.last_scan.get("attachments").and_then(Value::as_array) {
            for (i, att) in atts.iter().enumerate() {
                rows.push(vec![
                    att.get("filename").and_then(Value::as_str).unwrap_or("").to_string(),
                    att.get("size").and_then(Value::as_u64).unwrap_or(0).to_string(),
                    att.get("hash").and_then(Value::as_str).unwrap_or("").to_string(),
                    att.get("note").and_then(Value::as_str).unwrap_or("").to_string(),
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
                    let mut widgets = vec![label("Strings").heading(), separator()];
                    let extracted = parser::extract_strings(&bytes);
                    let joined = extracted.into_iter().take(1000).collect::<Vec<String>>().join("\n");
                    widgets.push(label(joined).mono()); 
                    window("Output", widgets)
                },
                Err(e) => window("Error", vec![label(format!("{} {}", t("errors.decode"), e)).strong()]),
            }
        } else {
            window("Error", vec![label(t("errors.not_found")).strong()])
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

        if hash.is_empty() { return window("Error", vec![label(t("errors.not_found")).strong()]); }
        
        match host.call("osint.reputation", "check_hash", json!({ "hash": hash })) {
            Ok(res) => res,
            Err(e) => window("Error", vec![label(format!("OSINT: {}", e)).weak()]),
        }
    }

    fn save_file(&self, params: &Value, host: &Host, lang: &str) -> Value {
        let t = |k: &str| catalog().tr(lang, k);
        let id = params.get("id").and_then(Value::as_str).unwrap_or("");
        
        let has_osint = host.has_capability("osint.reputation");
        let current_view = self.view_atts(has_osint, lang);
        
        if let Some(att) = self.last_attachments.get(id) {
            let filename = att.get("filename").and_then(Value::as_str).unwrap_or("dump.bin");
            let b64 = att.get("body_b64").and_then(Value::as_str).unwrap_or("");
            
            match STANDARD.decode(b64) {
                Ok(bytes) => match std::fs::write(filename, bytes) {
                    Ok(_) => notice(current_view, "ok", format!("{} {}", t("errors.fs_success"), filename)),
                    Err(e) => notice(current_view, "error", format!("{} {}", t("errors.fs_error"), e)),
                },
                Err(e) => notice(current_view, "error", format!("{} {}", t("errors.decode"), e)),
            }
        } else {
            notice(current_view, "error", t("errors.not_found"))
        }
    }
}

export_module!(EmlAnalyzer);