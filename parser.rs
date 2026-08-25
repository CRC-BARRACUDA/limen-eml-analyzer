use limen_sdk_rust::{json, Value};
use mailparse::*;
use md5::{Md5, Digest};
use std::fs;
use std::io::Cursor;
use base64::{Engine as _, engine::general_purpose::STANDARD};

use crate::{headers, ioc, scoring};

struct ParseState {
    attachments: Vec<Value>,
    iocs: Vec<String>,
    bad_attachments: usize,
    total_psycho_words: usize,
    html_anomalies: usize,
    has_pwd_keyword: bool,
    has_crypto: bool,
    has_archive: bool,
    is_encrypted_zip: bool,
    has_double_ext: bool,
    has_macro: bool,
}

pub fn parse(path: &str) -> Result<Value, String> {
    let content = fs::read(path).map_err(|e| format!("{}", e))?;
    let parsed_mail = parse_mail(&content).map_err(|e| e.to_string())?;
    
    let mut eml_hasher = Md5::new();
    eml_hasher.update(&content);
    let eml_hash = hex::encode(eml_hasher.finalize());

    let header_data = headers::analyze(&parsed_mail);
    
    let mut state = ParseState {
        attachments: Vec::new(),
        iocs: Vec::new(),
        bad_attachments: 0,
        total_psycho_words: 0,
        html_anomalies: 0,
        has_pwd_keyword: false,
        has_crypto: false,
        has_archive: false,
        is_encrypted_zip: false,
        has_double_ext: false,
        has_macro: false,
    };

    let subject = header_data.get("subject").and_then(Value::as_str).unwrap_or("");
    let (sc, pwd) = ioc::count_psycho_words(subject);
    state.total_psycho_words += sc;
    if pwd { state.has_pwd_keyword = true; }

    process_part(&parsed_mail, &mut state);

    let scoring_data = scoring::calculate(
        &header_data, state.bad_attachments, state.has_double_ext, state.total_psycho_words, 
        state.html_anomalies, state.has_crypto, state.has_archive, state.is_encrypted_zip, state.has_pwd_keyword, state.has_macro
    );

    Ok(json!({
        "eml_hash": eml_hash,
        "headers": header_data,
        "scoring": scoring_data,
        "iocs": state.iocs,
        "attachments": state.attachments
    }))
}

fn process_part(part: &ParsedMail, state: &mut ParseState) {
    let disp = part.get_content_disposition();
    let ctype = &part.ctype; 
    let body = part.get_body_raw().unwrap_or_default();

    let filename = disp.params.get("filename")
        .or_else(|| ctype.params.get("name"))
        .cloned();

    let is_attachment = disp.disposition == DispositionType::Attachment || filename.is_some();

    if is_attachment && !ctype.mimetype.starts_with("multipart/") {
        let filename = filename.unwrap_or_else(|| "unknown".to_string());
        
        let mut hasher = Md5::new();
        hasher.update(&body);
        let hash = hex::encode(hasher.finalize());
        let body_b64 = STANDARD.encode(&body); 
        
        let lower_name = filename.to_lowercase();
        let dot_count = lower_name.matches('.').count();
        
        let dangerous_exts = [".exe", ".bat", ".vbs", ".ps1", ".iso", ".scr", ".cmd", ".js", ".wsf", ".pif"];
        let office_exts = [".doc", ".xls", ".ppt", ".docm", ".xlsm", ".pptm", ".rtf"];
        
        let has_dangerous_ext = dangerous_exts.iter().any(|ext| lower_name.ends_with(ext));
        let has_office_ext = office_exts.iter().any(|ext| lower_name.ends_with(ext));
        let is_double = dot_count > 1 && has_dangerous_ext;
        
        let is_zip = lower_name.ends_with(".zip") || lower_name.ends_with(".docx") || lower_name.ends_with(".xlsx") || lower_name.ends_with(".docm") || lower_name.ends_with(".xlsm");
        let is_tar = lower_name.ends_with(".tar") || lower_name.ends_with(".gz") || lower_name.ends_with(".tgz");
        
        if is_zip || lower_name.ends_with(".rar") || lower_name.ends_with(".7z") || is_tar {
            state.has_archive = true;
            if is_zip && body.len() > 6 && body[0..4] == [0x50, 0x4B, 0x03, 0x04] && (body[6] & 1) != 0 {
                state.is_encrypted_zip = true;
            }
        }

        let mut note = String::from("OK");
        
        if is_double {
            note = "SUSPICIOUS (Double Ext)".to_string();
            state.bad_attachments += 1;
            state.has_double_ext = true;
        } else if has_dangerous_ext {
            note = "SUSPICIOUS (Executable)".to_string();
            state.bad_attachments += 1;
        } else if has_office_ext && lower_name.ends_with("m") {
            note = "SUSPICIOUS (Macro-enabled Format)".to_string();
            state.bad_attachments += 1;
            state.has_macro = true;
        } else if has_office_ext {
            note = "WARNING (Legacy Office Format)".to_string();
            state.bad_attachments += 1;
        } else if state.is_encrypted_zip {
            note = "WARNING (Encrypted ZIP)".to_string();
        } else {
            let mut found_in_zip = false;
            
            if is_zip && !state.is_encrypted_zip {
                let cursor = Cursor::new(&body);
                if let Ok(mut archive) = zip::ZipArchive::new(cursor) {
                    for i in 0..archive.len() {
                        if let Ok(file) = archive.by_index(i) {
                            let inner_name = file.name().to_lowercase();
                            if inner_name.contains("vbaproject.bin") {
                                note = "CRITICAL (Office Macro Detected)".to_string();
                                state.bad_attachments += 1;
                                state.has_macro = true;
                                found_in_zip = true;
                                break;
                            }
                            for ext in &dangerous_exts {
                                if inner_name.ends_with(ext) || inner_name.contains(&format!("{} ", ext)) {
                                    note = format!("SUSPICIOUS (Hidden: {})", file.name());
                                    state.bad_attachments += 1;
                                    state.has_double_ext = true;
                                    found_in_zip = true;
                                    break;
                                }
                            }
                            if found_in_zip { break; }
                        }
                    }
                }
            }

            if !found_in_zip {
                let inner_strings = extract_strings(&body);
                for s in inner_strings {
                    let sl = s.to_lowercase();
                    if sl.contains(".pdf.lnk") || sl.contains(".doc.lnk") || sl.contains(".pdf.exe") || sl.contains("..exe") {
                        note = format!("SUSPICIOUS (Hidden: {})", s);
                        state.bad_attachments += 1;
                        state.has_double_ext = true;
                        break;
                    }
                    if state.has_archive {
                        for ext in &dangerous_exts {
                            if sl.ends_with(ext) || sl.contains(&format!("{} ", ext)) || sl.contains(&format!("{}\"", ext)) {
                                note = format!("SUSPICIOUS (Archive contains: {})", s);
                                state.bad_attachments += 1;
                                state.has_double_ext = true;
                                found_in_zip = true;
                                break;
                            }
                        }
                    }
                    if found_in_zip || state.bad_attachments > 0 { break; }
                }
            }
        }

        state.attachments.push(json!({
            "filename": filename,
            "size": body.len(),
            "hash": hash,
            "note": note,
            "body_b64": body_b64,
        }));
    } else if ctype.mimetype == "text/plain" || ctype.mimetype == "text/html" {
        if let Ok(text) = part.get_body() {
            let (sc, pwd) = ioc::count_psycho_words(&text);
            state.total_psycho_words += sc;
            if pwd { state.has_pwd_keyword = true; }
            
            if ctype.mimetype == "text/html" {
                state.html_anomalies += ioc::check_html_anomalies(&text);
            }
            
            let extracted_iocs = ioc::extract(&text);
            if extracted_iocs.iter().any(|i| i.starts_with("BTC:") || i.starts_with("ETH:") || i.starts_with("XMR:")) {
                state.has_crypto = true;
            }
            state.iocs.extend(extracted_iocs);
        }
    }

    for subpart in &part.subparts {
        process_part(subpart, state);
    }
}

pub fn extract_strings(body: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = String::new();
    
    for &b in body {
        if b.is_ascii_graphic() || b == b' ' || b == b'\t' {
            current.push(b as char);
        } else {
            if current.len() >= 5 {
                strings.push(current.clone());
            }
            current.clear();
        }
    }
    if current.len() >= 5 { strings.push(current); }
    strings
}