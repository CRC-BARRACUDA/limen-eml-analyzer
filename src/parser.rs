use limen_sdk_rust::{json, Value};
use mailparse::*;
use md5::{Md5, Digest};
use std::fs;
use std::io::Cursor;
use base64::{Engine as _, engine::general_purpose::STANDARD};

use crate::{headers, ioc, links, scoring};

struct ParseState {
    attachments: Vec<Value>,
    iocs: Vec<String>,
    /// Who the message was sent to — needed to tell "a link carrying an
    /// address" from "a link carrying *your* address".
    recipient: String,
    /// Links that hide where they go: (what was written, where it ends up).
    cloaked: Vec<(String, String)>,
    /// A link carrying the recipient's own address in its fragment.
    victim_in_link: bool,
    /// The message asks for an account or a password.
    credential_ask: bool,
    /// It contains at least one link at all.
    has_link: bool,
    bad_attachments: usize,
    total_psycho_words: usize,
    html_anomalies: usize,
    has_pwd_keyword: bool,
    has_crypto: bool,
    has_archive: bool,
    is_encrypted_zip: bool,
    has_double_ext: bool,
    has_macro: bool,
    /// Everything readable in the message, for the checks that need a whole
    /// sentence rather than a single part.
    body_text: String,
}

pub fn parse(path: &str) -> Result<Value, String> {
    let content = fs::read(path).map_err(|e| format!("{}", e))?;
    let parsed_mail = parse_mail(&content).map_err(|e| e.to_string())?;
    
    let mut eml_hasher = Md5::new();
    eml_hasher.update(&content);
    let eml_hash = hex::encode(eml_hasher.finalize());

    let header_data = headers::analyze(&parsed_mail);
    
    let recipient = links::bare_address(
        header_data.get("to").and_then(Value::as_str).unwrap_or(""),
    );
    let mut state = ParseState {
        attachments: Vec::new(),
        iocs: Vec::new(),
        recipient,
        cloaked: Vec::new(),
        victim_in_link: false,
        credential_ask: false,
        has_link: false,
        bad_attachments: 0,
        total_psycho_words: 0,
        html_anomalies: 0,
        has_pwd_keyword: false,
        has_crypto: false,
        has_archive: false,
        is_encrypted_zip: false,
        has_double_ext: false,
        has_macro: false,
        body_text: String::new(),
    };

    let subject = header_data.get("subject").and_then(Value::as_str).unwrap_or("");
    let (sc, pwd) = ioc::count_psycho_words(subject);
    state.total_psycho_words += sc;
    if pwd { state.has_pwd_keyword = true; }

    process_part(&parsed_mail, &mut state);

    // The message talks about the recipient's own mail domain while coming from
    // somewhere else entirely — "your mk.gov.ua mailbox", sent from a ministry
    // in another country. A real notice about your mailbox comes from the
    // people who run it.
    let recipient_domain = links::domain_of(&state.recipient).to_string();
    let from_domain = links::domain_of(&links::bare_address(
        header_data.get("from").and_then(Value::as_str).unwrap_or(""),
    ))
    .to_string();
    let body_names_domain = !recipient_domain.is_empty()
        && (state.body_text.to_lowercase().contains(&recipient_domain)
            || subject.to_lowercase().contains(&recipient_domain));
    let impersonation = body_names_domain
        && !from_domain.is_empty()
        && links::registrable(&from_domain) != links::registrable(&recipient_domain);

    // The destination of a cloaked link is the one thing the analyst has to be
    // able to read, so it goes in with the indicators as well as in the score.
    for (_, target) in &state.cloaked {
        state.iocs.push(format!("Redirect: {target}"));
    }
    state.iocs.sort();
    state.iocs.dedup();

    let scoring_data = scoring::calculate(
        &header_data,
        &scoring::Signals {
            bad_attachments: state.bad_attachments,
            has_double_ext: state.has_double_ext,
            psycho_words: state.total_psycho_words,
            html_anomalies: state.html_anomalies,
            has_crypto: state.has_crypto,
            has_archive: state.has_archive,
            is_encrypted_zip: state.is_encrypted_zip,
            has_pwd_keyword: state.has_pwd_keyword,
            has_macro: state.has_macro,
            cloaked_links: state.cloaked.len(),
            victim_in_link: state.victim_in_link,
            // Asking for a password is only an attack if there is somewhere to
            // type it. The same sentence in a message with no link at all is a
            // notice about an account, which is ordinary mail.
            credential_ask: state.credential_ask && state.has_link,
            impersonates_recipient: impersonation,
            // `cert.gov.ua@notify-secure.example` — the domain is in the part
            // nobody reads past. Checked on Reply-To as well: a reply address is
            // where an answer actually goes.
            domain_in_local_part: [
                header_data.get("from").and_then(Value::as_str).unwrap_or(""),
                header_data.get("reply_to").and_then(Value::as_str).unwrap_or(""),
            ]
            .iter()
            .any(|h| links::domain_in_local_part(h)),
        },
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
        
        // `.lnk` runs an arbitrary command with a chosen icon, `.hta` runs
        // script through mshta outside the browser sandbox, and `.cpl` is a DLL
        // that rundll32 loads on a double-click. All three are ordinary in
        // current phishing and none of them look like a program to a recipient.
        let dangerous_exts = [".exe", ".bat", ".vbs", ".ps1", ".iso", ".scr",
                              ".cmd", ".js", ".wsf", ".pif", ".lnk", ".hta", ".cpl"];
        let office_exts = [".doc", ".xls", ".ppt", ".docm", ".xlsm", ".pptm", ".rtf"];
        
        let has_dangerous_ext = dangerous_exts.iter().any(|ext| lower_name.ends_with(ext));
        let has_office_ext = office_exts.iter().any(|ext| lower_name.ends_with(ext));
        let is_double = dot_count > 1 && has_dangerous_ext;
        
        let is_zip = lower_name.ends_with(".zip") || lower_name.ends_with(".docx") || lower_name.ends_with(".xlsx") || lower_name.ends_with(".docm") || lower_name.ends_with(".xlsm");
        let is_tar = lower_name.ends_with(".tar") || lower_name.ends_with(".gz") || lower_name.ends_with(".tgz");
        let is_pdf = lower_name.ends_with(".pdf");
        
        if is_zip || lower_name.ends_with(".rar") || lower_name.ends_with(".7z") || is_tar {
            state.has_archive = true;
            if is_zip && body.len() > 6 && body[0..4] == [0x50, 0x4B, 0x03, 0x04] && (body[6] & 1) != 0 {
                state.is_encrypted_zip = true;
            }
        }

        // A key rather than a sentence: `parser` has no locale, and the note
        // is the cell the analyst actually reads. `view_atts` translates it,
        // exactly as the dashboard translates `scoring`'s reasons.
        let mut note = json!({ "key": "notes.ok" });
        
        if is_double {
            note = json!({ "key": "notes.double_ext" });
            state.bad_attachments += 1;
            state.has_double_ext = true;
        } else if has_dangerous_ext {
            note = json!({ "key": "notes.exe" });
            state.bad_attachments += 1;
        } else if has_office_ext && lower_name.ends_with("m") {
            note = json!({ "key": "notes.macro_format" });
            state.bad_attachments += 1;
            state.has_macro = true;
        } else if has_office_ext {
            note = json!({ "key": "notes.legacy_office" });
            state.bad_attachments += 1;
        } else if state.is_encrypted_zip {
            note = json!({ "key": "notes.enc_zip" });
        } else {
            let mut found_in_zip = false;
            
            if is_zip && !state.is_encrypted_zip {
                let cursor = Cursor::new(&body);
                if let Ok(mut archive) = zip::ZipArchive::new(cursor) {
                    for i in 0..archive.len() {
                        if let Ok(file) = archive.by_index(i) {
                            let inner_name = file.name().to_lowercase();
                            if inner_name.contains("vbaproject.bin") {
                                note = json!({ "key": "notes.macro" });
                                state.bad_attachments += 1;
                                state.has_macro = true;
                                found_in_zip = true;
                                break;
                            }
                            for ext in &dangerous_exts {
                                if inner_name.ends_with(ext) || inner_name.contains(&format!("{} ", ext)) {
                                    note = json!({ "key": "notes.hidden", "arg": file.name() });
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
                        note = json!({ "key": "notes.hidden", "arg": s });
                        state.bad_attachments += 1;
                        state.has_double_ext = true;
                        break;
                    }
                    if state.has_archive {
                        for ext in &dangerous_exts {
                            if sl.ends_with(ext) || sl.contains(&format!("{} ", ext)) || sl.contains(&format!("{}\"", ext)) {
                                note = json!({ "key": "notes.in_archive", "arg": s });
                                state.bad_attachments += 1;
                                state.has_double_ext = true;
                                found_in_zip = true;
                                break;
                            }
                        }
                    }

                    // A PDF that carries a link to something executable. The
                    // PDF itself is inert; the payload is one click past it,
                    // which is the shape most current phishing takes — so it is
                    // reported as a link, not as a hidden extension.
                    //
                    // Matched on `/URI` so it is a link object rather than the
                    // extension appearing in prose, and at the end of the path
                    // rather than anywhere in the URL — so a detached signature
                    // beside an archive (`v1.zip.sig`) and a query that merely
                    // names one (`a.pdf?attachment=payload.zip`) are not read as
                    // the link serving it.
                    if is_pdf && sl.contains("/uri") && sl.contains("http") {
                        if let Some(url) = linked_payload(&sl) {
                            note = json!({ "key": "notes.pdf_link", "arg": url });
                            state.bad_attachments += 1;
                            // Not `has_double_ext`: nothing here has two
                            // extensions, and saying so would put the wrong
                            // reason on the score.
                            found_in_zip = true;
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
            state.body_text.push_str(&text);
            state.body_text.push('\n');

            // Where the links in this part actually go, and what they carry.
            // Read off the `href`s rather than the visible text: the whole point
            // of the technique is that the two are not the same.
            for href in links::hrefs(&text) {
                state.has_link = true;
                if let Some(target) = links::redirect_target(&href) {
                    state.cloaked.push((href.clone(), target));
                }
                if links::fragment_carries(&href, &state.recipient) {
                    state.victim_in_link = true;
                }
            }
            if links::asks_for_credentials(&text) {
                state.credential_ask = true;
            }

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

/// The first URL in `haystack` that points at something executable.
///
/// Matched at the **end of the path**, with the query and fragment cut off
/// first. Searching the whole URL instead would read `release/v1.zip.sig` — a
/// detached signature — as an archive, and `a.pdf?attachment=payload.zip` as a
/// zip when the link serves a PDF.
///
/// Returns the URL itself, because the note is only worth reading if it says
/// which link.
fn linked_payload(haystack: &str) -> Option<String> {
    const PAYLOAD: [&str; 11] = [
        ".zip", ".rar", ".7z", ".exe", ".iso", ".msi", ".cab", ".lnk", ".bat",
        ".vbs", ".ps1",
    ];
    for start in haystack.match_indices("http").map(|(i, _)| i) {
        let url: String = haystack[start..]
            .chars()
            .take_while(|c| !c.is_whitespace() && !matches!(c, ')' | '>' | '"' | '\''))
            .collect();
        // The path only: a query string can carry anything and says nothing
        // about what is served.
        let path = url.split(['?', '#']).next().unwrap_or(&url);
        if PAYLOAD.iter().any(|ext| path.ends_with(ext)) {
            return Some(url);
        }
    }
    None
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