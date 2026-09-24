//! Reading a message off disk: what comes back, and what refuses to.

use super::*;

fn parsed(test: &str, content: &str) -> Value {
    crate::parser::parse(&eml_file(test, content)).unwrap()
}

#[test]
fn a_benign_message_scores_low_and_carries_no_files() {
    let v = parsed("benign", BENIGN);
    assert!(v["scoring"]["score"].as_u64().unwrap() <= 30);
    assert_eq!(v["attachments"].as_array().unwrap().len(), 0);
    assert_eq!(v["headers"]["from"], json!("Anna <anna@example.org>"));
}

#[test]
fn the_hash_identifies_the_file_itself() {
    let v = parsed("hash", BENIGN);
    let hash = v["eml_hash"].as_str().unwrap();
    assert_eq!(hash.len(), 32, "md5, hex");
    // The same bytes hash the same way; different bytes do not.
    assert_eq!(hash, parsed("hash_again", BENIGN)["eml_hash"].as_str().unwrap());
    assert_ne!(hash, parsed("hash_other", &BENIGN.replace("one.", "two."))["eml_hash"]);
}

#[test]
fn an_executable_attachment_is_called_out() {
    let v = parsed("exe", &with_attachment("setup.exe", b"MZ...", "spf=pass; dkim=pass"));
    let att = &v["attachments"][0];
    assert_eq!(att["filename"], json!("setup.exe"));
    assert_eq!(att["note"], json!({ "key": "notes.exe" }));
    assert_eq!(att["size"], json!(5));
    assert_eq!(att["hash"].as_str().unwrap().len(), 32);
}

/// The extension the analyst reads is the last one. A file called
/// `invoice.pdf.exe` is an executable dressed as a document.
#[test]
fn a_double_extension_is_worth_the_whole_score() {
    let v = parsed("double", &with_attachment("invoice.pdf.exe", b"MZ", "spf=pass; dkim=pass"));
    assert_eq!(v["attachments"][0]["note"], json!({ "key": "notes.double_ext" }));
    assert_eq!(v["scoring"]["score"], json!(100));
}

#[test]
fn a_macro_enabled_document_is_not_treated_as_a_document() {
    let v = parsed("macro", &with_attachment("report.docm", b"PK\x03\x04", "spf=pass; dkim=pass"));
    assert_eq!(v["attachments"][0]["note"], json!({ "key": "notes.macro_format" }));
}

#[test]
fn an_encrypted_archive_is_recognised_by_its_flag() {
    let v = parsed("enczip", &with_attachment("archive.zip", &encrypted_zip(), "spf=pass; dkim=pass"));
    assert_eq!(v["attachments"][0]["note"], json!({ "key": "notes.enc_zip" }));
    let triggers = v["scoring"]["triggers"].to_string();
    assert!(triggers.contains("reasons.enc_zip"), "{triggers}");
}

#[test]
fn indicators_come_out_of_the_body() {
    let raw = BENIGN.replace("The place on 5th.", "wire it via http://evil.test/pay from 10.0.0.7");
    let iocs = parsed("iocs", &raw)["iocs"].to_string();
    assert!(iocs.contains("URL: http://evil.test/pay"), "{iocs}");
    assert!(iocs.contains("IP: 10.0.0.7"), "{iocs}");
}

/// The whole point of the module is opening hostile files, so the failure
/// that matters is the one that is not a failure: nothing here may panic.
#[test]
fn rubbish_is_read_without_panicking() {
    let v = crate::parser::parse(&eml_file("rubbish", "\u{0}\u{1}not a message at all\u{7}"));
    assert!(v.is_ok(), "mailparse is deliberately tolerant");
}

#[test]
fn a_missing_file_is_an_error_not_a_crash() {
    let missing = crate::parser::parse("/nonexistent/nowhere.eml");
    assert!(missing.is_err());
    assert!(!missing.unwrap_err().is_empty(), "the analyst is told why");
}

#[test]
fn strings_are_pulled_out_of_bytes_that_are_not_text() {
    let blob = b"\x00\x01hello world\xff\xfe\x00tiny\x00another string";
    let found = crate::parser::extract_strings(blob);
    assert!(found.contains(&"hello world".to_string()), "{found:?}");
    assert!(found.contains(&"another string".to_string()), "{found:?}");
    assert!(!found.iter().any(|s| s == "tiny"), "runs under 5 are noise: {found:?}");
}

// ---- contributed: PDF links and the wider executable list ------------------ //

/// A PDF is inert; the payload is one click past it.
///
/// That is the shape most current phishing takes — a clean-looking invoice whose
/// only link fetches an archive — so the link is what gets reported.
#[test]
fn a_pdf_linking_to_an_archive_is_flagged() {
    let pdf = b"%PDF-1.7\n<< /Type /Action /S /URI /URI (http://evil.test/invoice.zip) >>\ntrailer\n";
    let v = parsed("pdflink", &with_attachment("invoice.pdf", pdf, "spf=pass"));
    let note = &v["attachments"][0]["note"];
    assert_eq!(note["key"], json!("notes.pdf_link"), "note was {note}");
    assert!(
        note["arg"].as_str().unwrap().contains("invoice.zip"),
        "the note has to say which link: {note}"
    );
    // Reported as a link, not as a double extension — nothing here has two.
    assert_ne!(v["attachments"][0]["note"]["key"], json!("notes.double_ext"));
}

/// The extension is matched at the end of the path, not anywhere in the URL.
///
/// Searching the whole URL reads a detached signature as the archive it signs,
/// and a query that merely names a file as the file being served. A scanner that
/// cries wolf on ordinary mail stops being read.
#[test]
fn an_ordinary_pdf_link_is_left_alone() {
    for url in [
        // Both of these are flagged by a plain `contains` over the whole URL.
        "https://cdn.example.org/release/v1.zip.sig",
        "https://example.org/a.pdf?attachment=payload.zip",
        "https://example.org/files/report.pdf",
        "https://example.org/docs/isolation-guide.html",
    ] {
        let pdf = format!("%PDF-1.7\n<< /S /URI /URI ({url}) >>\n");
        let v = parsed("pdfok", &with_attachment("doc.pdf", pdf.as_bytes(), "spf=pass"));
        assert_eq!(
            v["attachments"][0]["note"]["key"],
            json!("notes.ok"),
            "{url} should not have been flagged: {}",
            v["attachments"][0]["note"]
        );
    }
}

/// `.lnk`, `.hta` and `.cpl` run code and look like nothing much to a recipient.
#[test]
fn the_newer_executable_extensions_are_caught() {
    for name in ["update.lnk", "report.hta", "settings.cpl"] {
        let v = parsed("newexts", &with_attachment(name, b"whatever", "spf=pass"));
        assert_eq!(
            v["attachments"][0]["note"]["key"],
            json!("notes.exe"),
            "{name} was not treated as executable"
        );
        assert!(v["scoring"]["score"].as_u64().unwrap() >= 50, "{name} scored low");
    }
}
