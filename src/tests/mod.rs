//! What the module is expected to do, in the language of what it is for.
//!
//! A cdylib has no rlib for an integration test to link against, so these live
//! inside the crate: one file per part, and the fixtures they share here.

use crate::*;
use base64::engine::general_purpose::STANDARD;

mod auth;
mod i18n;
mod indicators;
mod names;
mod parse;
mod risk;
mod views;

/// A message that should worry nobody: authenticated, plain text, no files.
pub const BENIGN: &str = "\
From: Anna <anna@example.org>\r
To: analyst@example.org\r
Subject: Lunch on Thursday\r
Authentication-Results: mx.example.org; spf=pass; dkim=pass; dmarc=pass\r
Content-Type: text/plain\r
\r
See you at one. The place on 5th.\r
";

/// Build a multipart message with one attachment, base64 as a real mail would
/// carry it. `name` is what the message *claims* the file is called.
pub fn with_attachment(name: &str, bytes: &[u8], auth: &str) -> String {
    format!(
        "From: Billing <billing@exarnple.com>\r\n\
         Reply-To: collector@evil.test\r\n\
         To: analyst@example.org\r\n\
         Subject: Invoice\r\n\
         Authentication-Results: mx.example.org; {auth}\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: multipart/mixed; boundary=\"B\"\r\n\
         \r\n\
         --B\r\n\
         Content-Type: text/plain\r\n\
         \r\n\
         Please see the attached.\r\n\
         --B\r\n\
         Content-Type: application/octet-stream; name=\"{name}\"\r\n\
         Content-Transfer-Encoding: base64\r\n\
         Content-Disposition: attachment; filename=\"{name}\"\r\n\
         \r\n\
         {}\r\n\
         --B--\r\n",
        STANDARD.encode(bytes)
    )
}

/// Write a message where the parser can read it. Named per test so two of them
/// running at once cannot collide.
pub fn eml_file(test: &str, content: &str) -> String {
    let dir = std::env::temp_dir().join("eml-analyzer-tests");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{test}.eml"));
    std::fs::write(&path, content).unwrap();
    path.to_string_lossy().into_owned()
}

/// An analyzer that has already looked at `content` — the state every view
/// below the summary assumes.
pub fn scanned(test: &str, content: &str) -> EmlAnalyzer {
    let mut a = EmlAnalyzer::default();
    let path = eml_file(test, content);
    a.scan(&json!({ "file_path": path }), "en");
    a
}

/// The first four bytes of a zip, with the "encrypted" bit set in the general
/// purpose flags — which is all the parser looks at.
pub fn encrypted_zip() -> Vec<u8> {
    let mut b = vec![0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x01, 0x00];
    b.extend_from_slice(b"\x08\x00rest of an archive");
    b
}

/// Every `section.key` a catalog defines, in the form the module asks for.
pub fn catalog_keys(toml: &str) -> Vec<String> {
    let mut section = String::new();
    let mut out = Vec::new();
    for line in toml.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = format!("{name}.");
        } else if let Some((k, _)) = line.split_once('=') {
            out.push(format!("{section}{}", k.trim()));
        }
    }
    out
}
