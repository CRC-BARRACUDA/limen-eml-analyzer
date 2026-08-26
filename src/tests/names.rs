//! The name an attachment gives itself decides nothing but the suggestion in
//! the save dialog.

use super::*;

#[test]
fn strips_every_directory_component() {
    assert_eq!(safe_name("../../.config/autostart/x.desktop"), "x.desktop");
    assert_eq!(safe_name("..\\..\\Startup\\x.exe"), "x.exe");
    assert_eq!(safe_name("/etc/cron.d/payload"), "payload");
    assert_eq!(safe_name("C:\\Windows\\System32\\evil.dll"), "evil.dll");
}

#[test]
fn falls_back_when_nothing_usable_is_left() {
    for declared in ["", ".", "..", "   ", "../", "\\", "<>|"] {
        assert_eq!(safe_name(declared), "dump.bin", "{declared:?}");
    }
}

/// A NUL or a newline can truncate the name where it is displayed, so the
/// extension the analyst reads would not be the one written to disk.
#[test]
fn drops_characters_that_hide_the_real_name() {
    assert_eq!(safe_name("invoice.pdf\u{0}.exe"), "invoice.pdf.exe");
    assert_eq!(safe_name("report\r\n.doc"), "report.doc");
    assert_eq!(safe_name("a:b*c?.bin"), "abc.bin");
}

#[test]
fn an_ordinary_name_is_left_alone() {
    assert_eq!(safe_name("invoice.pdf"), "invoice.pdf");
    assert_eq!(safe_name("Звіт.docx"), "Звіт.docx");
}
