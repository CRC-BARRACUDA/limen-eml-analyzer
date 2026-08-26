//! What the headers admit about who sent the message.

use super::*;
use mailparse::parse_mail;

fn analyzed(raw: &str) -> Value {
    crate::headers::analyze(&parse_mail(raw.as_bytes()).unwrap())
}

#[test]
fn a_passing_message_passes_all_three() {
    let h = analyzed(BENIGN);
    for k in ["spf_pass", "dkim_pass", "dmarc_pass"] {
        assert_eq!(h[k], json!(true), "{k}");
    }
    assert_eq!(h["spoofed"], json!(false));
    assert_eq!(h["subject"], json!("Lunch on Thursday"));
}

/// Absent is not the same as passing: a message with no Authentication-Results
/// header at all must not be read as authenticated.
#[test]
fn no_auth_header_is_not_a_pass() {
    let h = analyzed("From: a@b.c\r\nSubject: x\r\n\r\nbody\r\n");
    for k in ["spf_pass", "dkim_pass", "dmarc_pass"] {
        assert_eq!(h[k], json!(false), "{k}");
    }
}

#[test]
fn a_failing_result_is_read_as_failing() {
    let raw = "From: a@b.c\r\nAuthentication-Results: mx; spf=fail; dkim=none; dmarc=fail\r\n\r\nx\r\n";
    let h = analyzed(raw);
    for k in ["spf_pass", "dkim_pass", "dmarc_pass"] {
        assert_eq!(h[k], json!(false), "{k}");
    }
}

/// A reply that goes somewhere other than the sender is the oldest trick in
/// the trade, and the one the score weighs heaviest.
#[test]
fn a_reply_to_elsewhere_is_spoofing() {
    let raw = "From: Billing <billing@bank.example>\r\nReply-To: collector@evil.test\r\n\r\nx\r\n";
    assert_eq!(analyzed(raw)["spoofed"], json!(true));
}

#[test]
fn a_reply_to_the_sender_is_not() {
    let raw = "From: Billing <billing@bank.example>\r\nReply-To: billing@bank.example\r\n\r\nx\r\n";
    assert_eq!(analyzed(raw)["spoofed"], json!(false));
    // ...and neither is having none at all.
    assert_eq!(analyzed(BENIGN)["spoofed"], json!(false));
}
