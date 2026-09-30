//! What goes to a report provider, and when the action is offered at all.

use super::*;

/// The button appears only while something provides `report.build` — a button
/// that calls a capability nobody provides is one that answers with an error.
#[test]
fn the_action_is_offered_only_with_a_provider() {
    let a = scanned("report_btn", BENIGN);
    assert!(!a.render_dashboard(false, false, "en").to_string().contains("make_report"));
    assert!(a.render_dashboard(false, true, "en").to_string().contains("make_report"));
}

/// Nothing analysed is not an empty report.
#[test]
fn nothing_analysed_produces_no_spec() {
    assert!(EmlAnalyzer::default().report_spec("en").is_none());
}

/// The document is the message as this module read it: the verdict and what
/// produced it, who it claims to be from and whether that was authenticated,
/// every attachment with its hash, and every indicator. It is what gets
/// attached to a ticket, so nothing is left for the reader to come back for.
#[test]
fn the_report_carries_the_whole_analysis() {
    let a = scanned(
        "report_full",
        &with_attachment("invoice.pdf.exe", b"MZ", "spf=fail; dkim=fail"),
    );
    let spec = a.report_spec("en").expect("a scan produces a spec");

    // Filed under the message's own hash: two copies of one phishing run share
    // a subject and differ in nothing a filename would show.
    let name = spec["file_name"].as_str().unwrap();
    let hash = a.last_scan["eml_hash"].as_str().unwrap();
    assert!(name.starts_with("eml_"), "{name}");
    assert!(hash.starts_with(&name["eml_".len()..]), "{name} is not the hash");

    let text = spec.to_string();
    // The verdict, and the count of each kind of evidence.
    assert!(text.contains("/100"), "{text}");
    assert!(text.contains("High Risk"), "a double extension is not low risk");

    let headings: Vec<&str> = spec["sections"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["heading"].as_str().unwrap())
        .collect();
    assert!(headings.contains(&"Headers & Auth"), "{headings:?}");
    assert!(headings.contains(&"Risk Triggers"), "{headings:?}");
    assert!(headings.contains(&"Attachments"), "{headings:?}");

    // The attachment travels with its hash — the one thing a reader looks up.
    let atts = spec["sections"].as_array().unwrap()
        .iter().find(|s| s["heading"] == "Attachments").unwrap();
    let row = &atts["rows"][0];
    assert_eq!(row[0], "invoice.pdf.exe");
    assert_eq!(row[2].as_str().unwrap().len(), 32, "an md5");
    assert!(row[3].as_str().unwrap().contains("Double extension"), "{row}");

    // Authentication is reported as words, not as true/false.
    let hdr = spec["sections"].as_array().unwrap()
        .iter().find(|s| s["heading"] == "Headers & Auth").unwrap();
    let flags = hdr["rows"].to_string();
    assert!(flags.contains("fail"), "{flags}");
    assert!(!flags.contains("false"), "{flags}");
}

/// Worst first: the order somebody reads a verdict in.
#[test]
fn the_reasons_are_ordered_by_what_they_cost() {
    let a = scanned(
        "report_order",
        &with_attachment("report.docm", b"PK\x03\x04", "spf=fail"),
    );
    let spec = a.report_spec("en").unwrap();
    let triggers = spec["sections"].as_array().unwrap()
        .iter().find(|s| s["heading"] == "Risk Triggers").expect("reasons");
    let points: Vec<u64> = triggers["rows"].as_array().unwrap()
        .iter()
        .map(|r| r[0].as_str().unwrap().trim_start_matches('+').parse().unwrap())
        .collect();
    assert!(points.len() >= 2, "{points:?}");
    assert!(points.windows(2).all(|w| w[0] >= w[1]), "{points:?}");
}

/// A message with no attachments and no indicators still reports — with the
/// sections it has, and none it does not.
#[test]
fn a_clean_message_reports_what_there_is() {
    let a = scanned("report_clean", BENIGN);
    let spec = a.report_spec("en").unwrap();
    let headings: Vec<&str> = spec["sections"].as_array().unwrap()
        .iter().map(|s| s["heading"].as_str().unwrap()).collect();
    assert!(headings.contains(&"Headers & Auth"));
    assert!(!headings.contains(&"Attachments"), "{headings:?}");
    assert!(spec["summary"].to_string().contains("Low Risk"));
}

/// The report is written in the language on screen, headings and reasons alike.
#[test]
fn the_report_follows_the_language() {
    let a = scanned("report_uk", &with_attachment("x.exe", b"MZ", "spf=fail"));
    let uk = a.report_spec("uk").unwrap().to_string();
    assert!(uk.contains("Звіт про аналіз EML"), "the title");
    assert!(uk.contains("Заголовки"), "a section heading");
    // A reason is a catalog key until it is rendered; it must not reach the
    // document as one.
    assert!(!uk.contains("reasons."), "{uk}");
}

/// Every string the report asks for exists in both catalogs.
#[test]
fn the_report_strings_are_translated() {
    for lang in ["en", "uk"] {
        for key in [
            "ui.report", "report.title", "report.field", "report.value", "report.points",
            "report.reason", "report.reply_to", "report.to", "report.hash", "report.pass",
            "report.fail", "report.written", "report.failed",
        ] {
            assert_ne!(catalog().tr(lang, key), key, "{lang}: {key}");
        }
    }
}

/// A summary line carries one colon, whatever the label was written with.
///
/// Several of these names are the dashboard's, where they are written with
/// their own — `From:`. Left in, the line reads `From:: someone`, and a report
/// that splits it at the first colon prints a value beginning with the second.
#[test]
fn a_figure_has_exactly_one_colon() {
    assert_eq!(figure("From:", "a@b.test"), "From: a@b.test");
    assert_eq!(figure("From", "a@b.test"), "From: a@b.test");
    assert_eq!(figure("Subject :", "Hello"), "Subject: Hello");

    let a = scanned("report_colon", BENIGN);
    for line in a.report_spec("en").unwrap()["summary"].as_array().unwrap() {
        let line = line.as_str().unwrap();
        let (_, value) = line.split_once(':').expect("name: value");
        assert!(!value.trim_start().starts_with(':'), "{line}");
    }
}
