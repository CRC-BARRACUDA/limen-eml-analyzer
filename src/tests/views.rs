//! What the analyst is shown — including before there is anything to show.

use super::*;

fn text_of(v: &Value) -> String {
    v.to_string()
}

/// The regression that matters most. Every view below the summary reads state
/// that only a scan produces, and a panic here cannot unwind out of the
/// `extern "C"` entry point: it would abort the host process, every other tab
/// with it. Reaching any of them cold must produce a view instead.
#[test]
fn no_view_panics_before_a_scan() {
    let a = EmlAnalyzer::default();
    for lang in ["en", "uk"] {
        for v in [
            a.idle_view(lang),
            a.no_scan_view(lang),
            a.render_simple_summary(lang),
            a.render_dashboard(false, lang),
            a.render_dashboard(true, lang),
            a.view_iocs(false, lang),
            a.view_atts(false, lang),
        ] {
            assert!(v.get("title").is_some(), "{lang}: not a window: {v}");
        }
    }
}

/// A dead end is only fair if it is also the way out.
#[test]
fn the_cold_dashboard_asks_for_a_file() {
    let v = EmlAnalyzer::default().render_dashboard(false, "en");
    let s = text_of(&v);
    assert!(s.contains(&catalog().tr("en", "errors.no_scan")), "{s}");
    assert!(s.contains("\"kind\":\"file\""), "the picker is on the screen: {s}");
    assert!(s.contains("\"method\":\"scan\""), "and so is the button: {s}");
}

#[test]
fn a_scanned_message_reaches_the_dashboard() {
    let a = scanned("view_dash", &with_attachment("setup.exe", b"MZ", "spf=fail; dkim=fail"));
    let s = text_of(&a.render_dashboard(false, "en"));
    assert!(s.contains("100/100"), "{s}");
    assert!(s.contains("reasons.atts") || s.contains("Suspicious/executable"), "{s}");
    assert!(s.contains("Invoice"), "the subject is on the screen: {s}");
}

#[test]
fn the_attachment_table_offers_to_save_each_row() {
    let a = scanned("view_atts", &with_attachment("setup.exe", b"MZ", "spf=pass; dkim=pass"));
    let s = text_of(&a.view_atts(false, "en"));
    assert!(s.contains("setup.exe"), "{s}");
    assert!(s.contains("\"method\":\"save_file\""), "{s}");
    assert!(s.contains("\"row_ids\":[\"0\"]"), "the row carries the id save_file expects: {s}");
}

#[test]
fn an_empty_body_says_so_rather_than_showing_an_empty_table() {
    let a = scanned("view_iocs", BENIGN);
    let s = text_of(&a.view_iocs(false, "en"));
    assert!(s.contains(&catalog().tr("en", "iocs.empty")), "{s}");
}

/// The reputation entry leads to a capability that may not be loaded; offering
/// it anyway would produce a menu item that answers with nothing.
#[test]
fn osint_is_offered_only_when_a_provider_is_there() {
    let a = scanned("view_osint", &with_attachment("setup.exe", b"MZ", "spf=pass; dkim=pass"));
    // The attachment menu routes through the module, which calls the provider.
    assert!(!text_of(&a.view_atts(false, "en")).contains("check_reputation"));
    assert!(text_of(&a.view_atts(true, "en")).contains("check_reputation"));
    // The indicator table hands the row straight to the provider — and only
    // exists when the body yielded something to look up.
    let b = scanned(
        "view_osint_iocs",
        &BENIGN.replace("The place on 5th.", "pay at http://evil.test/x"),
    );
    assert!(!text_of(&b.view_iocs(false, "en")).contains("osint.reputation"));
    assert!(text_of(&b.view_iocs(true, "en")).contains("osint.reputation"));
}
