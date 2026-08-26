//! Both languages say the same things, and neither leaks the other.

use super::*;

#[test]
fn ukrainian_covers_every_english_key() {
    let en = catalog_keys(include_str!("../../locales/en.toml"));
    let uk = catalog_keys(include_str!("../../locales/uk.toml"));
    let missing: Vec<&String> = en.iter().filter(|k| !uk.contains(k)).collect();
    assert!(missing.is_empty(), "Ukrainian is missing: {missing:?}");

    let extra: Vec<&String> = uk.iter().filter(|k| !en.contains(k)).collect();
    assert!(extra.is_empty(), "Ukrainian defines what English does not: {extra:?}");
}

/// A key that resolves to itself is in no catalog at all — the fallback chain
/// is lang -> en -> the key, so that is how a typo surfaces.
#[test]
fn no_rendered_key_falls_through_to_itself() {
    let keys = catalog_keys(include_str!("../../locales/en.toml"));
    let a = scanned("i18n", &with_attachment("setup.exe", b"MZ", "spf=fail; dkim=fail"));
    let cold = EmlAnalyzer::default();
    for lang in ["en", "uk"] {
        for v in [
            a.idle_view(lang),
            a.render_simple_summary(lang),
            a.render_dashboard(true, lang),
            a.view_iocs(true, lang),
            a.view_atts(true, lang),
            cold.no_scan_view(lang),
        ] {
            let s = v.to_string();
            for k in &keys {
                assert!(
                    !s.contains(&format!(":\"{k}\"")),
                    "{lang}: key rendered instead of its translation: {k}"
                );
            }
        }
    }
}

/// Every reason the score can name is a key, resolved when the dashboard is
/// drawn rather than at the moment it is scored — so a missing translation
/// only shows up here.
#[test]
fn every_reason_translates_in_both_languages() {
    for k in catalog_keys(include_str!("../../locales/en.toml"))
        .iter()
        .filter(|k| k.starts_with("reasons."))
    {
        for lang in ["en", "uk"] {
            let s = catalog().tr(lang, k);
            assert_ne!(&s, k, "{lang} has no translation for {k}");
            assert!(!s.is_empty());
        }
    }
}

/// The two strings the save path added — a cancelled dialog and an empty
/// analyzer — are as much a part of the interface as the views are.
#[test]
fn the_save_path_speaks_both_languages() {
    for k in ["errors.no_scan", "errors.fs_cancelled", "errors.fs_success"] {
        for lang in ["en", "uk"] {
            assert_ne!(catalog().tr(lang, k), k, "{lang}: {k}");
        }
    }
    assert_ne!(catalog().tr("uk", "errors.no_scan"), catalog().tr("en", "errors.no_scan"));
}
