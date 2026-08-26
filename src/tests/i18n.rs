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

/// The note is the cell an analyst reads to decide what a file is, and it is
/// written by a parser with no locale — so it names a key. Every key it can
/// name must exist in both catalogs, and the two that carry a name found
/// inside the file must keep the `{}` that name is put into.
#[test]
fn every_attachment_note_translates() {
    const NOTES: [&str; 9] = [
        "notes.ok",
        "notes.exe",
        "notes.double_ext",
        "notes.macro_format",
        "notes.legacy_office",
        "notes.enc_zip",
        "notes.macro",
        "notes.hidden",
        "notes.in_archive",
    ];
    for key in NOTES {
        for lang in ["en", "uk"] {
            let said = catalog().tr(lang, key);
            assert_ne!(said, key, "{lang} has no note for {key}");
            let carries_a_name = key.ends_with("hidden") || key.ends_with("in_archive");
            assert_eq!(
                said.contains("{}"),
                carries_a_name,
                "{lang}: {key} = {said:?} — the placeholder is wrong"
            );
        }
    }
}

/// ...and the parser only ever names keys from that list.
#[test]
fn the_parser_names_no_note_the_catalog_lacks() {
    let source = include_str!("../parser.rs");
    let defined = catalog_keys(include_str!("../../locales/en.toml"));
    let mut found = 0;
    for chunk in source.split("\"key\": \"notes.").skip(1) {
        let key = format!("notes.{}", chunk.split('"').next().unwrap_or(""));
        assert!(defined.contains(&key), "parser writes {key}, no catalog entry");
        found += 1;
    }
    assert!(found >= 9, "only found {found} notes in the parser");
}
