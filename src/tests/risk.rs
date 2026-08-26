//! How the points add up, and what the analyst is told they were for.

use super::*;
use crate::scoring::Signals;

fn headers(spf: bool, dkim: bool, spoofed: bool) -> Value {
    json!({ "spf_pass": spf, "dkim_pass": dkim, "spoofed": spoofed })
}

fn score_of(v: &Value) -> u64 {
    v["score"].as_u64().unwrap()
}

fn keys_of(v: &Value) -> Vec<String> {
    v["triggers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["key"].as_str().unwrap().to_string())
        .collect()
}

fn calc(h: &Value) -> Value {
    crate::scoring::calculate(h, &Signals::default())
}

#[test]
fn an_authenticated_empty_message_scores_nothing() {
    let v = calc(&headers(true, true, false));
    assert_eq!(score_of(&v), 0);
    assert!(keys_of(&v).is_empty());
}

#[test]
fn each_failed_check_carries_its_own_weight() {
    assert_eq!(score_of(&calc(&headers(false, true, false))), 15);
    assert_eq!(score_of(&calc(&headers(true, false, false))), 15);
    assert_eq!(score_of(&calc(&headers(true, true, true))), 30);
    assert_eq!(score_of(&calc(&headers(false, false, true))), 60);
}

#[test]
fn an_executable_attachment_outweighs_every_header() {
    let clean = headers(true, true, false);
    let v = crate::scoring::calculate(&clean, &Signals { bad_attachments: 1, ..Default::default() });
    assert_eq!(score_of(&v), 40);
    assert_eq!(keys_of(&v), vec!["reasons.atts"]);

    // Two of them are worse than one.
    let v = crate::scoring::calculate(&clean, &Signals { bad_attachments: 2, ..Default::default() });
    assert_eq!(score_of(&v), 80);
}

/// A password beside an archive is the shape of a payload posted past a
/// scanner, and on its own it is enough to condemn the message.
#[test]
fn an_archive_with_its_password_is_decisive() {
    let clean = headers(true, true, false);
    let v = crate::scoring::calculate(
        &clean,
        &Signals { has_archive: true, has_pwd_keyword: true, ..Default::default() },
    );
    assert_eq!(score_of(&v), 100);
    assert!(keys_of(&v).contains(&"reasons.pwd_arc".to_string()));

    // The archive alone is not.
    let v = crate::scoring::calculate(&clean, &Signals { has_archive: true, ..Default::default() });
    assert_eq!(score_of(&v), 0);
}

#[test]
fn the_worst_message_still_scores_one_hundred() {
    let v = crate::scoring::calculate(
        &headers(false, false, true),
        &Signals {
            bad_attachments: 3,
            has_double_ext: true,
            psycho_words: 10,
            html_anomalies: 2,
            has_crypto: true,
            has_archive: true,
            is_encrypted_zip: true,
            has_pwd_keyword: true,
            has_macro: true,
        },
    );
    assert_eq!(score_of(&v), 100, "the score is a percentage, not a tally");
}

/// Every trigger is rendered through the catalog, so a key with no entry
/// would reach the analyst as `reasons.something`.
#[test]
fn every_trigger_names_a_key_the_catalog_defines() {
    let defined = catalog_keys(include_str!("../../locales/en.toml"));
    let v = crate::scoring::calculate(
        &headers(false, false, true),
        &Signals {
            bad_attachments: 2,
            has_double_ext: true,
            psycho_words: 4,
            html_anomalies: 1,
            has_crypto: true,
            has_archive: true,
            is_encrypted_zip: true,
            has_pwd_keyword: true,
            has_macro: true,
        },
    );
    for k in keys_of(&v) {
        assert!(defined.contains(&k), "no catalog entry for {k}");
    }
}
