//! How the points add up, and what the analyst is told they were for.

use super::*;

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
    crate::scoring::calculate(h, 0, false, 0, 0, false, false, false, false, false)
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
    let v = crate::scoring::calculate(&clean, 1, false, 0, 0, false, false, false, false, false);
    assert_eq!(score_of(&v), 40);
    assert_eq!(keys_of(&v), vec!["reasons.atts"]);

    // Two of them are worse than one.
    let v = crate::scoring::calculate(&clean, 2, false, 0, 0, false, false, false, false, false);
    assert_eq!(score_of(&v), 80);
}

/// A password beside an archive is the shape of a payload posted past a
/// scanner, and on its own it is enough to condemn the message.
#[test]
fn an_archive_with_its_password_is_decisive() {
    let clean = headers(true, true, false);
    let v = crate::scoring::calculate(&clean, 0, false, 0, 0, false, true, false, true, false);
    assert_eq!(score_of(&v), 100);
    assert!(keys_of(&v).contains(&"reasons.pwd_arc".to_string()));

    // The archive alone is not.
    let v = crate::scoring::calculate(&clean, 0, false, 0, 0, false, true, false, false, false);
    assert_eq!(score_of(&v), 0);
}

#[test]
fn the_worst_message_still_scores_one_hundred() {
    let v = crate::scoring::calculate(
        &headers(false, false, true), 3, true, 10, 2, true, true, true, true, true,
    );
    assert_eq!(score_of(&v), 100, "the score is a percentage, not a tally");
}

/// Every trigger is rendered through the catalog, so a key with no entry
/// would reach the analyst as `reasons.something`.
#[test]
fn every_trigger_names_a_key_the_catalog_defines() {
    let defined = catalog_keys(include_str!("../../locales/en.toml"));
    let v = crate::scoring::calculate(
        &headers(false, false, true), 2, true, 4, 1, true, true, true, true, true,
    );
    for k in keys_of(&v) {
        assert!(defined.contains(&k), "no catalog entry for {k}");
    }
}
