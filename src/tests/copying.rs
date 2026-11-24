//! Taking an indicator somewhere else: what is copied, and what is offered.

use super::*;

/// The list labels each indicator so it reads at a glance; what goes into a
/// search box is the value alone.
#[test]
fn what_is_copied_is_the_value_without_its_label() {
    assert_eq!(ioc::parts("URL: https://evil.test/a?b=c"), ("URL", "https://evil.test/a?b=c"));
    assert_eq!(ioc::parts("IP: 10.0.0.7"), ("IP", "10.0.0.7"));
    // A value with the separator inside it is still one value.
    assert_eq!(ioc::parts("Redirect: https://evil.test/?next=a: b"), ("Redirect", "https://evil.test/?next=a: b"));
    assert_eq!(ioc::parts("no label at all"), ("", "no label at all"));
}

/// Defanged, a link is not one any more — wherever it is pasted — and is still
/// the same thing to search for.
#[test]
fn a_defanged_indicator_is_no_longer_a_link() {
    for (ioc, safe) in [
        ("URL: https://firebasestorage.googleapis.com/v0/b/x.appspot.com/o/a.html?alt=media",
         "hxxps://firebasestorage[.]googleapis[.]com/v0/b/x.appspot.com/o/a.html?alt=media"),
        ("URL: http://evil.test", "hxxp://evil[.]test"),
        ("URL: HTTP://Evil.Test/Pay", "hxxp://Evil[.]Test/Pay"),
        ("URL: https://evil.test?x=1.2", "hxxps://evil[.]test?x=1.2"),
        ("Redirect: https://second.evil.test/landing", "hxxps://second[.]evil[.]test/landing"),
        ("Redirect: evil.test/landing.php", "evil[.]test/landing.php"),
        ("IP: 10.0.0.7", "10[.]0[.]0[.]7"),
        ("Email: collector@evil.test", "collector[@]evil[.]test"),
    ] {
        assert_eq!(ioc::defanged(ioc), safe, "{ioc}");
        assert!(!ioc::defanged(ioc).contains("http"), "{ioc}");
    }
}

/// A wallet address was never a link: there is nothing to take out of it.
#[test]
fn a_wallet_address_is_left_as_it_is() {
    for ioc in [
        "BTC: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
        "ETH: 0x52908400098527886E0F7030069857D2E4169EE7",
    ] {
        assert_eq!(ioc::defanged(ioc), ioc::parts(ioc).1);
    }
}

const BODY: &str = "From: a@example.org\r\nTo: b@example.org\r\nSubject: Pay\r\n\
Content-Type: text/plain\r\n\r\n\
visit http://evil.test/pay and pay to 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2\r\n";

/// One row's menu, as the host is sent it.
fn menu_of<'a>(view: &'a Value, indicator: &str) -> Vec<&'a Value> {
    let table = view["widgets"]
        .as_array()
        .and_then(|w| w.iter().find(|w| w["kind"] == "table"))
        .expect("the indicators are a table");
    let row = table["rows"]
        .as_array()
        .and_then(|rows| rows.iter().position(|r| r[0].as_str().is_some_and(|s| s.starts_with(indicator))))
        .unwrap_or_else(|| panic!("no {indicator} row in {table}"));
    table["row_menus"][row].as_array().expect("a menu per row").iter().collect()
}

fn labels(menu: &[&Value]) -> Vec<String> {
    menu.iter().map(|m| m["label"].as_str().unwrap_or("").to_string()).collect()
}

/// A right click on an indicator always has something to offer — it did not,
/// unless a reputation provider happened to be installed.
#[test]
fn every_indicator_can_be_copied_with_or_without_a_reputation_provider() {
    let a = scanned("copy_menu", BODY);
    for (lang, copy, defanged) in [("en", "Copy", "Copy defanged"), ("uk", "Копіювати", "Копіювати знешкодженим")] {
        let view = a.view_iocs(false, lang);
        let url = menu_of(&view, "URL: ");
        assert_eq!(labels(&url), [copy, defanged], "{lang}");
        assert_eq!(url[0]["action"], json!({ "capability": "eml.triage", "method": "copy_ioc" }));
        assert!(url[0].get("args").is_none(), "plain copy asks for nothing more");
        assert_eq!(url[1]["args"], json!({ "defang": true }));
        // Nothing to defang in a wallet address, so it is not offered.
        assert_eq!(labels(&menu_of(&view, "BTC: ")), [copy], "{lang}");
    }
}

/// With a provider, its check is there as before — after the copies.
#[test]
fn the_reputation_check_is_still_offered_when_there_is_a_provider() {
    let a = scanned("copy_menu_osint", BODY);
    let view = a.view_iocs(true, "en");
    assert_eq!(labels(&menu_of(&view, "URL: ")), ["Copy", "Copy defanged", "Check OSINT"]);
    assert_eq!(labels(&menu_of(&view, "BTC: ")), ["Copy", "Check OSINT"]);
}
