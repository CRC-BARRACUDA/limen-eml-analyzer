//! What is pulled out of the body: addresses to pivot on, and the pressure
//! the message applies.

#[test]
fn every_kind_of_indicator_is_labelled() {
    let text = "call 10.0.0.7 or visit http://evil.test/pay now, mail us at \
                collector@evil.test, pay to 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
    let found = crate::ioc::extract(text);
    assert!(found.contains(&"IP: 10.0.0.7".to_string()), "{found:?}");
    assert!(found.contains(&"URL: http://evil.test/pay".to_string()), "{found:?}");
    assert!(found.contains(&"Email: collector@evil.test".to_string()), "{found:?}");
    assert!(
        found.iter().any(|i| i.starts_with("BTC: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")),
        "{found:?}"
    );
}

/// The same address twice is one indicator. An analyst pivots on each once.
#[test]
fn repeats_collapse_and_the_list_is_ordered() {
    let found = crate::ioc::extract("10.0.0.7 and 10.0.0.7 and 10.0.0.7");
    assert_eq!(found, vec!["IP: 10.0.0.7".to_string()]);

    let mut sorted = crate::ioc::extract("zz@b.com http://a.test 10.0.0.7");
    let expected = sorted.clone();
    sorted.sort();
    assert_eq!(sorted, expected, "extract must return them sorted");
}

#[test]
fn ordinary_prose_yields_nothing() {
    assert!(crate::ioc::extract("See you at one. The place on 5th.").is_empty());
}

#[test]
fn urgency_is_counted_and_a_password_is_noticed() {
    let (count, pwd) = crate::ioc::count_psycho_words("ТЕРМІНОВО: штраф за заборгованість");
    assert!(count >= 3, "counted {count}");
    assert!(!pwd);

    let (_, pwd) = crate::ioc::count_psycho_words("архів, пароль: 1234");
    assert!(pwd, "a password in the body is what makes an archive worth 100");

    let (count, pwd) = crate::ioc::count_psycho_words("See you at one.");
    assert_eq!((count, pwd), (0, false));
}

#[test]
fn text_hidden_from_the_reader_is_an_anomaly() {
    assert_eq!(crate::ioc::check_html_anomalies("<p style=\"display:none\">x</p>"), 1);
    assert_eq!(crate::ioc::check_html_anomalies("<span style=\"font-size: 0\">x</span>"), 1);
    assert_eq!(crate::ioc::check_html_anomalies("<p>an ordinary paragraph</p>"), 0);
}

/// A link that reads as one place and goes to another is the whole mechanism
/// of a phishing message.
#[test]
fn a_link_that_lies_about_where_it_goes_is_an_anomaly() {
    let lying = "<a href=\"http://evil.test/x\">http://bank.example/login</a>";
    assert_eq!(crate::ioc::check_html_anomalies(lying), 1);

    let honest = "<a href=\"http://bank.example/login\">http://bank.example/login</a>";
    assert_eq!(crate::ioc::check_html_anomalies(honest), 0);
}
