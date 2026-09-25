//! Credential phishing: a message with no attachment at all.
//!
//! The fixtures here are a real message, defanged — the one that scored 30/100
//! and read "Low Risk" while being a login page with the recipient's address
//! already in the box. Hosts and addresses are replaced; the shape is not.

use super::*;
use crate::links;

/// Read a message off disk, as the module does. (`parse.rs` keeps its own copy
/// of this; they are two lines and sharing them across test files would mean
/// making them part of the module.)
fn parsed(test: &str, content: &str) -> Value {
    crate::parser::parse(&eml_file(test, content)).unwrap()
}

/// The link out of that message: a reputable outer host, the real destination
/// percent-encoded in its query through a second redirector, and the
/// recipient's address base64 in the fragment where only the landing page can
/// read it. `dHJpYWdlQGV4YW1wbGUub3Jn` is `triage@example.org`.
const CLOAKED: &str = "https://www.tiktok.com/link/v2?aid=1988&scene=bio_url\
&target=mail.qiye.example.cn%2Fapi%2Fj%2Fre%3Fc%3D%2F%2Fportal.example.br/senex/\
#dHJpYWdlQGV4YW1wbGUub3Jn";

/// The message as it arrived: HTML only, no attachment, no authentication
/// results, one button.
fn phish(link: &str) -> String {
    format!(
        "From: ict_access_Mk <poskothr@ministry.example.id>\r\n\
         To: triage@example.org\r\n\
         Subject: Potribne pidtverdzhennia elektronnoi poshty\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         \r\n\
         <div>Користувач: info, Ми виявили помилку у вашій поштовій скриньці \
         triage@example.org. Щоб забезпечити подальше надсилання та отримання \
         електронних листів, будь ласка, підтвердьте свої облікові дані. \
         <a href=\"{link}\">Підтвердити зараз</a></div>\r\n"
    )
}

/// The message that started this: it must not read as low risk.
#[test]
fn the_message_with_no_attachment_is_not_low_risk() {
    let v = parsed("credphish", &phish(CLOAKED));
    assert_eq!(v["attachments"].as_array().unwrap().len(), 0, "nothing is attached");

    let score = v["scoring"]["score"].as_u64().unwrap();
    assert_eq!(score, 100, "it is a credential page, and it scored {score}");

    let triggers = v["scoring"]["triggers"].to_string();
    for key in [
        "reasons.cloaked",
        "reasons.victim_link",
        "reasons.credential",
        "reasons.impersonation",
    ] {
        assert!(triggers.contains(key), "{key} is missing from {triggers}");
    }
}

/// The analyst has to be able to read where the link actually goes — the point
/// of the technique is that the message does not say.
#[test]
fn the_real_destination_is_reported() {
    let v = parsed("credphish_ioc", &phish(CLOAKED));
    let iocs = v["iocs"].to_string();
    assert!(
        iocs.contains("Redirect: portal.example.br/senex/"),
        "the last hop is what the browser lands on: {iocs}"
    );
}

/// A URL lifted out of an `href` used to keep the quote that closed it.
#[test]
fn an_indicator_is_the_url_and_not_its_quote() {
    let v = parsed("quotes", &phish("https://example.org/one"));
    let iocs = v["iocs"].as_array().unwrap().clone();
    let url = iocs
        .iter()
        .filter_map(Value::as_str)
        .find(|s| s.starts_with("URL: "))
        .expect("the link is an indicator");
    assert_eq!(url, "URL: https://example.org/one", "a quote is not part of a URL");
}

// ---- the pieces, each on its own ------------------------------------------ //

#[test]
fn a_redirector_is_followed_to_its_last_hop() {
    assert_eq!(
        links::redirect_target(CLOAKED).as_deref(),
        Some("portal.example.br/senex/#dHJpYWdlQGV4YW1wbGUub3Jn"),
        "two hops, both percent-encoded, no scheme on either"
    );
    // A scheme, spelled out, is the easy case.
    assert_eq!(
        links::redirect_target("https://r.example.com/c?url=https%3A%2F%2Fevil.example.net/login")
            .as_deref(),
        Some("evil.example.net/login")
    );
}

/// An ordinary link carries no second destination, and neither does a tracker
/// whose target is opaque — which is what most legitimate redirectors use.
#[test]
fn an_ordinary_link_is_not_a_redirector() {
    for url in [
        "https://example.org/news/2026/report",
        "https://example.org/a?utm_source=newsletter&utm_campaign=autumn",
        // A tracking link with a hashed target: no host inside it to find.
        "https://click.mailer.example/ss/c/u001.9dKJa7Fj2/3c/xyz",
        // A file name has the same shape as a host and is not one.
        "https://example.org/d?file=invoice.pdf",
        "https://cdn.example.org/assets/logo.png?v=2",
        // The same site's own subdomains are the same organisation.
        "https://example.org/go?to=mail.example.org/inbox",
    ] {
        assert_eq!(links::redirect_target(url), None, "{url} was read as a redirector");
    }
}

/// The recipient's address in the *fragment* is the phishing-kit hallmark;
/// in the query it is how an unsubscribe link works.
#[test]
fn only_the_fragment_counts_as_carrying_the_address() {
    let me = "triage@example.org";
    assert!(links::fragment_carries(CLOAKED, me), "base64 in the fragment");
    assert!(
        links::fragment_carries("https://example.org/login#triage@example.org", me),
        "plain in the fragment"
    );
    assert!(
        links::fragment_carries("https://example.org/l#u=dHJpYWdlQGV4YW1wbGUub3Jn", me),
        "base64 inside a fragment parameter"
    );
    // The query is where a server can act on it: unsubscribe, preferences,
    // a mailing-list confirmation. Ordinary, and not flagged.
    assert!(!links::fragment_carries(
        "https://example.org/unsubscribe?email=triage%40example.org",
        me
    ));
    assert!(!links::fragment_carries("https://example.org/login#section-2", me));
    // Somebody else's address is not the recipient's.
    assert!(!links::fragment_carries("https://example.org/l#other@example.org", me));
}

/// Both halves, or it is ordinary mail.
#[test]
fn asking_for_credentials_takes_a_verb_and_an_object() {
    for text in [
        "будь ласка, підтвердьте свої облікові дані",
        "Потрібне підтвердження електронної пошти",
        "Please confirm your account to continue",
        "Verify your mailbox password",
    ] {
        assert!(links::asks_for_credentials(text), "{text}");
    }
    for text in [
        // A confirmation of something that is not an account.
        "Please confirm you can attend on Thursday",
        "Підтвердьте, будь ласка, отримання документів",
        // An account mentioned without being asked for.
        "Your account was charged 12.00 EUR this morning",
        "See you at one. The place on 5th.",
    ] {
        assert!(!links::asks_for_credentials(text), "{text} is ordinary mail");
    }
}

/// A message about your own mail domain, sent from somewhere else.
#[test]
fn a_notice_about_your_mailbox_comes_from_your_own_domain() {
    // The real one: from an unrelated ministry, about the reader's mailbox.
    let v = parsed("imperson", &phish(CLOAKED));
    assert!(v["scoring"]["triggers"].to_string().contains("reasons.impersonation"));

    // The same message from the domain that actually runs the mailbox is not
    // impersonating anybody — its own IT department writes like this.
    let internal = phish(CLOAKED).replace("ministry.example.id", "example.org");
    let v = parsed("internal", &internal);
    assert!(
        !v["scoring"]["triggers"].to_string().contains("reasons.impersonation"),
        "mail from your own domain about your own mailbox is not impersonation"
    );
}

/// None of this may make ordinary mail suspicious.
#[test]
fn a_benign_message_is_untouched_by_any_of_it() {
    let v = parsed("still_benign", BENIGN);
    assert!(v["scoring"]["score"].as_u64().unwrap() <= 30);
    let triggers = v["scoring"]["triggers"].to_string();
    for key in ["cloaked", "victim_link", "credential", "impersonation"] {
        assert!(!triggers.contains(key), "{key} fired on a benign message");
    }
}

/// Asking about a password with nowhere to type it is a notice, not an attack —
/// the score for it needs a link in the message.
#[test]
fn credential_wording_alone_is_not_scored() {
    let text = BENIGN.replace(
        "See you at one. The place on 5th.",
        "Your mailbox password was changed. Confirm your account if this was not you.",
    );
    let v = parsed("nolink", &text);
    assert!(
        !v["scoring"]["triggers"].to_string().contains("reasons.credential"),
        "there is nowhere to type it"
    );
}

/// A host is its organisation, and two-label registries are not organisations.
#[test]
fn the_same_organisation_is_recognised_across_subdomains() {
    assert_eq!(links::registrable("mail.example.org"), "example.org");
    assert_eq!(links::registrable("mx1.mk.gov.ua"), "mk.gov.ua");
    assert_eq!(links::registrable("zmta4.kemnaker.go.id"), "kemnaker.go.id");
    assert_eq!(links::registrable("portal.example.co.uk"), "example.co.uk");
    assert_ne!(links::registrable("mk.gov.ua"), links::registrable("kemnaker.go.id"));
}

/// A domain sitting in the part before the `@`.
///
/// `cert.gov.ua@notify-secure.example` reads as `cert.gov.ua` at a glance, in a
/// mail client that shows the display name and truncates the rest. The domain
/// is there to be misread; the part that says who sent it is the part that gets
/// cut off.
#[test]
fn a_domain_before_the_at_sign_is_not_a_name() {
    for address in [
        "cert.gov.ua@notify-secure.example",
        "mk.gov.ua@gmail.example",
        "\"Support\" <support.microsoft.com@mail.example.ru>",
        "billing.com@invoices.example",
        "privat24.com.ua@secure-login.example",
    ] {
        assert!(links::domain_in_local_part(address), "{address}");
    }
}

/// And a name that merely has a dot in it is a name.
///
/// This is where a rule like this goes wrong: `van.de.berg` is a surname,
/// `anna.it` is a person, `o.brien` is most of Ireland. Only the labels that are
/// never anybody's name count — com, net, org, gov, edu, mil — or a full
/// two-label suffix, which is a domain and nothing else.
#[test]
fn an_ordinary_name_with_a_dot_is_left_alone() {
    for address in [
        "john.smith@example.org",
        "Anna Boyko <anna.boyko@example.org>",
        "o.brien@example.org",
        "van.de.berg@example.nl",
        "anna.it@example.org",
        "v.petrenko@example.ua",
        "info.desk@example.org",
        "no-reply@example.org",
        // The whole trick inverted: an ordinary mailbox at a government domain
        // is not suspicious, it is the thing being impersonated.
        "cert@cert.gov.ua",
        // `gov` as a mailbox name on its own is a role, not a hidden domain.
        "gov@example.org",
    ] {
        assert!(!links::domain_in_local_part(address), "{address} is an ordinary address");
    }
}

/// It is read off the message, and off the reply address too — an answer goes
/// where Reply-To says, not where From does.
#[test]
fn the_hidden_domain_is_scored_from_the_headers() {
    let msg = String::from(
        "From: \"CERT-UA\" <cert.gov.ua@notify-secure.example>\r\n\
         To: triage@example.org\r\n\
         Subject: Notice\r\n\
         Authentication-Results: mx.example.org; spf=pass; dkim=pass; dmarc=pass\r\n\
         Content-Type: text/plain\r\n\
         \r\n\
         Please read the attached notice.\r\n",
    );
    let v = parsed("localpart", &msg);
    let triggers = v["scoring"]["triggers"].to_string();
    assert!(triggers.contains("reasons.local_part_domain"), "{triggers}");

    // The same message from an ordinary address trips nothing.
    let clean = msg.replace("cert.gov.ua@notify-secure.example", "cert@cert.gov.ua");
    let v = parsed("localpart_ok", &clean);
    assert!(
        !v["scoring"]["triggers"].to_string().contains("local_part_domain"),
        "an ordinary address was flagged"
    );
    assert_eq!(v["scoring"]["score"], json!(0), "and it scores nothing at all");
}
