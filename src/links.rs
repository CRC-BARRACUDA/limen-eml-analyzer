//! What a link is really for.
//!
//! Attachments are only half of phishing, and the smaller half. A message with
//! no files at all — one link, one sentence — is the shape most credential theft
//! takes now, and nothing in `parser` could see it: the link's host was
//! `tiktok.com`, the text was polite, and the score came from the missing SPF
//! header alone.
//!
//! What is read here is where a link **goes**, what it **carries**, and whether
//! the message is asking for a password in the first place.

use base64::Engine as _;
use regex::Regex;

/// Every `href` in a chunk of HTML, in the order they appear.
pub fn hrefs(html: &str) -> Vec<String> {
    let Ok(re) = Regex::new(r#"(?i)href\s*=\s*["']([^"']+)["']"#) else {
        return Vec::new();
    };
    re.captures_iter(html)
        .map(|c| c[1].trim().to_string())
        .filter(|u| u.starts_with("http://") || u.starts_with("https://"))
        .collect()
}

/// Where a link that carries another link inside it actually ends up.
///
/// An open redirector is the current way past every "is this domain
/// reputable" check there is: the href is `tiktok.com`, and the destination is
/// spelled out in its query string — often through a second redirector, and
/// often without a scheme, as a bare host or a protocol-relative `//host/path`.
///
/// Returns the **deepest** host found, which is the one the browser stops at.
/// `None` when the link carries no other host, which is what an ordinary link
/// looks like.
pub fn redirect_target(url: &str) -> Option<String> {
    let (head, tail) = url.split_once(['?', '#'])?;
    let outer = registrable(host_of(head)?);
    // Redirectors chain, and each hop encodes the next, so one decode is rarely
    // enough. Three is past anything seen in the wild and terminates whatever
    // happens.
    let mut decoded = tail.to_string();
    for _ in 0..3 {
        let next = percent_decode(&decoded);
        if next == decoded {
            break;
        }
        decoded = next;
    }
    // Hosts only. Matching a path here as well would let the first host swallow
    // the rest of the string — including the second redirector inside it, which
    // is the hop that matters.
    let re = Regex::new(r"(?i)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9-]+)*\.([a-z]{2,24})").ok()?;
    let mut deepest: Option<usize> = None;
    for cap in re.captures_iter(&decoded) {
        let whole = cap.get(0).unwrap();
        // A file name is not a host. `report.pdf` and `logo.png` match the same
        // shape, and treating one as a destination would flag every newsletter.
        if NOT_A_TLD.contains(&&*cap[1].to_ascii_lowercase()) {
            continue;
        }
        if registrable(whole.as_str()) == outer {
            continue;
        }
        deepest = Some(whole.start());
    }
    // From the last host to the end of the value it sits in: that is the URL
    // the browser is left holding.
    let start = deepest?;
    let tail = &decoded[start..];
    let end = tail
        .find(|c: char| c == '&' || c.is_whitespace() || c == '"' || c == '\'')
        .unwrap_or(tail.len());
    // Kept as written: a host is case-insensitive but a path and a fragment are
    // not, and the fragment is often base64 — lowercased, it stops decoding.
    Some(tail[..end].to_string())
}

/// Whether this link carries `address` in its **fragment** — the part after
/// `#`, which never reaches the server.
///
/// A phishing kit puts the victim's address there so the login form it serves
/// opens already filled in with it; base64 as often as not, so that a glance at
/// the link shows nothing. There is no ordinary reason for a link in mail to
/// carry the recipient's own address where only the page's own script can read
/// it — an unsubscribe link puts it in the query, where the server can act on
/// it, which is why only the fragment is read here.
pub fn fragment_carries(url: &str, address: &str) -> bool {
    if address.is_empty() {
        return false;
    }
    let Some((_, fragment)) = url.split_once('#') else {
        return false;
    };
    let address = address.to_ascii_lowercase();
    let fragment = percent_decode(fragment);
    if fragment.to_ascii_lowercase().contains(&address) {
        return true;
    }
    // Anything base64-shaped in there, in either alphabet and padded or not.
    let Ok(re) = Regex::new(r"[A-Za-z0-9+/_-]{12,}={0,2}") else {
        return false;
    };
    for token in re.find_iter(&fragment) {
        for engine in [
            &base64::engine::general_purpose::STANDARD_NO_PAD,
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        ] {
            let trimmed = token.as_str().trim_end_matches('=');
            if let Ok(bytes) = engine.decode(trimmed) {
                if String::from_utf8_lossy(&bytes).to_ascii_lowercase().contains(&address) {
                    return true;
                }
            }
        }
    }
    false
}

/// Whether the message is asking the reader to hand over an account.
///
/// Both halves are required — a word of confirmation *and* the thing being
/// confirmed — because either alone is ordinary. "Please confirm" is how
/// meetings are arranged, and "your account" appears in every receipt ever
/// sent; "confirm your account details" is not a sentence a real mail system
/// writes to you.
pub fn asks_for_credentials(text: &str) -> bool {
    let lower = text.to_lowercase();
    const ASKS: [&str; 14] = [
        "підтверд", "перевірте", "оновіть", "відновіть", "авторизуйтеся",
        "подтверд", "проверьте", "обновите",
        "confirm", "verify", "validate", "reactivate", "re-activate", "sign in",
    ];
    const WHAT: [&str; 14] = [
        "облікові дані", "облікових даних", "обліковий запис", "облікового запису",
        "пошт", "пароль", "скриньк",
        "учетн", "почтов",
        "account", "credential", "password", "mailbox", "e-mail address",
    ];
    ASKS.iter().any(|w| lower.contains(w)) && WHAT.iter().any(|w| lower.contains(w))
}

/// The address a message was sent to, as a bare `user@host`.
pub fn bare_address(header: &str) -> String {
    let inner = match (header.find('<'), header.find('>')) {
        (Some(a), Some(b)) if b > a => &header[a + 1..b],
        _ => header,
    };
    inner.trim().to_ascii_lowercase()
}

/// Whether an address hides a domain in the part **before** the `@`.
///
/// `cert.gov.ua@notify-secure.example` reads, at a glance and in a narrow
/// column, as `cert.gov.ua` — the domain is right there in the text, and the
/// part that says who actually sent it is the part nobody reads. The local part
/// of a real address is a person or a role; it is not a domain, and a domain
/// sitting in it is there to be misread.
///
/// Only the endings that are never anybody's name count. `com`, `net`, `org`,
/// `gov`, `edu` and `mil` do not appear in `john.smith` or `o.brien`, while
/// country codes do — `van.de.berg` is a surname and `anna.it` is a person, so
/// a bare country code is not enough on its own. It has to arrive as a full
/// two-label suffix: `mk.gov.ua`, `example.co.uk`.
pub fn domain_in_local_part(address: &str) -> bool {
    let local = match bare_address(address).split_once('@') {
        Some((l, _)) => l.to_ascii_lowercase(),
        None => return false,
    };
    if !local.contains('.') {
        return false;
    }
    const NEVER_A_NAME: [&str; 6] = ["com", "net", "org", "gov", "edu", "mil"];
    let labels: Vec<&str> = local.split('.').collect();
    // Not the first label: `gov.example` is the trick, `gov` alone is a mailbox
    // name a ministry might really use.
    if labels[1..].iter().any(|l| NEVER_A_NAME.contains(l)) {
        return true;
    }
    // Or a full two-label suffix at the end, which is a domain and nothing else.
    labels.len() > 2 && TWO_LABEL.contains(&&*labels[labels.len() - 2..].join("."))
}

/// The domain part of an address, or "" if there is none.
pub fn domain_of(address: &str) -> &str {
    address.split_once('@').map_or("", |(_, d)| d)
}

/// `mail.example.co.uk` → `example.co.uk`; good enough to tell "the same
/// organisation" from "somebody else", which is all it is used for.
pub fn registrable(host: &str) -> String {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let parts: Vec<&str> = host.split('.').collect();
    let n = parts.len();
    if n < 2 {
        return host;
    }
    let last_two = parts[n - 2..].join(".");
    if n >= 3 && TWO_LABEL.contains(&&*last_two) {
        return parts[n - 3..].join(".");
    }
    last_two
}

/// Two-label public suffixes, common in exactly the places this tool is used —
/// `gov.ua`, `co.uk`, `go.id` — where the last two labels are not an
/// organisation but a registry.
const TWO_LABEL: [&str; 12] = [
    "gov.ua", "com.ua", "co.uk", "org.uk", "gov.uk", "ac.uk", "go.id", "co.id",
    "com.br", "com.au", "co.jp", "com.tr",
];

fn host_of(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("http://").or_else(|| url.strip_prefix("https://"))?;
    Some(rest.split('/').next().unwrap_or(rest))
}

/// The endings that make a match a file rather than a host.
const NOT_A_TLD: [&str; 18] = [
    "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "css", "js", "php",
    "html", "htm", "aspx", "jsp", "pdf", "doc", "docx", "txt",
];

/// `%2F` → `/`, once over the whole string. Invalid escapes are left as they
/// are: this is reading somebody's hostile input, not parsing a URL.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
            if let Ok(b) = u8::from_str_radix(hex, 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
