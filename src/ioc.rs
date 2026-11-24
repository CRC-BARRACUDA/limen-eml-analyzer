use regex::Regex;
use std::collections::HashSet;

pub fn extract(text: &str) -> Vec<String> {
    let mut results = HashSet::new();
    
    if let Ok(re) = Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b") {
        for cap in re.captures_iter(text) { results.insert(format!("IP: {}", &cap[0])); }
    }
    
    // Stops at whitespace and at the characters a URL is wrapped in — a quote,
    // an angle bracket, a closing paren. Without them, a link lifted out of an
    // `href="..."` keeps the quote and every later comparison is against a
    // string that is not the URL.
    if let Ok(re) = Regex::new("https?://[^\\s/$.?#][^\\s\"'<>)]*") {
        for cap in re.captures_iter(text) { results.insert(format!("URL: {}", &cap[0])); }
    }
    
    if let Ok(re) = Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b") {
        for cap in re.captures_iter(text) { results.insert(format!("Email: {}", &cap[0])); }
    }

    if let Ok(re) = Regex::new(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b") {
        for cap in re.captures_iter(text) { results.insert(format!("BTC: {}", &cap[0])); }
    }

    if let Ok(re) = Regex::new(r"\b0x[a-fA-F0-9]{40}\b") {
        for cap in re.captures_iter(text) { results.insert(format!("ETH: {}", &cap[0])); }
    }

    if let Ok(re) = Regex::new(r"\b(?:4|8)[0-9a-zA-Z]{94}\b") {
        for cap in re.captures_iter(text) { results.insert(format!("XMR: {}", &cap[0])); }
    }
    
    let mut sorted: Vec<String> = results.into_iter().collect();
    sorted.sort();
    sorted
}

pub fn count_psycho_words(text: &str) -> (usize, bool) {
    let lower = text.to_lowercase();
    let trigger_words = [
        "терміново", "невідкладно", "швидко", "увага", "блокування", "штраф", "срочно", "внимание", "заборгованість",
        "розпорядження", "наказ", "повістка", "мобілізація", "доповідь", "акт звірки", "рахунок", "оплата", "квитанція",
        "тцк", "сп", "реєстр", "військовозобов", "працівник", "звітність"
    ];
    let password_words = ["пароль", "password", "код доступу", "шифр"];

    let mut count = 0;
    for w in trigger_words {
        if lower.contains(w) { count += 1; }
    }

    let mut has_pwd = false;
    for w in password_words {
        if lower.contains(w) { has_pwd = true; break; }
    }

    (count, has_pwd)
}

pub fn check_html_anomalies(html: &str) -> usize {
    let mut anomalies = 0;
    let lower = html.to_lowercase();
    
    if lower.contains("font-size: 0") || lower.contains("font-size:0") || 
       lower.contains("color: transparent") || lower.contains("color:transparent") ||
       lower.contains("display: none") || lower.contains("display:none") {
        anomalies += 1;
    }
    
    if let Ok(re) = Regex::new(r#"<a[^>]+href\s*=\s*["'](https?://[^"']+)["'][^>]*>(https?://[^<]+)</a>"#) {
        for cap in re.captures_iter(&lower) {
            let href = &cap[1];
            let text = &cap[2];
            if extract_domain(href) != extract_domain(text) {
                anomalies += 1;
            }
        }
    }
    anomalies
}

fn extract_domain(url: &str) -> Option<&str> {
    let without_proto = url.strip_prefix("http://").or_else(|| url.strip_prefix("https://")).unwrap_or(url);
    without_proto.split('/').next()
}

/// An indicator as the list shows it, taken apart: `("URL", "https://…")`.
///
/// The list carries each one as `Kind: value` so it reads at a glance; what is
/// pasted into a search box or a ticket is the value alone.
pub fn parts(ioc: &str) -> (&str, &str) {
    ioc.split_once(": ").unwrap_or(("", ioc))
}

/// The value, written so that nothing it is pasted into makes a link of it.
///
/// An indicator is passed on — into a ticket, a chat, a mail to the people it
/// was aimed at — and every one of those turns `http://evil.test` into
/// something one slip of the hand opens. So the scheme becomes `hxxp`, and the
/// dots of the host `[.]`: still readable, still searchable, no longer live.
/// A path keeps its dots — it is the host that makes a link. A wallet address
/// was never one, and comes back as it is.
pub fn defanged(ioc: &str) -> String {
    let (kind, value) = parts(ioc);
    match kind {
        "IP" => value.replace('.', "[.]"),
        "Email" => value.replace('@', "[@]").replace('.', "[.]"),
        "URL" | "Redirect" => {
            let (scheme, rest) = match value.split_once("://") {
                Some((s, r)) => (Some(s), r),
                None => (None, value),
            };
            let host_ends = rest.find(['/', '?', '#']).unwrap_or(rest.len());
            let (host, tail) = rest.split_at(host_ends);
            let host = host.replace('.', "[.]");
            match scheme {
                // `http` and `https`, however they were capitalised.
                Some(s) if s.len() >= 4 && s[..4].eq_ignore_ascii_case("http") => {
                    format!("hxxp{}://{host}{tail}", &s[4..])
                }
                Some(s) => format!("{s}://{host}{tail}"),
                None => format!("{host}{tail}"),
            }
        }
        _ => value.to_string(),
    }
}
