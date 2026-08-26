use limen_sdk_rust::{json, Value};
use mailparse::{ParsedMail, MailHeaderMap};

pub fn analyze(parsed_mail: &ParsedMail) -> Value {
    let subject = parsed_mail.headers.get_first_value("Subject").unwrap_or_default();
    let from = parsed_mail.headers.get_first_value("From").unwrap_or_default();
    let reply_to = parsed_mail.headers.get_first_value("Reply-To").unwrap_or_default();
    
    let spoofed = !reply_to.is_empty() && !from.contains(&reply_to);
    
    let auth = parsed_mail.headers.get_first_value("Authentication-Results").unwrap_or_default().to_lowercase();
    let spf = auth.contains("spf=pass");
    let dkim = auth.contains("dkim=pass");
    let dmarc = auth.contains("dmarc=pass");

    json!({
        "subject": subject,
        "from": from,
        "reply_to": reply_to,
        "spoofed": spoofed,
        "spf_pass": spf,
        "dkim_pass": dkim,
        "dmarc_pass": dmarc
    })
}