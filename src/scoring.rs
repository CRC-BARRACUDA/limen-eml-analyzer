use limen_sdk_rust::{json, Value};

/// What the parser noticed on the way through the message — everything the
/// score is made of, apart from the headers.
///
/// A struct rather than nine positional arguments: they are all counts and
/// booleans, and at the call site nothing stopped two adjacent ones being
/// swapped. Named fields make that impossible to write by accident.
#[derive(Default)]
pub struct Signals {
    pub bad_attachments: usize,
    pub has_double_ext: bool,
    pub psycho_words: usize,
    pub html_anomalies: usize,
    pub has_crypto: bool,
    pub has_archive: bool,
    pub is_encrypted_zip: bool,
    pub has_pwd_keyword: bool,
    pub has_macro: bool,
}

pub fn calculate(headers: &Value, found: &Signals) -> Value {
    let Signals {
        bad_attachments,
        has_double_ext,
        psycho_words: total_psycho_words,
        html_anomalies,
        has_crypto,
        has_archive,
        is_encrypted_zip,
        has_pwd_keyword,
        has_macro,
    } = *found;
    let mut score = 0;
    let mut triggers = Vec::new();
    
    if !headers.get("spf_pass").and_then(Value::as_bool).unwrap_or(false) { 
        score += 15; 
        triggers.push(json!({"key": "reasons.spf", "pts": 15})); 
    }
    if !headers.get("dkim_pass").and_then(Value::as_bool).unwrap_or(false) { 
        score += 15; 
        triggers.push(json!({"key": "reasons.dkim", "pts": 15})); 
    }
    if headers.get("spoofed").and_then(Value::as_bool).unwrap_or(false) { 
        score += 30; 
        triggers.push(json!({"key": "reasons.spoof", "pts": 30})); 
    }
    
    if bad_attachments > 0 {
        let p = (bad_attachments as u32) * 40;
        score += p;
        triggers.push(json!({"key": "reasons.atts", "pts": p}));
    }
    
    if total_psycho_words > 0 {
        let p = (total_psycho_words as u32) * 2;
        score += p;
        triggers.push(json!({"key": "reasons.psycho", "pts": p}));
    }
    
    if html_anomalies > 0 {
        let p = (html_anomalies as u32) * 20;
        score += p;
        triggers.push(json!({"key": "reasons.html", "pts": p}));
    }
    
    if has_crypto { 
        score += 50; 
        triggers.push(json!({"key": "reasons.crypto", "pts": 50}));
    }
    
    if is_encrypted_zip {
        score += 20;
        triggers.push(json!({"key": "reasons.enc_zip", "pts": 20}));
    }
    
    if (is_encrypted_zip || has_archive) && has_pwd_keyword {
        score += 100;
        triggers.push(json!({"key": "reasons.pwd_arc", "pts": 100}));
    }

    if has_double_ext {
        score += 100;
        triggers.push(json!({"key": "reasons.double_ext", "pts": 100}));
    }
    
    if has_macro {
        score += 100;
        triggers.push(json!({"key": "reasons.macro", "pts": 100}));
    }
    
    let final_score = if score > 100 { 100 } else { score };
    
    json!({
        "score": final_score,
        "triggers": triggers
    })
}