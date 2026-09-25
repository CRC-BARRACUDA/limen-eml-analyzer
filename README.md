# eml-analyzer

A native [Limen](https://github.com/CRC-BARRACUDA/Limen) module for deep static analysis and triage of `.eml` files. Designed for local DFIR environments, it allows analysts to bypass MIME obfuscation, inspect malicious payloads, and evaluate threats without relying on external sandboxes.

Provides the `eml.triage` capability.

## Core Features

* **MIME Obfuscation Bypass:** Deep recursive traversal of nested `multipart` structures to uncover hidden or maliciously packed attachments.
* **In-Memory Archive X-Ray:** Safe, zero-decompression inspection of `.zip` containers (including `.docx`/`.xlsx`/`.docm`/`.xlsm`) — entry names are read from the central directory, never inflated, so a zip bomb has nothing to explode. Identifies hidden executables, Office macros (`vbaProject.bin`), double extensions, and encrypted containers. Other archives (`.rar`, `.7z`, `.tar`, `.gz`) are flagged as archives and scanned as raw bytes for tell-tale names, but are not opened.
* **Authentication & Header Analysis:** Verifies SPF, DKIM, and DMARC status. Flags domain spoofing anomalies between `From` and `Reply-To` headers.
* **IoC Extraction:** Automatically parses plain text and HTML bodies to extract IP addresses, URLs, email addresses, and cryptocurrency wallets (BTC, ETH, XMR).
* **Credential Phishing (no attachment required):** The common case now is one link and one polite sentence. Four things are read off the message body rather than off its files:
  * **Cloaked links.** A link whose query or fragment carries *another* destination — often through a second redirector, often with no scheme and percent-encoded twice. The href reads `tiktok.com`; the browser lands on somebody's compromised WordPress. The final hop is reported under IoCs as `Redirect: …`.
  * **Your own address in the fragment.** A phishing kit puts the recipient's address after the `#`, plain or base64, so the login page it serves opens already filled in. Nothing the server sees, and no ordinary reason for it — an unsubscribe link puts it in the query, which is not flagged.
  * **A request for credentials.** A word of confirmation *and* the thing being confirmed ("confirm your account", "підтвердьте свої облікові дані"), and only when the message also carries a link — the same sentence with nowhere to type it is a notice, not an attack.
  * **A domain hidden before the `@`.** `cert.gov.ua@notify-secure.example` reads as `cert.gov.ua` at a glance, and the part that says who actually sent it is the part a narrow column truncates. Only labels that are never anybody's name count (`com`, `net`, `org`, `gov`, `edu`, `mil`) or a full two-label suffix — `van.de.berg` and `o.brien` are surnames, not domains.
  * **Impersonating your own mail domain.** A message about your `example.org` mailbox that came from somewhere else entirely. Your own IT department writes from your own domain.
* **Heuristic Scoring Engine:** Generates an aggregated 0-100 Risk Score based on HTML anomalies (zero-font, transparent colors, display toggles) and social engineering triggers (urgency, panic, authoritative lures).

## API Methods

| Method | Description |
|---|---|
| `scan` | Returns a complete analysis JSON containing `eml_hash`, `headers`, `scoring`, `iocs`, and `attachments`. |
| `ui` | The landing view: a native File Picker with drag-and-drop support. |
| `dashboard` | Visual report rendering the final Risk Score and a detailed breakdown of triggered heuristics. |
| `view_iocs` / `view_atts` | Interactive data tables for extracted IoCs and attachments with contextual actions (e.g., Save to disk, Extract Strings). |
| `check_reputation` | Cross-module RPC. Forwards extracted hashes or IoCs to `osint.reputation` (if installed) for external threat intelligence checks. |

## Permissions

```toml
[permissions]
# Required to read the user-selected .eml file and save extracted payloads to local disk.
filesystem = ["<user-selected>"]
