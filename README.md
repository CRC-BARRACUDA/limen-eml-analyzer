# eml-analyzer

A native [Limen](https://github.com/CRC-BARRACUDA/Limen) module for deep static analysis and triage of `.eml` files. Designed for local DFIR environments, it allows analysts to bypass MIME obfuscation, inspect malicious payloads, and evaluate threats without relying on external sandboxes.

Provides the `eml.triage` capability.

## Core Features

* **MIME Obfuscation Bypass:** Deep recursive traversal of nested `multipart` structures to uncover hidden or maliciously packed attachments.
* **In-Memory Archive X-Ray:** Safe, zero-decompression inspection of archive headers (`.zip`, `.tar`, `.gz`). Identifies hidden executables, Office macros (`vbaProject.bin`), double extensions, and encrypted containers without the risk of ZIP bombs.
* **Authentication & Header Analysis:** Verifies SPF, DKIM, and DMARC status. Flags domain spoofing anomalies between `From` and `Reply-To` headers.
* **IoC Extraction:** Automatically parses plain text and HTML bodies to extract IP addresses, URLs, email addresses, and cryptocurrency wallets (BTC, ETH, XMR).
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
