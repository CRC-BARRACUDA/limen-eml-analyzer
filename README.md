\# eml-analyzer



A native \[Limen](https://github.com/CRC-BARRACUDA/Limen) module for deep static analysis and triage of `.eml` (email) files. Built for DFIR analysts to safely dissect sophisticated phishing campaigns, bypass MIME obfuscation, and inspect malicious payloads without relying on external sandbox environments.



Provides the capability \*\*`eml.triage`\*\*.



\## What it does



Parses raw mail structures and evaluates threats across multiple vectors, generating an aggregated 0-100 Risk Score through a SpamAssassin-lite heuristic engine.



| Category | What it detects |

|---|---|

| \*\*Recursive MIME Parsing\*\* | Deep recursive traversal through nested `multipart` structures to bypass MIME obfuscation and uncover hidden or maliciously nested attachments. |

| \*\*Safe Archive "X-Ray"\*\* | In-memory inspection of archive headers (`.zip`, `.tar`, `.gz`, etc.) without full decompression. Protects against ZIP bombs while exposing hidden executables, Office macros (`vbaProject.bin`), double extensions, and encrypted containers. |

| \*\*Headers \& Auth\*\* | Extracts routing history, verifies SPF/DKIM/DMARC status, and flags domain spoofing (From vs Reply-To). |

| \*\*IoC Extraction\*\* | Extracts IP addresses, URLs, Emails, and Cryptocurrency wallets (BTC, ETH, XMR) from plain text and HTML bodies. |

| \*\*Social Engineering\*\* | Scans subject and body for psychological pressure triggers (urgency, panic words) and regional lures (e.g., government, registry, military contexts). |

| \*\*HTML Anomalies\*\* | Detects hidden text techniques (zero-font, transparent colors, display:none) and visual link spoofing. |



\## Methods



| Method | Returns |

|---|---|

| `scan` | JSON: `{eml\_hash, headers, scoring, iocs\[], attachments\[]}` — the complete analysis result of the provided `.eml` file. |

| `ui`   | The landing view — a native File Picker with Drag-and-Drop support and an \*\*Analyze\*\* button. |

| `dashboard` | The primary visual report containing the Risk Score, detailed breakdown of triggered heuristics, and navigation. |

| `view\_iocs` / `view\_atts` | Detailed tables for extracted IoCs and attachments with contextual menus (Save to disk, Extract Strings). |

| `check\_reputation` | Cross-module RPC. Sends an IoC or Hash to `osint.reputation` (if installed) for external threat intelligence checking. |



\## Permissions



```toml

\[permissions]

filesystem = \["<user-selected>"]

