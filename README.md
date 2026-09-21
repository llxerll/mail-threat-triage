# Mail Threat Triage

A local-first `.eml` triage tool for email-security support, incident response, QA, and sales demos. It uses only the Python standard library and never uploads message data.

## What it checks

- SPF, DKIM, and DMARC results from `Authentication-Results`
- From / Reply-To mismatch and suspicious display names
- Executable, archive, and deceptive double-extension attachments
- Attachment SHA-256, MIME type, and size
- Punycode and raw-IP URL hosts
- Received-hop presence and full-message SHA-256
- A deterministic 0-100 risk score, JSON output, and a standalone HTML report

> This is a triage aid, not a replacement for DKIM cryptographic verification, sandboxing, URL reputation, or an email security gateway.

## Quick start

Requires Python 3.10+ and has no third-party dependencies.

```bash
python mail_triage.py suspicious.eml
python mail_triage.py suspicious.eml --format html -o report.html
```

Exit codes: `0` low risk, `1` suspicious, `2` high risk. This makes it easy to use in scripts and CI.

## Test

```bash
python -m unittest -v test_mail_triage.py
```

## Safe handling

Run this on a copy of the message. Do not open extracted attachments. The tool hashes attachment bytes in memory but does not write or execute them.

## License

MIT
