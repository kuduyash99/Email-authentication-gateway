# Email Authentication Gateway: SPF, DKIM, DMARC

Protects a domain against email spoofing and phishing using SPF, DKIM and DMARC, and includes a command-line tool that summarizes the authentication results in an email header.

The DNS records need a domain you own. The scripts run without one; `example.com` is used as a placeholder. Replace `example.com` with your domain and `203.0.113.10` with your sending server's IP.

## Setup

```
python -m venv venv
```

Activate it:

- Windows: `venv\Scripts\activate`
- Mac/Linux: `source venv/bin/activate`

Then install the dependencies:

```
pip install -r requirements.txt
```

Add a `.gitignore` containing `venv/`, `keys/` and `*.eml` so the private key is never committed.

## 1. SPF

Publish a TXT record at the domain root:

| Name | Type | Value |
|------|------|-------|
| `example.com` | TXT | `v=spf1 ip4:203.0.113.10 -all` |

`-all` rejects any IP not listed. While testing, use `~all` (soft fail) instead.

## 2. DKIM

Generate the key pair:

```
python generate_dkim.py --domain example.com --selector mail2026
```

The private key is saved to `keys/mail2026.private.pem`. Keep it secret. The script prints a TXT record: publish it at `mail2026._domainkey.example.com`.

The script refuses to overwrite an existing key. To create a new one, delete the old file or use a different `--selector`.

Sign a test email (one line):

```
python sign_email.py --from alice@example.com --to you@gmail.com --selector mail2026 --key keys/mail2026.private.pem --out signed.eml
```

This writes `signed.eml` with a `DKIM-Signature` header at the top. To send it, use any SMTP client from the authorized IP, for example:

```
swaks --server <smtp-host> --data signed.eml --from alice@example.com --to you@gmail.com
```

## 3. DMARC

**Phase 1: monitoring.** Publish a TXT record at `_dmarc.example.com`:

```
v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com; adkim=r; aspf=r
```

`dmarc-reports@example.com` must be a mailbox you can read, otherwise you will never see the reports.

Collect reports for 1-2 weeks and confirm that all legitimate mail passes SPF or DKIM **with alignment**.

**Phase 2: enforcement.** Tighten in steps. Each record **replaces** the previous one at `_dmarc.example.com`:

Step 1:
```
v=DMARC1; p=quarantine; pct=25; rua=mailto:dmarc-reports@example.com
```

Step 2:
```
v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@example.com
```

Step 3:
```
v=DMARC1; p=reject; rua=mailto:dmarc-reports@example.com
```

## 4. Header analyzer

1. Open an email in Gmail and choose **Show original**.
2. Click **Copy to clipboard** (this copies the raw text, not the summary box).
3. Paste it into a file named `headers.txt` in this folder.
4. Run:

```
python header_analyzer.py headers.txt
```

On Mac/Linux you can also pipe it in: `cat headers.txt | python header_analyzer.py`

The tool reads the receiving server's `Authentication-Results` header (falling back to `Received-SPF` for SPF), prints the SPF, DKIM and DMARC results, and checks identifier alignment against the From domain. Alignment is relaxed, and no public-suffix list is used.

Sample headers are included for testing without a domain:

```
python header_analyzer.py samples/legitimate.txt
python header_analyzer.py samples/spoofed.txt
```

The second sample shows SPF passing for `evil.test` while DMARC fails, because the SPF domain does not align with the From domain.

## How the layers fit together

- **SPF** checks that the sending IP is authorized for the envelope sender (Return-Path).
- **DKIM** checks that the message was signed by the domain and was not altered in transit.
- **DMARC** requires SPF or DKIM to pass *and* align with the visible From domain, and tells receivers what to do on failure.