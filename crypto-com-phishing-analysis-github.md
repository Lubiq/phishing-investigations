# Phishing Investigation: Fake Crypto.com OTP Campaign

> **Type:** Email Forensics / Threat Intelligence  
> **Skills:** Header Analysis · Infrastructure OSINT · Payload Decoding · Multi-victim Attribution  
> **Tools:** Python (zlib, base64, urllib) · WHOIS · Web Search  
> **Dataset:** 3 phishing emails across a 14-day window (April 6–20, 2026)

---

## Overview

Three unsolicited emails impersonating Crypto.com were received and analyzed across a 14-day window in April 2026. All three targeted confirmed Crypto.com account holders. The investigation reveals two independent threat actors abusing GoHighLevel's commercial CRM (Customer Relationship Management) email infrastructure to run coordinated vishing (voice phishing) campaigns — with their identities partially exposed through leaked campaign metadata and a recoverable encrypted payload in each email's tracking pixel.

This writeup documents the full methodology: header forensics → infrastructure attribution → payload decoding → cross-email correlation → probable breach sourcing.

---

## Table of Contents

1. [Infrastructure Chain](#1-infrastructure-chain)
2. [Email Authentication Analysis](#2-email-authentication-analysis)
3. [Sender Forensics](#3-sender-forensics)
4. [Tracking Pixel — Decoded Payload](#4-tracking-pixel--decoded-payload)
5. [CSS RTL Phone Obfuscation](#5-css-rtl-phone-obfuscation)
6. [WHOIS Domain Investigation](#6-whois-domain-investigation)
7. [GoHighLevel Account Fingerprinting](#7-gohighlevel-account-fingerprinting)
8. [Corporate Address Verification](#8-corporate-address-verification)
9. [Cross-Email Correlation](#9-cross-email-correlation)
10. [Attack Intent Assessment](#10-attack-intent-assessment)
11. [Probable Data Source](#11-probable-data-source)
12. [IOC Reference Table](#12-ioc-reference-table)
13. [Reporting Targets](#13-reporting-targets)
14. [Defensive Takeaways](#14-defensive-takeaways)

---

## 1. Infrastructure Chain

All three emails share the same delivery architecture regardless of which attacker sent them:

```
[Threat Actor]
    │
    │  Creates campaign via GoHighLevel CRM dashboard or API
    ▼
[GoHighLevel / LeadConnector Email]
    Domain:  send.lcmsgsndr.net  (Emails 1 & 2)
             send.lcmsgsndr.org  (Email 3)
    Bucket:  ghl_bucket (shared — no dedicated sending domain)
    Method:  API (automated/scripted send)
    │
    │  Routes through Mailgun relay
    ▼
[Mailgun Technologies Inc.]
    IP:       159.135.225.193
    Hostname: v5193.v5d85c8f2.use4.send.mailgun.net
    ASN:      AS396479
    Location: San Antonio, TX, USA
    Abuse:    abuse@mailgun.com
    │
    │  SMTP over TLS 1.2 (ECDHE-ECDSA-AES128-GCM-SHA256)
    ▼
[Gmail / Google MX]
    Recipient: [REDACTED]
```

**Why this matters:** GoHighLevel is a legitimate commercial CRM used by marketing agencies worldwide. By using its shared sending infrastructure, the attacker inherits GoHighLevel's and Mailgun's authentication reputation — causing all SPF (Sender Policy Framework), DKIM (DomainKeys Identified Mail), and DMARC (Domain-based Message Authentication, Reporting & Conformance) checks to pass cleanly. These passes do not authenticate *Crypto.com* — they authenticate *GoHighLevel's relay*.

---

## 2. Email Authentication Analysis

| Protocol | Result | Signing Domain | Notes |
|----------|--------|----------------|-------|
| DKIM | ✅ PASS | `send.lcmsgsndr.net` | GoHighLevel infra — **not** Crypto.com |
| DKIM | ✅ PASS | `mailgun.org` | Mailgun relay — **not** Crypto.com |
| SPF | ✅ PASS | `send.lcmsgsndr.net` | IP 159.135.225.193 is an authorized Mailgun sender |
| DMARC | ✅ PASS | `send.lcmsgsndr.net` | Policy: REJECT — aligns with lcmsgsndr.net, not crypto.com |

> **Key insight:** All authentication passes for GoHighLevel/Mailgun's own domains. The impersonated domain — `crypto.com` — is never verified anywhere in the chain. **DMARC PASS ≠ the sender is who they claim to be.** This is a fundamental limitation of email authentication: it verifies the *sending infrastructure*, not the *claimed brand identity*.

---

## 3. Sender Forensics

### Email 1 — April 20, 2026

| Header | Value |
|--------|-------|
| `From` (display) | `"Crypto.com"` |
| `From` (actual) | `319916-msg+safeguard.crypto.com@send.lcmsgsndr.net` |
| `Sender` | `319916-msg+safeguard.crypto.com@send.lcmsgsndr.net` |
| `Reply-To` | `319916-msg+safeguard.crypto.com@send.lcmsgsndr.net` |
| `Return-Path` | `bounce+[ID].[REDACTED]=gmail.com@send.lcmsgsndr.net` |

### Email 2 — April 15, 2026

| Header | Value |
|--------|-------|
| `From` (display) | `"Crypto.com"` |
| `From` (actual) | `ms784579-msg+crypto.company@send.lcmsgsndr.net` |
| `Reply-To` | `ms784579-msg+crypto.company@send.lcmsgsndr.net` |

### Email 3 — April 6, 2026

| Header | Value |
|--------|-------|
| `From` (display) | `"Crypto.com™"` |
| `From` (actual) | `email-714950+safeguard.crypto@send.lcmsgsndr.org` |
| `Reply-To` | `email-714950+safeguard.crypto@send.lcmsgsndr.org` |

**Pattern:** In each case, a substring resembling `crypto.com` or `crypto` is injected into the **local-part** of the address (before the `@`). The actual sending domain is always GoHighLevel's infrastructure. This exploits the fact that many email clients display only the `From` display name, hiding the real address.

---

## 4. Tracking Pixel — Decoded Payload

Each email contains a 1×1 invisible tracking pixel hosted at `https://email.send.lcmsgsndr.[net|org]/o/[PAYLOAD]`.

### Encoding

The URL payload is **zlib-deflate compressed** and **base64url-encoded**. It requires standard zlib decompression (`wbits=15`) — not the more common raw deflate variant. Decoded:

```python
import base64, zlib, urllib.parse

raw = "[BASE64URL_STRING_FROM_EMAIL]"
padded = raw + '=' * (4 - len(raw) % 4)
decoded = base64.urlsafe_b64decode(padded)
result = zlib.decompress(decoded, 15)  # wbits=15 for standard zlib
params = urllib.parse.parse_qs(result.decode())
```

### Decoded Fields (Email 1, sanitized)

```
c_id    = cU0wbJeo0JQYl8UVgQPv      ← Campaign ID
d       = f48712                     ← Sub-account ID (KEY ATTACKER IDENTIFIER)
domain  = send.lcmsgsndr.net
domain_ownership_type = ghl_bucket
e       = 1776702367                 ← Unix timestamp of send
email_message_id = kzlBwVxjk8WWwvj4mD11
loc_id  = Wez9M6I3B6ewRVrCyAz9      ← GHL workspace ID
method  = api                        ← Automated send confirmed
provider = leadconnector
r       = [REDACTED]@gmail.com       ← Recipient email (fires on pixel load)
source  = email-isv-worker
lc_email_internal = [AES-CBC ENCRYPTED BLOB]
```

### `lc_email_internal` — Encrypted Sender Identity

The `lc_email_internal` field base64-decodes to an **OpenSSL AES (Advanced Encryption Standard)-CBC encrypted blob** beginning with magic bytes `Salted__`:

| Email | Salt (hex) | Blob size |
|-------|-----------|-----------|
| Email 1 | `a660bf73c3239ebe` | 176 bytes |
| Email 2 | `49c49d0bc6f7f57a` | 176 bytes |
| Email 3 | `515b4a475bc9d799` | 176 bytes |

**GoHighLevel holds the decryption key.** This field contains account-level sender identity and is fully recoverable under a formal abuse/legal request. It is the strongest single artifact for account identification.

### Pixel OpSec (Operational Security) Note

If a recipient opens the email in a standard mail client, the pixel fires a GET request to GoHighLevel's servers with `r=[recipient_email]` in the payload — confirming the address is active and the message was read, along with the recipient's approximate IP and timestamp. **Viewing a phishing email in preview pane can confirm your address to the attacker.**

---

## 5. CSS RTL Phone Obfuscation

All three emails use an identical technique to hide a callback number from automated scanners while displaying it correctly to human readers.

### The Technique

```html
Contact support at (85<span style="unicode-bidi: bidi-override; direction: rtl;">
  0631-792&nbsp;(5
</span> if this was not you.
```

The `direction: rtl` CSS property reverses character rendering order. Per the Unicode Bidirectional Algorithm, bracket characters are also **mirrored** in RTL context: `(` renders as `)`.

### Decoding Logic (Python)

```python
span_text = "0631-792\u00a0(5"   # raw span content
mirror = {'(': ')', ')': '('}
visual = ''.join(mirror.get(c, c) for c in span_text[::-1])
prefix = "(85"
print(prefix + visual)           # → (855) 297-1360
```

### All Three Decoded Numbers

| Email | Raw span | Decoded number |
|-------|----------|---------------|
| Email 1 | `0631-792 (5` | **(855) 297-1360** |
| Email 2 | `1018-774 (6` | **(866) 477-8101** |
| Email 3 | `0269-053 (8` | **(888) 350-9620** |

All are US toll-free numbers — cheap, easily provisioned, geographically untraceable. Rotation across campaigns is consistent with burner VoIP (Voice over Internet Protocol) lines being replaced as numbers get reported/blocked.

**No legitimate company obfuscates phone numbers in transactional email.** This technique's sole purpose is evading automated content scanners.

---

## 6. WHOIS Domain Investigation

### `msgsndr.com` (unsubscribe / platform domain)

| Field | Value |
|-------|-------|
| Registered | 2018-05-16 |
| Registrar | GoDaddy.com, LLC |
| Registrant | Domains By Proxy, LLC (privacy-protected) |
| Name servers | `megan.ns.cloudflare.com`, `noah.ns.cloudflare.com` |

The `.us` variant (`msgsndr.us`) was registered without privacy protection, revealing: **Registrant: VARUN VAIRAVAN, Organization: HIGHLEVEL, Email: VARUN@GOHIGHLEVEL.COM** — confirming GoHighLevel corporate ownership of the entire `msgsndr` domain family across TLDs.

### `lcmsgsndr.net` / `lcmsgsndr.org`

Both are GoHighLevel's LeadConnector (`lc`) shared sending domains backed by Mailgun relay pools. GoHighLevel operates the `lcmsgsndr` namespace across at least `.net` and `.org` as redundant sending infrastructure. Abuse from either domain traces back to the same GoHighLevel account system.

---

## 7. GoHighLevel Account Fingerprinting

The `X-Mailgun-Variables` header and decoded pixel payload expose stable, persistent attacker-linked identifiers:

| Identifier | Purpose | Emails 1+2 | Email 3 |
|------------|---------|------------|---------|
| `d=` (sub-account) | **Primary attacker ID** | `f48712` | `a047bd` |
| `loc_id` | GHL workspace | varies per campaign | `Bdu68oGhWuMCDoHVsnQ6` |
| `c_id` / `campaign_id` | Specific campaign | varies | `mTKR5sDnmLAJJrdyFdoQ` |
| `method` | Send type | `api` | `api` |
| `domain_ownership_type` | Account tier | `ghl_bucket` | `ghl_bucket` |

The `d=` field is the GoHighLevel sub-account identifier — it appears identically across every email sent from the same account. **Emails 1 and 2 share `d=f48712`, confirming a single operator ran both campaigns.** Email 3 has `d=a047bd` — a second independent operator.

All campaigns use `method=api` and `ghl_bucket` (shared domain, no dedicated sending domain), indicating basic GoHighLevel plans running scripted/automated sends.

---

## 8. Corporate Address Verification

**Email 1 footer:** `Crypto.com | Foris DAX, Inc. | 3600 S Las Vegas Blvd, Las Vegas, NV 89109`

**3600 S Las Vegas Blvd, Las Vegas, NV 89109 is the Bellagio Hotel & Casino.**

Crypto.com's verified corporate addresses:

| Entity | Address |
|--------|---------|
| Foris DAX Asia Pte. Ltd. | 1 Raffles Quay, #09-06, Singapore 048583 |
| Foris DAX Inc. (US) | 1111 Brickell Ave, Suite 2725, Miami, FL 33131 |

Crypto.com does hold naming rights to **Crypto.com Arena** — but that venue is in Los Angeles, CA, not Las Vegas. The attacker likely conflated the brand's arena association with a Las Vegas landmark to fabricate a plausible-looking address. Verifiable with a single Google search.

**Emails 2 & 3 footer:** `© 2026 . All Rights Reserved.` — company name variable entirely absent, and Email 3 body contains `" employees will never ask for your OTP"` (leading space where `{{company_name}}` was meant to substitute). These are template variable injection failures confirming automated, mass-generated campaigns.

---

## 9. Cross-Email Correlation

### Timeline

| Date | Email | Attacker | Target | Infra domain |
|------|-------|----------|--------|-------------|
| Apr 6, 2026 | Email 3 | `a047bd` | Victim C | `lcmsgsndr.org` |
| Apr 15, 2026 | Email 2 | `f48712` | Victim B | `lcmsgsndr.net` |
| Apr 20, 2026 | Email 1 | `f48712` | Victim A | `lcmsgsndr.net` |

### Shared Indicators

| Indicator | Email 1 | Email 2 | Email 3 |
|-----------|---------|---------|---------|
| Sub-account `d=` | `f48712` | `f48712` ✅ | `a047bd` |
| Send method | `api` | `api` | `api` |
| Bucket type | `ghl_bucket` | `ghl_bucket` | `ghl_bucket` |
| CSS RTL obfuscation | ✅ | ✅ | ✅ |
| AES blob present | ✅ | ✅ | ✅ |
| Template errors | Footer fake | Footer missing | Company name missing |

**Attacker `f48712` ran two campaigns (Emails 1 & 2) against two separate victims.** Attacker `a047bd` ran one campaign (Email 3) against a third victim. Both targeted confirmed Crypto.com account holders. Both used identical tooling and send method.

---

## 10. Attack Intent Assessment

This campaign is a **vishing setup** — not a credential-harvesting link attack. The goal:

1. Deliver a fake OTP email to create urgency ("someone is accessing your account")  
2. Direct the panicked victim to call the obfuscated callback number  
3. Social-engineer the victim on the phone into disclosing account credentials, live 2FA (Two-Factor Authentication) codes, or PII (Personally Identifiable Information)

**No malicious URLs appear in the email body** — a deliberate choice. URL-based payloads are scanned by email security platforms (Google Safe Browsing, Microsoft Defender for Office 365, etc.). Phone-based social engineering bypasses all of these controls. The attacker trades the convenience of automated credential harvesting for the higher success rate of live human manipulation.

---

## 11. Probable Data Source

All three victims are confirmed Crypto.com account holders. Two independent operators ran identical Crypto.com impersonation campaigns against overlapping victim pools within 14 days. This is consistent with a **shared breach dataset** available to multiple buyers on dark web markets.

### Crypto.com Breach History

Crypto.com has documented data exposure incidents:

- **2023 (Scattered Spider):** Blockchain investigator ZachXBT revealed that hacking group Scattered Spider gained unauthorized access to a Crypto.com employee account through social engineering. Crypto.com officially characterized the exposure as "limited PII affecting a very small number of individuals." ZachXBT disputed this, stating leaked data included email addresses, phone numbers, wallet contents, and identity documents. He also asserted awareness of a second, larger undisclosed breach.
- **Disclosure posture:** Crypto.com filed regulatory notices but did not proactively notify affected users publicly. Whether the victims in this dataset were individually notified is unknown.

### Assessment

The targeting of confirmed Crypto.com account holders by two independent operators running identical brand-impersonation campaigns strongly suggests both sourced their lists from the same breach dataset — now circulating on dark web markets. **Attribution is assessed as "probable," not confirmed.** The exact breach dataset cannot be identified without access to the underlying data.

---

## 12. IOC Reference Table

### Attacker `f48712` (Emails 1 & 2)

| Type | Value |
|------|-------|
| GHL sub-account | `f48712` |
| Sending IP | `159.135.225.193` |
| IP hostname | `v5193.v5d85c8f2.use4.send.mailgun.net` |
| IP owner / ASN | Mailgun Technologies Inc. / AS396479 |
| Sending domain | `send.lcmsgsndr.net` |
| Relay | `mailgun.org` |
| GHL location ID (Email 1) | `Wez9M6I3B6ewRVrCyAz9` |
| GHL location ID (Email 2) | `HntRKOGVKqYfzb11hCOS` |
| Campaign ID (Email 1) | `cU0wbJeo0JQYl8UVgQPv` |
| Campaign ID (Email 2) | `JfgVbBSBbNFfIxaZN5Ib` |
| Message ID (Email 1) | `kzlBwVxjk8WWwvj4mD11` |
| Message ID (Email 2) | `Y7ez5uKiTWQeaifglP04` |
| Callback (Email 1, decoded) | `+1 (855) 297-1360` |
| Callback (Email 2, decoded) | `+1 (866) 477-8101` |
| AES blob salt (Email 1) | `a660bf73c3239ebe` |
| AES blob salt (Email 2) | `49c49d0bc6f7f57a` |
| Fabricated footer address | 3600 S Las Vegas Blvd NV 89109 (Bellagio Hotel) |

### Attacker `a047bd` (Email 3)

| Type | Value |
|------|-------|
| GHL sub-account | `a047bd` |
| Sending domain | `send.lcmsgsndr.org` |
| GHL location ID | `Bdu68oGhWuMCDoHVsnQ6` |
| Campaign ID | `mTKR5sDnmLAJJrdyFdoQ` |
| Message ID | `DUU8wk6DUkSGUmQSOfzb` |
| Callback (decoded) | `+1 (888) 350-9620` |
| AES blob salt | `515b4a475bc9d799` |

### Shared Evasion Techniques

| Technique | Description |
|-----------|-------------|
| CSS RTL bidi-override | Unicode bracket mirroring to hide callback number from scanners |
| GHL shared infra | Inherits legitimate sending reputation, passes DMARC |
| No malicious URLs | Bypasses URL scanning entirely |
| API-based send | Automated, scalable, no manual web UI interaction |
| Tracking pixel | Confirms active addresses + read receipts on email open |

---

## 13. Reporting Targets

| Target | Contact | What to Include |
|--------|---------|----------------|
| **GoHighLevel** | abuse@gohighlevel.com | Sub-accounts `f48712` and `a047bd`, all location IDs, campaign IDs, full headers |
| **Mailgun** | abuse@mailgun.com | Sending IP `159.135.225.193`, full Email 1 headers |
| **Crypto.com** | support@crypto.com | Brand impersonation, all three emails, full headers |
| **FTC** (US) | reportfraud.ftc.gov | All three callback numbers, vishing campaign description |
| **Google** | Gmail "Report phishing" | All three emails |

> GoHighLevel holds decryption keys for the `lc_email_internal` AES blobs in each email. A law enforcement request to GoHighLevel with the sub-account IDs and campaign metadata would likely yield the real identity behind both attacker accounts.

---

## 14. Defensive Takeaways

**For email users:**
- DMARC PASS does not mean a sender is who they claim. Always check the actual `From` address domain, not just the display name.
- Tracking pixels fire on email open — use plain-text view or disable remote image loading for unknown senders.
- Legitimate OTP emails never contain marketing unsubscribe links. Presence of `List-Unsubscribe` headers on a security email is an immediate red flag.
- Never call a number provided in an unsolicited security email. Navigate to the official site directly and find the support number there.

**For security researchers:**
- GoHighLevel's `X-Mailgun-Variables` header leaks stable sub-account and campaign identifiers in every email sent via their platform. The `d=` field is the primary attacker fingerprint.
- The tracking pixel payload is zlib-compressed (`wbits=15`) + base64url-encoded — not raw deflate. Decode accordingly.
- CSS `unicode-bidi: bidi-override; direction: rtl` on phone numbers is a reliable phishing indicator. Automated scanners should check for this pattern in email HTML.
- The `lc_email_internal` field is OpenSSL AES-CBC (magic bytes: `Salted__`) — recoverable by GoHighLevel under legal process.

**For Crypto.com account holders:**
- Replace SMS-based 2FA with an authenticator app (TOTP). SMS OTP is the exact credential this vishing campaign is designed to harvest via a live call.
- Check your email address at [haveibeenpwned.com](https://haveibeenpwned.com).
- File a data subject request with Crypto.com to confirm whether your email was included in any breach notification — EU/Slovak residents can do this under GDPR, Canadian residents under PIPEDA.

---

## Methodology

```
1. Raw email header collection
2. Authentication chain analysis (DKIM/SPF/DMARC)
3. Sending infrastructure identification
4. Tracking pixel extraction → base64url decode → zlib decompress → URL param parse
5. lc_email_internal field classification (OpenSSL AES-CBC)
6. CSS RTL phone decode (character reversal + Unicode bracket mirroring)
7. WHOIS lookup on platform domains
8. Cross-email correlation via sub-account ID (d= field)
9. Corporate address verification
10. Breach history research → targeting source assessment
```

---

*All personal identifiers (recipient email addresses, victim names) have been redacted. IOCs (Indicators of Compromise) are published for defensive and research purposes. No offensive use.*
