# CodeWhy Vercel Firewall & Edge Security Configuration Guide

This document provides exact instructions for configuring the **Vercel Web Application Firewall (WAF)**, **DDoS Mitigation**, and **Edge Security Rules** for the CodeWhy platform.

---

## 1. Architecture Overview

CodeWhy uses a **Defense-in-Depth** architecture across two complementary firewall layers:

```
[ Internet Traffic ]
        │
        ▼
[ Layer 1: Vercel Edge Firewall ]
   • Anycast Layer 3/4/7 DDoS Mitigation
   • Custom WAF Rules (Bot detection, Rate limiting, IP blocking)
   • Edge-enforced Security Headers & CSP
        │
        ▼
[ Layer 2: CodeWhy Application Firewall (Shield) ]
   • Sliding-window Rate Limiting with SQLite persistence
   • Request Payload Size & MIME Type Verification
   • Path Traversal, Null-Byte, and Query Sanitization
   • GitHub OAuth 2.0 & Role-Based Access Control (RBAC)
   • Sensitive Token Redaction & Audit Logging
        │
        ▼
[ Internal Core & AI Engines ]
   • Neo4j Knowledge Graph
   • Sarvam AI Multilingual Reasoning
```

---

## 2. Vercel Edge Firewall Setup (Dashboard Steps)

### Step 2.1: Enable Platform DDoS Mitigation
1. Open the [Vercel Project Dashboard](https://vercel.com/dashboard).
2. Select the **CodeWhy** project.
3. Navigate to **Settings** → **Security**.
4. Under **Attack Challenge Mode**, ensure it is set to **Automatic** (or **Managed**). This activates automatic challenges (Cloudflare / Edge challenges) when unusual volumetric traffic spikes occur.

### Step 2.2: Configure Custom WAF Rules

In the Vercel Dashboard under **Security** → **Firewall** → **Custom Rules**, add the following rules in order:

#### Rule 1: Protect Authentication & OAuth Callback
- **Rule Name**: `Protect-Auth-Endpoints`
- **Condition**:
  - `Path` equals `/api/auth/github` OR `Path` equals `/api/auth/callback`
- **Action**: **Rate Limit**
  - **Limit**: `15 requests` per `1 minute` per client IP.
  - **Action on exceed**: `HTTP 429 Too Many Requests`.
- **Reason**: Prevents credential stuffing, state-cookie flooding, and OAuth amplification abuse without interrupting normal developer sign-ins.

#### Rule 2: Protect Compute-Heavy AI & Scan Endpoints
- **Rule Name**: `Protect-Scan-And-AI-Endpoints`
- **Condition**:
  - `Path` starts with `/api/repos/scan` OR
  - `Path` contains `/sentinel/investigate` OR
  - `Path` contains `/pull-request/review`
- **Action**: **Rate Limit**
  - **Limit**: `10 requests` per `1 minute` per client IP.
  - **Action on exceed**: `HTTP 429 Too Many Requests`.
- **Reason**: Protects backend AST parsing, graph algorithms, and Sarvam AI synthesis from resource exhaustion.

#### Rule 3: Block Suspicious Automated Scrapers
- **Rule Name**: `Challenge-Automated-Scrapers`
- **Condition**:
  - `User-Agent` matches regex `(?i)(sqlmap|nikto|nmap|dirbuster|acunetix|masscan|zgrab)`
- **Action**: **Deny (HTTP 403)** or **Interactive Challenge**.
- **Reason**: Instantly terminates known malicious scanner reconnaissance.

#### Rule 4: Block Malformed Request URIs
- **Rule Name**: `Block-Malformed-Paths`
- **Condition**:
  - `Path` contains `/..` OR `Path` contains `..\\` OR `Query` contains `%00`
- **Action**: **Deny (HTTP 400)**.
- **Reason**: Drops directory traversal attempts at the edge before hitting serverless functions.

---

## 3. Edge Security Headers (`vercel.json`)

The platform's [vercel.json](file:///c:/Users/kanik/OneDrive/Desktop/codewhy1/codewhyfinal/vercel.json) enforces enterprise-grade HTTP response headers at the edge:

| Header | Value | Purpose |
| :--- | :--- | :--- |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` | Forces HTTPS for 2 years across all domains. |
| `X-Content-Type-Options` | `nosniff` | Prevents MIME-sniffing attacks. |
| `X-Frame-Options` | `DENY` | Prevents UI clickjacking and iframe framing. |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Protects referrer leakage on outbound requests. |
| `Permissions-Policy` | `camera=(), microphone=(self), geolocation=(), payment=()` | Restricts hardware APIs (allows mic for Sarvam voice). |
| `Content-Security-Policy` | `default-src 'self'; ...` | Restricts script, style, image, and socket origins. |

---

## 4. Monitoring & Alerting

1. **Firewall Activity Stream**:
   - Access **Security** → **Firewall** in Vercel to inspect live traffic, challenge pass rates, and blocked IP statistics.
2. **Webhook Security Alerts**:
   - Navigate to **Settings** → **Webhooks**.
   - Create a webhook subscribed to `security.attack.detected` and `firewall.rule.triggered`.
   - Forward alerts to your incident notification channel (e.g. Slack/Discord webhook or PagerDuty).
3. **Application Synchronization**:
   - All layer-2 firewall blocks are automatically captured in CodeWhy's local `security_events` database and visible to Administrators under the **Security Shield** tab.
