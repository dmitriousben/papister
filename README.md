# papister
A tool ready for APIs analysis and security that's Papister.
Everything is explained at 

```bash
https://dmitriousben.github.io/papister
```
But a brief explanation is cool..

## What Papister does

Papister is a local API security and testing toolkit built for developers who test their own APIs, third-party integrations (Binance, Stripe, Africa's Talking, etc.), and want to go deep on security without opening Postman or Burp Suite.

## Build instructions

### 1. Requirements

- Python 3.9 or higher
- pip

Check your version:
```bash
python3 --version
```

---

### 2. Clone or unzip

If you have the folder as a zip, unzip it:
```bash
unzip papister.zip -d papister
cd papister
```

Or if you cloned from git:
```bash
git clone <your-repo-url>
cd papister
```

---

### 3. (Recommended) Create a virtual environment

```bash
python3 -m venv venv

# Activate — Linux / macOS
source venv/bin/activate

# Activate — Windows
venv\Scripts\activate
```

---

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

What gets installed:
```
requests        — HTTP engine
typer           — CLI framework
rich            — terminal output (tables, colors, panels)
pyyaml          — YAML collection files
cryptography    — AES-256-GCM vault encryption
requests-oauthlib — OAuth1 signing
httpx           — async HTTP (proxy layer)
nvdlib          — NVD CVE feed
python-dateutil — date parsing
```

---

### 5. Verify installation

```bash
python cli.py version
```

You should see:
```
Papister  v1.0.0
CVE DB last updated: never — run: papister cve update
```

---

### 6. Open the command reference

```bash
python cli.py docs
```

Opens `docs/commands.html` in your browser — full offline reference.

---

### 7. Run your first scan

```bash
# Test a single endpoint directly
python cli.py test https://httpbin.org/get

# Scan the sample collection file
python cli.py scan endpoints/endpoints.yaml --mode S

# Open the HTML report
python cli.py report
```

---

### 8. Set up your first vault entry (Mpesa example)

```bash
python cli.py vault set mpesa
```

Papister will prompt:

### 9. Set up a Binance vault entry

```bash
python cli.py vault set binance
# prompts: api_key, secret_key, testnet (yes/no), label
```

---

### 10. Run a security scan

```bash
# SQLi — level 3 (deepest)
python cli.py sqli "https://api.example.com/v1/users?id=1" --level 3

# BOLA — check if object IDs are protected
python cli.py bola https://api.example.com/v1/orders/1042 --auth my_bearer

# BOLA cross-account (two users)
python cli.py bola https://api.example.com/v1/profile/99 --auth user_a --alt-auth user_b

# Fingerprint a host + CVE check
python cli.py fingerprint https://api.example.com

# Header security audit
python cli.py headers https://api.example.com

# Fuzz parameters
python cli.py fuzz "https://api.example.com/v1/search?q=test"
```

---

### 11. Update the CVE database

```bash
python cli.py cve update
```

Run this periodically (weekly recommended — set in config/settings.yaml).

---

### 12. Add your own endpoints

Option A — edit `endpoints/endpoints.txt` (simplest):
```
GET  https://api.yoursite.com/v1/users
POST https://api.yoursite.com/v1/login
GET  https://api.yoursite.com/v1/orders/1
```

Option B — edit `endpoints/endpoints.yaml` (full control):
```yaml
- url: https://api.yoursite.com/v1/orders
  method: GET
  auth_profile: my_bearer
  tags: [orders, protected]
  mode: S
```

Option C — add from CLI while testing:
```bash
python cli.py add https://api.yoursite.com/v1/internal/debug --method GET
```

---

## Important — protect your vault

Add these to `.gitignore` (already included):
```
vault/.vault.key
vault/.vault.salt
vault/keys/
storage/history.db
storage/cve.db
reports/
```

**Never commit `.vault.key` or `.vault.salt`** — these are your encryption keys.
If you lose `.vault.key` you cannot decrypt your stored API keys. Back it up somewhere safe (not git).

---

## Adding a new integration (future)

1. Create `integrations/yourservice.py` — copy `integrations/stripe.py` as template
2. Register in `cli.py` under `integrations_run`
3. Add vault schema in `vault/schemas.py`

That's it. Nothing else needs to change.

---

## Adding a new security module (future — v0.1.1)

Planned:
- `security/jwt.py` — algorithm confusion, claim tampering, weak secret brute-force
- `security/graphql.py` — introspection, batching, deep nesting, mutation testing
- `security/soap.py` — WSDL discovery, XXE injection, SOAPAction spoofing

---

## Tech stack

| Layer | Library |
|---|---|
| CLI | Typer + Click |
| Terminal UI | Rich |
| HTTP engine | requests + urllib3 |
| Encryption | cryptography (AES-256-GCM + PBKDF2) |
| Database | SQLite3 (built-in) |
| Config | PyYAML |
| CVE data | nvdlib (NVD API) |
| OAuth1 | requests-oauthlib |

---



---

Make papister your favourite too

support my project guys..|||

Buy me coffee atleast i upgrade my machine 

### Bitcoin address
bc1q4ez87z244vs7uxqyz4sernkamjx53kkd4uyksz



# HappyWhenItHappens
# DmitriousBen
