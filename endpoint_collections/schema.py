"""
collections/schema.py — Endpoint file format reference
=======================================================
Describes the expected shape for .json and .yaml collection files.
Also used to validate files before loading.
"""

# ── YAML example (canonical reference) ──────────────────────────────────────
YAML_EXAMPLE = """
# endpoints.yaml — Papister collection file
# ------------------------------------------
# Each item is an endpoint to test.
# Only 'url' is required; everything else is optional.

- url: https://api.example.com/v1/users
  method: GET
  tags: [users, public]
  note: "List all users"

- url: https://api.example.com/v1/login
  method: POST
  json_body:
    username: testuser
    password: testpass
  tags: [auth]

- url: https://api.example.com/v1/orders
  method: GET
  auth_profile: my_bearer_token     # name of a saved auth profile
  headers:
    X-Custom-Header: papister
  tags: [orders, protected]

- url: https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest
  method: POST
  mode: S                           # S=sandbox  P=production
  auth_profile: mpesa_bearer
  json_body:
    BusinessShortCode: "174379"
    Amount: "1"
  tags: [mpesa, payments]
"""

# ── JSON example ─────────────────────────────────────────────────────────────
JSON_EXAMPLE = """
[
  {
    "url": "https://api.example.com/v1/users",
    "method": "GET",
    "tags": ["users", "public"],
    "note": "List all users"
  },
  {
    "url": "https://api.example.com/v1/login",
    "method": "POST",
    "json_body": { "username": "testuser", "password": "testpass" },
    "tags": ["auth"]
  }
]
"""

# ── .txt example ─────────────────────────────────────────────────────────────
TXT_EXAMPLE = """
# endpoints.txt — one URL per line
# Lines starting with # are comments
# Optional: prefix with METHOD

https://api.example.com/v1/users
POST https://api.example.com/v1/login
GET  https://api.example.com/v1/orders
https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest
"""
