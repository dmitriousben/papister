# Papister Plugins

Plugins are drop-in modules that extend Papister with custom checks,
integrations, or workflows. Drop a file here, register one command
in `cli.py` — that's all.

---

## How a plugin works

```
plugins/
└── your_plugin.py   ← your file
```

Every plugin follows the same pattern:

```python
from core.runner   import Runner       # for sending requests
from core.reporter import print_result # for terminal output
from core.detector import classify     # for classifying responses
from vault.vault   import Vault        # for reading encrypted keys
from storage.db    import save_result  # for persisting findings
```

---

## Minimal plugin skeleton

```python
from core.runner import Runner
from core import reporter

class MyPlugin:

    def __init__(self, proxy=None, timeout=15, auth=None):
        self.runner = Runner(proxy=proxy, timeout=timeout)
        self.auth   = auth

    def run(self, url: str):
        r = self.runner.get(url, auth=self.auth)
        reporter.print_result(r)
        return r

    def close(self):
        self.runner.close()
```

---

## Register in cli.py

```python
@app.command("myplugin")
def myplugin_cmd(url: str = typer.Argument(...)):
    """My custom plugin description."""
    from plugins.my_plugin import MyPlugin
    p = MyPlugin()
    result = p.run(url)
    p.close()
```

Then run it:
```bash
python cli.py myplugin https://api.example.com/v1/endpoint
```

---

## Using vault keys inside a plugin

```python
from vault.vault import Vault

v    = Vault()
keys = v.get("mpesa")          # decrypts vault/keys/mpesa.enc
key  = keys["consumer_key"]    # use the key
```

---

## Plugin ideas

- Rate limit detector — measure response times across repeated calls
- API version scanner — probe /v1, /v2, /v3, /v4 automatically
- Webhook tester — fire events and verify callbacks
- JWT decoder — inspect tokens in Authorization headers
- Response differ — compare two environments (staging vs prod)
- Custom telecom probe — vendor-specific endpoint tests

---

## Rules

- Import from `core/`, `auth/`, `vault/`, `storage/` — never copy their logic
- Use `Runner` for all HTTP — never import `requests` directly in a plugin
- Use `reporter.print_result()` for output — keeps style consistent
- One class per file, named `<Name>Plugin`
- Include a `close()` method that calls `self.runner.close()`

---

See `example_plugin.py` for a full working template.
