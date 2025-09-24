# email-auth-auditor

**Fast, no-nonsense CLI** to audit **SPF • DKIM • DMARC** for any domain — colorized console tables, JSON/Markdown output, and a risk score for CI.

---

## Quick Install & Run

```bash
# clone
git clone https://github.com/saurabhj4in/email-auth-auditor.git
cd email-auth-auditor

# optional: create a venv
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# install
python3 -m pip install -r requirements.txt

# run (example)
python3 email-auth-auditor.py -d example.com
```

---

## What It Checks

### SPF
- Finds the `v=spf1` record
- Grades `-all/~all/?all` (strong/weak/neutral)
- Counts DNS lookups (estimates includes, a/mx/ptr/exists/redirect)
- Flags risky bits like `+all`, `ptr`, too many lookups (>10)

### DMARC
- Parses `p`, `sp`, `adkim`, `aspf`, `rua`, `ruf`, `ri`, `fo`, `pct`
- Calls out weak policies (`p=none`) and non-strict alignment (`adkim=r`, `aspf=r`)
- Practical, prioritized recommendations

### DKIM
- Tries common selectors (configurable)
- Notes public key presence and **approx.** key size
- Encourages RSA 2048+ or ed25519

### Extras
- **BIMI** TXT at `default._bimi.<domain>`
- **MTA-STS** TXT at `_mta-sts.<domain>`

---

## Common Usage
```bash
# default colored table
python3 email-auth-auditor.py -d example.com

# JSON for automation
python3 email-auth-auditor.py -d example.com -f json

# try specific DKIM selectors
python3 email-auth-auditor.py -d example.com -s selector1 s2

# skip BIMI/MTA-STS
python3 email-auth-auditor.py -d example.com --no-extras
```

### Key Flags
- `-d, --domain` : domain to check (required)
- `-s, --selectors` : DKIM selectors to probe
- `-f, --format` : `table` (default) / `markdown` / `json`

---

## Exit Codes (for CI/CD)

- `0` → **LOW** risk
- `1` → **MEDIUM** risk
- `2` → **HIGH** risk

---

## Notes
- Requires **Python 3.9+** and network/DNS access.
- SPF lookup counting & DKIM key-size are heuristics — useful guidance, not guarantees.

---

MIT 
