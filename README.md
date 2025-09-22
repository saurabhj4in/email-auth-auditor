# email-auth-auditor

A fast, no-nonsense CLI to audit **SPF, DKIM, and DMARC** for any domain.

- Clean, **colorized** terminal output (via [`colored`](https://pypi.org/project/colored/)) in simple **psql-style** tables
- Heuristics for SPF strength & DNS lookup count
- DMARC policy/alignment/reporting parsing with practical guidance
- DKIM selector probing with rough key-size estimation
- Optional hygiene checks: **BIMI** and **MTA-STS**
- **Risk score** (0–100) + exit codes (great for CI)
- Also supports **JSON** and **Markdown** output

---

## Requirements

- Python **3.9+**
- Network/DNS access (the tool queries public DNS)
- A modern terminal that supports ANSI colors (most Linux/macOS shells, Windows Terminal, PowerShell 7+)

---

## Installation

Create a virtual environment (recommended) and install dependencies.

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
python3 -m pip install -r requirements.txt
```

---

## Usage

```text
usage: audit_email_auth.py [-h] -d DOMAIN [-s [SELECTORS ...]] [-f {table,markdown,json}] [--timeout TIMEOUT] [--lifetime LIFETIME] [--no-extras]

options:
  -d, --domain        Domain to check (e.g., example.com)
  -s, --selectors     DKIM selectors to try (default: default google selector1 selector2 s1 s2 mail mx)
  -f, --format        Output format: table (colorized psql), markdown, json  [default: table]
  --timeout           DNS query timeout in seconds (default: 3.0)
  --lifetime          Total time for DNS query resolution (default: 5.0)
  --no-extras         Skip optional BIMI/MTA-STS checks
```

### Quick examples

**Colorized console (default):**
```bash
python3 audit_email_auth.py -d example.com
```

**Try specific DKIM selectors:**
```bash
python3 audit_email_auth.py -d example.com -s default s1 s2
```

**Machine-readable JSON:**
```bash
python3 audit_email_auth.py -d example.com -f json | jq
```

**Markdown for tickets/reports:**
```bash
python3 audit_email_auth.py -d example.com -f markdown > audit.md
```

**Skip BIMI/MTA-STS checks:**
```bash
python3 audit_email_auth.py -d example.com --no-extras
```

---

## What it checks

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

## Exit codes (for CI/CD)

- `0` → **LOW** risk
- `1` → **MEDIUM** risk
- `2` → **HIGH** risk

GitHub Actions example:
```yaml
- name: Mail auth audit
  run: |
    python3 audit_email_auth.py -d ${{ env.DOMAIN }} -f json > audit.json
```

---

## Color not showing?

- Ensure **`colored`** is installed (`pip install colored`)
- Use a terminal that supports ANSI colors (Windows Terminal, PowerShell 7+, iTerm2, most Linux terminals)
- Colors are applied in **table** mode; `markdown` and `json` are intentionally uncolored
- Some terminals strip colors when piping; view directly in the terminal

---

## Limitations

- SPF DNS lookup counting is **approximate** (follows `include`/`redirect`, counts `a/mx/ptr/exists`)
- DKIM key size is a **heuristic** based on the `p=` value; it cannot guarantee actual modulus size
- DNS timeouts or filtered resolvers can affect results
- The tool only performs **public DNS lookups** (no email sending, no private APIs)

---

## Development

- Linting/formatting is up to you; the script is a single, self-contained file: `audit_email_auth.py`
- Useful improvements:
  - Bulk mode (read domains from a file)
  - CSV/HTML exporters
  - Smarter DKIM key parsing

---

## License

MIT
