#!/usr/bin/env python3
# -*- coding: utf-8 -*-


"""
Author : Saurabh Jain

Email Auth Auditor: SPF, DKIM, DMARC (Simple, Colorful, Email-aware)
- Console: simple 'psql' tables + ANSI colors (via `colored`)
- Also supports Markdown / JSON output
- EXTRA:
  * Accept an email with -e/--email, extract domain, then audit
  * Save results to JSON file with -o/--output-json

Examples
  python3 audit_email_auth.py -e alice@example.com
  python3 audit_email_auth.py -d example.com -o result.json
  python3 audit_email_auth.py -e bob@bücher.example -f markdown
  python3 audit_email_auth.py -e user@example.com -f json -o out.json
"""

import argparse
import base64
import binascii
import idna
import json
import re
import sys
import time
from typing import List, Dict, Tuple, Any, Optional, Set
from email.utils import parseaddr

import dns.resolver
import dns.exception
from tabulate import tabulate

# ---------- COLORS (colored) ----------
try:
    from colored import fg, attr
    USE_COLORED = True
except ImportError:
    USE_COLORED = False
    def fg(_): return ""
    def attr(_): return ""

def colorize(s: str, color: Optional[str] = None, bold: bool = False) -> str:
    if not USE_COLORED:
        return s
    return f"{attr('bold') if bold else ''}{fg(color) if color else ''}{s}{attr('reset')}"

def c_good(s: str) -> str:   return colorize(s, "green", True)
def c_warn(s: str) -> str:   return colorize(s, "yellow", True)
def c_bad(s: str) -> str:    return colorize(s, "red", True)
def c_info(s: str) -> str:   return colorize(s, "cyan", True)
def c_title(s: str) -> str:  return colorize(s, "magenta", True)

def color_status(s: str) -> str:
    t = (s or "").lower()
    if t == "found": return c_good(s)
    if t == "not_found": return c_bad(s)
    return s

def color_strength(s: str) -> str:
    t = (s or "").lower()
    if "strong" in t: return c_good(s)
    if "weak" in t or "unknown" in t: return c_warn(s)
    return s

def color_policy(p: str) -> str:
    t = (p or "-").lower()
    if t == "reject": return c_good(p)
    if t == "quarantine": return c_warn(p)
    if t in ("none", "-", "not set"): return c_bad(p)
    return p

def color_lookup(n: int, limit: int = 10) -> str:
    if n > limit: return c_bad(str(n))
    if n >= 8:    return c_warn(str(n))
    return c_good(str(n))

def color_notes(notes: List[str]) -> str:
    out = []
    for n in notes:
        low = n.lower()
        if low.startswith("danger") or "permerror" in low:
            out.append(c_bad(n))
        elif low.startswith(("avoid", "pct=")) or "partial" in low:
            out.append(c_warn(n))
        elif low.startswith(("consider", "add ", "set ")):
            out.append(c_info(n))
        else:
            out.append(n)
    return " ; ".join(out) if out else "-"

def color_risk_band(b: str) -> str:
    b = (b or "").upper()
    if b == "HIGH": return c_bad(b)
    if b == "MEDIUM": return c_warn(b)
    return c_good(b)

# ---------- Constants ----------
COMMON_DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "s1", "s2", "mail", "mx"]
SPF_LOOKUP_LIMIT = 10
TABLEFMT = "psql"   

# ---------- DNS helpers ----------
def dns_txt_query(resolver: dns.resolver.Resolver, name: str) -> List[str]:
    records: List[str] = []
    try:
        answers = resolver.resolve(name, "TXT")
        for rr in answers:
            if hasattr(rr, "strings") and rr.strings:
                parts = [
                    p.decode("utf-8", "ignore") if isinstance(p, (bytes, bytearray)) else str(p)
                    for p in rr.strings
                ]
                records.append("".join(parts).strip())
            else:
                records.append(str(rr).strip().strip('"'))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        pass
    return records

def dns_exists(resolver: dns.resolver.Resolver, name: str, rrtype: str) -> bool:
    try:
        resolver.resolve(name, rrtype)
        return True
    except Exception:
        return False

# ---------- SPF ----------
SPF_MECH_PATTERN = re.compile(r'\b(v=spf1)(?P<body>.*)', re.I)

def extract_spf(txts: List[str]) -> str:
    for t in txts:
        if t.lower().startswith("v=spf1"):
            return t
    return ""

def spf_mechanisms(spf: str) -> List[str]:
    if not spf:
        return []
    m = SPF_MECH_PATTERN.search(spf)
    body = m.group("body") if m else spf[len("v=spf1"):]
    return [tok for tok in re.split(r'\s+', body.strip()) if tok]

def spf_dns_lookups(resolver: dns.resolver.Resolver, spf: str, domain: str, visited: Optional[Set[str]] = None, depth: int = 0) -> int:
    if not spf:
        return 0
    visited = visited or set()
    lookups = 0
    tokens = spf_mechanisms(spf)

    def _is_ip(tok: str) -> bool: return tok.startswith(("ip4:", "ip6:"))

    for tok in tokens:
        base = tok.lstrip("+-~?")
        if base.startswith("include:"):
            lookups += 1
            target = base.split(":", 1)[1]
            key = f"include:{target}"
            if key not in visited and depth < 10:
                visited.add(key)
                inc_spf = extract_spf(dns_txt_query(resolver, target))
                lookups += spf_dns_lookups(resolver, inc_spf, target, visited, depth + 1)
        elif base == "a" or base.startswith("a:"):
            lookups += 1
        elif base == "mx" or base.startswith("mx:"):
            lookups += 1
        elif base.startswith(("ptr", "exists:")):
            lookups += 1
        elif base.startswith("redirect="):
            lookups += 1
            target = base.split("=", 1)[1]
            key = f"redirect:{target}"
            if key not in visited and depth < 10:
                visited.add(key)
                red_spf = extract_spf(dns_txt_query(resolver, target))
                lookups += spf_dns_lookups(resolver, red_spf, target, visited, depth + 1)
            break
        elif _is_ip(tok):
            pass
    return lookups

def parse_spf(resolver: dns.resolver.Resolver, txts: List[str], domain: str) -> Tuple[str, Dict[str, Any]]:
    spf = extract_spf(txts)
    info: Dict[str, Any] = {
        "status": "not_found", "strength": "-", "notes": [], "lookups": 0, "mechanisms": []
    }
    if not spf: return spf, info

    info["status"] = "found"
    mechs = spf_mechanisms(spf)
    info["mechanisms"] = mechs

    all_token = next((m for m in mechs if m.endswith("all")), None)
    if all_token:
        if all_token.startswith("-"): info["strength"] = "strong (-all)"
        elif all_token.startswith("~"):
            info["strength"] = "weak (~all)"; info["notes"].append("Softfail; spoofed mail may be accepted downstream.")
        elif all_token.startswith("?"):
            info["strength"] = "weak (?all)"; info["notes"].append("Neutral; no enforcement.")
        else:
            info["strength"] = "unknown (no qualifier on all)"; info["notes"].append("Consider -all for hard-fail.")
    else:
        info["strength"] = "unknown (no all)"; info["notes"].append("SPF missing 'all' — add '-all' to enforce.")

    if any(t for t in mechs if t.startswith("+all") or t == "all"):
        info["notes"].append("Danger: '+all' or bare 'all' permits any sender.")
    if any(t for t in mechs if t.startswith("ptr")):
        info["notes"].append("Avoid 'ptr' — slow/unreliable and discouraged.")
    if "a" in mechs or any(t.startswith("a:") for t in mechs):
        info["notes"].append("Broad 'a' mechanism; ensure only intended hosts resolve.")
    if "mx" in mechs or any(t.startswith("mx:") for t in mechs):
        info["notes"].append("Broad 'mx' mechanism; ensure MX hosts aren't open relays.")
    if not any(t.startswith(("ip4:", "ip6:", "include:")) for t in mechs):
        info["notes"].append("No explicit ip/include mechanisms; verify coverage.")

    info["lookups"] = spf_dns_lookups(resolver, spf, domain)
    if info["lookups"] > SPF_LOOKUP_LIMIT:
        info["notes"].append(f"SPF triggers {info['lookups']} DNS lookups (>10) — receivers may permerror.")
    return spf, info

# ---------- DMARC ----------
def parse_tag(record: str, key: str, default: Optional[str] = None) -> Optional[str]:
    if not record: return default
    pattern = re.compile(r'\b' + re.escape(key) + r'\s*=\s*([^;]+)', re.IGNORECASE)
    m = pattern.search(record)
    if not m: return default
    val = m.group(1).strip().strip('"').strip("'")
    return val if val else default

def extract_dmarc(txts: List[str]) -> str:
    for t in txts:
        if t.lower().startswith("v=dmarc1"):
            return t
    return ""

def mailto_list_is_valid(val: Optional[str]) -> bool:
    if not val: return False
    for part in val.split(","):
        part = part.strip()
        if not part.lower().startswith("mailto:"): return False
        addr = part.split(":", 1)[1].split("!")[0]
        if not addr or "@" not in addr or addr.startswith("@") or addr.endswith("@"): return False
    return True

def parse_dmarc(txts: List[str]) -> Tuple[str, Dict[str, Any]]:
    dmarc = extract_dmarc(txts)
    info: Dict[str, Any] = {
        "status": "not_found", "policy": "-", "sp_policy": "-",
        "alignment": {"adkim": "r", "aspf": "r"},
        "reporting": {"rua": None, "ruf": None, "ri": None, "fo": None, "pct": 100},
        "notes": [],
    }
    if not dmarc: return dmarc, info

    info["status"] = "found"
    policy = parse_tag(dmarc, "p", "none")
    sp_policy = parse_tag(dmarc, "sp")
    adkim = parse_tag(dmarc, "adkim", "r")
    aspf = parse_tag(dmarc, "aspf", "r")
    rua = parse_tag(dmarc, "rua")
    ruf = parse_tag(dmarc, "ruf")
    ri = parse_tag(dmarc, "ri")
    fo = parse_tag(dmarc, "fo")
    pct = parse_tag(dmarc, "pct")

    info["policy"] = (policy or "none").lower()
    info["sp_policy"] = (sp_policy or "-").lower()
    info["alignment"] = {"adkim": (adkim or "r").lower(), "aspf": (aspf or "r").lower()}
    info["reporting"] = {
        "rua": rua, "ruf": ruf, "ri": int(ri) if ri and ri.isdigit() else None,
        "fo": fo, "pct": int(pct) if pct and pct.isdigit() else 100
    }

    if info["policy"] == "none":
        info["notes"].append("Policy p=none (monitoring only); spoofing not blocked.")
    if info["policy"] not in ("quarantine", "reject"):
        info["notes"].append("Set p=reject (or p=quarantine as a ramp-step).")
    if info["alignment"]["adkim"] != "s" or info["alignment"]["aspf"] != "s":
        info["notes"].append("Use strict alignment: adkim=s; aspf=s for best protection.")
    if rua and not mailto_list_is_valid(rua):
        info["notes"].append("rua is malformed; must be mailto:addr[,mailto:addr...]")
    if ruf and not mailto_list_is_valid(ruf):
        info["notes"].append("ruf is malformed; must be mailto:addr[,mailto:addr...]")
    if info["reporting"]["pct"] < 100 and info["policy"] in ("quarantine", "reject"):
        info["notes"].append(f"pct={info['reporting']['pct']} — partial enforcement; consider pct=100.")
    if not rua:
        info["notes"].append("Add rua for aggregate visibility.")
    if not fo:
        info["notes"].append("Consider fo=1 for detailed failure reports (if you can process them).")
    return dmarc, info

# ---------- DKIM ----------
def approx_key_bits_from_p(p_b64: str) -> Optional[int]:
    try:
        # pad base64 if needed and decode strictly
        p_b64_padded = p_b64 + '=' * (-len(p_b64) % 4)
        key_bytes = base64.b64decode(p_b64_padded, validate=True)
        return (len(key_bytes) * 8) if key_bytes else None
    except (binascii.Error, ValueError):
        return None

def parse_dkim(txts: List[str]) -> Tuple[str, Dict[str, Any]]:
    dkim = ""
    info: Dict[str, Any] = {"status": "not_found", "key_info": "-", "notes": []}
    for t in txts:
        if t.lower().startswith("v=dkim1"):
            dkim = t; break
    if not dkim: return dkim, info

    info["status"] = "found"
    k = parse_tag(dkim, "k", "rsa")
    p = parse_tag(dkim, "p")
    if p:
        bits = approx_key_bits_from_p(p)
        if bits:
            info["key_info"] = f"public key present (~{bits} bits est.)"
            if bits < 1024: info["notes"].append("Key appears very small (<1024b); rotate immediately.")
            elif (k or "rsa").lower() == "rsa" and bits < 2048:
                info["notes"].append("Use RSA 2048-bit or ed25519 for modern security.")
        else:
            info["key_info"] = "public key present (size unknown)"
            info["notes"].append("p= value is not valid base64.")
    else:
        info["key_info"] = "missing p= (no public key)"
        info["notes"].append("Publish p= with base64 public key.")
    if k and k.lower() not in ("rsa", "ed25519"):
        info["notes"].append(f"Uncommon key type k={k}; ensure receiver support.")
    return dkim, info

# ---------- Extras ----------
def check_bimi(resolver: dns.resolver.Resolver, domain: str) -> Optional[str]:
    recs = dns_txt_query(resolver, f"default._bimi.{domain}")
    for t in recs:
        if t.lower().startswith("v=bimi1"):
            return t
    return None

# ---------- Scoring & Recommendations ----------
def assess_risk(spf_info: Dict[str, Any], dmarc_info: Dict[str, Any], dkim_found: bool, dkim_weak: bool) -> Dict[str, Any]:
    score = 0; reasons: List[str] = []
    if dmarc_info["status"] != "found": score += 60; reasons.append("DMARC missing.")
    elif dmarc_info["policy"] == "none": score += 40; reasons.append("DMARC p=none (no enforcement).")
    elif dmarc_info["policy"] == "quarantine": score += 15; reasons.append("DMARC p=quarantine (partial enforcement).")
    if dmarc_info["status"] == "found":
        if dmarc_info["alignment"]["adkim"] != "s": score += 5; reasons.append("DKIM alignment relaxed (adkim=r).")
        if dmarc_info["alignment"]["aspf"] != "s": score += 5; reasons.append("SPF alignment relaxed (aspf=r).")
        if dmarc_info["reporting"]["pct"] < 100 and dmarc_info["policy"] in ("quarantine", "reject"):
            score += 10; reasons.append("DMARC pct<100 (partial rollout).")
    if spf_info["status"] != "found": score += 35; reasons.append("SPF missing.")
    else:
        if "weak" in spf_info["strength"]: score += 20; reasons.append(f"SPF {spf_info['strength']}.")
        if "unknown" in spf_info["strength"]: score += 10; reasons.append("SPF lacks explicit -all.")
        if any("Danger: '+all'" in n for n in spf_info["notes"]): score += 40; reasons.append("SPF has +all/bare all.")
        if spf_info.get("lookups", 0) > SPF_LOOKUP_LIMIT: score += 10; reasons.append("SPF exceeds 10 DNS lookups.")
    if not dkim_found: score += 15; reasons.append("No DKIM selectors found.")
    elif dkim_weak: score += 8; reasons.append("DKIM key likely <2048-bit.")
    score = max(0, min(100, score))
    band = "LOW" if score < 25 else "MEDIUM" if score < 60 else "HIGH"
    return {"risk_score": score, "risk_band": band, "reasons": reasons}

def build_recommendations(resolver: dns.resolver.Resolver, domain: str, spf_info: Dict[str, Any],
                          dmarc_info: Dict[str, Any], dkim_found: bool, dkim_weak: bool) -> List[str]:
    recs: List[str] = []
    if spf_info["status"] != "found":
        recs.append("Publish SPF: e.g., v=spf1 include:_spf.google.com -all")
    else:
        if "weak" in spf_info["strength"] or "unknown" in spf_info["strength"]:
            recs.append("Change SPF to hard-fail: use '-all' at end.")
        if any("Danger: '+all'" in n for n in spf_info["notes"]):
            recs.append("Remove '+all' (or bare 'all'); allows anyone to send.")
        if spf_info.get("lookups", 0) > SPF_LOOKUP_LIMIT:
            recs.append("Reduce SPF DNS lookups to ≤10 (flatten includes or consolidate).")
    if dmarc_info["status"] != "found":
        recs.append(f"Publish DMARC at _dmarc.{domain} with p=reject and rua to monitored mailbox.")
    else:
        if dmarc_info["policy"] not in ("quarantine", "reject"):
            recs.append("Set DMARC policy to p=reject (or ramp via p=quarantine → p=reject).")
        if dmarc_info["alignment"]["adkim"] != "s" or dmarc_info["alignment"]["aspf"] != "s":
            recs.append("Set strict alignment: adkim=s; aspf=s.")
        if not dmarc_info["reporting"].get("rua"):
            recs.append(f"Add rua=mailto:dmarc-reports@{domain} for aggregate visibility.")
        if dmarc_info["reporting"]["pct"] < 100 and dmarc_info["policy"] in ("quarantine", "reject"):
            recs.append("Increase pct to 100 for full enforcement.")
        if not dmarc_info["reporting"].get("fo"):
            recs.append("Add fo=1 to receive failure samples (if you can process them).")
    if not dkim_found:
        recs.append("Enable DKIM for all sending platforms; publish selectors with v=DKIM1; k=rsa; p=<key>.")
    elif dkim_weak:
        recs.append("Rotate DKIM keys to RSA 2048-bit (or ed25519) and set adkim=s.")
    if not dns_exists(resolver, f"_mta-sts.{domain}", "TXT"):
        recs.append(f"Consider MTA-STS (_mta-sts.{domain} TXT + HTTPS policy) to improve TLS delivery.")
    if not check_bimi(resolver, domain):
        recs.append("Optional: Publish BIMI (v=BIMI1) once DMARC quarantine/reject is in place and reputation allows.")
    return recs

# ---------- Markdown (plain) ----------
def format_table_md(headers: List[str], rows: List[List[str]]) -> str:
    return tabulate(rows, headers=headers, tablefmt="github")

def to_markdown(report: Dict[str, Any]) -> str:
    lines = [f"# Email Authentication Audit for `{report['domain']}`",
             f"**Risk:** {report['risk']['risk_band']} ({report['risk']['risk_score']}/100)", ""]
    spf = report["spf"]
    lines += ["## SPF", "",
              format_table_md(["Control","Status","Strength","Lookups","Notes","Record"],
                              [["SPF", spf["status"], spf.get("strength","-"), str(spf.get("lookups",0)),
                                "; ".join(spf.get("notes", [])) or "-", report['records'].get('spf','-')]]),
              ""]
    dmarc = report["dmarc"]
    align = f"adkim={dmarc['alignment']['adkim']}; aspf={dmarc['alignment']['aspf']}"
    rep = dmarc["reporting"]
    rep_s = f"pct={rep['pct']}; ri={rep['ri']}; fo={rep['fo']}; rua={rep['rua']}; ruf={rep['ruf']}"
    lines += ["## DMARC", "",
              format_table_md(["Control","Status","Policy","Alignment","Reporting","Record"],
                              [["DMARC", dmarc["status"], dmarc.get("policy","-"), align, rep_s, report['records'].get('dmarc','-')]]),
              ""]
    rows_plain = report["dkim"]["rows"]
    lines += ["## DKIM", "",
              format_table_md(["Selector","Status","Key","Notes"], rows_plain or [["-","not_checked","-","-"]]),
              "",
              "## Recommendations", ""]
    for rec in report["recommendations"]:
        lines.append(f"- {rec}")
    return "\n".join(lines)

# ---------- Helpers ----------
def extract_domain_from_email(email_input: str) -> str:
    """Parse email (handles 'Name <user@domain>') and return unicode domain (no trailing dot)."""
    addr = parseaddr(email_input)[1].strip()
    if "@" not in addr:
        raise ValueError(f"Invalid email address: {email_input!r}")
    domain_part = addr.split("@", 1)[1].strip().rstrip(".")
    if not domain_part:
        raise ValueError(f"Invalid email address: {email_input!r}")
    return domain_part  # unicode domain; will IDNA-encode later

# ---------- Main ----------
def main():
    parser = argparse.ArgumentParser(description="Audit SPF, DKIM, DMARC for a domain (simple colorful output).")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--domain", help="Domain to check (e.g., example.com)")
    group.add_argument("-e", "--email", help="Email to check (extracts domain and audits it)")
    parser.add_argument("-s", "--selectors", nargs="*", default=COMMON_DKIM_SELECTORS,
                        help=f"DKIM selectors to try (default: {' '.join(COMMON_DKIM_SELECTORS)})")
    parser.add_argument("-f", "--format", choices=["table", "markdown", "json"], default="table",
                        help="Output format")
    parser.add_argument("-o", "--output-json", help="Save full JSON results to this file path")
    parser.add_argument("--timeout", type=float, default=3.0, help="DNS query timeout in seconds")
    parser.add_argument("--lifetime", type=float, default=5.0, help="Total time for DNS query resolution")
    parser.add_argument("--no-extras", action="store_true", help="Skip optional BIMI/MTA-STS checks")
    args = parser.parse_args()

    # Determine domain (from email or domain option)
    try:
        if args.email:
            email_input = args.email.strip()
            domain_u = extract_domain_from_email(email_input)
        else:
            domain_u = args.domain.strip().rstrip(".")
        # IDNA encode to ASCII for DNS; keep unicode for display if needed
        domain = idna.encode(domain_u).decode("ascii")
    except (idna.IDNAError, ValueError) as e:
        print(c_bad(f"{e}"))
        sys.exit(2)

    resolver = dns.resolver.Resolver()
    resolver.timeout = args.timeout
    resolver.lifetime = args.lifetime

    start = time.time()
    records: Dict[str, str] = {}

    # SPF
    spf_txts = dns_txt_query(resolver, domain)
    spf_string, spf_info = parse_spf(resolver, spf_txts, domain)
    if spf_string: records["spf"] = spf_string

    # DMARC
    dmarc_txts = dns_txt_query(resolver, f"_dmarc.{domain}")
    dmarc_string, dmarc_info = parse_dmarc(dmarc_txts)
    if dmarc_string: records["dmarc"] = dmarc_string

    # DKIM
    dkim_rows_raw: List[List[str]] = []
    any_dkim_found = False
    any_dkim_weak = False
    for sel in (args.selectors or []):
        qname = f"{sel}._domainkey.{domain}"
        txts = dns_txt_query(resolver, qname)
        _, dkim_info = parse_dkim(txts)
        status = dkim_info["status"]
        notes_col = "; ".join(dkim_info["notes"]) if dkim_info["notes"] else "-"
        if status == "found":
            any_dkim_found = True
            if any(x in notes_col for x in ("<1024", "<2048", "very small")):
                any_dkim_weak = True
        dkim_rows_raw.append([sel, status, dkim_info["key_info"], notes_col])

    # Extras
    bimi_record, mta_sts_present = None, False
    if not args.no_extras:
        bimi_record = check_bimi(resolver, domain)
        mta_sts_present = dns_exists(resolver, f"_mta-sts.{domain}", "TXT")

    # Risk & Recs
    risk = assess_risk(spf_info, dmarc_info, any_dkim_found, any_dkim_weak)
    recs = build_recommendations(resolver, domain, spf_info, dmarc_info, any_dkim_found, any_dkim_weak)

    # -------- Report object ----------
    report: Dict[str, Any] = {
        "input": {"type": "email" if args.email else "domain",
                  "value": args.email if args.email else args.domain},
        "domain": domain_u,
        "idna_domain": domain,
        "records": records,
        "spf": spf_info,
        "dmarc": dmarc_info,
        "dkim": {"rows": dkim_rows_raw, "any_found": any_dkim_found, "any_weak": any_dkim_weak},
        "extras": {"bimi": bimi_record, "mta_sts": mta_sts_present} if not args.no_extras else {},
        "risk": risk,
        "recommendations": recs,
        "timing_ms": int((time.time() - start) * 1000),
    }

    # Save JSON if requested (independent of display format)
    if args.output_json:
        try:
            with open(args.output_json, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            print(c_info(f"Saved JSON report to: {args.output_json}"))
        except Exception as ex:
            print(c_bad(f"Failed to write JSON file: {ex}"))

    # -------- OUTPUT ----------
    if args.format == "json":
        print(json.dumps(report, indent=2))
    elif args.format == "markdown":
        print(to_markdown({
            "domain": domain,
            "records": records,
            "spf": spf_info,
            "dmarc": dmarc_info,
            "dkim": {"rows": dkim_rows_raw, "any_found": any_dkim_found, "any_weak": any_dkim_weak},
            "extras": {"bimi": bimi_record, "mta_sts": mta_sts_present} if not args.no_extras else {},
            "risk": risk,
            "recommendations": recs,
        }))
    else:
        title = f"\n● Email Authentication Audit for: {domain_u} ({'from email' if args.email else 'domain'})\n"
        print(c_title(title))

        # SPF (single-row)
        spf_row = [[
            "SPF",
            color_status(spf_info["status"]),
            color_strength(spf_info["strength"]),
            color_lookup(spf_info["lookups"], SPF_LOOKUP_LIMIT),
            color_notes(spf_info["notes"]),
            c_info(records.get("spf", "-"))
        ]]
        print(tabulate(spf_row, headers=["Control","Status","Strength","Lookups","Notes","Record"], tablefmt=TABLEFMT))
        print()

        # DMARC (single-row)
        rep = dmarc_info["reporting"]
        align = f"adkim={dmarc_info['alignment']['adkim']}; aspf={dmarc_info['alignment']['aspf']}"
        rep_s = f"pct={rep['pct']}; ri={rep['ri']}; fo={rep['fo']}; rua={rep['rua']}; ruf={rep['ruf']}"
        dmarc_row = [[
            "DMARC",
            color_status(dmarc_info["status"]),
            color_policy(dmarc_info.get("policy","-")),
            align,
            rep_s,
            c_info(records.get("dmarc","-"))
        ]]
        print(tabulate(dmarc_row, headers=["Control","Status","Policy","Alignment","Reporting","Record"], tablefmt=TABLEFMT))
        print()

        # DKIM (multi-row)
        dkim_rows_colored = [[c_info(sel), color_status(st), key, notes] for sel, st, key, notes in dkim_rows_raw]
        print(tabulate(dkim_rows_colored or [["-","not_checked","-","-"]],
                       headers=["Selector","Status","Key","Notes"], tablefmt=TABLEFMT))
        print()

        # Extras
        if not args.no_extras:
            extras_rows = [
                ["BIMI", c_good("present") if bimi_record else c_bad("missing")],
                ["MTA-STS", c_good("present") if mta_sts_present else c_bad("missing")],
            ]
            print(tabulate(extras_rows, headers=["Optional Controls","Status"], tablefmt=TABLEFMT))
            print()

        # Risk
        risk_row = [[color_risk_band(risk["risk_band"]), str(risk["risk_score"]), "; ".join(risk["reasons"]) or "-"]]
        print(tabulate(risk_row, headers=["Overall Risk","Score","Reasons"], tablefmt=TABLEFMT))
        print()

        # Recommendations (bulleted list)
        print(c_title("Recommendations:"))
        for r in recs:
            bullet = "• " + (c_info(r) if r.lower().startswith(("publish","enable","set","add","change","remove","increase","reduce")) else r)
            print(bullet)
        print()

    # Exit code by risk band
    if risk["risk_band"] == "HIGH":
        sys.exit(2)
    elif risk["risk_band"] == "MEDIUM":
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()

