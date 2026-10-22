#!/usr/bin/env python3
"""Static checks for the generated module. Exit 1 on errors; regex compile issues are warnings
(Surge uses ICU regex, Python's engine differs in a few corners)."""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build as B  # noqa: E402

ROOT = B.ROOT
src = json.load(open(os.path.join(ROOT, "config", "sources.json"), encoding="utf-8"))
pol = json.load(open(os.path.join(ROOT, "config", "policy.json"), encoding="utf-8"))
text = open(os.path.join(ROOT, src["output"]), encoding="utf-8").read()
header, secs = B.parse_module(text)
errors, warns = [], []

if not any(l.startswith("#!name=") for l in header):
    errors.append("missing #!name")
for name in secs:
    if name not in B.SECTION_ORDER:
        errors.append(f"unexpected section [{name}]")

RULE_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD", "IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP",
              "URL-REGEX", "USER-AGENT", "PROCESS-NAME", "AND", "OR", "NOT", "DEST-PORT", "PROTOCOL"}
in_exc, seen = False, set()
for line in secs.get("Rule", []):
    s = line.strip()
    if s.startswith("# ===== 例外放行"):
        in_exc = True
    elif s.startswith("# ===== 来源"):
        in_exc = False
    if not s or s.startswith("#"):
        continue
    if s in seen:
        errors.append("duplicate rule: " + s)
    seen.add(s)
    p = B.split_rule(s)
    t = p[0].upper()
    if t not in RULE_TYPES:
        errors.append("unknown rule type: " + s)
        continue
    policy = s.rsplit(",", 1)[-1].strip() if t in ("AND", "OR", "NOT") else p[2]
    if policy == "DIRECT":
        if not in_exc:
            errors.append("DIRECT outside exceptions: " + s)
    elif policy not in B.REJECT_POLICIES:
        errors.append("bad policy: " + s)
    if t in ("IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP") and "no-resolve" not in s:
        errors.append("IP rule without no-resolve (would force DNS for every request): " + s)
    if t in ("DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD") and policy != "DIRECT":
        for h in pol["protect_domains"]:
            if B.rule_hits(t, p[1], h):
                errors.append(f"rule blocks protected host {h}: {s}")

def check_regex(pat, where):
    pat = pat.strip('"')
    try:
        re.compile(pat)
    except re.error as e:
        warns.append(f"{where}: python cannot compile ({e}): {pat[:90]}")

for sec in B.REWRITE_SECTIONS:
    for line in secs.get(sec, []):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s in seen:
            errors.append(f"duplicate {sec}: {s[:120]}")
        seen.add(s)
        if sec == "Script":
            for k in ("type", "pattern", "script-path"):
                if B.script_field(s, k) is None:
                    errors.append(f"script missing {k}: {s[:120]}")
            sp = B.script_field(s, "script-path") or ""
            if not sp.startswith("https://"):
                errors.append("script-path not https: " + s[:120])
        elif sec == "Body Rewrite" and not re.match(r"^http-(request|response)(-jq)?\s", s):
            errors.append("bad body rewrite: " + s[:120])
        elif sec == "Header Rewrite" and not re.match(r"^http-(request|response)\s", s):
            errors.append("bad header rewrite: " + s[:120])
        elif sec == "URL Rewrite" and len(s.split()) < 3:
            errors.append("bad url rewrite: " + s[:120])
        pat = B.line_pattern(sec, s)
        if pat:
            check_regex(pat, sec)
        if sec in ("Body Rewrite", "Map Local") and B.unlock_signature(s.split(None, 1)[-1]):
            errors.append("unlock signature: " + s[:120])

mitm = [l for l in secs.get("MITM", []) if l.strip().startswith("hostname")]
if len(mitm) != 1 or "%APPEND%" not in mitm[0]:
    errors.append("MITM must be one hostname = %APPEND% line")
else:
    hosts = [h.strip() for h in mitm[0].split("%APPEND%", 1)[1].split(",") if h.strip()]
    if len(hosts) != len(set(hosts)):
        errors.append("duplicate MITM hosts")
    for h in hosts:
        if h.startswith("-"):
            continue
        hit = B.mitm_match(h, pol["protect_mitm"])
        if hit:
            errors.append(f"MITM host {h} inside protected {hit}")

print(f"errors={len(errors)} warnings={len(warns)}")
for e in errors[:50]:
    print("ERROR", e)
for w in warns[:30]:
    print("WARN ", w)
sys.exit(1 if errors else 0)
