#!/usr/bin/env python3
"""Build dist/Anning-AdBlock.sgmodule from upstream Surge modules.

Steps: fetch upstreams (fall back to the last good copy in cache/), drop entries
listed in config/policy.json, drop scripts that unlock paid features, protect
critical hosts, prepend config/exceptions.list, write the module and a report.

Only the Python standard library is used.

Exit codes: 0 ok; 2 no usable upstream; 3 built from cached upstream (fetch or
sanity check failed); 4 built, but some scripts could not be verified and were
left out.
"""
import argparse
import datetime as dt
import fnmatch
import hashlib
import json
import os
import re
import sys
import urllib.request
from collections import OrderedDict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CFG = os.path.join(ROOT, "config")
CACHE = os.path.join(ROOT, "cache")
TZ = dt.timezone(dt.timedelta(hours=8))
UA = "surge-modules-ann-builder (+https://github.com/AnnLhl/surge-modules-ann)"
REJECT_POLICIES = {"REJECT", "REJECT-DROP", "REJECT-NO-DROP", "REJECT-TINYGIF"}
REWRITE_SECTIONS = ("Header Rewrite", "URL Rewrite", "Body Rewrite", "Map Local", "Script")
SECTION_ORDER = ("Rule",) + REWRITE_SECTIONS + ("MITM",)

# Paid-feature unlock signatures: a VIP/member flag set to true/1, or a VIP expiry
# pushed far into the future. Plain ad start/end times are not matched.
SIG_FLAG = re.compile(
    r"""\b(?:is_?vip|vip|svip|is_?svip|vip_?level|vip_?type|vip_?status|bought_?vip|is_?paid|is_?member|"""
    r"""is_?\w*member|is_?premium|premium|has_?purchased|purchased|vip_?code|can_?play)\b["'\\]*\]?\s*(?:=|:)\s*"""
    r"""["'\\]*(?:true|!0|[1-9])""", re.I)
SIG_EXPIRY = re.compile(
    r"""\b(?:vip_?expire\w*|vip_?end\w*|bought_vip_end|due_?date|expire_?time|expires_?date|expiration_?date)\b"""
    r"""["'\\]*\]?\s*(?:=|:)\s*["'\\]*(?:\d{10,}|20[4-9]\d|2[1-9]\d\d|9999|z\b)""", re.I)


def now():
    return dt.datetime.now(TZ)


def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return default


def save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1, sort_keys=True)
        f.write("\n")


class Fetcher:
    """HTTP fetch, or a local mirror of raw.githubusercontent.com for offline tests."""

    def __init__(self, offline_dir=None):
        self.offline_dir = offline_dir

    def get(self, url, timeout=30):
        if self.offline_dir:
            m = re.match(r"https://(?:raw\.githubusercontent\.com/([^/]+)/([^/]+)/(?:refs/heads/)?[^/]+/"
                         r"|github\.com/([^/]+)/([^/]+)/raw/(?:refs/heads/)?[^/]+/)(.+)$", url)
            if not m:
                raise OSError("offline: no mirror for " + url)
            owner, repo = (m.group(1), m.group(2)) if m.group(1) else (m.group(3), m.group(4))
            path = os.path.join(self.offline_dir, f"{owner}_{repo}", m.group(5))
            with open(path, "rb") as f:
                return f.read()
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()


def strip_js_comments(text):
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return "\n".join(l for l in text.split("\n") if not l.lstrip().startswith("//"))


def unlock_signature(text):
    m = SIG_FLAG.search(text) or SIG_EXPIRY.search(text)
    return m.group(0) if m else None


def parse_module(text):
    header, sections, cur = [], OrderedDict(), None
    for line in text.replace("\r\n", "\n").split("\n"):
        m = re.match(r"^\s*\[([^\]]+)\]\s*$", line)
        if m:
            cur = m.group(1).strip()
            sections.setdefault(cur, [])
            continue
        if cur is None:
            header.append(line)
        else:
            sections[cur].append(line)
    return header, sections


def host_regex(pattern):
    """Return a compiled regex for the host part of a URL pattern, or None."""
    p = pattern.strip().strip('"')
    p = p[1:] if p.startswith("^") else p
    m = re.match(r"(?:https?\??|http\(s\)\?|http\(s\))?:\\/\\/", p)
    if not m:
        return None
    p = p[m.end():]
    depth, i, out = 0, 0, []
    while i < len(p):
        c = p[i]
        if c == "\\" and i + 1 < len(p):
            if p[i + 1] == "/" and depth == 0:
                break
            out.append(p[i:i + 2])
            i += 2
            continue
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
            if depth < 0:
                return None
        elif depth == 0 and c in "/?$":
            break
        out.append(c)
        i += 1
    if depth != 0 or not out:
        return None
    try:
        return re.compile("".join(out), re.I)
    except re.error:
        return None


def sample_host(h):
    return h.replace("*", "a1b2c3")


def host_in(host_rx, hosts):
    if host_rx is None:
        return False
    return any(host_rx.fullmatch(sample_host(h)) for h in hosts)


def mitm_match(host, patterns):
    s = sample_host(host)
    for p in patterns:
        if fnmatch.fnmatch(s, p) or fnmatch.fnmatch(sample_host(p), host) or host == p:
            return p
    return None


def rule_hits(rtype, value, host):
    value = value.lower()
    if rtype == "DOMAIN":
        return host == value
    if rtype == "DOMAIN-SUFFIX":
        return host == value or host.endswith("." + value)
    if rtype == "DOMAIN-KEYWORD":
        return value in host
    return False


def split_rule(line):
    parts, buf, q = [], "", False
    for c in line:
        if c == '"':
            q = not q
        if c == "," and not q:
            parts.append(buf.strip())
            buf = ""
        else:
            buf += c
    parts.append(buf.strip())
    return parts


def script_field(line, key):
    m = re.search(r"(?:^|[,\s])" + key + r'\s*=\s*("([^"]*)"|[^,]+)', line)
    if not m:
        return None
    return (m.group(2) if m.group(2) is not None else m.group(1)).strip()


def line_pattern(section, line):
    toks = line.split()
    if section in ("URL Rewrite", "Map Local"):
        return toks[0] if toks else None
    if section in ("Body Rewrite", "Header Rewrite"):
        return toks[1] if len(toks) > 1 else None
    if section == "Script":
        return script_field(line, "pattern")
    return None


class Builder:
    def __init__(self, fetcher):
        self.f = fetcher
        self.sources = load_json(os.path.join(CFG, "sources.json"), None)
        self.policy = load_json(os.path.join(CFG, "policy.json"), None)
        self.state = load_json(os.path.join(CACHE, "state.json"), {})
        self.script_cache = load_json(os.path.join(CACHE, "scripts.json"), {})
        self.dropped = OrderedDict()
        self.notes = []
        self.exit = 0
        self.drop_host_reason = {}
        for reason, hosts in self.policy["drop_hosts"].items():
            for h in hosts:
                self.drop_host_reason[h] = reason
        self.drop_scripts = [(s, r) for r, ss in self.policy["drop_scripts"].items() for s in ss]
        self.script_name_rx = re.compile(self.policy["script_filename_block_regex"])
        self.protect = [h.lower() for h in self.policy["protect_domains"]]

    def drop(self, reason, section, line):
        self.dropped.setdefault(reason, []).append(f"[{section}] {line.strip()}")

    # ---------------------------------------------------------------- upstream
    def load_upstream(self, up):
        cache_path = os.path.join(CACHE, "upstream", up["id"] + ".module")
        text, problem = None, None
        try:
            raw = self.f.get(up["url"])
            text = raw.decode("utf-8")
            _, secs = parse_module(text)
            rules = [l for l in secs.get("Rule", []) if l.strip() and not l.lstrip().startswith("#")]
            if len(raw) < up.get("min_bytes", 0):
                problem = f"内容过小（{len(raw)} 字节）"
            elif "MITM" not in secs or len(rules) < up.get("min_rules", 0):
                problem = f"结构不完整（规则 {len(rules)} 条）"
        except Exception as e:  # network or decode error
            problem = f"获取失败：{e}"
        if problem is None:
            os.makedirs(os.path.dirname(cache_path), exist_ok=True)
            with open(cache_path, "w", encoding="utf-8") as fh:
                fh.write(text)
            return text, True
        self.notes.append(f"上游 {up['id']} {problem}，改用上一次成功获取的版本。")
        self.exit = max(self.exit, 3)
        try:
            with open(cache_path, encoding="utf-8") as fh:
                return fh.read(), False
        except FileNotFoundError:
            self.notes.append(f"上游 {up['id']} 没有可用的缓存。")
            return None, False

    # ---------------------------------------------------------------- scripts
    def script_verdict(self, url):
        fname = url.split("?")[0].rsplit("/", 1)[-1]
        if self.script_name_rx.search(fname):
            return "文件名显示为付费解锁/破解"
        for frag, reason in self.drop_scripts:
            if frag in url:
                return reason
        entry = self.script_cache.get(url)
        try:
            body = self.f.get(url, timeout=20).decode("utf-8", errors="ignore")
            sig = unlock_signature(strip_js_comments(body))
            entry = {"sha256": hashlib.sha256(body.encode()).hexdigest(),
                     "verdict": ("unlock: " + sig) if sig else "ok",
                     "checked": now().strftime("%Y-%m-%d")}
            self.script_cache[url] = entry
        except Exception:
            if entry is None:
                self.exit = max(self.exit, 4)
                return "脚本暂时无法获取，未能检查"
        if entry["verdict"].startswith("unlock"):
            return f"脚本内容包含付费解锁（{entry['verdict'][8:][:40]}）"
        return None

    # ---------------------------------------------------------------- sections
    def filter_rules(self, lines):
        out = []
        for line in lines:
            s = line.strip()
            if not s or s.startswith("#"):
                out.append(line)
                continue
            p = split_rule(s)
            rtype = p[0].upper()
            policy = (p[-1] if rtype in ("AND", "OR", "NOT") else (p[2] if len(p) > 2 else "")).strip()
            if rtype in ("AND", "OR", "NOT"):
                policy = s.rsplit(",", 1)[-1].strip()
            if policy not in REJECT_POLICIES:
                self.drop("上游规则不是拦截类（模块只保留拦截规则，放行统一写在 exceptions.list）", "Rule", s)
                continue
            if rtype in ("DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"):
                hit = next((h for h in self.protect if rule_hits(rtype, p[1], h)), None)
                if hit:
                    self.drop(f"会拦截受保护的主机 {hit}", "Rule", s)
                    continue
            if rtype == "URL-REGEX":
                rx = host_regex(p[1])
                if host_in(rx, self.drop_host_reason):
                    self.drop("指向已排除的主机", "Rule", s)
                    continue
            out.append(line)
        return out

    def filter_rewrites(self, section, lines):
        out = []
        for line in lines:
            s = line.strip()
            if not s or s.startswith("#"):
                out.append(line)
                continue
            pat = line_pattern(section, s)
            rx = host_regex(pat) if pat else None
            hosts = [h for h in self.drop_host_reason if rx is not None and rx.fullmatch(sample_host(h))]
            if hosts:
                self.drop(self.drop_host_reason[hosts[0]], section, s)
                continue
            if section == "Script":
                url = script_field(s, "script-path")
                reason = self.script_verdict(url) if url else "缺少 script-path"
                if reason:
                    self.drop(reason, section, s)
                    continue
            elif section in ("Body Rewrite", "Map Local"):
                rest = s.split(None, 2 if section == "Body Rewrite" else 1)[-1]
                sig = unlock_signature(rest)
                if sig:
                    self.drop(f"改写内容包含付费解锁（{sig[:40]}）", section, s)
                    continue
            out.append(line)
        return out

    def filter_mitm(self, lines):
        hosts = []
        for line in lines:
            m = re.match(r"^\s*hostname\s*=\s*(.*)$", line)
            if not m:
                continue
            for h in m.group(1).replace("%APPEND%", "").replace("%INSERT%", "").split(","):
                h = h.strip()
                if h:
                    hosts.append(h)
        out, excl, seen = [], [], set()
        for h in hosts:
            if h in seen:
                continue
            seen.add(h)
            if not re.fullmatch(r"-?[A-Za-z0-9*?.:\-\[\]]+", h) or "hostname" in h:
                self.drop("无效的主机名", "MITM", h)
                continue
            if h.startswith("-"):
                excl.append(h)  # upstream exclusions only narrow decryption; keep them first
                continue
            fam = mitm_match(h, self.drop_host_reason)
            if fam:
                self.drop(self.drop_host_reason[fam], "MITM", h)
                continue
            prot = mitm_match(h, self.policy["protect_mitm"])
            if prot:
                self.drop(f"在解密保护范围内（{prot}）", "MITM", h)
                continue
            out.append(h)
        return excl + out

    # ---------------------------------------------------------------- build
    def build(self, write=True):
        merged = OrderedDict((k, []) for k in SECTION_ORDER)
        mitm_lines, args_lines, up_meta, used_cache = [], [], [], False
        for up in self.sources["upstreams"]:
            text, fresh = self.load_upstream(up)
            if text is None:
                continue
            used_cache |= not fresh
            header, secs = parse_module(text)
            meta = {l.split("=", 1)[0][2:]: l.split("=", 1)[1] for l in header if l.startswith("#!") and "=" in l}
            up_meta.append((up, meta, hashlib.sha256(text.encode()).hexdigest()[:12]))
            for name, lines in secs.items():
                if name == "MITM":
                    mitm_lines += lines
                elif name in merged:
                    merged[name].append(f"# ===== 来源：{up['title']}（{up['author']}）=====")
                    merged[name] += lines
                else:
                    for l in lines:
                        if l.strip() and not l.lstrip().startswith("#"):
                            self.drop(f"模块不应修改 [{name}]", name, l)
            declared = [a.split(":")[0].strip() for a in meta.get("arguments", "").split(",") if a.strip()]
            used = [a for a in declared if "{{{" + a + "}}}" in text]
            if used:
                args_lines = [l for l in header if l.startswith("#!arguments")]
        if not up_meta:
            return 2

        merged["Rule"] = self.filter_rules(merged["Rule"])
        for sec in REWRITE_SECTIONS:
            merged[sec] = self.filter_rewrites(sec, merged[sec])
        hosts = self.filter_mitm(mitm_lines)

        exc = open(os.path.join(CFG, "exceptions.list"), encoding="utf-8").read().strip().split("\n")
        merged["Rule"] = ["# ===== 例外放行（config/exceptions.list）====="] + exc + [""] + merged["Rule"]

        # exact-duplicate removal and blank-line folding
        for sec, lines in merged.items():
            seen, out = set(), []
            for l in lines:
                k = l.strip()
                if k and not k.startswith("#"):
                    if k in seen:
                        continue
                    seen.add(k)
                if not k and out and not out[-1].strip():
                    continue
                out.append(l.rstrip())
            merged[sec] = out

        counts = {sec: sum(1 for l in lines if l.strip() and not l.lstrip().startswith("#"))
                  for sec, lines in merged.items()}
        counts["MITM"] = len(hosts)
        built = now()
        up_desc = "；".join(f"{u['title']} {m.get('date', '日期未知')}" for u, m, _ in up_meta)
        head = [
            f"#!name={self.sources['name']}",
            f"#!desc=每日自动构建。上游：{up_desc}。已去除付费解锁与重复部分，加入例外放行。构建于 {built:%Y-%m-%d %H:%M}（北京时间）。",
            "#!author=" + ", ".join(f"{u['author']}[{u['homepage']}]" for u, _, _ in up_meta) + "; 构建 AnnLhl[https://github.com/AnnLhl/surge-modules-ann]",
            "#!homepage=https://github.com/AnnLhl/surge-modules-ann",
            "#!category=Anning",
            "#!system=ios",
            f"#!date={built:%Y-%m-%d %H:%M:%S}",
        ] + args_lines + [
            "",
            "# 本文件由 https://github.com/AnnLhl/surge-modules-ann 自动生成，请勿手动修改。",
        ] + [f"# 上游：{u['title']}（{u['author']}，{u['license']}）{u['homepage']}，上游日期 {m.get('date', '未知')}，内容摘要 {h}"
             for u, m, h in up_meta] + [
            "# 本模块按 GPL-3.0 修改与分发；修改内容见仓库中的 config/ 与 dist/REPORT.md。",
            "",
        ]
        body = []
        for sec in SECTION_ORDER:
            if sec == "MITM":
                body += ["[MITM]", "hostname = %APPEND% " + ", ".join(hosts), ""]
            elif counts[sec]:
                body += [f"[{sec}]"] + merged[sec] + [""]
        module = "\n".join(head + body).rstrip() + "\n"

        scripts_now = sorted({script_field(l, "script-path") for l in merged["Script"]
                              if l.strip() and not l.lstrip().startswith("#") and script_field(l, "script-path")})
        prev_scripts = set(self.state.get("scripts", []))
        report = self.report(built, up_meta, counts, scripts_now, prev_scripts, used_cache)
        if write:
            out_path = os.path.join(ROOT, self.sources["output"])
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            old = open(out_path, encoding="utf-8").read() if os.path.exists(out_path) else ""
            # keep the file stable when only the build timestamp would change
            strip_ts = lambda t: re.sub(r"(构建于 [^（]+|#!date=.*)", "", t)
            if strip_ts(old) != strip_ts(module):
                with open(out_path, "w", encoding="utf-8") as fh:
                    fh.write(module)
                with open(os.path.join(ROOT, self.sources["report"]), "w", encoding="utf-8") as fh:
                    fh.write(report)
                self.state.update({"scripts": scripts_now, "counts": counts,
                                   "built": built.strftime("%Y-%m-%d %H:%M:%S"),
                                   "upstreams": {u["id"]: {"date": m.get("date"), "digest": h} for u, m, h in up_meta}})
                save_json(os.path.join(CACHE, "state.json"), self.state)
                print("module updated")
            else:
                print("module unchanged")
            save_json(os.path.join(CACHE, "scripts.json"), self.script_cache)
        self.module, self.report_text, self.counts = module, report, counts
        return self.exit

    def report(self, built, up_meta, counts, scripts_now, prev_scripts, used_cache):
        L = [f"# 构建报告", "", f"- 构建时间：{built:%Y-%m-%d %H:%M:%S}（北京时间）"]
        for u, m, h in up_meta:
            L.append(f"- 上游：[{u['title']}]({u['homepage']})（{u['author']}，{u['license']}），上游日期 {m.get('date', '未知')}，内容摘要 `{h}`")
        if used_cache:
            L.append("- **注意：本次使用了缓存的上游内容**")
        L += [f"- 说明：{n}" for n in self.notes]
        L += ["", "| 段落 | 条目数 |", "|---|---|"] + [f"| {k} | {v} |" for k, v in counts.items()]
        new = sorted(set(scripts_now) - prev_scripts) if prev_scripts else []
        gone = sorted(prev_scripts - set(scripts_now)) if prev_scripts else []
        if new or gone:
            L += ["", "## 脚本变化（与上次构建相比）", ""] + [f"- 新增：{s}" for s in new] + [f"- 移除：{s}" for s in gone]
        L += ["", "## 被去除的条目", ""]
        for reason, items in self.dropped.items():
            L.append(f"### {reason}（{len(items)}）")
            L.append("")
            L += [f"- `{i[:200]}`" for i in items[:40]]
            if len(items) > 40:
                L.append(f"- ……另有 {len(items) - 40} 条")
            L.append("")
        return "\n".join(L).rstrip() + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", help="directory with <owner>_<repo> mirrors (tests only)")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    b = Builder(Fetcher(a.offline))
    code = b.build(write=not a.dry_run)
    if code == 2:
        print("no usable upstream", file=sys.stderr)
    else:
        print(json.dumps(b.counts, ensure_ascii=False))
        for r, items in b.dropped.items():
            print(f"dropped {len(items):4d}  {r}")
        for n in b.notes:
            print("note:", n)
    sys.exit(code)


if __name__ == "__main__":
    main()
