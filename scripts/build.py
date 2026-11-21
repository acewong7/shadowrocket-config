#!/usr/bin/env python3
"""把上游 Shadowrocket 配置加工成我们自己的稳定版本。

设计目标：**上游怎么更新都冲不掉我们的订正**。
自动化流程：定时拉上游 → 在本脚本里重新施加本地订正 → 产出 out/shadowrocket.conf。
设备只认我们仓库的 raw URL，所以 TUN 旁路和 Tailscale 规则永远在基线里，不是补丁。

用法：
    python3 scripts/build.py                     # 用默认上游（coolxll 模板）
    python3 scripts/build.py --upstream <url>    # 换上游
    python3 scripts/build.py --check             # 只校验 out/ 里的成品，不重新生成
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import re
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "out" / "shadowrocket.conf"
MANIFEST = ROOT / "out" / "manifest.json"

DEFAULT_UPSTREAM = (
    "https://raw.githubusercontent.com/coolxll/proxy-routing/main/templates/shadowrocket-tailscale.conf"
)

# 家里 LAN 要在隧道里，才能在外面访问 31 网段
LAN_CIDR = "192.168.31.0/24"

# TUN 旁路只留这些；100.64.0.0/10 与 192.168.0.0/16 必须去掉，
# 否则 Tailnet 地址和家里 LAN 都进不了隧道。
BYPASS_ROUTES = "127.0.0.0/8, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255/32"

TAILSCALE_BLOCK = f"""# >>> hermes:tailscale（scripts/build.py 维护，勿手改）
DOMAIN-SUFFIX,ts.net,TAILSCALE
IP-CIDR,100.64.0.0/10,TAILSCALE,no-resolve
IP-CIDR6,fd7a:115c:a1e0::/48,TAILSCALE,no-resolve
IP-CIDR,{LAN_CIDR},TAILSCALE,no-resolve
# <<< hermes:tailscale"""

# 任何像凭据的东西都不许进公开仓库
SECRET_PATTERNS = [
    r"ss://", r"ssr://", r"vmess://", r"vless://", r"trojan://",
    r"hysteria2?://", r"tuic://", r"snell://", r"bc://",
    r"token\s*=", r"password\s*=", r"passwd\s*=", r"secret\s*=",
]
SECRET_RE = re.compile("|".join(SECRET_PATTERNS), re.IGNORECASE)


class BuildError(Exception):
    pass


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "sr-config-build/1.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8")


def split_sections(text: str) -> tuple[list[str], dict[str, list[str]], list[str]]:
    """返回 (头部注释, {section: 行列表}, 尾部残余)。顺序保持。"""
    head: list[str] = []
    sections: dict[str, list[str]] = {}
    order: list[str] = []
    cur: str | None = None
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            cur = s[1:-1]
            order.append(cur)
            sections[cur] = []
        elif cur is None:
            head.append(line)
        else:
            sections[cur].append(line)
    return head, sections, order


def patch_general(lines: list[str]) -> tuple[list[str], list[str]]:
    """强制写入 tun-excluded-routes，去掉 100.64/10 与 192.168/16。"""
    changes: list[str] = []
    kept: list[str] = []
    had = False
    for line in lines:
        if line.strip().lower().startswith("tun-excluded-routes"):
            had = True
            old = line.split("=", 1)[1].strip() if "=" in line else ""
            if old != BYPASS_ROUTES:
                changes.append(f"tun-excluded-routes: {old!r} -> {BYPASS_ROUTES!r}")
            else:
                changes.append("tun-excluded-routes: 已是目标值")
            continue
        kept.append(line)
    if not had:
        changes.append(f"tun-excluded-routes: 缺失 -> 新增 {BYPASS_ROUTES!r}")
    kept.append(f"tun-excluded-routes = {BYPASS_ROUTES}")
    # 去掉紧邻的空行重复
    out: list[str] = []
    for line in kept:
        if line.strip() == "" and out and out[-1].strip() == "":
            continue
        out.append(line)
    return out, changes


def patch_rules(lines: list[str]) -> tuple[list[str], list[str]]:
    """把 Tailscale 段固定放在 [Rule] 最前面，去重后插入。"""
    changes: list[str] = []
    body = [l for l in lines if "hermes:tailscale" not in l]
    before = len(body)

    def is_ts_rule(l: str) -> bool:
        s = l.strip()
        return s.startswith(("DOMAIN-SUFFIX,ts.net", "IP-CIDR,100.64.0.0/10", "IP-CIDR6,fd7a:115c:a1e0"))

    body = [l for l in body if not is_ts_rule(l)]
    if before != len(body):
        changes.append(f"清理旧的 Tailscale 规则 {before - len(body)} 行")

    # 保留 [Rule] 顶部原有的注释行
    idx = 0
    while idx < len(body) and body[idx].strip().startswith("#"):
        idx += 1
    new_body = body[:idx] + TAILSCALE_BLOCK.splitlines() + [""] + body[idx:]
    if not any(l.strip().startswith("FINAL,") for l in new_body):
        changes.append("警告：缺少 FINAL 兜底规则")
    return new_body, changes


def sanitize(text: str) -> None:
    for i, line in enumerate(text.splitlines(), 1):
        if SECRET_RE.search(line) and "raw.githubusercontent.com" not in line:
            raise BuildError(f"检测到疑似凭据（第 {i} 行），拒绝写入公开仓库: {line.strip()[:80]}")


def build(upstream: str) -> dict:
    raw = fetch(upstream)
    head, sections, order = split_sections(raw)
    for need in ("General", "Rule"):
        if need not in sections:
            raise BuildError(f"上游缺少 [{need}] 段")

    changes: list[str] = []
    general, ch = patch_general(sections["General"])
    changes += ch
    sections["General"] = general
    rules, ch = patch_rules(sections["Rule"])
    changes += ch
    sections["Rule"] = rules

    lines = list(head)
    if lines and lines[-1].strip():
        lines.append("")
    for name in order:
        lines.append(f"[{name}]")
        lines.extend(sections[name])
        lines.append("")
    text = "\n".join(lines).rstrip() + "\n"

    sanitize(text)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")

    digest = hashlib.sha256(text.encode()).hexdigest()
    MANIFEST.write_text(
        json.dumps(
            {
                "upstream": upstream,
                "built_at": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
                "sha256": digest,
                "bytes": len(text.encode()),
                "lan_cidr": LAN_CIDR,
                "bypass_routes": BYPASS_ROUTES,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return {"changes": changes, "sha256": digest, "bytes": len(text.encode())}


def check() -> int:
    if not OUT.exists():
        print("✗ out/shadowrocket.conf 不存在，先运行 build")
        return 1
    text = OUT.read_text(encoding="utf-8")
    errs: list[str] = []
    m = re.search(r"^tun-excluded-routes\s*=\s*(.+)$", text, re.M)
    if not m:
        errs.append("缺少 tun-excluded-routes")
    else:
        val = m.group(1)
        for bad in ("100.64.0.0/10", "192.168.0.0/16"):
            if bad in val:
                errs.append(f"tun-excluded-routes 仍包含 {bad}")
    rule_idx = text.index("[Rule]")
    for need in ("ts.net,TAILSCALE", "100.64.0.0/10,TAILSCALE", f"{LAN_CIDR},TAILSCALE"):
        pos = text.find(need)
        if pos < 0:
            errs.append(f"缺少规则 {need}")
        elif text.find("RULE-SET", rule_idx) > 0 and pos > text.find("RULE-SET", rule_idx):
            errs.append(f"规则 {need} 排在 RULE-SET 之后（会被私有地址先命中）")
    try:
        sanitize(text)
    except BuildError as e:
        errs.append(str(e))
    if errs:
        print("✗ 校验失败:")
        for e in errs:
            print("  -", e)
        return 1
    print("✓ 校验通过:", OUT, re.search(r"sha256", MANIFEST.read_text()).group(0) if MANIFEST.exists() else "")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--upstream", default=DEFAULT_UPSTREAM)
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    if args.check:
        return check()
    try:
        res = build(args.upstream)
    except (BuildError, urllib.error.URLError) as e:
        print(f"✗ 构建失败: {e}", file=sys.stderr)
        return 1
    print(f"✓ 已生成 {OUT}  ({res['bytes']} 字节, sha256={res['sha256'][:16]}…)")
    for c in res["changes"]:
        print("  ·", c)
    return check()


if __name__ == "__main__":
    sys.exit(main())
