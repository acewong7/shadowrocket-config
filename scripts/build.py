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
    "https://raw.githubusercontent.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever/master/lazy_group.conf"
)

# 家里 LAN 要在隧道里，才能在外面访问 31 网段
LAN_CIDR = "192.168.31.0/24"

# TUN 旁路只留这些；100.64.0.0/10 与 192.168.0.0/16 必须去掉，
# 否则 Tailnet 地址和家里 LAN 都进不了隧道。
# 上游缺失这一行时的兜底值（通常用不到，Johnshall 会写）。
BYPASS_FALLBACK = (
    "10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, "
    "192.0.2.0/24, 192.88.99.0/24, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, "
    "255.255.255.255/32, 239.255.255.250/32, ff02::fb/128"
)

# 必须从 TUN 旁路里剔除的网段：
#   100.64.0.0/10  Tailscale 地址段，留着就连不上 Tailnet
#   192.168.0.0/16 家里 LAN，留着就到不了 192.168.31.x
# 只删这两条，上游新增的其它旁路段一律保留。
FORBIDDEN_BYPASS = ("100.64.0.0/10", "192.168.0.0/16")

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
    """从上游的 tun-excluded-routes 里**减去**禁用网段，其余原样保留。"""
    changes: list[str] = []
    out: list[str] = []
    replaced = False
    for line in lines:
        if line.strip().lower().startswith("tun-excluded-routes"):
            old = line.split("=", 1)[1].strip() if "=" in line else ""
            kept = [
                x.strip()
                for x in old.split(",")
                if x.strip() and x.strip() not in FORBIDDEN_BYPASS
            ]
            new_line = "tun-excluded-routes = " + ", ".join(kept)
            out.append(new_line)
            replaced = True
            dropped = [x.strip() for x in old.split(",") if x.strip() in FORBIDDEN_BYPASS]
            changes.append(
                "tun-excluded-routes: 上游本来就没有禁用网段" if not dropped
                else "tun-excluded-routes: 剔除 " + ", ".join(dropped)
            )
            continue
        out.append(line)
    if not replaced:
        while out and out[-1].strip() == "":
            out.pop()
        out.append(f"tun-excluded-routes = {BYPASS_FALLBACK}")
        changes.append("tun-excluded-routes: 上游缺失 -> 插入兜底值")
    return out, changes


def _dropped(old: str) -> str:
    """列出被我们剔除的网段，便于构建日志一眼看清。"""
    keep = {x.strip() for x in BYPASS_ROUTES.split(",")}
    dropped = [x.strip() for x in old.split(",") if x.strip() and x.strip() not in keep]
    return ", ".join(dropped) if dropped else "（无变化）"


JMS_GROUP_NAME = "JMS 线路"
JMS_GROUP_LINE = (
    f"{JMS_GROUP_NAME} = url-test,policy-regex-filter=JMS|c2s,"
    "url=http://www.gstatic.com/generate_204,interval=600,tolerance=0,timeout=5,select=0"
)
# 只把这些组的候选里加入 JMS：AI 类服务吃延迟和稳定性、不吃带宽；
# YouTube / Netflix 之类吃带宽，JMS 实测抖动时只有 0.3 MB/s，不挂进去。
JMS_TARGET_GROUPS = ("AI",)


def patch_groups(lines: list[str]) -> tuple[list[str], list[str]]:
    """新增 JMS 线路组，并把它作为候选塞进指定 select 组（默认仍是 PROXY）。"""
    changes: list[str] = []
    out: list[str] = []
    has_group = any(l.split("=", 1)[0].strip() == JMS_GROUP_NAME for l in lines if "=" in l)

    for line in lines:
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            out.append(line)
            continue
        name, rest = s.split("=", 1)
        name = name.strip()
        if name in JMS_TARGET_GROUPS and JMS_GROUP_NAME not in rest:
            parts = [x.strip() for x in rest.split(",")]
            # 第一个非 key=value 的成员之后插入（通常是 PROXY）
            idx = next(
                (i + 1 for i, x in enumerate(parts) if "=" not in x and x.upper() == "PROXY"), 1
            )
            parts.insert(idx, JMS_GROUP_NAME)
            out.append(f"{name} = " + ",".join(parts))
            changes.append(f"{name} 组: 候选加入 {JMS_GROUP_NAME}（默认选择不变）")
            continue
        out.append(line)

    if not has_group:
        # 插在第一个 select 组之前，保持可读性
        pos = next(
            (i for i, l in enumerate(out) if l.strip() and not l.strip().startswith("#")),
            len(out) - 1,
        )
        out.insert(pos, JMS_GROUP_LINE)
        changes.append(f"新增分组 {JMS_GROUP_NAME}（policy-regex-filter=JMS|c2s）")
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


BUILTIN_POLICIES = {"DIRECT", "PROXY", "REJECT", "TAILSCALE", "REJECT-TINYGIF"}


def validate_policies(sections: dict[str, list[str]]) -> list[str]:
    """规则里引用的策略必须是已定义的组或内置策略，否则该规则会静默失效。"""
    groups: set[str] = set()
    for line in sections.get("Proxy Group", []):
        if line.strip() and not line.strip().startswith("#") and "=" in line:
            groups.add(line.split("=", 1)[0].strip())

    known = {g.upper() for g in groups} | BUILTIN_POLICIES
    problems: list[str] = []
    for line in sections.get("Rule", []):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        kind = s.split(",", 1)[0]
        if kind in ("AND", "OR", "NOT"):
            continue
        parts = s.split(",")
        if len(parts) == 2:                      # FINAL / MATCH 这类只有两段
            policy = parts[1]
        elif len(parts) >= 3:
            policy = next(
                (p for p in parts[2:] if p and p != "no-resolve" and not p.startswith("http")),
                None,
            )
        else:
            continue
        if policy and policy.upper() not in known:
            problems.append(f"规则引用了未定义的策略 {policy!r}: {s[:70]}")
    return problems


def sanitize(text: str) -> None:
    for i, line in enumerate(text.splitlines(), 1):
        if line.strip().startswith("#"):        # 注释里的示例不算凭据
            continue
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
    if "Proxy Group" in sections:
        groups, ch = patch_groups(sections["Proxy Group"])
        changes += ch
        sections["Proxy Group"] = groups
    rules, ch = patch_rules(sections["Rule"])
    changes += ch
    sections["Rule"] = rules

    problems = validate_policies(sections)
    if problems:
        raise BuildError("策略引用校验失败:\n  " + "\n  ".join(problems))

    lines = list(head)
    if lines and lines[-1].strip():
        lines.append("")
    for name in order:
        body = list(sections[name])
        while body and body[-1].strip() == "":
            body.pop()
        lines.append(f"[{name}]")
        lines.extend(body)
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
                "sha256": digest,
                "bytes": len(text.encode()),
                "lan_cidr": LAN_CIDR,
                "forbidden_bypass": list(FORBIDDEN_BYPASS),
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
        for bad in FORBIDDEN_BYPASS:
            if bad in val:
                errs.append(f"tun-excluded-routes 仍包含 {bad}")
    lines = text.splitlines()
    rule_start = next(i for i, l in enumerate(lines) if l.strip() == "[Rule]")
    first_ruleset = next(
        (i for i in range(rule_start, len(lines)) if lines[i].strip().startswith("RULE-SET,")), None
    )
    for need in ("ts.net,TAILSCALE", "100.64.0.0/10,TAILSCALE", f"{LAN_CIDR},TAILSCALE"):
        idx = next(
            (i for i, l in enumerate(lines) if need in l and not l.strip().startswith("#")), None
        )
        if idx is None:
            errs.append(f"缺少规则 {need}")
        elif first_ruleset is not None and idx > first_ruleset:
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
