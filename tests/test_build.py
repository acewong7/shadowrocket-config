#!/usr/bin/env python3
"""build.py 的回归测试：不需要网络，全部用本地 fixture。"""
from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import build as B  # noqa: E402

FIXTURE = """# fixture upstream

[General]
loglevel = notify
tun-excluded-routes = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10
ipv6 = false

[Proxy]
DIRECT = direct

[Proxy Group]
🚀 节点选择 = select, DIRECT, include-all-proxies=1

[Rule]
DOMAIN-SUFFIX,ts.net,TAILSCALE
IP-CIDR,100.64.0.0/10,TAILSCALE,no-resolve
RULE-SET,https://raw.githubusercontent.com/x/y/private.list,DIRECT
FINAL,🚀 节点选择
"""


class BuildTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)
        self.src = self.dir / "upstream.conf"
        self.src.write_text(FIXTURE, encoding="utf-8")
        # 把输出重定向到临时目录，避免污染 out/
        self._out, self._man = B.OUT, B.MANIFEST
        B.OUT = self.dir / "shadowrocket.conf"
        B.MANIFEST = self.dir / "manifest.json"

    def tearDown(self):
        B.OUT, B.MANIFEST = self._out, self._man
        self.tmp.cleanup()

    def _build(self, text: str | None = None):
        if text is not None:
            self.src.write_text(text, encoding="utf-8")
        res = B.build(self.src.as_uri())
        return res, B.OUT.read_text(encoding="utf-8")

    def test_bypass_drops_tailnet_and_lan_ranges(self):
        _, out = self._build()
        line = [l for l in out.splitlines() if l.startswith("tun-excluded-routes")][0]
        for bad in B.FORBIDDEN_BYPASS:
            self.assertNotIn(bad, line)
        # 上游的其它旁路段必须原样保留，不能被我们整体替换掉
        for keep in ("10.0.0.0/8", "172.16.0.0/12"):   # fixture 里存在的其它网段
            self.assertIn(keep, line)

    def test_upstream_extra_bypass_ranges_survive(self):
        extra = FIXTURE.replace("172.16.0.0/12,", "172.16.0.0/12, 198.18.0.0/15,")
        _, out = self._build(extra)
        line = [l for l in out.splitlines() if l.startswith("tun-excluded-routes")][0]
        self.assertIn("198.18.0.0/15", line, "上游新增的旁路段不应被丢掉")

    def test_tailscale_rules_precede_ruleset_and_are_deduped(self):
        _, out = self._build()
        rule_block = out.split("[Rule]", 1)[1]
        lan = rule_block.index("192.168.31.0/24,TAILSCALE")
        first_ruleset = rule_block.index("RULE-SET")
        self.assertLess(lan, first_ruleset, "LAN 规则必须排在 RULE-SET 之前")
        self.assertEqual(out.count("IP-CIDR,100.64.0.0/10,TAILSCALE"), 1, "Tailscale 规则不应重复")
        self.assertEqual(out.count("DOMAIN-SUFFIX,ts.net,TAILSCALE"), 1)

    def test_idempotent(self):
        _, first = self._build()
        _, second = self._build()
        self.assertEqual(first, second, "重复构建产物必须一致")

    def test_rejects_credentials(self):
        bad = FIXTURE + "\nss://YWVzOnBhc3N3b3Jk\n"
        with self.assertRaises(B.BuildError):
            self._build(bad)

    def test_comment_placeholders_allowed(self):
        ok = FIXTURE.replace("[Proxy]\n", "[Proxy]\n# 节点名称=ss,地址,端口,password=密码\n")
        _, out = self._build(ok)
        self.assertIn("password=密码", out)

    def test_manifest_sha_matches_output(self):
        res, out = self._build()
        import hashlib

        self.assertEqual(res["sha256"], hashlib.sha256(out.encode()).hexdigest())

    def test_jms_group_added_to_ai_only(self):
        fix = FIXTURE.replace(
            "🚀 节点选择 = select, DIRECT, include-all-proxies=1",
            "🚀 节点选择 = select, DIRECT, include-all-proxies=1\n"
            "AI = select,PROXY,香港节点,policy-select-name=PROXY\n"
            "YouTube = select,PROXY,香港节点,policy-select-name=PROXY",
        )
        _, out = self._build(fix)
        self.assertIn("JMS 线路 = url-test,policy-regex-filter=JMS|c2s", out)
        ai = [l for l in out.splitlines() if l.startswith("AI = ")][0]
        self.assertIn("JMS 线路", ai)
        self.assertIn("policy-select-name=PROXY", ai, "默认选择必须保持 PROXY")
        yt = [l for l in out.splitlines() if l.startswith("YouTube = ")][0]
        self.assertNotIn("JMS 线路", yt, "YouTube 不应挂 JMS")

    def test_jms_patch_idempotent(self):
        fix = FIXTURE.replace(
            "🚀 节点选择 = select, DIRECT, include-all-proxies=1",
            "🚀 节点选择 = select, DIRECT, include-all-proxies=1\nAI = select,PROXY,香港节点,policy-select-name=PROXY",
        )
        _, first = self._build(fix)
        _, second = self._build(fix)
        self.assertEqual(first, second)
        self.assertEqual(second.count("JMS 线路 = url-test"), 1, "重复构建不应重复插入分组")

    def test_undefined_policy_rejected(self):
        bad = FIXTURE.replace("FINAL,🚀 节点选择", "FINAL,不存在的组")
        with self.assertRaises(B.BuildError):
            self._build(bad)

    def test_missing_rule_section_fails(self):
        with self.assertRaises(B.BuildError):
            self._build("# only comments\n[General]\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
