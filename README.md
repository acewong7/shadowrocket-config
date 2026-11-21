# shadowrocket-config

自持的 Shadowrocket 配置。**上游怎么更新都冲不掉本地订正** —— 因为订正不在配置里手动改，而在构建时重新施加。

## 为什么存在

Shadowrocket 的「更新配置」会用远端版本整体覆盖本地文件（官方手册原话），所以：

- 手动删掉 `tun-excluded-routes` 里的 `100.64.0.0/10` / `192.168.0.0/16` → 下次自动更新又回来
- Tailscale 内网访问随之失效（翻墙不受影响）

解法是把配置变成自己的：上游 → `scripts/build.py` → `out/shadowrocket.conf`，设备只认这个产物。

## 上游

默认 `Johnshall/Shadowrocket-ADBlock-Rules-Forever` 的 **`lazy_group.conf`**（★32k，每日 8 点重建）：

- 国内外划分（中国网站直连、国外走代理）+ 按服务分组（AI / YouTube / Netflix / Telegram / Spotify …），分组规则来自 blackmatrix7 的 RULE-SET，AI 组来自 iab0x00
- 只有 28KB、370 行，diff 干净；对比 `sr_cnip_ad.conf`（2.1MB、5.4 万行内联规则）好维护得多
- `[Proxy]` 段全部是注释示例，不含任何真实节点

换上游：`python3 scripts/build.py --upstream <url>`，或在 `scripts/build.py` 里改 `DEFAULT_UPSTREAM`。

## 产物做了什么

固定写死两件事，其余原样继承上游：

1. **`tun-excluded-routes`** 只保留 `127.0.0.0/8, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255/32`
   —— 去掉 `100.64.0.0/10`（Tailnet 地址段）和 `192.168.0.0/16`（家里 LAN）
2. **`[Rule]` 最前面**插入 Tailscale 段（在私有地址 `/ RULE-SET` 之前）：
   ```
   DOMAIN-SUFFIX,ts.net,TAILSCALE
   IP-CIDR,100.64.0.0/10,TAILSCALE,no-resolve
   IP-CIDR6,fd7a:115c:a1e0::/48,TAILSCALE,no-resolve
   IP-CIDR,192.168.31.0/24,TAILSCALE,no-resolve
   ```

## 用法

```bash
python3 scripts/build.py              # 拉上游 + 施加订正 + 校验
python3 scripts/build.py --check      # 只校验 out/ 成品
python3 tests/test_build.py           # 6 个回归用例，无网络依赖
```

## 设备端

小火箭 / Shadowrocket for Mac → 配置 → 添加远程配置，填：

```
https://raw.githubusercontent.com/<owner>/<repo>/main/out/shadowrocket.conf
```

**自动更新保持开启**。这是这套方案的意义：更新的是我们自己的产物，订正永远在基线里。

节点仍然来自设备上已有的订阅（配置里用 `include-all-proxies=1` 自动纳入），仓库里**没有任何订阅地址或密钥**。

## 安全边界

`build.py` 会扫描产物，命中 `ss://`、`vmess://`、`token=`、`password=` 等模式直接拒绝写入并退出非零。所以这个仓库可以公开。

## 上游变更怎么跟

GitHub Actions 每天定时重建一次；上游结构大改（新增段、策略组改名）时构建会失败并留红，人工看一眼再合。也可以本地：

```bash
python3 scripts/build.py && git diff out/
```
