# 中间人攻击 (Man-in-the-Middle, MITM)

> 分类：网络层 | 风险：高 | MITRE T1557 / T1556 | 攻击链：凭据访问

## 1. 攻击原理

攻击者在通信双方之间插入自己，使双方以为在直接通信，从而**窃听、篡改、重放**流量。前提是能影响链路或名称解析。

| 手法 | 层级 | 说明 |
|---|---|---|
| ARP 欺骗 | 局域网 | 伪造 ARP 应答，把网关 IP 映射到自己 MAC |
| DNS 欺骗/劫持 | 名称解析 | 返回恶意 IP；改路由器 DNS、劫持注册商 |
| DHCP 欺骗 | 局域网 | 下发恶意网关/DNS |
| Evil Twin | 无线 | 仿冒同名 Wi-Fi，诱导连接 |
| SSL Stripping | 应用 | 把 HTTPS 降级为 HTTP，再代理到真实站点 |
| BGP 劫持 | 互联网 | 宣告他人网段，吸引流量 |
| 恶意 CA / 企业根证书 | 信任链 | 签发伪造证书实现解密 |
| 代理/恶意扩展 | 终端 | 浏览器或系统代理被篡改 |

TLS 本身能防窃听，但以下情况会失效：用户忽略证书警告、系统被装了恶意根证书、应用未校验证书、使用 HTTP、HSTS 未启用或首次访问被降级。

## 2. 攻击示例

### 2.1 ARP 欺骗（局域网）

```bash
# 仅授权测试环境
sudo ettercap -T -q -i en0 -M arp:remote /192.168.1.1// /192.168.1.50//
# 或 bettercap
sudo bettercap -iface en0 -eval "set arp.spoof.targets 192.168.1.50; arp.spoof on; net.sniff on"
```

### 2.2 Evil Twin

```text
1. 架设同名 SSID "Company-WiFi"，信号更强
2. 受害者自动连接 → 弹出伪造的「认证页面」
3. 诱导输入企业账号 / 安装「证书」→ 后续流量可解密
```

### 2.3 SSL Stripping

```text
受害者访问 http://bank.com（或点击 http 链接）
→ 攻击者代理到 https://bank.com
→ 回给受害者仍是 http，凭据与 Cookie 明文可见
```

### 2.4 DNS 欺骗

```text
污染本地 DNS 或路由器 DNS 设置
→ login.site.com 解析到攻击者 IP
→ 受害者看到合法 HTTPS 图标（攻击者持有该域名的有效证书或使用相似域名）
```

### 2.5 BGP 劫持

```text
攻击者宣告受害者的 IP 前缀（错误配置或恶意）
→ 全球部分流量被导向攻击者网络
→ 配合伪造证书或明文协议窃取
```

## 3. 影响

- 账号密码、会话 Cookie、Token 被窃取
- 流量被篡改（注入广告、替换下载包、改收款账号）
- 内网横向的跳板
- 供应链投毒（替换更新包）

## 4. 防御措施

1. **强制 HTTPS + HSTS**
   - `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
   - 全站 301 跳转，禁止混合内容
2. **证书校验不可关闭**：客户端/服务端都不得设置 `verify=False`、`--insecure`、自定义信任所有证书。
3. **证书透明度（CT）监控**：发现为自有域名签发的异常证书。
4. **DNS 安全**：DNSSEC、DoH/DoT、锁定注册商账号（MFA + Registrar Lock）、CAA 记录。
5. **局域网加固**：
   - 交换机开 DHCP Snooping、Dynamic ARP Inspection、IP Source Guard
   - 端口安全、802.1X 准入
   - 禁用未使用端口
6. **无线安全**：WPA3-Enterprise / WPA2-Enterprise + 802.1X；禁止自动连接开放 SSID；员工禁用「自动加入热点」。
7. **终端防护**：检测代理/根证书变更；企业根证书最小化并审计；EDR 监控 ARP 异常。
8. **VPN / Zero Trust**：远程访问走加密隧道；内网默认不信任。
9. **邮件与下载**：校验签名与哈希，避免 HTTP 下载可执行文件。
10. **监控**：ARP 表突变、网关 MAC 变化、DNS 响应异常、证书告警。

## 5. 配置与检测对比

```nginx
# ✅ 服务端强制 HTTPS + HSTS
server {
    listen 80;
    server_name site.com;
    return 301 https://$host$request_uri;
}
server {
    listen 443 ssl http2;
    server_name site.com;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
}
```

```dns
; ✅ CAA：只允许指定 CA 为域名签发证书
site.com. CAA 0 issue "letsencrypt.org"
site.com. CAA 0 iodef "mailto:security@site.com"
```

```python
# ❌ 关闭证书校验
requests.get(url, verify=False)
# ✅ 使用系统信任库
requests.get(url, timeout=10)
```

```bash
# ✅ 交换机（Cisco 示例）
ip dhcp snooping
ip dhcp snooping vlan 10
ip arp inspection vlan 10
interface GigabitEthernet1/0/1
  ip dhcp snooping limit rate 10
  ip arp inspection limit rate 100
```

```yaml
# ✅ 检测：网关 MAC 变化 / ARP 冲突
- alert: GatewayMacChanged
  expr: changes(arp_gateway_mac[10m]) > 0
- alert: ArpConflictSpike
  expr: rate(arp_conflict_total[5m]) > 0.1
```

## 6. 自查清单

- [ ] 全站 HTTPS + HSTS preload，无混合内容
- [ ] 所有客户端/服务端证书校验开启
- [ ] 已启用 CT 监控与 CAA 记录
- [ ] 域名注册商开启 MFA 与 Registrar Lock
- [ ] 交换机启用 DAI / DHCP Snooping / 端口安全
- [ ] 无线使用 WPA3/WPA2-Enterprise + 802.1X
- [ ] 员工设备禁止自动连接开放热点
- [ ] 代理与根证书变更受监控
- [ ] 远程访问走 VPN/零信任
- [ ] 有 ARP/DNS/证书异常告警

## 7. 参考资料

- MITRE ATT&CK T1557: Adversary-in-the-Middle
- MITRE ATT&CK T1556: Modifying Authentication Process
- NIST SP 800-153（无线局域网安全）
- OWASP: Transport Layer Security Cheat Sheet
- 关联本库：`36-host-header-injection`、`41-phishing`（AiTM）
