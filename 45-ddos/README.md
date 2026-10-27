# 分布式拒绝服务 DDoS (Distributed Denial of Service)

> 分类：可用性 / 网络层 | 风险：高 | MITRE T1498 / T1499 | 攻击链：影响

## 1. 攻击原理

攻击者控制大量分布主机（僵尸网络、IoT、被滥用的云函数/代理池），同时向目标发送请求，耗尽**带宽、连接数、CPU、内存或应用线程**，使正常用户无法访问。

| 层次 | 典型手法 | 放大倍数 |
|---|---|---|
| 流量型（L3/L4） | UDP Flood、ICMP Flood、DNS/NTP/memcached/CLDAP 反射放大 | 数十至数万倍 |
| 协议型（L4） | SYN Flood、ACK Flood、RST Flood、TCP 连接耗尽 | 中 |
| 应用型（L7） | HTTP Flood、Slowloris、超大请求、API 刷、ReDoS | 低但难防 |
| 协议缺陷 | HTTP/2 Rapid Reset（CVE-2023-44487）、HTTP/3 攻击面 | 高 |
| 资源型 | 无限分页、大文件下载、视频转码、AI 推理刷 | — |

现代趋势：

- **混合攻击**：流量打满 + 应用层绕过清洗
- **DDoS 勒索**：先小规模演示，再索要赎金
- **僵尸网络即服务**（Booter/Stresser），门槛极低
- **CDN 回源攻击**：攻击源站真实 IP，绕过 CDN
- **地毯式轰炸（Carpet Bombing）**：分散打整个网段，规避阈值告警

## 2. 攻击示例

### 2.1 SYN Flood

```bash
# 仅授权测试环境
hping3 -S --flood -p 80 target.example.com
```

大量半开连接占满 SYN 队列，正常握手失败。

### 2.2 DNS 反射放大

```bash
# 伪造源 IP 为受害者，向开放解析器查询大记录
dig @open-resolver.example.com ANY isc.org
```

响应远大于请求，流量被反射到受害者。

### 2.3 HTTP Flood

```bash
# 高频请求动态接口，绕过简单缓存
hey -n 1000000 -c 500 https://target.example.com/api/search?q=test
```

### 2.4 Slowloris

```text
建立大量连接，每次只发极少字节，长期占用 worker
→ 连接池耗尽，正常请求排队超时
```

### 2.5 HTTP/2 Rapid Reset

```text
快速发起并 RST_STREAM 取消大量并发流
→ 服务端为每个流分配资源后被立即释放，CPU 被打满
```

## 3. 影响

- 业务中断（电商、支付、医疗、政务）
- 云账单暴涨（按量计费、自动扩容被利用）
- 作为烟雾弹掩护数据窃取
- 品牌与 SLA 损失，勒索前置

## 4. 防御措施

1. **容量与架构**
   - 接入 CDN / Anycast / 云清洗（Cloudflare、AWS Shield Advanced、阿里云 DDoS 高防）
   - 隐藏源站 IP：源站只允许 CDN 回源 IP，禁止直接解析
   - 多可用区、自动伸缩（设上限，防账单爆炸）
2. **网络层**
   - SYN Cookies、连接数限制、超时缩短
   - BGP Flowspec / RTBH 黑洞（慎用，按需）
   - 清洗中心 + 本地清洗设备联动
3. **应用层**
   - 分层限流（IP / 用户 / 接口 / 成本）
   - 请求体、并发、超时、队列长度全部设限
   - 缓存静态与热点内容，动态接口做防刷（验证码、挑战）
   - 识别异常 UA、无头浏览器、TLS 指纹、行为特征
4. **协议加固**
   - 及时升级 Nginx/Envoy/Go 等修复 Rapid Reset
   - 限制 HTTP/2 并发流与头部大小
5. **运营**
   - 监控：带宽、PPS、连接数、5xx、P99 延迟、回源流量
   - 预案：分级响应、联系人、清洗切换演练
   - 保险与合规报备
6. **不要做的事**：不要仅靠 WAF、不要暴露源站、不要无限自动扩容。

## 5. 配置与检测对比

```nginx
# ✅ 连接与请求限速
limit_conn_zone $binary_remote_addr zone=perip:10m;
limit_req_zone $binary_remote_addr zone=req:10m rate=20r/s;

server {
    limit_conn perip 20;
    limit_req zone=req burst=40 nodelay;
    client_body_timeout 10s;
    client_header_timeout 10s;
    keepalive_timeout 15s;
    client_max_body_size 10m;
}
```

```bash
# ✅ Linux 内核缓解 SYN Flood
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.tcp_max_syn_backlog=4096
sysctl -w net.ipv4.tcp_fin_timeout=15
sysctl -w net.core.somaxconn=4096
```

```yaml
# ✅ 云侧：只允许 CDN 回源
# 安全组入站仅放行 CDN 回源网段，80/443 不对 0.0.0.0/0 开放
```

```yaml
# ✅ 告警规则（示意）
- alert: TrafficSpike
  expr: rate(node_network_receive_bytes_total[1m]) > 5e8
  for: 2m
- alert: Upstream5xxSpike
  expr: sum(rate(http_requests_total{code=~"5.."}[1m])) > 50
  for: 2m
- alert: SourceIPDiversity
  expr: count(count by (ip) (rate(http_requests_total[1m]))) > 10000
```

## 6. 自查清单

- [ ] 已接入 CDN/清洗，源站 IP 未暴露
- [ ] 源站安全组仅允许 CDN 回源
- [ ] 网络与应用层限流均已配置
- [ ] 请求体/并发/超时/队列有上限
- [ ] HTTP/2 组件已修复 Rapid Reset 等已知缺陷
- [ ] 自动扩容设置上限与预算告警
- [ ] 有带宽/PPS/连接数/5xx 监控与告警
- [ ] DDoS 应急预案与演练已完成
- [ ] 关键业务有降级方案（静态页、只读模式）
- [ ] 已评估 DDoS 保险与合规报备流程

## 7. 参考资料

- MITRE ATT&CK T1498: Network Denial of Service
- MITRE ATT&CK T1499: Endpoint Denial of Service
- CISA: DDoS Quick Guide
- Cloudflare / AWS Shield 防护最佳实践
- CVE-2023-44487: HTTP/2 Rapid Reset
- 关联本库：`32-dos`（应用层资源耗尽）
