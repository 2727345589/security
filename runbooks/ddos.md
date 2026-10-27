# RB-004 DDoS / 流量攻击

| 项 | 内容 |
|---|---|
| Runbook ID | RB-004 |
| 版本 | v1.0 |
| 负责人 | 网络/基础设施负责人 |
| 最后演练 | 待定（建议每半年） |
| 默认级别 | **P2**（业务中断 **P1**） |
| 关联 | `../45-ddos/`、`../32-dos/` |

## 1. 触发条件

- 带宽、PPS、连接数突增（超过基线 3 倍）
- 5xx 比例突增、P99 延迟飙升、健康检查失败
- 源 IP 数量异常多、单一 ASN 流量集中
- 云厂商/清洗服务告警
- 用户大面积反馈「打不开/超时」
- 收到 DDoS 勒索邮件（附小规模演示）

## 2. 分级与响应时限

| 情形 | 级别 | 首次响应 |
|---|---|---|
| 业务不可用 / 核心接口不可用 | P1 | 15 分钟 |
| 部分功能受影响 / 延迟上升 | P2 | 30 分钟 |
| 流量异常但业务正常 | P3 | 1 小时 |

## 3. 角色与职责

| 角色 | 职责 |
|---|---|
| IC | 决策（切清洗、限流、停服） |
| 网络 | 流量分析、清洗、ACL |
| 运维/SRE | 扩容、限流、降级 |
| 云厂商 | 清洗、工单升级 |
| 客服/PR | 用户沟通、状态页 |
| 法务 | 勒索/报案 |

## 4. 前置准备

- [ ] 已接入 CDN/Anycast/云清洗，源站 IP 未暴露
- [ ] 源站安全组仅允许清洗节点回源
- [ ] 预案：限流阈值、降级页面、静态化方案
- [ ] 云厂商紧急支持通道与账号权限
- [ ] 状态页与通知渠道可用
- [ ] 自动扩容上限与预算告警已设置

## 5. 处置步骤

### Step 1 确认（0–10 分钟）

```text
1. 区分「真实攻击」与「业务突增/发布故障/爬虫」
2. 看指标：带宽、PPS、连接数、QPS、5xx、P99、源 IP 分布
3. 看是否多向量（流量 + 应用层同时）
4. 确认是否有勒索邮件
```

```bash
# 只读：快速看连接与流量
ss -s
ss -ant | awk '{print $1}' | sort | uniq -c | sort -rn
netstat -an | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head
sar -n DEV 1 5
```

### Step 2 启用清洗（10–20 分钟）

```text
1. 打开 CDN/清洗服务的「under attack」模式
2. 确认回源只来自清洗节点
3. 若源站 IP 已泄露：更换 IP（先切 DNS，TTL 提前调小）
4. 对 L7：开启 JS 挑战/验证码（注意 API 客户端兼容）
```

```bash
# Cloudflare 思路
# Dashboard → Security → Settings → Under Attack Mode: On
# 或 API：
curl -X PATCH "https://api.cloudflare.com/client/v4/zones/$ZONE/settings/security_level" \
  -H "Authorization: Bearer $CF_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"value":"under_attack"}'
```

```bash
# AWS Shield Advanced 思路
aws shield update-subscription --auto-renew ENABLED
# 确认 WAF 关联到 ALB/CloudFront
aws wafv2 list-web-acls --scope REGIONAL
```

### Step 3 应用层限流与降级

```nginx
# ⚠️ 双人确认后生效：限流
limit_req_zone $binary_remote_addr zone=ddos:10m rate=10r/s;
limit_conn_zone $binary_remote_addr zone=conn:10m;

server {
    limit_req zone=ddos burst=20 nodelay;
    limit_conn conn 20;
    # 静态降级页
    error_page 429 503 = @fallback;
    location @fallback { return 200 '{"status":"busy"}'; add_header Content-Type application/json; }
}
```

```text
降级顺序（从轻到重）：
1. 关闭非核心功能（推荐、搜索、导出）
2. 静态化高频页面
3. 只读模式
4. 全站维护页（最后手段）
```

### Step 4 精准封禁（谨慎）

```text
1. 优先按 ASN/地域/行为特征封禁，不要大面积封 IP 段
2. 封禁前确认不会误伤真实用户/合作方
3. 记录封禁规则与时间，事后清理
4. 对反射放大：联系上游/云厂商做源端过滤
```

```bash
# 示例：封禁单一恶意 IP（⚠️ 双人确认）
iptables -I INPUT -s 203.0.113.10 -j DROP
# 或云 WAF 自定义规则
```

### Step 5 扩容与容量

```text
1. 在预算上限内扩容（注意按量计费被利用）
2. 数据库/缓存扩容前评估连接数
3. 避免「扩容 → 更贵 → 攻击者获益」的循环
```

### Step 6 沟通

```text
1. 更新状态页（每 30 分钟）
2. 客服话术统一：不猜测攻击来源，不承诺恢复时间
3. 若为勒索：不回应、不付款，交法务/执法
4. 内部同步：IC → 管理层 → 业务方
```

### Step 7 结束后

```text
1. 保留攻击流量样本与日志（取证）
2. 逐步撤除临时规则，避免长期误伤
3. 评估暴露面：源站 IP、未防护端口、API
4. 复盘：为何被选中？防护缺口？成本？
```

## 6. 验证标准

- [ ] 带宽/PPS/连接数回落至基线
- [ ] 5xx 与 P99 恢复正常
- [ ] 核心业务功能验证通过
- [ ] 源站未被直接访问（仅清洗节点回源）
- [ ] 临时封禁规则已评估/清理
- [ ] 状态页与用户通知已更新

## 7. 升级与通知

| 情形 | 动作 |
|---|---|
| 清洗无效 / 业务持续不可用 | 升级 P1，联系云厂商 TAM/紧急支持 |
| 源站 IP 暴露 | 立即更换 IP + 收紧安全组 |
| 收到勒索 | 法务 + 执法 + 管理层，不私下接触 |
| 多向量混合攻击 | 同时启用 L3/L4 清洗与 L7 挑战 |

## 8. 沟通模板

```text
【服务状态通告】
时间：____
现象：部分用户访问缓慢或失败
原因：正在遭受异常流量攻击
已采取措施：启用流量清洗与应用层限流
当前状态：核心功能已恢复 / 处置中
下次更新：____
```

## 9. 取证与保全

| 证据 | 用途 |
|---|---|
| 流量采样（NetFlow/PCAP） | 分析攻击向量 |
| WAF/CDN 日志 | 源 IP、UA、路径分布 |
| 告警时间线 | 复盘与报案 |
| 勒索邮件原文 | 执法证据 |
| 扩容与费用记录 | 保险理赔 |

## 10. 恢复与复盘

- 恢复顺序：核心 API → 登录/支付 → 次要功能
- 复盘指标：检测时延、清洗生效时延、业务恢复时延、误伤率、成本
- 改进：容量、清洗策略、限流阈值、源站隐藏、应急自动化

## 11. 附录

```text
快速判断
- 带宽打满：L3/L4 流量型 → 清洗/运营商
- 连接数打满：SYN Flood → SYN Cookies/清洗
- CPU 打满但流量不大：L7/慢速攻击 → 限流/超时
- 单一接口被打：业务限流 + 缓存 + 降级
```

- 关联：`../45-ddos/`、`../32-dos/`、`RB-001`
