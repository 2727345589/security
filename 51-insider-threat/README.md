# 内部威胁 (Insider Threat)

> 分类：人员 / 数据安全 | 风险：高 | MITRE T1078 / T1567 | 攻击链：凭据访问 → 外带

## 1. 攻击原理

内部人员利用合法权限实施或协助攻击。因为**不需要突破边界**，传统防护（防火墙、WAF）几乎无效，检测依赖行为基线。

三类内部威胁：

| 类型 | 特征 | 例子 |
|---|---|---|
| 恶意（Malicious） | 主动窃取/破坏 | 离职前批量下载客户数据、植入后门 |
| 疏忽（Negligent） | 无恶意但违规 | 把数据发到个人邮箱、用弱口令、误共享链接 |
| 被胁迫/被利用（Compromised） | 账号被收买或社工 | 被钓鱼后账号被外部控制（见 `42`） |

高风险信号：

- 离职/转岗前后大量访问与下载
- 非工作时间、异常地点、异常设备
- 访问与岗位无关的数据
- 批量导出、截图、打印、外发
- 创建邮件转发规则、共享链接设为公开
- 反复尝试访问无权限资源

## 2. 攻击示例

### 2.1 离职前数据搬运

```text
1. 提交离职申请
2. 一周内下载 5 万条客户记录（CSV 导出）
3. 同步到个人网盘 / 私人邮箱
4. 删除本地痕迹，正常交接
```

### 2.2 邮件自动转发

```text
在邮箱设置里添加规则：
匹配：发件人包含 "合同" 或 "报价"
动作：转发到 personal@gmail.com，并在收件箱隐藏
```

即使用户改密码，规则仍持续外带。

### 2.3 合法权限滥用

```text
客服有查询用户信息的权限
→ 用他人账号/批量脚本查询明星、前任、竞争对手客户
→ 截图外传（无文件外带，DLP 也难拦）
```

### 2.4 共享链接配置错误

```text
把「仅内部」的云盘文件夹改为「任何有链接的人可查看」
→ 索引后被搜索引擎收录 → 全量泄露
```

### 2.5 供应链内鬼

```text
外包/运维人员拥有生产访问权
→ 植入定时任务或后门账号
→ 离职后继续访问
```

## 3. 影响

- 大规模客户/员工数据泄露，合规重罚
- 商业机密与源代码外流
- 资金损失（内鬼勾结外部）
- 信任崩塌，客户流失
- 若为破坏型，可导致业务中断

## 4. 防御措施

1. **最小权限 + 即时授权（JIT）**
   - 默认最小权限，敏感操作按需临时授权并审批
   - 定期权限复核（季度），离职/转岗立即回收
2. **职责分离**
   - 开发/运维/财务/审计权限分离
   - 生产数据访问需双人审批
3. **数据防泄漏（DLP）**
   - 识别敏感数据（身份证、卡号、源码、合同）
   - 监控外发渠道：邮件、IM、云盘、USB、打印、剪贴板
   - 对批量导出设阈值与审批
4. **UEBA / 行为分析**
   - 建立用户行为基线（访问量、时间、地点、设备）
   - 异常评分与告警，而非仅靠规则
5. **审计与不可抵赖**
   - 全量记录数据访问、导出、权限变更
   - 日志集中、只追加、管理员也不可删
6. **离职/转岗流程（Offboarding）**
   - 当日禁用账号、吊销会话与 Token、回收设备与门禁
   - 检查邮箱转发规则、OAuth 授权、API Key、共享链接
   - 交接期限制批量下载
7. **技术管控**
   - 禁用个人邮箱/个人网盘（或强制代理审计）
   - USB 存储管控（见 `52-physical-usb`）
   - 屏幕水印、打印审计、剪贴板管控
8. **蜜罐与诱饵**
   - 蜜罐文件/账号/数据库表，访问即告警
   - 虚假客户记录用于追踪泄露源
9. **合同与合规**
   - 保密协议、可接受使用政策、背景调查（合法合规）
   - 明确监控告知，避免法律风险
10. **文化与举报**
    - 匿名举报渠道、心理支持、减少「被迫内鬼」

## 5. 配置与检测对比

```yaml
# ✅ DLP 规则（示意）
rules:
  - name: bulk_export_customer_data
    match: { action: export, table: customers, rows: ">1000" }
    action: require_approval + alert
  - name: external_email_with_pii
    match: { channel: email, destination: "not in corporate_domains", content: pii }
    action: block + notify_security
  - name: public_share_link
    match: { action: share, visibility: public }
    action: block
```

```yaml
# ✅ SIEM 检测：离职期批量下载
- alert: OffboardingBulkDownload
  expr: |
    sum by (user) (rate(data_export_rows_total{user=~"$offboarding_users"}[1h])) > 5000
  for: 10m
  labels: { severity: high }
```

```yaml
# ✅ SIEM 检测：新建外部转发规则
- alert: MailForwardingRuleCreated
  expr: increase(mail_rule_created_total{forward_to_external="true"}[5m]) > 0
```

```bash
# ✅ 离职检查清单（自动化脚本思路）
# 1. 禁用账号 / 吊销所有会话
# 2. 撤销 OAuth 授权与 API Key
# 3. 检查邮箱转发规则
# 4. 检查云盘共享链接
# 5. 回收设备、门禁、VPN 证书
# 6. 转移数据所有权（云盘/代码仓库）
```

```sql
-- ✅ 数据访问审计（示例）
SELECT actor, action, object, rows_affected, ip, ts
FROM audit_log
WHERE ts > now() - interval '24 hours'
  AND action IN ('export', 'download', 'bulk_read')
ORDER BY rows_affected DESC
LIMIT 50;
```

## 6. 自查清单

- [ ] 权限按最小化分配，季度复核
- [ ] 敏感操作 JIT 授权 + 双人审批
- [ ] DLP 覆盖邮件/IM/云盘/USB/打印/剪贴板
- [ ] 批量导出有阈值与审批
- [ ] UEBA 行为基线已建立并告警
- [ ] 数据访问审计完整且不可篡改
- [ ] 离职/转岗当日完成账号与权限回收
- [ ] 离职检查含邮件规则、OAuth、API Key、共享链接
- [ ] USB 与个人网盘受管控
- [ ] 蜜罐文件/账号已部署
- [ ] 有保密协议、监控告知与举报渠道

## 7. 参考资料

- MITRE ATT&CK T1078: Valid Accounts
- MITRE ATT&CK T1567: Exfiltration Over Web Service
- CERT/CC: Insider Threat Center
- CISA: Insider Threat Mitigation Guide
- NIST SP 800-53 AC / AU 控制族
- 关联本库：`30-sensitive-data-exposure`、`40-logging-monitoring`、`42-account-takeover`
