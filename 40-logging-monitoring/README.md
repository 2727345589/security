# 日志与监控失效 (Logging & Monitoring Failures)

> 分类：可观测性 | 风险：中 | CWE-778 | OWASP A09:2021

## 1. 攻击原理

攻击发生后无人发现，或发现后无法追溯。多数重大入侵的平均发现时间以「月」计，根源是：

| 缺陷 | 说明 |
|---|---|
| 关键事件未记录 | 登录失败、权限变更、数据导出无日志 |
| 日志不集中 | 只存本机，攻击者删改即消失 |
| 无告警 | 有日志但没人看 |
| 日志含敏感信息 | 密码、Token 明文落盘（二次泄露） |
| 日志可被篡改 | 应用账号可删日志 |
| 无关联分析 | 单点日志无法还原攻击链 |
| 保留期过短 | 事后取证无数据 |
| 时钟不同步 | 多源日志无法关联 |

## 2. 攻击示例

```text
1. 攻击者用泄露凭据登录 → 失败 2000 次，无告警
2. 成功登录（异地）→ 无新设备提醒
3. 创建管理员账号 → 无审计
4. 导出全量用户数据 → 无日志
5. 删除应用日志 → 本地日志被清空
6. 数周后用户投诉才发现
```

日志注入配合（见 09-log-injection）：伪造「正常」记录掩盖真实行为。

## 3. 影响

- 入侵长期潜伏，损失扩大
- 无法定责、无法取证、无法满足合规（等保、ISO 27001、PCI-DSS）
- 无法复盘与改进
- 攻击者重复利用同一入口

## 4. 防御措施

1. **必录事件清单**
   - 认证：登录成功/失败、登出、MFA、密码重置
   - 授权：权限变更、角色分配、越权拒绝（403）
   - 数据：批量导出、下载、删除
   - 管理：配置变更、账号创建/禁用、密钥轮换
   - 安全：WAF 拦截、异常请求、上传失败
2. **结构化日志**：JSON 格式，统一字段（时间、traceId、userId、ip、ua、action、resource、result）。
3. **集中收集**：应用 → 采集器（Fluent Bit / Vector）→ 日志平台（ELK / Loki / Splunk），本机仅缓冲。
4. **不可篡改**：应用只追加写；使用 WORM 存储或对象锁；日志平台与业务账号隔离。
5. **脱敏**：密码、Token、Cookie、身份证、卡号统一过滤（见 30）。
6. **告警规则**（示例）
   - 单账号 5 分钟内失败 ≥ 10 次
   - 同一 IP 触发 403 突增
   - 管理账号在非工作时段/异地登录
   - 单用户 1 小时内导出 > 阈值
   - 关键配置变更
   - 5xx 比例突增、WAF 拦截激增
7. **关联分析**：以 traceId / userId / ip 串联；建立攻击链看板。
8. **保留与合规**：安全日志 ≥ 180 天（按合规要求），冷热分层。
9. **时钟同步**：全部节点 NTP，统一 UTC 存储、展示时转换。
10. **演练**：定期做「紫队」演练，验证告警是否能被发现。
11. **隐私合规**：日志中个人数据最小化，访问受控。

## 5. 代码对比

```js
// ✅ 结构化安全日志
logger.info({
  event: 'auth.login',
  result: 'failure',
  userId: user?.id ?? null,
  emailHash: sha256(email),      // 不明文存邮箱
  ip: req.ip,
  ua: req.get('user-agent'),
  traceId: req.id,
  reason: 'bad_password',
}, 'login failed');

// ✅ 审计日志（独立 logger / 独立索引）
audit.info({
  event: 'admin.user.role_changed',
  actorId: req.user.id,
  targetId: params.id,
  from: 'user',
  to: 'admin',
  ip: req.ip,
  traceId: req.id,
});

// ✅ 敏感操作告警
if (exportedRows > 10000) {
  alerting.warn('data.export.large', { userId: req.user.id, rows: exportedRows });
}
```

```yaml
# ✅ Promtail / Fluent Bit 采集
scrape_configs:
  - job_name: app
    static_configs:
      - targets: ['localhost']
        labels:
          app: web
          env: prod
```

```yaml
# ✅ 告警规则（Prometheus 风格示意）
- alert: BruteForceSuspected
  expr: sum(rate(auth_login_failure_total[5m])) by (account) > 0.2
  for: 5m
  labels: { severity: high }
  annotations: { summary: "账号 {{ $labels.account }} 登录失败突增" }
```

```js
// ✅ 请求级 traceId
import { randomUUID } from 'crypto';
app.use((req, res, next) => {
  req.id = req.get('X-Request-Id') ?? randomUUID();
  res.setHeader('X-Request-Id', req.id);
  next();
});
```

## 6. 自查清单

- [ ] 认证/授权/数据/管理/安全事件全部有日志
- [ ] 结构化日志 + 统一字段 + traceId
- [ ] 日志集中收集，本机不可作为唯一存储
- [ ] 应用无删除/修改日志权限
- [ ] 敏感字段已脱敏
- [ ] 关键场景有告警规则并验证有效
- [ ] 保留期满足合规要求
- [ ] 全节点时钟同步
- [ ] 有定期演练验证检测能力
- [ ] 日志访问受控（RBAC）

## 7. 参考资料

- OWASP: Logging Cheat Sheet
- OWASP A09:2021 Security Logging and Monitoring Failures
- CWE-778: Insufficient Logging
- NIST SP 800-92 (Log Management)
