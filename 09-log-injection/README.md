# 日志注入 / 日志伪造 (Log Injection & Log Forging)

> 分类：注入类 | 风险：中 | CWE-117

## 1. 攻击原理

应用把用户可控数据直接写入日志。攻击者插入换行符或伪造的日志格式，可以：

- 伪造日志条目（把攻击行为伪装成正常请求）
- 污染日志解析，导致 SIEM 误报或漏报
- 在查看日志的终端中注入 ANSI 转义序列（终端劫持）
- 若日志被渲染到 HTML 后台，形成存储型 XSS（日志查看器 XSS）

## 2. 攻击示例

```js
// ❌ 直接拼接
logger.info(`login failed for user=${username} ip=${ip}`);
```

输入 `username = "admin\n2026-01-01 INFO login success for user=root"`，日志变成：

```text
login failed for user=admin
2026-01-01 INFO login success for user=root ip=...
```

安全分析人员会误认为 root 登录成功。

终端转义：

```text
\x1b[2J\x1b[31mFAKE ALERT\x1b[0m
```

日志查看器 XSS（后台把日志当 HTML 渲染）：

```html
<img src=x onerror=alert(document.cookie)>
```

## 3. 影响

- 掩盖攻击痕迹，影响取证与合规审计
- SIEM 规则被绕过、告警疲劳
- 运维终端被控制或误导
- 日志后台的 XSS → 管理员会话被劫持（高危组合）

## 4. 防御措施

1. **结构化日志**：使用 JSON 日志（pino / winston / logback JSON encoder / zap），值作为字段而非拼接字符串。
2. **转义控制字符**：至少替换 `\r`、`\n`、`\t` 与 `\x00`；ANSI 转义统一剥离。
3. **长度截断**：单字段限制长度（如 256/1024），防止日志炸弹。
4. **日志查看器转义**：后台展示日志时按纯文本渲染（`textContent`），禁止 `innerHTML`；或下载为文件查看。
5. **日志完整性**：只追加写入、集中收集（Fluent Bit / Filebeat → SIEM），应用账号无删除权限。
6. **敏感信息脱敏**：手机号、身份证、卡号、Token、密码在写入前脱敏。
7. **时间与来源可信**：由服务端生成时间戳，客户端 IP 取可信代理链结果。

## 5. 代码对比

```js
// ❌
console.log(`user=${user} action=${action}`);

// ✅ 结构化
logger.info({ user: sanitizeLog(user), action, ip }, 'user action');

function sanitizeLog(v) {
  return String(v)
    .replace(/[\r\n\t]/g, ' ')
    .replace(/\x1b\[[0-9;]*[A-Za-z]/g, '')
    .slice(0, 1024);
}
```

```python
# ✅ Python logging（参数化，不拼串）
logger.info("login failed user=%s ip=%s", sanitize(user), ip)
```

```html
<!-- ✅ 日志后台 -->
<pre><code>{{ logLine }}</code></pre>   <!-- 模板自动转义 -->
```

## 6. 自查清单

- [ ] 全部使用结构化日志，无字符串拼接用户输入
- [ ] 控制字符与 ANSI 转义已剥离
- [ ] 单字段长度限制已生效
- [ ] 日志查看界面按纯文本渲染，无 HTML 注入
- [ ] 日志只追加，应用无删除/修改权限
- [ ] 敏感字段已脱敏
- [ ] 日志集中收集并有完整性校验

## 7. 参考资料

- OWASP: Logging Cheat Sheet
- CWE-117: Improper Output Neutralization for Logs
- CWE-532: Insertion of Sensitive Information into Log File
