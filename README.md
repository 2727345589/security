# Web 应用安全攻击面知识库

按「一种攻击 = 一个文件夹」组织。每个目录内 `README.md` 包含：攻击原理 → 攻击示例 → 影响 → 防御措施 → 代码对比 → 自查清单 → 参考资料。

## 目录索引

| 编号 | 目录 | 攻击名称 | 风险 | CWE |
|---|---|---|---|---|
| 01 | [sql-injection](./01-sql-injection/README.md) | SQL 注入 | 严重 | CWE-89 |
| 02 | [command-injection](./02-command-injection/README.md) | 命令注入 / 代码执行 | 严重 | CWE-78 / CWE-94 |
| 03 | [xss](./03-xss/README.md) | 跨站脚本 XSS | 高 | CWE-79 |
| 04 | [nosql-injection](./04-nosql-injection/README.md) | NoSQL 注入 | 高 | CWE-943 |
| 05 | [ldap-xpath-injection](./05-ldap-xpath-injection/README.md) | LDAP / XPath 注入 | 中高 | CWE-90 / CWE-643 |
| 06 | [ssti](./06-ssti/README.md) | 服务端模板注入 SSTI | 严重 | CWE-1336 |
| 07 | [crlf-header-injection](./07-crlf-header-injection/README.md) | CRLF / HTTP 头注入 | 中高 | CWE-113 |
| 08 | [email-header-injection](./08-email-header-injection/README.md) | 邮件头注入 | 中 | CWE-93 |
| 09 | [log-injection](./09-log-injection/README.md) | 日志注入 / 日志伪造 | 中 | CWE-117 |
| 10 | [prototype-pollution](./10-prototype-pollution/README.md) | 原型污染 | 高 | CWE-1321 |
| 11 | [xxe](./11-xxe/README.md) | XML 外部实体注入 XXE | 高 | CWE-611 |
| 12 | [insecure-deserialization](./12-insecure-deserialization/README.md) | 不安全反序列化 | 严重 | CWE-502 |
| 13 | [csrf](./13-csrf/README.md) | 跨站请求伪造 CSRF | 高 | CWE-352 |
| 14 | [brute-force](./14-brute-force/README.md) | 暴力破解 / 撞库 | 高 | CWE-307 / CWE-916 |
| 15 | [password-storage](./15-password-storage/README.md) | 密码存储不当 | 严重 | CWE-256 / CWE-916 |
| 16 | [session-fixation](./16-session-fixation/README.md) | 会话固定 / 会话管理缺陷 | 高 | CWE-384 |
| 17 | [jwt-vulnerabilities](./17-jwt-vulnerabilities/README.md) | JWT 安全缺陷 | 高 | CWE-347 |
| 18 | [idor](./18-idor/README.md) | 越权访问 IDOR / BOLA | 严重 | CWE-639 |
| 19 | [bfla](./19-bfla/README.md) | 功能级越权 BFLA | 高 | CWE-285 |
| 20 | [mass-assignment](./20-mass-assignment/README.md) | 批量赋值 | 高 | CWE-915 |
| 21 | [path-traversal](./21-path-traversal/README.md) | 目录穿越 / 任意文件读取 | 高 | CWE-22 |
| 22 | [file-upload](./22-file-upload/README.md) | 恶意文件上传 | 严重 | CWE-434 |
| 23 | [clickjacking](./23-clickjacking/README.md) | 点击劫持 | 中 | CWE-1021 |
| 24 | [cors-misconfiguration](./24-cors-misconfiguration/README.md) | CORS 配置错误 | 高 | CWE-942 |
| 25 | [open-redirect](./25-open-redirect/README.md) | 开放重定向 | 中 | CWE-601 |
| 26 | [postmessage-opener](./26-postmessage-opener/README.md) | postMessage / window.opener 滥用 | 中 | CWE-346 |
| 27 | [client-side-storage](./27-client-side-storage/README.md) | 客户端存储敏感数据 | 中高 | CWE-922 |
| 28 | [supply-chain](./28-supply-chain/README.md) | 供应链 / 第三方依赖风险 | 高 | CWE-1104 |
| 29 | [security-misconfiguration](./29-security-misconfiguration/README.md) | 安全配置错误 | 高 | CWE-16 |
| 30 | [sensitive-data-exposure](./30-sensitive-data-exposure/README.md) | 敏感数据泄露 | 高 | CWE-200 |
| 31 | [ssrf](./31-ssrf/README.md) | 服务端请求伪造 SSRF | 严重 | CWE-918 |
| 32 | [dos](./32-dos/README.md) | 拒绝服务 / 资源耗尽 | 中高 | CWE-400 / CWE-1333 |
| 33 | [race-condition](./33-race-condition/README.md) | 竞态条件 / TOCTOU | 高 | CWE-362 |
| 34 | [business-logic](./34-business-logic/README.md) | 业务逻辑漏洞 | 高 | CWE-840 |
| 35 | [http-request-smuggling](./35-http-request-smuggling/README.md) | HTTP 请求走私 | 高 | CWE-444 |
| 36 | [host-header-injection](./36-host-header-injection/README.md) | Host 头注入 | 中高 | CWE-644 |
| 37 | [websocket-security](./37-websocket-security/README.md) | WebSocket 安全缺陷 | 中高 | CWE-1385 |
| 38 | [graphql-api](./38-graphql-api/README.md) | GraphQL / API 安全 | 高 | CWE-863 |
| 39 | [prompt-injection](./39-prompt-injection/README.md) | 提示词注入（LLM） | 高 | CWE-1427 |
| 40 | [logging-monitoring](./40-logging-monitoring/README.md) | 日志与监控失效 | 中 | CWE-778 |

## 风险分级说明

| 等级 | 含义 |
|---|---|
| 严重 | 可直接导致远程代码执行、全量数据泄露或账号体系失守 |
| 高 | 可越权访问、批量数据泄露或接管单个账号 |
| 中高 | 需组合利用，或在特定配置下造成实质影响 |
| 中 | 影响有限，但常作为攻击链的一环 |

## 通用防御原则

1. **默认拒绝**：鉴权、CORS、反序列化、路径访问都从白名单出发。
2. **不信任任何输入**：客户端校验只提升体验，服务端必须再校验。
3. **上下文相关编码**：输出到 HTML / JS / URL / SQL 的编码规则不同。
4. **最小权限**：数据库账号、云 IAM、容器权限、接口能力都最小化。
5. **纵深防御**：编码 + CSP + HttpOnly + 监控，不押注单点。
6. **安全左移**：SAST / SCA / 密钥扫描进 CI，上线前 DAST 与渗透测试。

## 最小必做项（覆盖 80% 真实入侵）

- 参数化查询，杜绝字符串拼接 SQL
- 输出编码 + CSP，富文本白名单净化
- 每个接口做对象级 + 功能级鉴权
- CSRF Token + `SameSite` Cookie
- Argon2id/bcrypt 存密码 + 登录限流与 MFA
- 全站 HTTPS + 安全响应头
- SSRF 出网白名单、上传白名单 + 不可执行目录

## 推荐标准

- OWASP Top 10 / OWASP ASVS / OWASP Cheat Sheet Series
- CWE Top 25
- NIST SP 800-63B（认证与口令）
- MITRE ATT&CK（Web 相关战术）
