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
| 41 | [phishing](./41-phishing/README.md) | 钓鱼与社工攻击（含 AiTM / BEC） | 高 | MITRE T1566 |
| 42 | [account-takeover](./42-account-takeover/README.md) | 账号接管 ATO | 严重 | CWE-287 / 522 / 640 |
| 43 | [clickfix](./43-clickfix/README.md) | 假验证码剪贴板攻击 ClickFix | 高 | MITRE T1204.004 |
| 44 | [watering-hole](./44-watering-hole/README.md) | 水坑攻击 | 高 | MITRE T1189 |
| 45 | [ddos](./45-ddos/README.md) | 分布式拒绝服务 DDoS | 高 | MITRE T1498 / T1499 |
| 46 | [mitm](./46-mitm/README.md) | 中间人攻击 MITM | 高 | MITRE T1557 |
| 47 | [dns-attacks](./47-dns-attacks/README.md) | DNS 攻击（投毒/隧道/接管） | 高 | MITRE T1071.004 |
| 48 | [malware](./48-malware/README.md) | 恶意软件（勒索/窃密/无文件） | 严重 | MITRE TA0002 / TA0040 |
| 49 | [credential-theft](./49-credential-theft/README.md) | 凭据窃取与横向移动 | 严重 | MITRE TA0006 / TA0008 |
| 50 | [cloud-container](./50-cloud-container/README.md) | 云与容器攻击 | 严重 | MITRE T1078.004 / T1611 |
| 51 | [insider-threat](./51-insider-threat/README.md) | 内部威胁 | 高 | MITRE T1078 / T1567 |
| 52 | [physical-usb](./52-physical-usb/README.md) | 物理与近场攻击（BadUSB 等） | 高 | MITRE T1200 / T1091 |
| 53 | [deepfake](./53-deepfake/README.md) | 深度伪造与 AI 社工 | 高 | MITRE T1566 / T1656 |

> 说明：01–40 是「Web 漏洞 / 缺陷」维度；41–53 是「非 Web 攻击链」维度，覆盖**人、网络、终端、身份、云、物理、AI** 七层。它们不依赖目标站代码缺陷，Web 只是其中一个入口。

## 攻击链视图

真实入侵往往不是单点，而是把多篇内容串成一条链。

### 时间线：从侦察到影响

```text
侦察/准备 ──▶ 投递/初始访问 ──▶ 执行/植入 ──▶ 横向/提权 ──▶ 外带/影响
              41 钓鱼              43 ClickFix      49 凭据窃取      48 勒索/窃密
              44 水坑              48 恶意软件      50 云与容器      51 内部威胁
              53 深度伪造          52 物理/USB      42 账号接管      45 DDoS
              46 中间人 / 47 DNS
```

### 社工主线：靠人完成，不碰代码

```text
41-phishing ──▶ 43-clickfix ──▶ 42-account-takeover ──▶ 变现
骗密码 / OTP     骗用户执行代码      窃会话 / 持久化        转账 / 盗数据
     └──────────────┴──▶ 借道 25-open-redirect、03-xss
                          让恶意链接寄生在可信域名下
```

### 漏洞主线：直接打系统，跳过「骗人」环节

```text
01-sql-injection / 02-command-injection
12-insecure-deserialization / 31-ssrf
      └──▶ RCE 或全量数据泄露
```

### 三条主线，三种防线

| 主线 | 关键防线 |
|---|---|
| 社工（人） | 抗钓鱼 MFA、剪贴板策略、演练、流程复核、回拨验证 |
| 网络/终端（系统） | 分段、出网白名单、EDR、补丁、最小权限、备份 |
| Web 漏洞（代码） | 参数化、输出编码、鉴权、SSRF 白名单、安全配置 |

## 应急处置（Runbooks）

前面的目录回答「怎么防」，[`runbooks/`](./runbooks/README.md) 回答「已经出事怎么办」：把角色、命令、验证、升级路径写死，值班时照着执行。

| ID | 场景 | 默认级别 |
|---|---|---|
| [RB-001](./runbooks/ransomware.md) | 勒索软件 / 批量加密 | P1 |
| [RB-002](./runbooks/account-takeover.md) | 账号接管 ATO | P2（管理员 P1） |
| [RB-003](./runbooks/data-breach.md) | 数据泄露 / 外泄 | P1 |
| [RB-004](./runbooks/ddos.md) | DDoS / 流量攻击 | P2 |
| [RB-005](./runbooks/phishing-report.md) | 钓鱼邮件上报与处置 | P3 |
| [RB-006](./runbooks/malware-isolation.md) | 恶意软件隔离与取证 | P2 |
| [RB-007](./runbooks/credential-leak.md) | 密钥 / 凭据泄露 | P1 |
| [RB-008](./runbooks/cloud-compromise.md) | 云账号失陷 | P1 |
| [RB-009](./runbooks/cert-expiry.md) | 证书过期 / 即将过期 | P3（已过期 P1） |

> 通用原则：先止血、再取证，不要关机；破坏性操作双人确认；对外沟通统一出口。详见 [`runbooks/README.md`](./runbooks/README.md)。

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
- 抗钓鱼 MFA（Passkey/WebAuthn）+ 会话可即时吊销
- 全盘加密 + 3-2-1 离线/不可变备份 + 恢复演练
- 终端 EDR + 出网白名单 + 网络分段（默认拒绝）
- 大额转账/改账户：回拨已知号码 + 双人复核

## 推荐标准

- OWASP Top 10 / OWASP ASVS / OWASP Cheat Sheet Series
- CWE Top 25
- NIST SP 800-63B（认证与口令）
- MITRE ATT&CK（Web 相关战术）
