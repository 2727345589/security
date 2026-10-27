# 暴力破解 / 撞库 (Brute Force & Credential Stuffing)

> 分类：身份认证 | 风险：高 | CWE-307 / CWE-916

## 1. 攻击原理

攻击者通过自动化手段反复尝试凭据：

| 类型 | 说明 |
|---|---|
| 暴力破解 | 枚举密码空间（6 位数字验证码仅 100 万种） |
| 字典攻击 | 使用常见密码/弱口令字典 |
| 撞库 | 用其他站点泄露的「邮箱+密码」批量尝试 |
| 密码喷洒 | 少量常见密码（`Password123`）横向尝试大量账号，规避锁定 |
| 凭据填充 API | 针对登录、OTP、找回密码、邀请码等接口 |

自动化工具：Hydra、Burp Intruder、Sentry MBA、OpenBullet。

## 2. 攻击示例

```bash
# 对登录接口做字典攻击
ffuf -u https://site.com/api/login -X POST \
  -H 'Content-Type: application/json' \
  -d '{"email":"victim@x.com","password":"FUZZ"}' \
  -w rockyou.txt -mc 200 -fr 'invalid'
```

OTP 爆破：6 位验证码接口无限流，几分钟即可穷举。

密码喷洒：

```text
user1@corp.com : Summer2026
user2@corp.com : Summer2026
...
```

## 3. 影响

- 账号接管、批量数据泄露
- 内部系统被攻破（VPN、邮箱、后台）
- 结合泄露数据形成连锁失守

## 4. 防御措施

1. **登录限流（多层）**
   - 按 IP、按账号、按 IP+账号组合分别限流。
   - 指数退避：失败次数越多延迟越长。
   - 分布式限流（Redis 计数器），避免单实例绕过。
2. **账号锁定 / 挑战**：连续失败后触发验证码、MFA 或临时锁定（注意防「锁死他人账号」的 DoS，使用渐进式挑战而非硬锁）。
3. **强密码策略**：最小长度 12，比对已泄露密码库（HIBP k-anonymity API），禁止常见弱口令。
4. **MFA**：后台、支付、改密等强制二次验证；优先 WebAuthn/Passkey。
5. **OTP 防护**：短有效期（5 分钟）、单次使用、失败限次（如 5 次后失效重发）、发送频率限制。
6. **设备与行为风控**：新设备、异地、异常 UA、无头浏览器特征触发挑战。
7. **统一响应与耗时**：失败信息不区分「账号不存在/密码错误」，避免账号枚举；比较使用常量时间。
8. **监控告警**：单 IP/单账号失败率突增、分布式低频喷洒模式（按 ASN/指纹聚合）。
9. **泄露凭据检测**：登录时校验密码是否在泄露库中，命中则强制改密。

## 5. 代码对比

```js
// ✅ 分层限流 + 渐进延迟
const MAX_PER_IP = 20;      // 每分钟
const MAX_PER_ACCOUNT = 5;  // 每 15 分钟

async function login(req, res) {
  const { email, password } = req.body;
  const ipKey = `login:ip:${req.ip}`;
  const accKey = `login:acc:${email}`;

  const [ipCount, accCount] = await Promise.all([
    redis.incr(ipKey).then((n) => (n === 1 ? redis.expire(ipKey, 60) : n)),
    redis.incr(accKey).then((n) => (n === 1 ? redis.expire(accKey, 900) : n)),
  ]);
  if (ipCount > MAX_PER_IP || accCount > MAX_PER_ACCOUNT) {
    return res.status(429).json({ error: 'too many attempts' });
  }

  const user = await User.findOne({ email });
  const ok = user ? await argon2.verify(user.passwordHash, password) : await fakeVerify();
  if (!ok) {
    await recordFailure(email, req.ip);
    return res.status(401).json({ error: 'invalid credentials' }); // 统一文案
  }
  await clearFailures(accKey);
  req.session.regenerate(() => { /* 绑定用户 */ });
  res.json({ ok: true });
}
```

```js
// ✅ OTP 限次
if (await redis.get(`otp:tries:${userId}`) >= 5) {
  await redis.del(`otp:${userId}`);
  return res.status(429).json({ error: 'code expired, request a new one' });
}
```

## 6. 自查清单

- [ ] 登录接口有 IP / 账号 / 组合三维限流
- [ ] 失败次数触发渐进挑战或临时锁定
- [ ] 密码长度 ≥ 12 并校验泄露库
- [ ] 关键场景强制 MFA，优先 Passkey
- [ ] OTP 短时效 + 单次 + 限次 + 发送频率限制
- [ ] 登录响应统一，无账号枚举
- [ ] 异常登录有告警与用户通知
- [ ] 限流在网关或 Redis 层，多实例共享

## 7. 参考资料

- OWASP: Credential Stuffing Prevention Cheat Sheet
- OWASP: Authentication Cheat Sheet
- NIST SP 800-63B
- CWE-307 / CWE-916
