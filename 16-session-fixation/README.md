# 会话固定 / 会话管理缺陷 (Session Fixation & Session Management)

> 分类：身份/会话 | 风险：高 | CWE-384 / CWE-613 / CWE-614

## 1. 攻击原理

### 会话固定
攻击者预先获得/设置一个 Session ID，诱导受害者用该 ID 登录；登录后服务端**未更换** Session ID，攻击者的 ID 即成为已认证会话，直接接管账号。

设置途径：

- URL 中携带 `?jsessionid=xxx`，服务端接受并沿用
- 子域可写 Cookie（`Domain=.site.com`）被恶意子域覆盖
- 攻击者自建账号拿到 ID 后诱导受害者使用（少见）

### 其他会话缺陷

| 缺陷 | 说明 |
|---|---|
| Session ID 可预测 | 用时间戳、自增、弱随机 |
| 不失效 | 登出/改密后旧会话仍有效 |
| 无超时 | 会话永久有效 |
| URL 传 Session | 泄露到 Referer、日志、历史记录 |
| Cookie 缺属性 | 无 HttpOnly / Secure / SameSite |
| 并发会话失控 | 泄露的旧会话长期潜伏 |

## 2. 攻击示例

```text
1. 攻击者访问 site.com，获得 SID=abc123
2. 诱导受害者打开 https://site.com/?sid=abc123（或通过 XSS 设置 Cookie）
3. 受害者登录，服务端沿用 abc123 作为已认证会话
4. 攻击者用 abc123 访问，直接进入受害者账户
```

会话预测：SID 为 `user_1001`、`1002`... 或基于 `md5(timestamp)`。

## 3. 影响

- 账号接管，且受害者无感知（无需知道密码）
- 登出后仍可被重放
- 会话泄露面扩大（日志/Referer）

## 4. 防御措施

1. **登录成功后重新生成 Session ID**（最关键）：`req.session.regenerate()` / `request.changeSessionId()`；改密、提权、绑定 MFA 后同样轮换。
2. **登出销毁服务端会话**：`session.destroy()` + 清 Cookie，而非仅前端删 Token。
3. **Session ID 高熵**：≥ 128 bit 密码学随机（框架默认即可，勿自研）。
4. **Cookie 三属性**：`HttpOnly; Secure; SameSite=Lax/Strict; Path=/`，必要时 `__Host-` 前缀。
5. **空闲超时 + 绝对超时**：如 30 分钟空闲失效、12 小时绝对失效；敏感系统更短。
6. **禁止 URL 传 Session**：不读取 `?sid=`，关闭 `URL rewriting`（如 Tomcat `tracking-mode=COOKIE`）。
7. **会话存储安全**：Redis 加密/隔离，设置 TTL；多实例共享但不可被外部访问。
8. **并发会话策略**：改密后使其他会话失效；提供「登录设备管理」。
9. **绑定辅助因子（可选）**：IP/UA 变化时要求重新认证（注意移动网络误伤）。

## 5. 代码对比

```js
// ✅ Express + express-session
app.post('/login', async (req, res) => {
  const user = await verify(req.body);
  if (!user) return res.status(401).end();

  req.session.regenerate((err) => {          // 关键：换 ID
    if (err) return res.status(500).end();
    req.session.userId = user.id;
    req.session.createdAt = Date.now();
    req.session.save(() => res.json({ ok: true }));
  });
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('sid', { path: '/' });
    res.json({ ok: true });
  });
});

app.use(session({
  name: 'sid',
  secret: process.env.SESSION_SECRET,   // 高熵，来自 KMS
  resave: false,
  saveUninitialized: false,
  rolling: true,                        // 活跃时续期
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    maxAge: 30 * 60 * 1000,             // 空闲超时
  },
  store: new RedisStore({ client: redis, ttl: 1800 }),
}));
```

```java
// ✅ Servlet
request.changeSessionId();   // 登录成功后调用
request.getSession().invalidate();  // 登出
```

```xml
<!-- ✅ Tomcat：只接受 Cookie 传会话，禁止 URL 重写 -->
<!-- conf/context.xml -->
<Context sessionCookiePath="/" useHttpOnly="true">
  <CookieProcessor sameSiteCookies="lax" />
</Context>

<!-- conf/server.xml：Connector 上设置 -->
<Connector port="8080" protocol="HTTP/1.1" tracking-mode="COOKIE" />
```

## 6. 自查清单

- [ ] 登录/提权/改密后 Session ID 已轮换
- [ ] 登出销毁服务端会话并清除 Cookie
- [ ] Session ID 高熵随机，非自增/时间戳
- [ ] Cookie 具备 HttpOnly + Secure + SameSite
- [ ] 空闲超时与绝对超时已配置
- [ ] 不接受 URL 中的 Session ID
- [ ] 会话存储不可公网访问且有 TTL
- [ ] 改密后其他设备会话失效

## 7. 参考资料

- OWASP: Session Management Cheat Sheet
- CWE-384: Session Fixation
- CWE-613: Insufficient Session Expiration
- CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
