# 跨站请求伪造 CSRF (Cross-Site Request Forgery)

> 分类：身份/会话 | 风险：高 | CWE-352 | OWASP A01:2021

## 1. 攻击原理

浏览器会自动携带目标站点的 Cookie。攻击者诱导已登录用户在**不知情**的情况下向目标站发送状态变更请求（转账、改密、加管理员），服务端只凭 Cookie 认定身份，无法区分请求来源。

前提条件：

1. 认证依赖 Cookie（或 Basic Auth）自动携带；
2. 参数可被攻击者预测/构造；
3. 没有不可预测的校验因子。

GET 型 CSRF 最容易被利用（`<img src="https://bank/transfer?to=evil&amt=1000">`）；POST 型可用自动提交表单或 `fetch`（受 CORS 限制但简单请求仍会发出）。

## 2. 攻击示例

```html
<!-- 放在攻击者站点 -->
<form action="https://bank.com/transfer" method="POST" id="f">
  <input name="to" value="attacker">
  <input name="amount" value="10000">
</form>
<script>document.getElementById('f').submit();</script>
```

用户访问攻击页面 → 浏览器带上 `bank.com` 的 Cookie 提交 → 转账成功。

JSON 接口若接受 `text/plain`（简单请求），也可用表单绕过预检：

```html
<form action="https://api.site.com/user/email" method="POST" enctype="text/plain">
  <input name='{"email":"evil@x.com","x":"' value='"}'>
</form>
```

## 3. 影响

- 以受害者身份执行任意操作（转账、改密、授权）
- 账号接管（修改邮箱/密码后走找回流程）
- 管理员被诱导创建后门账号

## 4. 防御措施

1. **CSRF Token（核心）**
   - 同步令牌：服务端生成随机 Token 绑定 Session，写入页面隐藏域或 Header，服务端比对。
   - Double Submit Cookie：Token 同时放 Cookie 与请求体/Header，服务端比对二者（需注意子域注入 Cookie 风险）。
   - Token 必须**不可预测、与会话绑定、使用后可选轮换**。
2. **SameSite Cookie**：`SameSite=Lax` 覆盖大多数场景（顶层 GET 导航仍带 Cookie，但 POST 跨站不带）；高敏感操作可用 `Strict`。`None` 必须配 `Secure` 且需额外 Token 防护。
3. **校验 Origin / Referer**：写操作请求校验 `Origin` 是否在白名单；缺失时按策略拒绝。
4. **不使用 GET 做状态变更**：所有写操作使用 POST/PUT/PATCH/DELETE。
5. **敏感操作二次确认**：重输密码、MFA、验证码。
6. **自定义请求头**：要求 `X-Requested-With` 或自定义 Header（触发预检，跨站无法伪造）——仅作辅助。
7. **避免 CORS 宽松配置**：`Access-Control-Allow-Origin: *` + 凭证会放大风险。
8. **纯 Token API**：Authorization Header 传递 Bearer Token（不存 Cookie）天然免疫 CSRF，但要防 XSS 窃取。

## 5. 代码对比

```js
// ✅ Express：生成 + 校验
const crypto = require('crypto');
app.use((req, res, next) => {
  if (!req.session.csrf) req.session.csrf = crypto.randomBytes(32).toString('hex');
  res.locals.csrf = req.session.csrf;
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
    const token = req.get('X-CSRF-Token') || req.body?._csrf;
    const a = Buffer.from(String(token ?? ''));
    const b = Buffer.from(req.session.csrf);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return res.status(403).json({ error: 'invalid csrf token' });
    }
  }
  next();
});
```

```js
// ✅ Cookie
app.use(session({
  cookie: { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 1800000 },
}));
```

```js
// ✅ Origin 校验
const ALLOWED = new Set(['https://app.site.com']);
app.use((req, res, next) => {
  if (['POST','PUT','PATCH','DELETE'].includes(req.method)) {
    const origin = req.get('Origin');
    if (origin && !ALLOWED.has(origin)) return res.status(403).end();
  }
  next();
});
```

```html
<!-- ✅ 模板中注入 -->
<form method="post" action="/transfer">
  <input type="hidden" name="_csrf" value="{{ csrf }}">
  ...
</form>
```

## 6. 自查清单

- [ ] 所有写操作接口有 CSRF Token 校验（或纯 Bearer Token 认证）
- [ ] Cookie 设置 `SameSite=Lax/Strict` + `Secure` + `HttpOnly`
- [ ] 写操作校验 Origin/Referer
- [ ] 无 GET 型状态变更接口
- [ ] 敏感操作有二次验证
- [ ] CORS 未使用 `*` 搭配 credentials
- [ ] 登出、改密、绑卡等关键流程单独测试 CSRF

## 7. 参考资料

- OWASP: Cross-Site Request Forgery Prevention Cheat Sheet
- CWE-352
- PortSwigger: CSRF
