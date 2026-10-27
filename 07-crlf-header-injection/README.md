# CRLF / HTTP 头注入 (CRLF Injection & HTTP Header Injection)

> 分类：注入类 | 风险：中高 | CWE-113

## 1. 攻击原理

HTTP 头以 `\r\n`（CRLF）分隔。若应用把用户输入拼进响应头、重定向 Location、Cookie 或日志，攻击者可插入 CRLF 提前结束头部，**注入新的响应头或响应体**。

常见入口：

- 重定向参数：`?url=/path` → `Location: /path%0d%0aSet-Cookie: ...`
- 自定义头回显：`X-Request-Id: <用户输入>`
- 日志写入：污染日志解析（日志注入）
- 邮件发送、SMTP 头

## 2. 攻击示例

```http
GET /redirect?url=%0d%0aSet-Cookie:%20admin%3d1%3b%20Path%3d%2f HTTP/1.1
```

服务端拼接：

```
Location: /%0d%0aSet-Cookie: admin=1; Path=/
```

浏览器收到：

```http
Location: /
Set-Cookie: admin=1; Path=/
```

注入伪造 Cookie / 缓存投毒：

```text
%0d%0a%0d%0a<script>alert(1)</script>
```

（配合响应拆分可形成 XSS）注入 `Content-Length` 还可能触发请求走私或缓存污染。

## 3. 影响

- 会话固定、Cookie 覆盖、权限提升
- 响应拆分导致 XSS
- Web 缓存投毒（污染 CDN 缓存影响所有用户）
- 日志伪造、绕过安全监控

## 4. 防御措施

1. **使用框架的 header API**：`res.setHeader(name, value)` / `res.redirect()`，框架会拒绝含 `\r\n` 的值。**不要手工拼 HTTP 报文**。
2. **输入校验**：对进入头部的值做白名单（如 UUID、枚举、`^[A-Za-z0-9._~-]+$`），显式拒绝 `\r`、`\n`、`%0d`、`%0a`。
3. **URL 编码后再比较**：先解码再校验，避免双重编码绕过。
4. **重定向白名单**：不做开放重定向（见 25-open-redirect），仅允许站内相对路径。
5. **Cookie 由框架设置**，不让用户输入成为 Cookie 名/值的一部分。
6. **日志结构化**：JSON 日志 + 转义换行，避免日志注入。
7. **反向代理层校验**：Nginx/网关拒绝含裸 CR/LF 的请求行与头部。

## 5. 代码对比

```js
// ❌ 手工拼接
res.writeHead(302, { Location: req.query.url });
res.setHeader('X-Trace', req.query.trace);

// ✅ 校验 + 框架 API
const trace = String(req.query.trace ?? '');
if (!/^[A-Za-z0-9-]{1,64}$/.test(trace)) return res.status(400).end();
res.setHeader('X-Trace', trace);

const target = safeInternalPath(req.query.next); // 仅允许站内路径
res.redirect(302, target);
```

```python
# ✅ Django
from django.http import HttpResponseRedirect
from django.utils.http import url_has_allowed_host_and_scheme

if url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}):
    return HttpResponseRedirect(next_url)
return HttpResponseRedirect('/')
```

```nginx
# ✅ 网关拒绝裸 CR/LF
if ($request_uri ~* "%0d|%0a") { return 400; }
```

## 6. 自查清单

- [ ] 无手工拼接原始 HTTP 响应
- [ ] 所有进入 header / Location / Cookie 的输入经过白名单校验
- [ ] 校验在 URL 解码之后进行
- [ ] 重定向目标仅限站内路径或白名单域名
- [ ] 日志为结构化格式并转义换行
- [ ] 网关/代理已拦截裸 CR/LF
- [ ] 缓存层对含敏感头的响应不缓存

## 7. 参考资料

- OWASP: HTTP Response Splitting
- CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers
- PortSwigger: HTTP response splitting
