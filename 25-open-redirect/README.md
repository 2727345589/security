# 开放重定向 (Open Redirect)

> 分类：客户端 / 浏览器 | 风险：中 | CWE-601

## 1. 攻击原理

应用接受用户可控的跳转目标（`?next=`、`?redirect=`、`?returnUrl=`）且未校验，攻击者可构造指向自己站点的链接。由于链接域名是可信站点，钓鱼成功率极高；也常被用于绕过 OAuth 回调白名单、SSRF 链、窃取 Token。

## 2. 攻击示例

```text
https://trusted.com/login?next=https://evil.com/phish
```

登录成功后跳转至钓鱼页，用户看到的是真实登录流程，更易输入凭据。

常见绕过技巧：

```text
//evil.com
https://evil.com
\/\/evil.com
https://trusted.com.evil.com
https://trusted.com@evil.com
https://trusted.com%2f@evil.com
//trusted.com.evil.com
%2f%2fevil.com
```

OAuth 场景：`redirect_uri` 校验不严，授权码被投递到攻击者域名 → 账号接管。

## 3. 影响

- 钓鱼攻击（利用可信域名提升成功率）
- OAuth Token / 授权码窃取
- 配合 SSRF、CSRF 扩大影响
- 品牌信誉受损

## 4. 防御措施

1. **只允许相对路径（最安全）**：拒绝任何包含 `://`、`//`、`\` 的值，只接受以单个 `/` 开头的站内路径。
2. **映射表**：用 key → 路径的白名单映射（`?next=dashboard`），不接受任意 URL。
3. **完整域名比对**：解析 URL 后比较 `protocol` + `host` + `port`，而不是字符串包含。
4. **禁止用户信息与片段**：拒绝 `user:pass@`、`#` 等易混淆结构。
5. **登录/授权后跳转**：目标只允许站内，禁止外部域名。
6. **OAuth `redirect_uri`**：**精确匹配**注册值，不做前缀/通配；授权码一次性、短时效、PKCE。
7. **警告页**：确需跳转外部时，展示「即将离开本站」确认页。

## 5. 代码对比

```js
// ❌
res.redirect(req.query.next);

// ✅ 仅允许站内相对路径
function safeNext(next) {
  if (typeof next !== 'string') return '/';
  if (!next.startsWith('/') || next.startsWith('//') || next.startsWith('/\\')) return '/';
  if (next.includes('\\') || next.includes('://')) return '/';
  try {
    const u = new URL(next, 'https://site.com');
    if (u.origin !== 'https://site.com') return '/';
    return u.pathname + u.search;
  } catch {
    return '/';
  }
}
res.redirect(safeNext(req.query.next));

// ✅ 映射表
const NEXT_MAP = { dashboard: '/dashboard', settings: '/settings' };
res.redirect(NEXT_MAP[req.query.next] ?? '/');
```

```python
# ✅ Django
from django.utils.http import url_has_allowed_host_and_scheme
if url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}, require_https=True):
    return redirect(next_url)
return redirect('/')
```

```java
// ✅ Spring
UriComponentsBuilder.fromUriString(next).build();
if (!isSameOrigin(next, request)) throw new BadRequestException();
```

## 6. 自查清单

- [ ] 所有跳转参数只接受站内相对路径或白名单映射
- [ ] 拒绝 `//`、`\`、`://`、`@`、编码变体
- [ ] 使用 URL 解析后比较 origin，而非字符串包含
- [ ] OAuth `redirect_uri` 精确匹配 + PKCE
- [ ] 外部跳转有确认提示页
- [ ] 有自动化测试覆盖常见绕过 payload

## 7. 参考资料

- OWASP: Unvalidated Redirects and Forwards Cheat Sheet
- CWE-601: URL Redirection to Untrusted Site
- PortSwigger: Open redirection
