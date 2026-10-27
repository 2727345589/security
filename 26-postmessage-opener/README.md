# postMessage / window.opener 滥用 (Cross-Window Messaging & Tabnabbing)

> 分类：客户端 / 浏览器 | 风险：中 | CWE-346 / CWE-1022

## 1. 攻击原理

### postMessage 未校验来源
`window.postMessage` 允许跨源通信。接收方若直接信任 `event.data` 而不校验 `event.origin`，任意站点都能发送消息，导致：

- 敏感数据被读取（发送方把数据回传给任意源）
- DOM XSS（接收方把消息写入 `innerHTML`）
- 逻辑绕过（伪造「已认证」「支付成功」消息）

### window.opener / tabnabbing
`target="_blank"` 打开的页面可通过 `window.opener` 反向控制原页面（跳转到钓鱼页）。`postMessage` 未指定 `targetOrigin` 为 `*` 时，消息也会被任意源接收。

## 2. 攻击示例

### 接收端未校验 origin

```js
// ❌ 受害页面
window.addEventListener('message', (e) => {
  document.getElementById('content').innerHTML = e.data;   // XSS
});
```

攻击页面：

```js
const w = window.open('https://trusted.com/widget');
w.postMessage('<img src=x onerror=alert(document.cookie)>', '*');
```

### 发送端用 `*`

```js
// ❌ 泄露数据给任意嵌入方
iframe.contentWindow.postMessage({ token: userToken }, '*');
```

攻击者把自己的页面作为父窗口嵌入该 widget，即可收到 Token。

### tabnabbing

```html
<!-- ❌ -->
<a href="https://evil.com" target="_blank">文档</a>
<script>
  // evil.com 上执行：
  window.opener.location = 'https://trusted.com.evil.com/login';
</script>
```

用户切回原标签，看到的是伪造登录页。

## 3. 影响

- Token / 用户数据泄露
- DOM XSS
- 原页面被跳转至钓鱼站
- 跨窗口逻辑绕过

## 4. 防御措施

1. **接收端严格校验**：
   ```js
   window.addEventListener('message', (e) => {
     if (e.origin !== 'https://trusted.com') return;
     if (e.source !== expectedWindow) return;
     // 校验并白名单处理消息类型
     if (e.data?.type !== 'resize') return;
   });
   ```
2. **发送端指定精确 `targetOrigin`**：绝不用 `'*'`，除非消息完全公开。
3. **消息协议白名单**：`type` 枚举 + schema 校验；不用 `innerHTML` 渲染消息内容。
4. **`target="_blank"` 加 `rel="noopener noreferrer"`**；现代浏览器默认 `noopener`，但仍应显式声明。
5. **`Cross-Origin-Opener-Policy: same-origin`**：隔离 opener 关系。
6. **iframe 加 `sandbox`**：最小权限（`allow-scripts` 与 `allow-same-origin` 不要同时给）。
7. **`X-Frame-Options` / `frame-ancestors`**：限制被嵌入（见 23-clickjacking）。

## 5. 代码对比

```js
// ✅ 接收端
const ALLOWED_ORIGINS = new Set(['https://app.site.com']);
const ALLOWED_TYPES = new Set(['resize', 'navigate']);

window.addEventListener('message', (event) => {
  if (!ALLOWED_ORIGINS.has(event.origin)) return;
  const { type, payload } = event.data ?? {};
  if (!ALLOWED_TYPES.has(type)) return;
  if (type === 'resize' && Number.isFinite(payload?.height)) {
    document.body.style.height = `${payload.height}px`;   // 不用 innerHTML
  }
});

// ✅ 发送端
iframe.contentWindow.postMessage({ type: 'init' }, 'https://app.site.com');
```

```html
<!-- ✅ -->
<a href="https://external.com" target="_blank" rel="noopener noreferrer">外部链接</a>

<iframe src="https://widget.site.com"
        sandbox="allow-scripts"
        referrerpolicy="no-referrer"></iframe>
```

```
# ✅ 响应头
Cross-Origin-Opener-Policy: same-origin
```

## 6. 自查清单

- [ ] 所有 `message` 监听校验 `origin` 与 `source`
- [ ] 所有 `postMessage` 使用精确 `targetOrigin`
- [ ] 消息内容按 schema 校验，渲染不用 `innerHTML`
- [ ] `target="_blank"` 全部带 `rel="noopener noreferrer"`
- [ ] 已设置 `Cross-Origin-Opener-Policy`
- [ ] iframe 使用最小 `sandbox` 权限
- [ ] 嵌入组件有 origin 白名单

## 7. 参考资料

- OWASP: HTML5 Security Cheat Sheet
- CWE-346: Origin Validation Error
- CWE-1022: Use of Web Link to Untrusted Target with window.opener Access
- MDN: Window.postMessage
