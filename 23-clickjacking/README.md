# 点击劫持 (Clickjacking)

> 分类：客户端 / 浏览器 | 风险：中 | CWE-1021

## 1. 攻击原理

攻击者用自己的页面通过 `<iframe>` 嵌入目标站点，叠加透明层/遮罩诱导用户点击。用户以为在点「领取奖品」，实际点的是目标站的「确认转账」「授权应用」按钮。

变体：

| 变体 | 说明 |
|---|---|
| 经典点击劫持 | 透明 iframe 覆盖 |
| 拖拽劫持 | 诱导拖拽内容到隐藏区域 |
| 光标劫持 | 伪造光标位置 |
| 双击劫持 | 复制粘贴/双击触发 |
| 表单劫持 | 覆盖输入框窃取键入内容 |

## 2. 攻击示例

```html
<style>
  iframe {
    position: absolute; top: 0; left: 0;
    width: 100%; height: 100%;
    opacity: 0.0001; z-index: 2;
  }
  .bait {
    position: absolute; top: 220px; left: 340px;
    z-index: 1; font-size: 24px;
  }
</style>
<div class="bait">🎉 点击领取 100 元红包</div>
<iframe src="https://bank.com/transfer?to=attacker&amount=1000" scrolling="no"></iframe>
```

用户点击「红包」→ 实际点到转账确认按钮。

## 3. 影响

- 以用户身份执行敏感操作（转账、授权、改密、加好友）
- 结合社工危害放大
- 移动端同样可被利用（触摸劫持）

## 4. 防御措施

1. **CSP `frame-ancestors`（首选）**
   ```
   Content-Security-Policy: frame-ancestors 'none';
   ```
   需允许被自家页面嵌入时：
   ```
   Content-Security-Policy: frame-ancestors 'self' https://app.site.com;
   ```
2. **`X-Frame-Options`（兼容旧浏览器）**
   ```
   X-Frame-Options: DENY
   # 或 SAMEORIGIN
   ```
3. **JS 防御（辅助，不可靠）**：`if (top !== self) top.location = self.location;` — 可被 sandbox 绕过，只作补充。
4. **敏感操作二次确认**：转账、授权需重新输入密码 / MFA。
5. **SameSite Cookie**：降低跨站场景下的会话可用性（辅助）。
6. **一次性 Token**：授权、支付确认使用一次性 nonce，防重放。

## 5. 代码对比

```js
// ✅ Express：统一安全头（helmet）
import helmet from 'helmet';
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      frameAncestors: ["'none'"],   // 或 ["'self'"]
      objectSrc: ["'none'"],
    },
  },
  frameguard: { action: 'deny' },    // X-Frame-Options: DENY
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
}));
```

```nginx
# ✅ Nginx
add_header Content-Security-Policy "frame-ancestors 'none';" always;
add_header X-Frame-Options "DENY" always;
```

```yaml
# ✅ 仅允许特定页面被嵌入
# 登录页 / 支付页：frame-ancestors 'none'
# 可嵌入的 widget 页：frame-ancestors https://partner.com
```

## 6. 自查清单

- [ ] 全站响应带 `frame-ancestors 'none'` 或白名单
- [ ] 保留 `X-Frame-Options` 兼容旧浏览器
- [ ] 支付/授权/改密等敏感页面二次确认
- [ ] 敏感操作使用一次性 nonce
- [ ] 移动端页面同样验证
- [ ] 第三方嵌入需求单独列白名单，不全局放开

## 7. 参考资料

- OWASP: Clickjacking Defense Cheat Sheet
- CWE-1021: Improper Restriction of Rendered UI Layers or Frames
- MDN: X-Frame-Options / CSP frame-ancestors
