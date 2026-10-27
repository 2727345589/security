# HTTP 请求走私 (HTTP Request Smuggling)

> 分类：协议层 | 风险：高 | CWE-444

## 1. 攻击原理

链路中存在多个 HTTP 解析器（CDN → 负载均衡 → 反向代理 → 应用服务器）。当它们对**消息边界**的理解不一致时，攻击者可构造一个请求，被前端解析为 1 个、被后端解析为 2 个（或反之），从而把「夹带」的请求注入到下一个用户的连接中。

根源：`Content-Length`（CL）与 `Transfer-Encoding`（TE）处理差异。

| 类型 | 说明 |
|---|---|
| CL.TE | 前端用 CL，后端用 TE |
| TE.CL | 前端用 TE，后端用 CL |
| TE.TE | 两端都用 TE，但对 `Transfer-Encoding` 的畸形值处理不同 |
| CL.CL | 两处 CL 头值不一致，各取其一 |
| HTTP/2 降级 | H2 转 H1 时头部被注入 CRLF |

## 2. 攻击示例

### CL.TE

```http
POST / HTTP/1.1
Host: site.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

前端按 CL=13 只读到 `0\r\n\r\nSMUGGLED` 的前 13 字节；后端按 chunked 读到 `0` 结束，剩余的 `SMUGGLED` 留在缓冲区，成为**下一个请求的前缀**。

### 利用后果

```http
GET /admin HTTP/1.1
Host: site.com
```

若被拼接到受害者请求前，攻击者可：

- 绕过前端访问控制（前端看不到 `/admin`）
- 捕获下一个用户的请求（含 Cookie、Token）
- 缓存投毒（把恶意响应缓存给所有人）
- 反射型 XSS 放大

## 3. 影响

- 绕过 WAF / 反向代理的鉴权与限流
- 窃取其他用户请求（会话劫持）
- Web 缓存投毒，影响全站用户
- 结合 XSS 形成大规模攻击

## 4. 防御措施

1. **统一解析器**：尽量让代理与应用使用一致的、严格遵循 RFC 的实现；升级到最新稳定版本。
2. **拒绝歧义请求**：
   - 同时出现 `Content-Length` 与 `Transfer-Encoding` → 400
   - 多个 `Content-Length` 且值不同 → 400
   - `Transfer-Encoding` 值畸形（`chunked, identity`、空格、大小写混用）→ 400
3. **Nginx 配置**：
   ```nginx
   # 默认会拒绝同时存在 CL 与 TE 的请求
   # 确保版本 ≥ 1.21 并开启严格解析
   ```
4. **禁用后端连接复用（临时缓解）**：上游 `Connection: close`，牺牲性能换取安全。
5. **HTTP/2 端到端**：避免 H2 → H1 降级；若必须降级，严格校验 `:path`、`:authority` 不含 CRLF。
6. **WAF 规则**：拦截畸形 TE/CL 组合（仅作补充）。
7. **监控**：400/413 突增、异常 404 模式、缓存命中异常作为告警信号。
8. **缓存隔离**：缓存 key 包含完整 host + path + 关键头；对含争议头的请求不缓存。

## 5. 代码对比

```nginx
# ✅ Nginx：严格拒绝歧义
# nginx >= 1.21 默认拒绝 CL+TE 同时存在
# 显式关闭上游复用可作临时缓解
upstream app {
    server 127.0.0.1:3000;
    keepalive 0;
}
```

```js
// ✅ Node：显式校验（作为应用层兜底）
app.use((req, res, next) => {
  const cl = req.headers['content-length'];
  const te = req.headers['transfer-encoding'];
  if (cl !== undefined && te !== undefined) return res.status(400).end();
  if (te && te.toLowerCase() !== 'chunked') return res.status(400).end();
  next();
});
```

```yaml
# ✅ 网关/Ingress 层统一
# 确保所有入口都经过同一套严格解析的网关，不绕过直连后端
```

```bash
# ✅ 检测（授权测试环境）
# 使用 Burp 的 HTTP Request Smuggler 扩展
# 或 nmap --script http-request-smuggling
```

## 6. 自查清单

- [ ] 代理、LB、应用服务器均为最新稳定版
- [ ] 网关拒绝 CL+TE 同时存在
- [ ] 拒绝多个不一致的 Content-Length
- [ ] 拒绝畸形 Transfer-Encoding
- [ ] 无 H2 → H1 不安全降级，或降级时严格校验
- [ ] 后端不可被绕过网关直连
- [ ] 缓存 key 设计合理，争议请求不缓存
- [ ] 有 400/异常模式监控告警

## 7. 参考资料

- PortSwigger: HTTP request smuggling
- CWE-444: Inconsistent Interpretation of HTTP Requests
- RFC 7230 §3.3.3（消息体长度判定）
- HTTP Request Smuggler (Burp 扩展)
