# Host 头注入 (Host Header Injection)

> 分类：协议层 / 配置 | 风险：中高 | CWE-644

## 1. 攻击原理

HTTP `Host` 头由客户端提供，可被任意伪造（除非网关强制覆盖）。若应用用它来：

- 生成绝对 URL（密码重置链接、邮件链接、支付回调）
- 判断站点域名 / 路由租户
- 做缓存 key
- 做访问控制

攻击者就能投毒链接、劫持租户、污染缓存。

相关头：`X-Forwarded-Host`、`X-Forwarded-For`、`X-Original-URL`、`X-Rewrite-URL`、`Forwarded`。

## 2. 攻击示例

### 密码重置投毒

```http
POST /api/password/reset HTTP/1.1
Host: evil.com
Content-Type: application/json

{ "email": "victim@x.com" }
```

服务端生成：

```text
https://evil.com/reset?token=SECRET
```

受害者点击后，Token 通过 Referer/日志泄露给攻击者，或直接被钓鱼页面收集 → 账号接管。

### 缓存投毒

```http
GET /home HTTP/1.1
Host: evil.com
```

若页面中包含绝对 URL 且被 CDN 缓存，所有用户都会拿到指向 evil.com 的资源链接。

### 租户混淆

多租户系统按 `Host` 判断租户，攻击者指定他人租户域名访问，可能读到他人数据或进入错误上下文。

### 头部覆盖绕过

```http
GET /admin HTTP/1.1
X-Original-URL: /admin
X-Rewrite-URL: /admin
```

部分框架/中间件会信任这些头做路由重写，导致访问控制绕过。

### 绝对 URI 请求行

```http
GET http://internal.local/admin HTTP/1.1
Host: site.com
```

代理若按请求行中的 host 转发，可绕过基于 Host 的规则。

## 3. 影响

- 账号接管（重置链接投毒）
- 缓存投毒影响全站
- 租户数据越界
- 访问控制绕过
- 邮件/回调链接被劫持

## 4. 防御措施

1. **使用配置的固定域名**：生成链接时用 `APP_URL` 环境变量 / 配置，绝不从请求头取值。
2. **Host 白名单校验**：中间件校验 `Host` 是否在允许列表，否则 400；多租户用映射表而非直接信任。
3. **不信任 `X-Forwarded-*`**：仅在请求确实来自可信代理时启用，并配置 `trust proxy` 为具体 IP 段（Express `app.set('trust proxy', 'loopback')`）。
4. **网关强制覆盖**：Nginx/ALB 将 `Host` 设为后端期望值；丢弃客户端传入的 `X-Original-URL`、`X-Rewrite-URL`。
5. **虚拟主机默认拒绝**：未匹配任何 server_name 的请求直接 444。
6. **缓存 key 加固**：CDN 缓存 key 固定为配置域名，不随 Host 变化。
7. **重置/邀请链接**：Token 一次性、短时效、绑定用户与会话；链接域名固定。
8. **相对 URL**：前端资源尽量使用相对路径或 `window.location.origin` 之外的可信配置。

## 5. 代码对比

```js
// ❌ 用请求头生成链接
const link = `https://${req.headers.host}/reset?token=${token}`;
const link2 = `https://${req.get('X-Forwarded-Host')}/reset?token=${token}`;

// ✅ 使用配置
const APP_URL = process.env.APP_URL;   // https://app.site.com
const link = `${APP_URL}/reset?token=${encodeURIComponent(token)}`;

// ✅ Host 白名单中间件
const ALLOWED_HOSTS = new Set(['app.site.com', 'www.site.com']);
app.use((req, res, next) => {
  const host = (req.headers.host || '').split(':')[0].toLowerCase();
  if (!ALLOWED_HOSTS.has(host)) return res.status(400).end();
  next();
});

// ✅ 仅在可信代理后信任转发头
app.set('trust proxy', ['127.0.0.1', '10.0.0.0/8']);
```

```nginx
# ✅ 默认拒绝未匹配域名 + 覆盖 Host
server {
    listen 80 default_server;
    server_name _;
    return 444;
}

server {
    listen 80;
    server_name app.site.com;
    location / {
        proxy_set_header Host app.site.com;                 # 强制覆盖
        proxy_set_header X-Forwarded-Host "";
        proxy_set_header X-Original-URL "";
        proxy_set_header X-Rewrite-URL "";
        proxy_pass http://app;
    }
}
```

```python
# ✅ Django
ALLOWED_HOSTS = ['app.site.com', 'www.site.com']
USE_X_FORWARDED_HOST = False
```

## 6. 自查清单

- [ ] 所有绝对链接来自配置，不用请求头
- [ ] Host 白名单校验生效
- [ ] 仅可信代理可影响 `X-Forwarded-*`
- [ ] 网关强制覆盖 Host 并清洗危险头
- [ ] 未匹配域名的请求被拒绝
- [ ] CDN 缓存 key 固定域名
- [ ] 重置/邀请链接 Token 一次性且短时效
- [ ] 危险头（`X-Original-URL` 等）已被丢弃

## 7. 参考资料

- OWASP: Host Header Injection
- CWE-644: Improper Neutralization of HTTP Headers for Scripting Syntax
- PortSwigger: Host header attacks
