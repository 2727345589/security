# 敏感数据泄露 (Sensitive Data Exposure)

> 分类：数据保护 | 风险：高 | CWE-200 | OWASP A02:2021

## 1. 攻击原理

敏感数据在**传输、存储、展示、日志、缓存**任一环节缺乏保护，就可能被直接或间接获取。它常与其它漏洞叠加：一个越权或 XSS 就能把「未加密的敏感数据」变成事故。

敏感数据范围：口令、Token、身份证/护照、银行卡、手机号、住址、健康记录、生物特征、密钥、源码、内部 IP/架构。

常见途径：

| 环节 | 问题 |
|---|---|
| 传输 | HTTP 明文、混合内容、弱 TLS、证书校验关闭 |
| 存储 | 明文入库、明文备份、日志落盘、缓存未加密 |
| 展示 | API 返回多余字段、错误信息含数据、导出无脱敏 |
| 客户端 | localStorage、URL 参数、前端 source map |
| 缓存/代理 | 敏感响应被 CDN/浏览器缓存 |
| 第三方 | 分析 SDK 上报、错误监控上报请求体 |

## 2. 攻击示例

### API 过度返回

```http
GET /api/users/1001
{
  "id": 1001,
  "name": "张三",
  "phone": "13800138000",
  "idCard": "110101199001011234",
  "passwordHash": "$2b$12$...",
  "internalNote": "VIP，勿催款"
}
```

前端不展示 ≠ 安全，攻击者直接看响应。

### 明文传输

```
http://site.com/login  → 中间人获取账号密码
```

### 缓存泄露

```
GET /api/me
Cache-Control: public, max-age=3600
```

共享代理缓存后，其他用户可能拿到他人资料。

### 错误信息泄露

```json
{ "error": "Duplicate entry '13800138000' for key 'users.phone'" }
```

### 源码映射

生产环境保留 `.map` 文件 → 完整前端源码与内部接口。

## 3. 影响

- 大规模个人信息泄露（合规重罚）
- 账号接管（Token/密码哈希）
- 内网信息暴露，辅助进一步攻击
- 品牌与法律风险

## 4. 防御措施

1. **分类分级**：识别敏感字段，制定处理规则（谁能看、存多久、如何脱敏）。
2. **传输加密**：全站 HTTPS、HSTS、TLS 1.2+、禁用弱套件、启用 OCSP Stapling；内部服务间也建议 mTLS。
3. **存储加密**：数据库透明加密 / 字段级加密（KMS 管理密钥）；备份加密；密钥与数据分离。
4. **最小化返回**：API 使用 DTO/序列化白名单，绝不 `res.json(user)` 整个实体。
5. **脱敏展示**：手机号 `138****8000`、身份证 `1101**********1234`；导出文件同样脱敏。
6. **日志脱敏**：统一拦截器过滤 `password`、`token`、`authorization`、`idCard` 等字段。
7. **缓存控制**：
   ```
   Cache-Control: no-store
   Pragma: no-cache
   ```
   仅对公开资源使用长缓存。
8. **错误收敛**：对外只返回通用信息 + traceId，细节进内部日志。
9. **前端治理**：生产关闭 source map（或上传到私有监控平台）；不在 URL 携带敏感参数。
10. **第三方管控**：审查 SDK 上报内容，禁用请求体上报，必要时自建代理。
11. **数据最小化与生命周期**：不收集非必要数据，设定保留期限，支持删除。

## 5. 代码对比

```js
// ❌ 整实体返回
res.json(user);

// ✅ DTO + 脱敏
function toPublicUser(u) {
  return {
    id: u.id,
    name: u.name,
    phone: maskPhone(u.phone),
    avatar: u.avatar,
  };
}
res.json(toPublicUser(user));

const maskPhone = (p) => (p ? p.replace(/^(\d{3})\d{4}(\d{4})$/, '$1****$2') : null);
```

```js
// ✅ 日志脱敏
const REDACT = ['password', 'token', 'authorization', 'cookie', 'idCard', 'bankCard'];
function redact(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  const out = Array.isArray(obj) ? [] : {};
  for (const [k, v] of Object.entries(obj)) {
    out[k] = REDACT.some((r) => k.toLowerCase().includes(r)) ? '[REDACTED]' : redact(v);
  }
  return out;
}
logger.info({ req: redact(req.body) }, 'request');
```

```js
// ✅ 敏感接口禁缓存
app.use('/api', (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  next();
});
```

```nginx
# ✅ 生产不暴露 source map
location ~ \.map$ { deny all; }
```

## 6. 自查清单

- [ ] 已识别并分级敏感数据
- [ ] 全站 HTTPS + HSTS + 强 TLS
- [ ] 数据库/备份加密，密钥在 KMS
- [ ] API 返回字段最小化，无整实体透传
- [ ] 展示与导出均脱敏
- [ ] 日志统一脱敏
- [ ] 敏感响应 `no-store`
- [ ] 错误信息不泄露内部细节
- [ ] 生产无 source map / 源码
- [ ] 第三方 SDK 上报内容已审查
- [ ] 数据保留期限与删除机制已落实

## 7. 参考资料

- OWASP: Cryptographic Storage Cheat Sheet
- OWASP: Transport Layer Security Cheat Sheet
- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- GDPR / 个人信息保护法
