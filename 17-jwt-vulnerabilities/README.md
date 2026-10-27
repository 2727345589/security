# JWT 安全缺陷 (JWT Vulnerabilities)

> 分类：身份/会话 | 风险：高 | CWE-347 / CWE-345

## 1. 攻击原理

JWT 常见实现错误导致**伪造身份**或**绕过鉴权**：

| 缺陷 | 说明 |
|---|---|
| `alg: none` 未校验 | 攻击者改为 none 并去掉签名 |
| 算法混淆 | RS256 公钥被当作 HS256 密钥使用 |
| 弱密钥 | HS256 密钥可离线爆破 |
| 未校验签名 | 直接 `jwt.decode()` 而非 `jwt.verify()` |
| 不校验 `exp` / `iss` / `aud` | 过期 Token 永久有效，跨服务复用 |
| 无法吊销 | 泄露后有效期内不可撤销 |
| 敏感信息入载荷 | JWT 仅 Base64 编码，非加密 |
| `kid` 注入 | kid 指向文件/命令（路径穿越、SQL 注入、SSRF） |
| `jku` / `x5u` 未校验 | 指向攻击者 JWKS 地址 |

## 2. 攻击示例

### alg=none

```text
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.
```

若服务端信任头部算法且未强制校验，直接通过。

### 算法混淆（RS256 → HS256）

```python
# 用公开的 RSA 公钥作为 HMAC 密钥签名
import jwt
token = jwt.encode({"sub": "admin"}, public_key_pem, algorithm="HS256")
```

### 弱密钥爆破

```bash
hashcat -m 16500 token.txt jwt.txt    # HS256
```

### kid 路径穿越

```json
{ "alg": "HS256", "kid": "../../../../dev/null" }
```

签名密钥变为空字符串 / 可预测值。

## 3. 影响

- 任意用户身份伪造（含管理员）
- 权限提升、横向访问其他服务
- Token 泄露后可长期重放

## 4. 防御措施

1. **强制算法白名单**：`verify(token, key, { algorithms: ['RS256'] })`，绝不让 Token 头部决定算法。
2. **完整校验**：签名、`exp`、`nbf`、`iat`、`iss`、`aud`，并设置时钟偏移容忍（如 60s）。
3. **强密钥**：HS256 密钥 ≥ 256 bit 随机；优先 RS256/ES256 并正确管理密钥对。
4. **短有效期 + Refresh Token 轮换**：Access Token 5–15 分钟；Refresh Token 一次性轮换并检测重用（重用即撤销全家族）。
5. **支持吊销**：维护 `jti` 黑名单（Redis + TTL）或版本号（`tokenVersion` 变更即失效）。
6. **不存敏感数据**：JWT 载荷仅放 `sub`、`scope`、`exp` 等非敏感声明；需要保密用 JWE。
7. **校验 `kid` / `jku` / `x5u`**：只允许服务端预置的 key id 与固定 JWKS 地址，不按用户输入读取文件/URL。
8. **Token 存储**：优先 `HttpOnly` Cookie（防 XSS 窃取）或内存；避免 localStorage。
9. **TLS 强制**：防止 Token 在传输中被截获。

## 5. 代码对比

```js
// ❌ 只解码，不验签
const payload = jwt.decode(token);
if (payload.role === 'admin') { /* ... */ }

// ❌ 信任头部算法
jwt.verify(token, secret);   // 某些库默认接受 alg 变体

// ✅ 明确算法与完整校验
import jwt from 'jsonwebtoken';
try {
  const payload = jwt.verify(token, PUBLIC_KEY, {
    algorithms: ['RS256'],
    issuer: 'https://auth.site.com',
    audience: 'site-api',
    clockTolerance: 60,
  });
  // 再做服务端授权判断，role 不完全信任
} catch (e) {
  return res.status(401).end();
}
```

```python
# ✅ PyJWT
import jwt
payload = jwt.decode(
    token, public_key,
    algorithms=["RS256"],
    audience="site-api",
    issuer="https://auth.site.com",
    options={"require": ["exp", "iat", "sub"]},
)
```

```js
// ✅ 可吊销：jti + 版本号
if (await redis.get(`revoked:${payload.jti}`)) return res.status(401).end();
const user = await User.findByPk(payload.sub);
if (!user || user.tokenVersion !== payload.ver) return res.status(401).end();
```

## 6. 自查清单

- [ ] 所有校验使用 `verify` 并显式指定 `algorithms`
- [ ] 拒绝 `alg: none` 与算法混淆
- [ ] 校验 exp / nbf / iss / aud
- [ ] HS256 密钥强度足够，密钥不在代码库
- [ ] Access Token 短时效 + Refresh 轮换 + 重用检测
- [ ] 有吊销机制（jti 黑名单 / tokenVersion）
- [ ] 载荷无敏感数据
- [ ] `kid` / `jku` 不从用户输入取值
- [ ] Token 未存 localStorage

## 7. 参考资料

- OWASP: JSON Web Token Cheat Sheet
- RFC 7519 (JWT) / RFC 8725 (JWT Best Current Practices)
- CWE-347: Improper Verification of Cryptographic Signature
- PortSwigger: JWT attacks
