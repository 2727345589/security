# 密码存储不当 (Improper Password Storage)

> 分类：身份认证 / 数据保护 | 风险：严重 | CWE-256 / CWE-916 / CWE-759

## 1. 攻击原理

密码若以明文、可逆加密或**快速哈希**（MD5/SHA-1/SHA-256）存储，一旦数据库泄露，攻击者可立即还原大部分口令：

- 彩虹表直接命中未加盐的 MD5
- GPU 每秒可计算数十亿次 SHA-256，8 位以内口令几分钟破解
- 同一口令在不同用户间哈希相同，暴露「共用密码」关系

常见错误：

| 错误做法 | 后果 |
|---|---|
| 明文存储 | 直接泄露 |
| `md5(password)` | 彩虹表秒破 |
| `sha1(salt + password)` | GPU 高速爆破 |
| 全局固定盐 | 批量破解 |
| 可逆加密（AES） | 密钥泄露即全破 |
| 自研「加密算法」 | 通常比标准更弱 |

## 2. 攻击示例

泄露的 `users` 表：

```text
id | email          | password
1  | admin@x.com    | admin123
2  | bob@x.com      | 5f4dcc3b5aa765d61d8327deb882cf99   -- md5("password")
3  | eve@x.com      | 5f4dcc3b5aa765d61d8327deb882cf99   -- 同一口令
```

攻击者用 hashcat：

```bash
hashcat -m 0 hashes.txt rockyou.txt    # MD5
hashcat -m 1000 ntlm.txt rockyou.txt
```

## 3. 影响

- 全站账号接管
- 用户在其他站点复用密码导致连锁失守（撞库）
- 合规违规（等保、GDPR、PCI-DSS）

## 4. 防御措施

1. **使用慢哈希 + 加盐**
   - 首选 **Argon2id**（OWASP 推荐）：`memory=19MiB, iterations=2, parallelism=1`（按服务器调优）
   - 次选 **bcrypt**（cost ≥ 12）或 **scrypt**（N=2^17, r=8, p=1）
   - 每个用户独立随机盐（库通常自动处理），盐长度 ≥ 16 字节
2. **禁止自研算法**，使用成熟库（`argon2`、`bcrypt`、`node:crypto scrypt`）
3. **参数可升级**：存储算法标识与参数（如 `$argon2id$v=19$m=19456,t=2,p=1$...`），登录成功时按需 rehash
4. **常量时间比较**：`timingSafeEqual` / `crypto.verify`
5. **传输与存储双加密**：HTTPS 传输；数据库/备份加密；密钥放 KMS，不入库不入 Git
6. **泄露检测**：比对 HIBP（k-anonymity），命中强制改密
7. **MFA 兜底**：即使口令泄露也难以登录
8. **审计**：定期扫描代码库中 `md5(`、`sha1(`、`createHash('sha256')` 用于密码的场景

## 5. 代码对比

```js
// ❌
const hash = crypto.createHash('md5').update(password).digest('hex');
const hash2 = crypto.createHash('sha256').update(password + '固定盐').digest('hex');

// ✅ Argon2id
import argon2 from 'argon2';
const hash = await argon2.hash(password, {
  type: argon2.argon2id,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
});
const ok = await argon2.verify(hash, password);

// ✅ bcrypt
import bcrypt from 'bcrypt';
const hashB = await bcrypt.hash(password, 12);
const okB = await bcrypt.compare(password, hashB);
```

```python
# ✅
from argon2 import PasswordHasher
ph = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)
h = ph.hash(password)
ph.verify(h, password)
```

```java
// ✅ Spring Security
PasswordEncoder enc = new Argon2PasswordEncoder(16, 32, 1, 19456, 2);
String hash = enc.encode(raw);
boolean ok = enc.matches(raw, hash);
```

## 6. 自查清单

- [ ] 密码使用 Argon2id / bcrypt / scrypt，参数符合 OWASP 建议
- [ ] 每用户独立盐，无全局固定盐
- [ ] 无 MD5/SHA-1/裸 SHA-256 存密码
- [ ] 哈希串包含算法与参数，支持平滑升级
- [ ] 比较使用常量时间函数
- [ ] 数据库与备份加密，密钥在 KMS
- [ ] 登录命中泄露库时强制改密
- [ ] 关键账号启用 MFA

## 7. 参考资料

- OWASP: Password Storage Cheat Sheet
- NIST SP 800-63B
- CWE-256 / CWE-916 / CWE-759
- RFC 9106: Argon2
