# NoSQL 注入 (NoSQL Injection)

> 分类：注入类 | 风险：高 | CWE-943

## 1. 攻击原理

NoSQL 数据库（MongoDB、CouchDB、Redis 等）查询使用 JSON/BSON 结构。若服务端直接把请求体对象传入查询，攻击者可通过**操作符注入**（`$ne`、`$gt`、`$regex`、`$where`）或**类型混淆**改变查询语义，实现认证绕过、数据遍历、盲注甚至 JS 执行。

两种形态：

| 类型 | 说明 |
|---|---|
| 语法注入 | 在字符串值中注入 `' || '1'=='1`（多见于拼接的 `$where`） |
| 操作符注入 | 传对象而非字符串：`{"password": {"$ne": null}}` |

## 2. 攻击示例

```js
// 原始实现
const user = await db.collection('users').findOne({
  email: req.body.email,
  password: req.body.password,
});
```

请求体：

```json
{ "email": "admin@x.com", "password": { "$ne": null } }
```

生成查询 `{ email: 'admin@x.com', password: { $ne: null } }`，只要密码字段非空即匹配，登录成功。

正则盲注枚举数据：

```json
{ "email": { "$regex": "^a" }, "password": { "$ne": null } }
```

`$where` 注入（MongoDB 允许执行 JS）：

```json
{ "$where": "this.password.length > 0" }
```

Redis 场景：未校验参数被拼入命令（含换行 `\r\n`）造成命令注入。

## 3. 影响

- 认证绕过、越权读取全表
- 盲注逐字符提取敏感数据
- `$where` 可导致服务端 JS 执行 / DoS
- Redis 未授权/注入可写文件、反弹 shell

## 4. 防御措施

1. **强制类型校验**：明确期望 `typeof input === 'string'`，拒绝对象/数组。使用 schema 校验（Zod / Joi / class-validator / Pydantic）。
2. **不把整个对象传入查询**：显式挑选字段，绝不 `findOne(req.body)`。
3. **过滤以 `$` 开头的键**：MongoDB 官方建议拒绝含 `$` 与 `.` 的键名（或用 `mongo-sanitize` 类库）。
4. **禁用 `$where`、`$accumulator`、`$function`**：服务端禁用 JS 执行（`--noscripting`）。
5. **使用 ODM 的强类型模型**：Mongoose 严格 schema，避免 `strict: false`。
6. **最小权限**：数据库账号只授予必要集合与操作；Redis 设置 `requirepass` + ACL + 禁止公网。
7. **限流与审计**：对查询接口限流，记录异常查询模式（大量正则、超长 `$in`）。

## 5. 代码对比

```js
// ❌ 直接透传
const user = await User.findOne(req.body);

// ✅ schema 校验 + 显式字段
const schema = z.object({
  email: z.string().email(),
  password: z.string().min(8).max(128),
});
const { email, password } = schema.parse(req.body);
const user = await User.findOne({ email });

// ✅ 或用哈希比较，不把密码作为查询条件
const user = await User.findOne({ email });
const ok = user && await argon2.verify(user.passwordHash, password);
```

```js
// ✅ 递归清理危险键（防御性）
function sanitize(obj) {
  if (obj === null || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(sanitize);
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    if (k.startsWith('$') || k.includes('.')) continue;
    out[k] = sanitize(v);
  }
  return out;
}
```

## 6. 自查清单

- [ ] 所有查询输入经过 schema 类型校验，拒绝对象型参数
- [ ] 无 `find(req.body)` / `update(req.body)` 式透传
- [ ] 已过滤 `$` 前缀键与含 `.` 键
- [ ] MongoDB 关闭服务端 JS（`$where` / `$function`）
- [ ] Redis 有密码与 ACL，未暴露公网
- [ ] 查询接口有限流，异常模式有告警

## 7. 参考资料

- OWASP: Query Parameterization / NoSQL Security
- CWE-943: Improper Neutralization of Special Elements in Data Query Logic
- MongoDB Security Checklist
