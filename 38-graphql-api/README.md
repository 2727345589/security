# GraphQL / API 安全 (GraphQL & API Security)

> 分类：API | 风险：高 | CWE-863 | OWASP API Top 10

## 1. 攻击原理

API 与 GraphQL 把业务能力直接暴露，攻击面与传统页面不同：

| 风险 | 说明 |
|---|---|
| BOLA / IDOR | 按 ID 访问他人资源（API1） |
| BFLA | 调用高权限接口（API5） |
| 对象属性越权 | 返回/写入不该暴露的字段（API3） |
| 资源消耗 | 深分页、复杂查询、批量请求（API4） |
| 功能滥用 | 注册/发短信/导出被脚本化滥用（API6） |
| 配置错误 | 调试端点、宽松 CORS、默认凭据（API8） |
| 库存管理 | 旧版本接口未下线（API9） |
| 不安全消费 | 信任第三方 API 数据（API10） |
| GraphQL introspection | 生产暴露完整 schema |
| 查询深度/复杂度 | 嵌套 20 层导致数据库爆炸 |
| 别名批量 | 一个请求内用别名放大 N 倍操作 |
| 字段级授权缺失 | 查询 `user { email passwordHash }` 全返回 |

## 2. 攻击示例

### GraphQL 过度获取

```graphql
query {
  user(id: 1002) {
    email
    phone
    idCard
    passwordHash
    apiKeys { secret }
  }
}
```

若无字段级授权与返回白名单，直接泄露。

### 深度/复杂度攻击

```graphql
query {
  users(first: 100) {
    posts(first: 100) {
      comments(first: 100) {
        author { posts(first: 100) { comments(first: 100) { id } } }
      }
    }
  }
}
```

指数级数据库查询 → DoS。

### 别名批量绕过限流

```graphql
mutation {
  a1: login(email: "a@x.com", password: "1")
  a2: login(email: "a@x.com", password: "2")
  ...
  a1000: login(email: "a@x.com", password: "1000")
}
```

一次 HTTP 请求尝试 1000 次密码，绕过按请求数限流。

### introspection 泄露

```graphql
{ __schema { types { name fields { name } } } }
```

暴露内部字段与未公开接口。

### REST 批量与枚举

```http
GET /api/users?page=1&limit=100000
GET /api/export?format=csv        ← 导出全量数据
GET /api/v1/internal/debug
```

### 旧版本接口

```http
GET /api/v1/users/1002     ← 已废弃但未下线，缺少新鉴权
```

## 3. 影响

- 大规模数据泄露（BOLA 是 API 泄露首要原因）
- 账号枚举与接管
- 服务不可用（查询炸弹）
- 业务被脚本化滥用（短信轰炸、薅羊毛）

## 4. 防御措施

1. **每个字段/接口做授权**：GraphQL 用字段级 resolver 鉴权或指令（`@auth`），REST 用中间件 + 对象级校验。默认拒绝。
2. **返回白名单**：GraphQL 用 `graphql-js` 的字段级权限或 `graphql-shield`；REST 用 DTO。
3. **关闭生产 introspection**：或仅对内部网络开放。
4. **查询深度/复杂度限制**：`graphql-depth-limit`、`graphql-cost-analysis`；设置最大深度（如 10）与最大复杂度。
5. **分页强制上限**：Relay 风格 `first/last` 上限 100；REST `limit` 上限。
6. **按操作成本限流**：GraphQL 按复杂度计费限流，而非请求数；别名批量需逐个别名计入。
7. **批量请求限制**：单请求最大别名数、REST 批量数组长度上限。
8. **禁用危险操作**：生产禁用 `__schema`、调试 mutation、内省；关闭 Playground。
9. **接口版本与生命周期**：旧版本明确下线时间，网关层阻断。
10. **输入校验与类型安全**：schema 校验、字段白名单、拒绝未知字段。
11. **监控与异常检测**：单 IP 高频、异常查询模式、导出行为告警。
12. **网关防护**：统一认证、限流、WAF、请求大小限制。

## 5. 代码对比

```js
// ✅ GraphQL：深度/复杂度限制 + 字段授权
import depthLimit from 'graphql-depth-limit';
import { createComplexityLimitRule } from 'graphql-validation-complexity';

const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== 'production',
  validationRules: [
    depthLimit(10),
    createComplexityLimitRule(1000),
  ],
  plugins: [ApolloServerPluginLandingPageDisabled()],
});

// ✅ 字段级授权
const resolvers = {
  User: {
    email: (parent, _args, ctx) => {
      if (ctx.user.id !== parent.id && !ctx.user.isAdmin) return null;   // 字段级
      return parent.email;
    },
    passwordHash: () => { throw new ForbiddenError('forbidden'); },
  },
};

// ✅ 对象级授权
Query: {
  user: async (_, { id }, ctx) => {
    if (ctx.user.id !== id && !ctx.user.isAdmin) throw new ForbiddenError();
    return User.findByPk(id);
  },
},
```

```js
// ✅ REST 分页上限 + DTO
const limit = Math.min(parseInt(req.query.limit ?? '20', 10) || 20, 100);
const rows = await User.findAll({ limit, offset, attributes: ['id', 'name', 'avatar'] });
```

```js
// ✅ 按复杂度限流
const cost = computeQueryCost(req.body.query);
if (!(await limiter.consume(req.user.id, cost))) return res.status(429).end();
```

```yaml
# ✅ 网关：旧版本下线 + 请求体限制
# /api/v1/** → 410 Gone（或重定向到 v2）
```

## 6. 自查清单

- [ ] 每个接口与字段都有授权校验
- [ ] 返回字段白名单，无整实体透传
- [ ] 生产关闭 introspection / Playground
- [ ] 查询深度与复杂度受限
- [ ] 分页有硬上限
- [ ] 限流按操作成本，别名批量计入
- [ ] 批量请求有数量上限
- [ ] 旧版本接口已下线或网关阻断
- [ ] 敏感操作（导出、发短信）有额外风控
- [ ] 有异常查询与滥用告警

## 7. 参考资料

- OWASP API Security Top 10 (2023)
- OWASP: GraphQL Cheat Sheet
- CWE-863: Incorrect Authorization
- graphql-depth-limit / graphql-shield 文档
