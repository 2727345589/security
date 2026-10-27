# 越权访问 IDOR / BOLA (Insecure Direct Object Reference)

> 分类：访问控制 | 风险：严重 | CWE-639 | OWASP API1:2023

## 1. 攻击原理

接口用用户可控的标识符（ID、UUID、文件名、订单号）直接查询资源，却只校验「是否登录」而不校验「是否拥有该资源」。攻击者遍历/替换 ID 即可读取或修改他人数据。

| 类型 | 说明 |
|---|---|
| 水平越权 | 同角色用户间互相访问（用户 A 读用户 B 的订单） |
| 垂直越权 | 低权限访问高权限资源（普通用户调管理接口，见 19-bfla） |
| 盲 IDOR | 无回显，但副作用存在（如删除他人资源） |

高危场景：`/api/orders/:id`、`/api/users/:id/profile`、下载接口 `?fileId=`、Webhook 回调、GraphQL 按 ID 查询。

## 2. 攻击示例

```http
GET /api/invoices/1001 HTTP/1.1
Authorization: Bearer <userA token>
```

服务端实现：

```js
const invoice = await Invoice.findByPk(req.params.id);   // ❌ 只按 ID 查
res.json(invoice);
```

攻击者改成 `1002`、`1003` 批量遍历，拿到所有发票（含他人地址、金额）。

修改型：

```http
PATCH /api/users/2002
{ "email": "attacker@evil.com" }
```

若未校验 `req.user.id === 2002`，可直接接管他人账号（改邮箱后走找回密码）。

嵌套资源绕过：

```http
GET /api/projects/1/tasks/999
```

只校验了 project 1 的权限，未校验 task 999 是否属于 project 1。

## 3. 影响

- 批量数据泄露（常为最严重的实际泄露原因）
- 账号接管、资金损失
- 满足合规事故认定条件

## 4. 防御措施

1. **对象级授权（每次请求都做）**
   ```js
   const resource = await Repo.find(id);
   if (!resource) return res.sendStatus(404);
   if (resource.ownerId !== req.user.id && !req.user.isAdmin) return res.sendStatus(404);
   ```
   建议封装成统一函数 `assertCanAccess(user, resource, action)`，避免遗漏。
2. **查询时带上归属条件**（更安全的写法）：
   ```js
   const invoice = await Invoice.findOne({ where: { id, userId: req.user.id } });
   ```
   查不到即 404，天然防枚举。
3. **嵌套资源校验归属链**：`task.projectId === projectId` 且 `project.ownerId === user.id`。
4. **默认拒绝**：路由默认需要授权，白名单放行公开接口；用中间件强制。
5. **UUID 只是辅助**：不可预测 ID 降低遍历效率，但**不能替代授权**。
6. **返回 404 而非 403**：避免泄露资源存在性。
7. **集中式授权（策略引擎）**：如 Casbin、OPA，把规则从业务代码中抽离，便于审计。
8. **测试覆盖**：每个接口用「用户 A 访问用户 B 资源」的用例做回归。

## 5. 代码对比

```js
// ❌ 只按 ID 查
router.get('/invoices/:id', auth, async (req, res) => {
  const inv = await Invoice.findByPk(req.params.id);
  res.json(inv);
});

// ✅ 归属条件 + 统一策略
router.get('/invoices/:id', auth, async (req, res) => {
  const inv = await Invoice.findOne({
    where: { id: req.params.id, userId: req.user.id },
  });
  if (!inv) return res.sendStatus(404);
  res.json(inv);
});

// ✅ 复杂场景用策略函数
router.patch('/invoices/:id', auth, async (req, res) => {
  const inv = await Invoice.findByPk(req.params.id);
  if (!inv) return res.sendStatus(404);
  if (!can(req.user, 'update', inv)) return res.sendStatus(404);
  await inv.update(pick(req.body, ['memo']));
  res.json(inv);
});
```

```java
// ✅ Spring Security + @PreAuthorize
@PreAuthorize("#invoice.ownerId == authentication.principal.id")
@GetMapping("/invoices/{id}")
public Invoice get(@PathVariable Long id) { ... }
```

## 6. 自查清单

- [ ] 每个返回/修改资源的接口都做对象级授权
- [ ] 查询语句包含 `userId = currentUser` 条件
- [ ] 嵌套资源校验完整归属链
- [ ] 未授权返回 404，不泄露存在性
- [ ] 授权逻辑集中管理，有单元/集成测试覆盖
- [ ] 导出、批量、Webhook、GraphQL 等边缘接口同样覆盖
- [ ] 管理接口独立鉴权，不与用户接口混用

## 7. 参考资料

- OWASP: Authorization Cheat Sheet
- OWASP API Security Top 10: API1 BOLA
- CWE-639: Authorization Bypass Through User-Controlled Key
- PortSwigger: IDOR
