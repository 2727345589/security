# 功能级越权 BFLA (Broken Function Level Authorization)

> 分类：访问控制 | 风险：高 | CWE-285 | OWASP API5:2023

## 1. 攻击原理

系统只在前端隐藏了高权限功能（菜单、按钮），后端接口未做角色校验。攻击者直接构造请求调用管理接口，或以低权限角色调用高权限操作。

与 IDOR 的区别：IDOR 是「访问了不属于自己的**同一类资源**」，BFLA 是「调用了**不该调用的功能**」。

常见形态：

- `/api/admin/*` 仅靠前端路由守卫保护
- HTTP 方法未限制（`GET` 有校验，`DELETE` 没有）
- 接口内部只判断「已登录」，不判断角色/权限点
- 角色判断写死在前端 JWT 载荷中且服务端信任

## 2. 攻击示例

普通用户在前端看不到「删除用户」按钮，但接口存在：

```http
DELETE /api/admin/users/2002 HTTP/1.1
Authorization: Bearer <普通用户 token>
```

服务端：

```js
router.delete('/admin/users/:id', authMiddleware, handler);  // ❌ 只校验登录
```

结果：删除任意用户。

方法绕过：

```http
GET  /api/users/2002      → 403
POST /api/users/2002/delete → 200（未校验）
```

角色参数篡改：

```json
{ "role": "admin" }   // 注册时直接提交，见 20-mass-assignment
```

## 3. 影响

- 普通用户执行管理员操作（增删用户、改配置、导出全量数据）
- 权限模型形同虚设
- 与其他漏洞组合可完全接管系统

## 4. 防御措施

1. **服务端强制鉴权中间件**：每个路由显式声明所需权限点（`requirePermission('user:delete')`），默认拒绝。
2. **RBAC / ABAC 模型**：角色 → 权限点映射集中在服务端；不要用「角色名」散落在业务代码里。
3. **路由分组保护**：`/admin` 前缀整体挂管理员中间件，防止单条遗漏。
4. **方法级覆盖**：同一路径的每个 HTTP 方法都要有校验，不要只保护 `GET`。
5. **不信任前端**：前端隐藏只是 UX；JWT 中的角色也要服务端复核（角色变更需即时生效）。
6. **审计日志**：记录管理操作的操作者、目标、时间、结果。
7. **测试**：为每个高权限接口准备「低权限调用应 403」的自动化用例。
8. **网关层兜底**：管理接口独立域名/网段 + IP 白名单 + MFA。

## 5. 代码对比

```js
// ❌ 只校验登录
router.delete('/admin/users/:id', auth, deleteUser);

// ✅ 权限点校验 + 默认拒绝
const requirePermission = (perm) => (req, res, next) => {
  if (!req.user?.permissions?.includes(perm)) return res.sendStatus(403);
  next();
};

router.delete('/admin/users/:id',
  auth,
  requirePermission('user:delete'),
  deleteUser
);

// ✅ 路由组整体保护
router.use('/admin', auth, requireRole('admin'), adminRoutes);
```

```java
// ✅ Spring Security
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/api/admin/**").hasRole("ADMIN")
    .requestMatchers(HttpMethod.DELETE, "/api/users/**").hasAuthority("user:delete")
    .anyRequest().authenticated()
);
```

## 6. 自查清单

- [ ] 所有管理接口有服务端角色/权限点校验
- [ ] 每个 HTTP 方法单独校验，无遗漏
- [ ] 前端隐藏不作为安全边界
- [ ] JWT 中的角色由服务端复核，变更即时生效
- [ ] 有低权限调用高权限接口的自动化测试
- [ ] 管理接口有 IP 白名单 / 独立入口 / MFA
- [ ] 管理操作有审计日志与告警

## 7. 参考资料

- OWASP API Security Top 10: API5 BFLA
- OWASP: Authorization Cheat Sheet
- CWE-285: Improper Authorization
- PortSwigger: Access control vulnerabilities
