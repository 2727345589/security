# 批量赋值 (Mass Assignment)

> 分类：访问控制 | 风险：高 | CWE-915 | OWASP API3:2023

## 1. 攻击原理

框架通常提供「把请求体自动映射到模型」的能力（如 `User.update(req.body)`、Spring 的 `@ModelAttribute`、Rails 的 `update(params)`）。若未限制可写字段，攻击者可提交本不该由他控制的字段：`role`、`isAdmin`、`balance`、`verified`、`ownerId`、`price`。

同源问题还包括 **自动绑定（autobinding）** 与 **对象注入**。

## 2. 攻击示例

```js
// ❌ 直接透传
const user = await User.create(req.body);
```

正常注册请求：

```json
{ "email": "a@x.com", "password": "..." }
```

攻击者提交：

```json
{ "email": "a@x.com", "password": "...", "role": "admin", "isVerified": true, "balance": 999999 }
```

更新场景更危险：

```js
await User.update(req.body, { where: { id: req.user.id } });
// { "role": "admin" } → 自我提权
```

嵌套对象注入：

```json
{ "profile": { "ownerId": 1 } }
```

## 3. 影响

- 自我提权为管理员
- 篡改余额、价格、状态（已支付、已审核）
- 转移资源归属（ownerId）实现越权
- 绕过邮箱/实名验证

## 4. 防御措施

1. **DTO + 字段白名单（首选）**：为每个接口定义输入模型，只接收显式字段。
2. **禁止对象透传**：不使用 `req.body` 整体写入模型；显式赋值或 `pick()`。
3. **框架级防护**：
   - Rails：Strong Parameters（`params.require(:user).permit(:email, :password)`）
   - Spring：`@InitBinder` 设置 `setAllowedFields`，或使用专用 DTO
   - Laravel：`$fillable` / `$guarded`
   - Django：`ModelForm` 的 `fields` 白名单
   - Sequelize：`attributes` 白名单、`fields` 选项
4. **角色/状态字段禁止客户端写入**：这些字段只能由服务端受控流程修改。
5. **schema 校验器**：Zod / Joi / class-validator / Pydantic，开启「拒绝未知字段」（`strict()`、`forbidNonWhitelisted`）。
6. **代码评审规则**：`update(req.body)`、`create(req.body)` 视为高危模式，静态扫描拦截。

## 5. 代码对比

```js
// ❌
await User.create(req.body);
await User.update(req.body, { where: { id: req.user.id } });

// ✅ 显式白名单
const RegisterDto = z.object({
  email: z.string().email(),
  password: z.string().min(12).max(128),
  name: z.string().max(64),
}).strict();   // 拒绝未知字段

const data = RegisterDto.parse(req.body);
await User.create({ ...data, role: 'user', isVerified: false });

// ✅ 更新
const UpdateProfileDto = z.object({
  name: z.string().max(64).optional(),
  avatar: z.string().url().optional(),
}).strict();

const patch = UpdateProfileDto.parse(req.body);
await User.update(patch, { where: { id: req.user.id }, fields: Object.keys(patch) });
```

```python
# ✅ Pydantic
class RegisterIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
```

```ruby
# ✅ Rails Strong Parameters
def user_params
  params.require(:user).permit(:email, :password, :name)
end
```

```java
// ✅ Spring DTO
public record RegisterRequest(@Email String email, @Size(min=12) String password, @Size(max=64) String name) {}
```

## 6. 自查清单

- [ ] 无 `create(req.body)` / `update(req.body)` 透传
- [ ] 每个写接口有显式 DTO 与字段白名单
- [ ] schema 校验开启「拒绝未知字段」
- [ ] `role` / `isAdmin` / `balance` / `verified` 等字段服务端独占
- [ ] 嵌套对象同样做白名单
- [ ] CI 有规则扫描批量赋值模式
- [ ] 单测覆盖「提交非法字段应被忽略/拒绝」

## 7. 参考资料

- OWASP API Security Top 10: API3 Broken Object Property Level Authorization
- OWASP: Mass Assignment Cheat Sheet
- CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes
