# 竞态条件 / TOCTOU (Race Condition)

> 分类：并发 | 风险：高 | CWE-362 / CWE-367

## 1. 攻击原理

业务逻辑在「检查」与「使用」之间存在时间窗口（Time-of-Check to Time-of-Use），并发请求可同时通过检查，造成：

- 优惠券/积分重复领取
- 余额重复扣减或超额提现
- 限购商品超卖
- 一次验证码多次使用
- 重复注册同名账号
- 文件权限检查后被替换（符号链接攻击）

单次请求看似合规，靠**并发**放大。

## 2. 攻击示例

### 重复领取优惠券

```js
// ❌ 先查后写
const existing = await Coupon.findOne({ userId, couponId });
if (existing) return res.status(400).json({ error: 'already claimed' });
await Coupon.create({ userId, couponId });
```

同时发 50 个请求，全部在 `findOne` 时未命中 → 创建 50 条记录。

### 余额并发扣减

```js
const acc = await Account.findByPk(id);
if (acc.balance < amount) throw new Error('insufficient');
await acc.update({ balance: acc.balance - amount });   // ❌ 读-改-写
```

两个并发请求都读到 100，各扣 80 → 余额 -60。

### 验证码重放

```js
const ok = await checkOtp(userId, code);   // 校验
await doSensitiveAction();                  // 执行
await deleteOtp(userId);                    // 删除（在动作之后）
```

并发请求在删除前都通过校验。

### 文件 TOCTOU

```c
if (access(path, W_OK) == 0) {   // 检查
    // 攻击者在此把 path 换成符号链接
    fd = open(path, O_WRONLY);   // 使用
}
```

## 3. 影响

- 直接资金损失（重复提现、超卖、优惠券套利）
- 业务规则被绕过，数据不一致
- 权限提升（TOCTOU 文件操作 → 覆盖敏感文件）
- 难以复现，常规功能测试发现不了

## 4. 防御措施

1. **数据库唯一约束（最可靠）**
   ```sql
   ALTER TABLE coupons ADD CONSTRAINT uq_user_coupon UNIQUE (user_id, coupon_id);
   ```
   插入冲突即返回「已领取」，天然防并发。
2. **原子操作 / 条件更新**
   ```sql
   UPDATE accounts SET balance = balance - :amt
   WHERE id = :id AND balance >= :amt;
   -- 影响行数为 0 表示余额不足
   ```
3. **行锁 / 悲观锁**：`SELECT ... FOR UPDATE`（事务内），或 Redis 分布式锁（注意锁续期与误删）。
4. **乐观锁**：版本号 `WHERE version = :v`，冲突则重试。
5. **幂等键**：客户端生成 `Idempotency-Key`，服务端去重（Redis SETNX + TTL）。
6. **状态机 + 条件流转**：`UPDATE ... WHERE status = 'pending'`，只有一次能成功。
7. **事务边界正确**：检查与写入在同一事务；隔离级别按需（`REPEATABLE READ` / `SERIALIZABLE`）。
8. **验证码一次性原子消费**：`DEL` 或 `GETDEL` 与校验原子化。
9. **文件操作**：用 `O_CREAT|O_EXCL`、`O_NOFOLLOW`、`openat` + `fstat` 校验；不使用「先检查后打开」。
10. **压测验证**：用并发脚本（如 `hey`、`k6`、`ab`）对所有资金/权益接口做并发测试。

## 5. 代码对比

```js
// ✅ 唯一约束 + 捕获冲突
try {
  await Coupon.create({ userId, couponId });
} catch (e) {
  if (e.code === '23505') return res.status(409).json({ error: 'already claimed' });
  throw e;
}

// ✅ 条件更新（原子）
const [affected] = await sequelize.query(
  'UPDATE accounts SET balance = balance - :amt WHERE id = :id AND balance >= :amt',
  { replacements: { amt, id } }
);
if (affected === 0) return res.status(400).json({ error: 'insufficient balance' });

// ✅ 乐观锁
const acc = await Account.findByPk(id);
const [n] = await Account.update(
  { balance: acc.balance - amt, version: acc.version + 1 },
  { where: { id, version: acc.version } }
);
if (n === 0) throw new Error('conflict, retry');

// ✅ 幂等键
const key = req.get('Idempotency-Key');
const locked = await redis.set(`idem:${key}`, '1', { NX: true, EX: 3600 });
if (!locked) return res.status(409).json({ error: 'duplicate request' });
```

```sql
-- ✅ 悲观锁
BEGIN;
SELECT balance FROM accounts WHERE id = 1 FOR UPDATE;
UPDATE accounts SET balance = balance - 80 WHERE id = 1;
COMMIT;
```

```python
# ✅ 验证码原子消费（Redis）
if redis.getdel(f"otp:{user_id}") == code:
    do_action()
```

## 6. 自查清单

- [ ] 所有唯一性业务有数据库唯一约束
- [ ] 余额/库存使用原子条件更新，非读-改-写
- [ ] 关键流程有行锁、乐观锁或分布式锁
- [ ] 支付/下单/领券接口支持幂等键
- [ ] 状态流转使用条件更新
- [ ] 验证码/一次性 Token 原子消费
- [ ] 文件操作防 TOCTOU（O_EXCL / O_NOFOLLOW）
- [ ] 有并发压测用例覆盖资金与权益接口

## 7. 参考资料

- OWASP: Race Conditions
- CWE-362: Concurrent Execution Using Shared Resource with Improper Synchronization
- CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
- PortSwigger: Race conditions
