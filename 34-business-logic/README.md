# 业务逻辑漏洞 (Business Logic Flaws)

> 分类：业务逻辑 | 风险：高 | CWE-840

## 1. 攻击原理

代码没有「技术漏洞」，但业务流程的假设被打破。自动化扫描器几乎发现不了，需要理解业务。

典型模式：

| 模式 | 例子 |
|---|---|
| 客户端可信 | 价格、折扣、角色由前端传 |
| 步骤跳过 | 跳过支付直接回调「成功」 |
| 数值边界 | 负数数量、0 元订单、超大数量 |
| 重复执行 | 退款多次、优惠叠加 |
| 状态机缺失 | 已取消订单仍可发货 |
| 参数复用 | 用 A 商品的优惠券买 B 商品 |
| 时间窗口 | 活动结束后仍能提交 |
| 权限假设 | 「用户不会改这个参数」 |
| 汇率/单位 | 分与元混用、币种未校验 |

## 2. 攻击示例

### 价格篡改

```http
POST /api/cart/checkout
{ "productId": 1, "price": 0.01, "quantity": 1 }
```

服务端直接使用客户端传的 `price` → 1 分钱买 iPhone。

### 负数数量

```json
{ "productId": 1, "quantity": -5 }
```

总价变负，或退款金额 = 单价 × -5 → 反向加钱。

### 跳过支付

```http
POST /api/order/123/confirm     ← 前端在支付成功后调用
```

攻击者不支付直接调用 → 订单变「已支付」。

### 优惠券叠加

同一订单重复应用多张互斥券；或用「满 100 减 50」券 + 退款后券未回收。

### 状态机绕过

```http
POST /api/orders/123/ship        ← 已取消订单仍可发货
POST /api/refund/123             ← 同一订单多次退款
```

## 3. 影响

- 直接资金损失（最常见、最直接）
- 商品/权益被薅走
- 数据不一致，运营决策失真
- 合规与审计风险

## 4. 防御措施

1. **服务端权威**：价格、折扣、库存、权限、状态全部服务端计算，客户端只传商品 ID 与数量。
2. **严格状态机**：定义合法状态迁移表，非法迁移拒绝（`pending → paid → shipped → done`，`cancelled` 为终态）。
3. **数值校验**：数量 `1..N` 整数、金额用最小货币单位整数、禁止负数与 0（除非业务允许）、上限检查。
4. **幂等与去重**：支付回调、退款、领券接口使用幂等键 + 唯一约束。
5. **步骤服务端串联**：支付结果以**支付网关异步通知**为准，绝不信任前端回调。
6. **优惠规则引擎**：互斥、叠加、门槛、适用范围在服务端统一判定，并锁定券状态（`locked` → `used`）。
7. **时间校验**：活动起止时间以服务端时间为准。
8. **对账与监控**：资金流水日对账；异常订单（0 元、负金额、高频退款）实时告警。
9. **滥用检测**：同设备/同 IP 高频下单、批量注册、异常收货地址。
10. **威胁建模**：每个业务流程画「攻击者视角」流程图，逐步骤问「能否跳过/重复/篡改」。

## 5. 代码对比

```js
// ❌ 信任客户端价格
const total = req.body.price * req.body.quantity;

// ✅ 服务端计算
const product = await Product.findByPk(req.body.productId);
if (!product || !product.active) return res.status(400).json({ error: 'invalid product' });
const qty = req.body.quantity;
if (!Number.isInteger(qty) || qty < 1 || qty > 10) return res.status(400).json({ error: 'invalid quantity' });

const unit = product.priceCents;                   // 分为单位整数
const subtotal = unit * qty;
const discount = await couponEngine.evaluate({ userId: req.user.id, items: [{ product, qty }] });
const total = Math.max(subtotal - discount, 0);

const order = await Order.create({
  userId: req.user.id, totalCents: total, status: 'pending',
  items: [{ productId: product.id, qty, unitCents: unit }],
});
```

```js
// ✅ 状态机
const TRANSITIONS = {
  pending: ['paid', 'cancelled'],
  paid: ['shipped', 'refunded'],
  shipped: ['done'],
  done: [],
  cancelled: [],
  refunded: [],
};

async function transition(order, next) {
  if (!TRANSITIONS[order.status]?.includes(next)) throw new Error('invalid transition');
  const [n] = await Order.update(
    { status: next },
    { where: { id: order.id, status: order.status } }   // 条件更新，防并发
  );
  if (n === 0) throw new Error('state changed, retry');
}
```

```js
// ✅ 支付以前端回调为「查询触发」，以网关通知为准
app.post('/pay/notify', async (req, res) => {
  if (!verifyGatewaySignature(req)) return res.sendStatus(400);
  const order = await Order.findByPk(req.body.orderId);
  if (order.status !== 'pending') return res.sendStatus(200);   // 幂等
  if (req.body.amountCents !== order.totalCents) return res.sendStatus(400);
  await transition(order, 'paid');
  res.sendStatus(200);
});
```

## 6. 自查清单

- [ ] 价格/折扣/库存全部服务端计算
- [ ] 数量与金额有正负、范围、整数校验
- [ ] 状态机完整，非法迁移被拒绝
- [ ] 支付结果以网关通知为准，前端仅触发查询
- [ ] 支付/退款/领券接口幂等
- [ ] 优惠券互斥与叠加规则服务端统一判定
- [ ] 活动时间以服务端时间为准
- [ ] 有资金对账与异常订单告警
- [ ] 每个流程做过攻击者视角威胁建模

## 7. 参考资料

- OWASP: Business Logic Security Cheat Sheet
- CWE-840: Business Logic Errors
- OWASP WSTG: Business Logic Testing
