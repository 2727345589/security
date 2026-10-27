# 拒绝服务 / 资源耗尽 (DoS & Resource Exhaustion)

> 分类：可用性 | 风险：中高 | CWE-400 / CWE-770 / CWE-1333

## 1. 攻击原理

攻击者用极小成本消耗服务端大量资源，使正常用户不可用。Web 层常见：

| 类型 | 手段 |
|---|---|
| 流量型 | 大流量打满带宽（需 DDoS 防护） |
| 应用层 | 高频请求、慢速攻击（Slowloris） |
| 复杂查询 | 深分页、超大全表扫描、复杂正则（ReDoS） |
| 大对象 | 超大 JSON/XML、压缩炸弹、图片解压炸弹 |
| 计算放大 | 密码哈希、PDF 渲染、视频转码、AI 推理被高频调用 |
| 存储耗尽 | 无限上传、日志放大、缓存污染 |
| 锁竞争 | 持锁请求卡住全站 |
| 第三方依赖 | 触发下游限流，自身级联失败 |

## 2. 攻击示例

### 无分页限制

```http
GET /api/orders?limit=100000000
```

全表 JOIN + 排序，数据库 CPU 打满。

### ReDoS

```js
// ❌ 灾难性回溯
const re = /^(a+)+$/;
re.test('a'.repeat(40) + '!');   // 卡死事件循环
```

### 压缩炸弹

上传 1MB 的 zip，解压后 10GB → 磁盘/内存耗尽。

### 慢速攻击

```text
POST /upload HTTP/1.1
Content-Length: 1000000
...
（每秒发 1 字节，长期占用连接）
```

### 密码哈希放大

登录接口无限制 + Argon2 高内存参数 → 少量请求即打满内存。

## 3. 影响

- 服务不可用，业务中断
- 云账单暴涨（按量计费被刷）
- 与其他漏洞组合（如用 ReDoS 掩盖攻击行为）
- SLA 违约与声誉损失

## 4. 防御措施

1. **分层限流**：网关/边缘按 IP、用户、API Key、接口维度限流；登录、发送验证码、AI 推理等重接口更严格。
2. **请求体限制**：Nginx `client_max_body_size`、框架 body parser 上限、JSON 深度与键数量限制。
3. **分页强制上限**：`limit` 最大 100，`offset` 上限或改为游标分页。
4. **超时与截止时间**：连接、读、写、上游调用、数据库查询都要有超时；全链路 deadline 传递。
5. **并发限制与队列**：每实例并发上限、线程池隔离、熔断降级（circuit breaker）。
6. **防 ReDoS**：避免嵌套量词正则；用 `re2` 或对输入长度设硬上限；正则执行加超时。
7. **解压限制**：限制解压后总大小、文件数、压缩比（如 > 100:1 拒绝）。
8. **异步与队列**：重任务（转码、PDF、AI）进队列，限制 worker 数与队列长度。
9. **成本控制**：云 WAF + DDoS 防护（Cloudflare/AWS Shield）、自动伸缩上限、预算告警。
10. **缓存与降级**：热点数据缓存，故障时返回降级内容。

## 5. 代码对比

```js
// ✅ Express：请求体与超时
app.use(express.json({ limit: '100kb' }));
app.use((req, res, next) => {
  req.setTimeout(15000);
  res.setTimeout(15000);
  next();
});

// ✅ 分页上限
const limit = Math.min(Math.max(parseInt(req.query.limit ?? '20', 10) || 20, 1), 100);

// ✅ 限流
import rateLimit from 'express-rate-limit';
app.use('/api/', rateLimit({ windowMs: 60_000, max: 120 }));
app.use('/api/login', rateLimit({ windowMs: 60_000, max: 10 }));
app.use('/api/ai', rateLimit({ windowMs: 60_000, max: 5 }));
```

```nginx
# ✅ 网关层
client_max_body_size 10m;
client_body_timeout 10s;
client_header_timeout 10s;
send_timeout 10s;
limit_req_zone $binary_remote_addr zone=api:10m rate=20r/s;
limit_req zone=api burst=40 nodelay;
```

```js
// ✅ 防 ReDoS
const RE2 = require('re2');
const re = new RE2('^[a-z0-9-]{1,64}$');
if (!re.test(input.slice(0, 128))) return res.status(400).end();

// ✅ 解压限制
const MAX_UNZIPPED = 50 * 1024 * 1024;
if (totalSize > MAX_UNZIPPED || ratio > 100) throw new Error('zip too large');
```

```js
// ✅ 熔断（opossum）
const breaker = new CircuitBreaker(callUpstream, { timeout: 3000, errorThresholdPercentage: 50, resetTimeout: 30000 });
```

## 6. 自查清单

- [ ] 全站有分层限流（IP / 用户 / 接口）
- [ ] 请求体大小、JSON 深度、字段数受限
- [ ] 分页有硬上限或用游标分页
- [ ] 所有网络与数据库调用有超时
- [ ] 重接口有并发限制与队列
- [ ] 正则无灾难性回溯，或使用 RE2
- [ ] 解压有大小/数量/比率限制
- [ ] 有 WAF / DDoS 防护与预算告警
- [ ] 熔断降级策略已配置

## 7. 参考资料

- OWASP: Denial of Service Cheat Sheet
- CWE-400 / CWE-770 / CWE-1333
- OWASP API Security Top 10: API4 Unrestricted Resource Consumption
