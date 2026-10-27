# 服务端请求伪造 SSRF (Server-Side Request Forgery)

> 分类：服务端 | 风险：严重 | CWE-918 | OWASP A10:2021

## 1. 攻击原理

应用根据用户输入发起服务端请求（抓取图片、Webhook、URL 预览、文件导入、PDF 渲染、代理）。若未限制目标地址，攻击者可让服务器访问：

- **云元数据**：`http://169.254.169.254/`（AWS/GCP/Azure 临时凭证）
- **内网服务**：`http://127.0.0.1:6379`、`http://10.0.0.5/admin`、`http://192.168.1.1`
- **本地文件**：`file:///etc/passwd`（部分库支持）
- **内部 API**：K8s API Server、Consul、Elasticsearch

变体：**盲 SSRF**（无回显，靠时间/错误差异判断）、**半盲**（可读取部分响应）。

## 2. 攻击示例

```js
// ❌
app.post('/fetch-image', async (req, res) => {
  const r = await axios.get(req.body.url, { responseType: 'arraybuffer' });
  res.send(r.data);
});
```

### 读取云凭证

```json
{ "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/" }
```

返回角色名，再请求：

```text
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
```

获得 `AccessKeyId` / `SecretAccessKey` / `Token` → 接管云账号。

### 探测内网

```text
http://127.0.0.1:22      → 连接被拒（端口关闭）
http://127.0.0.1:6379    → 响应时间不同（端口开放）
```

### 绕过技巧

```text
http://127.0.0.1        → http://2130706433（十进制）
http://0x7f000001
http://127.1
http://[::1]
http://127.0.0.1.sslip.io（DNS 解析到内网）
http://attacker.com → 302 跳转到内网（需跟随重定向时才生效）
http://internal@attacker.com
```

**DNS Rebinding**：域名第一次解析为公网 IP 通过校验，第二次解析为内网 IP 发起连接。

## 3. 影响

- 云凭证泄露 → 云上资源被完全控制
- 内网服务未授权访问（Redis 写 crontab → RCE）
- 端口/资产扫描，为横向移动铺路
- 读取本地文件

## 4. 防御措施

1. **协议白名单**：只允许 `http` / `https`，禁止 `file`、`gopher`、`dict`、`ftp`。
2. **域名白名单（首选）**：只允许预置域名（如图片 CDN），不做任意 URL 抓取。
3. **解析后校验 IP**：DNS 解析后检查是否为内网/保留地址，并用**同一 IP 发起连接**（防 rebinding）。
   - 禁止：`127.0.0.0/8`、`10/8`、`172.16/12`、`192.168/16`、`169.254/16`、`::1`、`fc00::/7`、`0.0.0.0`、`100.64/10`
4. **禁止跟随重定向**，或每一跳重新校验。
5. **端口限制**：只允许 80/443。
6. **网络层兜底**：请求服务部署在独立子网，出网走代理（白名单域名），无法访问内网与元数据地址；启用 IMDSv2 并限制 hop limit。
7. **禁用危险功能**：PDF 渲染/HTML 转图片服务的 URL 加载关闭，或走代理。
8. **响应限制**：大小上限、超时、并发限制，防被当作扫描器/DoS 工具。
9. **盲 SSRF 缓解**：统一错误与耗时，减少侧信道。

## 5. 代码对比

```js
// ❌ 任意 URL
await fetch(req.body.url);

// ✅ 白名单 + IP 校验 + 禁跳转
import { URL } from 'url';
import dns from 'dns/promises';
import net from 'net';
import ipaddr from 'ipaddr.js';

const ALLOWED_HOSTS = new Set(['images.cdn.com', 'api.partner.com']);
const BLOCKED = new net.BlockList();
BLOCKED.addSubnet('127.0.0.0', 8, 'ipv4');
BLOCKED.addSubnet('10.0.0.0', 8, 'ipv4');
BLOCKED.addSubnet('172.16.0.0', 12, 'ipv4');
BLOCKED.addSubnet('192.168.0.0', 16, 'ipv4');
BLOCKED.addSubnet('169.254.0.0', 16, 'ipv4');
BLOCKED.addSubnet('100.64.0.0', 10, 'ipv4');
BLOCKED.addAddress('::1', 'ipv6');

async function safeFetch(raw) {
  const u = new URL(raw);
  if (!['http:', 'https:'].includes(u.protocol)) throw new Error('bad protocol');
  if (!ALLOWED_HOSTS.has(u.hostname)) throw new Error('host not allowed');
  if (u.port && !['80', '443'].includes(u.port)) throw new Error('bad port');

  const { address } = await dns.lookup(u.hostname);   // 只解析一次
  const parsed = ipaddr.parse(address);
  const range = parsed.range();
  if (range !== 'unicast') throw new Error('blocked ip');

  return fetch(u, {
    redirect: 'manual',
    signal: AbortSignal.timeout(5000),
    // 关键：连接到已校验的 IP，避免二次解析
    // 生产可用 undici Agent 的 connect.lookup 固定 address
  });
}
```

```python
# ✅ Python：ipaddress 校验
import ipaddress, socket
ip = socket.gethostbyname(host)
if ipaddress.ip_address(ip).is_private or ipaddress.ip_address(ip).is_loopback:
    raise ValueError("blocked")
```

```yaml
# ✅ 云侧：强制 IMDSv2
# aws ec2 modify-instance-metadata-options --http-tokens required --http-put-response-hop-limit 1
```

## 6. 自查清单

- [ ] 所有出站请求有协议与域名白名单
- [ ] DNS 解析后校验 IP 且连接固定该 IP（防 rebinding）
- [ ] 禁止私有/保留地址与云元数据地址
- [ ] 不跟随重定向或每跳校验
- [ ] 端口限制为 80/443
- [ ] 请求服务独立子网，出网走白名单代理
- [ ] 云主机启用 IMDSv2
- [ ] 响应大小/超时/并发受限
- [ ] 盲 SSRF 有统一错误与耗时处理

## 7. 参考资料

- OWASP: Server Side Request Forgery Prevention Cheat Sheet
- CWE-918: Server-Side Request Forgery
- PortSwigger: SSRF
- AWS IMDSv2 文档
