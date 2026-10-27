# RB-009 证书过期 / 即将过期

| 项 | 内容 |
|---|---|
| Runbook ID | RB-009 |
| 版本 | v1.0 |
| 负责人 | 平台/运维负责人 |
| 最后演练 | 待定（建议每季度检查一次告警有效性） |
| 默认级别 | 即将过期 **P3**；已过期 **P1** |
| 关联 | `../46-mitm/`、`../29-security-misconfiguration/` |

## 1. 触发条件

- 监控告警：证书剩余 30 / 14 / 7 / 1 天
- 浏览器报错：`NET::ERR_CERT_DATE_INVALID`、证书不受信任
- API/客户端调用失败：TLS handshake error、certificate expired
- 用户/客户反馈「网站打不开/不安全」
- 移动 App 因证书固定（pinning）失效而崩溃
- 内部服务间 mTLS 认证失败

## 2. 分级与响应时限

| 情形 | 级别 | 首次响应 |
|---|---|---|
| 生产对外证书已过期 | **P1** | 15 分钟 |
| 内部关键服务证书已过期 | P1/P2 | 30 分钟 |
| 剩余 ≤ 7 天 | P2 | 4 小时 |
| 剩余 ≤ 30 天 | P3 | 1 个工作日 |

## 3. 角色与职责

| 角色 | 职责 |
|---|---|
| 证书 Owner | 续签、部署、验证 |
| 运维/SRE | 发布、回滚 |
| 网络/CDN | 边缘证书更新 |
| 安全 | 私钥保管、CT 监控 |
| 客服/PR | 用户沟通（已过期时） |

## 4. 前置准备

- [ ] 完整证书清单（域名、用途、到期日、Owner、签发方式）
- [ ] 自动续签（ACME / cert-manager / ACM）已启用
- [ ] 监控覆盖所有对外域名与内部 mTLS
- [ ] 私钥安全存储（KMS/HSM/Vault）
- [ ] 回滚与备用证书方案
- [ ] 移动端 pinning 的更新计划

## 5. 处置步骤

### Step 1 确认（0–10 分钟）

```bash
# 只读：查看证书详情
openssl s_client -connect example.com:443 -servername example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName

# 检查链是否完整
openssl s_client -connect example.com:443 -servername example.com -showcerts </dev/null
```

```text
确认：
1. 哪些域名/服务受影响（SAN 列表）
2. 是「过期」还是「链不完整/不受信任/域名不匹配」
3. 是否有多个入口（CDN、LB、Ingress、内部服务）
4. 是否有客户端 pinning（改证书会导致 App 失败）
```

### Step 2 续签（10–30 分钟）

```bash
# ACME（certbot）
certbot renew --cert-name example.com
# 或强制续签（仅确认需要时）
certbot renew --cert-name example.com --force-renewal

# cert-manager（K8s）
kubectl get certificate -A
kubectl describe certificate example-tls -n prod
kubectl cert-manager renew example-tls -n prod
```

```text
手动签发（商业 CA）：
1. 生成 CSR（复用或新建私钥）
2. 提交 CA，完成域名验证（DNS/HTTP）
3. 下载证书链（fullchain）
4. 校验：openssl verify + 域名匹配
```

### Step 3 部署（30–60 分钟）

```text
部署顺序（降低风险）：
1. 先在预发/灰度环境验证
2. 更新边缘（CDN）→ 源站 → 内部服务
3. 平滑 reload，不断连接
4. 保留旧证书以便快速回滚
```

```bash
# Nginx：先测试配置再 reload
nginx -t && nginx -s reload

# 检查部署后的证书
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null \
  | openssl x509 -noout -dates -subject
```

```yaml
# K8s Ingress（cert-manager 自动注入）
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: app
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
    - hosts: [app.example.com]
      secretName: app-tls
```

### Step 4 验证（部署后 5 分钟）

```bash
# 1. 有效期正确
openssl s_client -connect example.com:443 -servername example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -enddate

# 2. 链完整
openssl s_client -connect example.com:443 -servername example.com -verify_return_error </dev/null

# 3. 多地域/多入口验证
for h in www.example.com api.example.com; do
  echo "== $h"; echo | openssl s_client -connect $h:443 -servername $h 2>/dev/null | openssl x509 -noout -dates
done

# 4. HTTP 客户端验证（不使用 -k）
curl -sS -o /dev/null -w '%{http_code}\n' https://example.com
```

```text
还要检查：
- 混合内容（页面内 http 资源）
- HSTS 是否仍生效
- 移动 App / 桌面客户端是否正常（pinning）
- 内部服务 mTLS 是否互通
```

### Step 5 已过期时的应急

```text
优先级：
1. 立即续签并部署（最快路径）
2. 若 CA 验证受阻：切换备用 CA / 备用证书
3. 若有 CDN：先更新边缘证书，缓解用户侧
4. 内部服务：通过配置管理批量分发，避免逐台操作

禁止：
- ❌ 让用户「忽略证书警告」
- ❌ 客户端关闭证书校验（verify=False）
- ❌ 用自签名证书替代对外服务（除非临时且明确告知）
```

### Step 6 通知（已过期时）

```text
1. 状态页/公告：说明影响与预计恢复时间
2. 客服话术：不要建议用户「继续访问（不安全）」
3. 大客户/合作方：单独通知
4. 若影响 API 合作方：提供备用域名/时间窗
```

## 6. 验证标准

- [ ] 所有受影响入口的新证书已生效
- [ ] `openssl s_client` 显示正确有效期与完整链
- [ ] 浏览器/客户端无证书错误
- [ ] 内部 mTLS 服务互通
- [ ] 监控显示新到期日，告警重置
- [ ] 旧证书已按计划吊销/归档（如需要）
- [ ] 无用户侧报错（连续 1 小时）

## 7. 升级与通知

| 情形 | 动作 |
|---|---|
| 对外主站已过期 | P1，全员响应，30 分钟内恢复 |
| 支付/登录域名过期 | P1，通知业务与风控 |
| 移动端 pinning 失效 | 评估发版，必要时服务端双证书过渡 |
| CA 根证书变更 | 提前评估客户端信任库，制定过渡期 |

## 8. 沟通模板

```text
【服务通告 · 证书更新】
时间：____
影响：部分用户访问 ____ 时可能看到证书警告
原因：TLS 证书更新
当前状态：正在部署新证书，预计 ____ 恢复
建议：恢复前请勿在该站点输入敏感信息
```

## 9. 取证与保全

| 证据 | 用途 |
|---|---|
| 旧证书与到期时间 | 复盘、合规 |
| 监控告警记录 | 证明告警是否生效 |
| 部署与验证日志 | 时间线 |
| 用户报错截图 | 影响评估 |

> 私钥泄露场景按 RB-007 处理，并吊销旧证书。

## 10. 恢复与复盘

```text
1. 为何过期？自动续签失败？监控未覆盖？Owner 缺失？
2. 检测时延：告警是否在 30 天前发出？
3. 部署时延：从续签到生效多久？
4. 改进：
   - 全面启用自动续签
   - 监控覆盖所有域名（含内部、泛域名、CDN）
   - 建立证书清单与 Owner
   - 到期前 30/14/7/1 天多级告警
   - 把证书纳入变更管理与演练
```

## 11. 附录

```text
证书检查速查
- 到期时间：openssl x509 -noout -enddate
- SAN：openssl x509 -noout -ext subjectAltName
- 链：openssl s_client -showcerts
- 域名匹配：openssl x509 -checkhost example.com
- 吊销状态：openssl ocsp -issuer ... -cert ...
```

```text
常见坑
- 只更新了负载均衡，忘了 CDN 边缘
- 只更新了主域，漏了 www/api/静态域
- 证书链缺中间证书（部分客户端报错）
- 自动续签任务因权限/端口失败但无人发现
- 移动端 pinning 未规划，更新即崩溃
```

- 关联：`../46-mitm/`、`../29-security-misconfiguration/`、`RB-007`
