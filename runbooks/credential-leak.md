# RB-007 密钥 / 凭据泄露

| 项 | 内容 |
|---|---|
| Runbook ID | RB-007 |
| 版本 | v1.0 |
| 负责人 | 应用安全 / 平台安全 |
| 最后演练 | 待定（建议每半年） |
| 默认级别 | **P1 紧急** |
| 关联 | `../15-password-storage/`、`../49-credential-theft/`、`../28-supply-chain/` |

## 1. 触发条件

- 代码仓库/公开 Gist 中出现密钥（secret scanning 告警）
- CI/CD 日志、构建产物、前端 bundle 泄露 Token
- 云厂商/第三方通知「检测到你的密钥公开」
- 密钥出现在截图、工单、聊天记录、日志
- 离职人员仍持有有效凭据
- 暗网/ Telegram 出售组织凭据

## 2. 分级与响应时限

| 密钥类型 | 级别 | 首次响应 |
|---|---|---|
| 云根账号 / 生产数据库 / 支付密钥 / CA 私钥 | P1 | 15 分钟 |
| 生产服务 Token / CI 部署密钥 | P1 | 30 分钟 |
| 测试环境 / 只读低权限 | P2 | 2 小时 |
| 已失效的历史密钥 | P3 | 1 个工作日 |

## 3. 角色与职责

| 角色 | 职责 |
|---|---|
| 密钥 Owner | 确认影响、执行轮换 |
| 平台/云管理员 | 吊销、审计、重建 |
| 研发 | 修改代码/配置、重新部署 |
| 安全 | 判定范围、取证、监控 |
| 法务/DPO | 若涉及数据访问 → RB-003 |

## 4. 前置准备

- [ ] 密钥清单与 Owner（Secrets Manager / Vault / KMS）
- [ ] 支持「先禁用后删除」的轮换能力
- [ ] 可查询密钥使用审计（云厂商 Access Log）
- [ ] 代码仓库 secret scanning 已开启
- [ ] 知道各密钥的下游依赖（改一个会影响谁）

## 5. 处置步骤

> **第一原则：先轮换，后清理。** 清理历史不会让已泄露的密钥失效，攻击者可能早已复制。

### Step 1 识别（0–15 分钟）

```text
1. 是什么密钥？（云 AK、数据库口令、JWT 签名密钥、SSH 私钥、TLS 私钥、API Token、CI Secret）
2. 权限范围？（只读/读写/管理员/跨账号）
3. 是否仍有效？
4. 暴露在哪里？暴露多久？谁可能看到？
5. 是否已被使用？（查审计日志的源 IP、时间、操作）
```

```bash
# 只读：确认密钥是否仍有效（谨慎，会产生日志）
aws sts get-caller-identity --access-key-id AKIA... --secret-access-key ...
# 或只查 IAM 状态
aws iam list-access-keys --user-name app-user
```

### Step 2 立即禁用（0–30 分钟）

```bash
# AWS：先禁用，不删除（便于取证）
aws iam update-access-key --user-name app-user --access-key-id AKIA... --status Inactive

# ⚠️ 双人确认：吊销该用户所有临时会话
aws iam put-user-policy --user-name app-user --policy-name RevokeSessions \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"2026-01-01T00:00:00Z"}}}]}'
```

```bash
# 数据库：立即改密并踢掉现有连接
ALTER USER app_user WITH PASSWORD '<new-strong-password>';
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = 'app_user';
```

```bash
# SSH：从 known_hosts / authorized_keys 移除并轮换
# ⚠️ 双人确认
sed -i.bak '/<old-key-fingerprint>/d' ~/.ssh/authorized_keys
```

### Step 3 保全使用记录（30–60 分钟）

```text
1. 导出该密钥近 90 天的使用日志（CloudTrail / 数据库审计 / API 网关）
2. 标记异常：陌生 IP、异常时间、敏感操作（CreateUser、GetSecret、DeleteBucket）
3. 计算哈希存档，不修改原始日志
```

```bash
aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIA... \
  --start-time 2025-10-01 --end-time 2026-01-01 > ct.json
shasum -a 256 ct.json > ct.sha256
```

### Step 4 轮换（30–120 分钟）

| 类型 | 轮换要点 |
|---|---|
| 云 AK | 新建 → 更新部署 → 验证 → 删除旧 |
| 数据库 | 改密 → 更新连接池 → 重启应用 → 验证 |
| JWT 签名密钥 | 支持双密钥过渡（旧验新签）→ 全量换签 → 旧失效 |
| TLS 私钥 | 重新签发证书 → 部署 → 验证 → 吊销旧证书 |
| SSH Key | 生成新对 → 分发 → 移除旧公钥 |
| CI Secret | 平台内更新 → 触发一次部署验证 |
| OAuth Client Secret | 新建 Secret → 更新 → 删除旧 |

```text
轮换顺序（重要）：
1. 创建新密钥（不删旧）
2. 部署到所有使用方（灰度）
3. 验证新密钥工作正常
4. 将旧密钥置为 Inactive（观察 24h）
5. 确认无调用后删除
```

### Step 5 清理暴露源

```bash
# 从 Git 历史移除（轮换后执行）
git filter-repo --path path/to/secret --invert-paths
# 或使用 BFG
bfg --delete-files secret.env
# 强制推送并通知所有协作者重新克隆
git push --force --all
```

```text
其他清理：
- 删除公开 Gist / 工单附件 / 聊天记录中的密钥
- 清理 CI 日志与构建产物
- 撤销泄露的 OAuth 应用与 Refresh Token
- 搜索镜像/备份/日志中的同一密钥（可能多处）
```

### Step 6 验证与监控

```bash
# ✅ 旧密钥必须失效
aws sts get-caller-identity --access-key-id AKIA... --secret-access-key ...   # 应返回 InvalidClientTokenId
curl -H "Authorization: Bearer <old-token>" https://api.example.com/health    # 应 401
```

```text
监控：
- 为旧密钥的调用设置告警（应始终为 0）
- 监控异常 CreateUser/CreateAccessKey/GetSecret
- 将密钥加入泄露检测规则（gitleaks/trufflehog）
```

## 6. 验证标准

- [ ] 泄露密钥已失效（实测 401/InvalidClientTokenId）
- [ ] 新密钥已部署且业务正常
- [ ] 使用记录已导出并分析，无异常操作
- [ ] 历史/日志/镜像中的同一密钥已清理
- [ ] 下游依赖密钥（如派生密钥）已一并轮换
- [ ] 监控规则已上线（旧密钥调用告警）
- [ ] 无新增未授权资源/账号

## 7. 升级与通知

| 情形 | 动作 |
|---|---|
| 云根账号/管理员密钥 | 立即 P1，通知 CISO + 云厂商 |
| 发现异常使用 | 升级 RB-008 / RB-003 |
| 支付/CA 私钥 | 立即通知财务/合规，评估吊销 |
| 供应链密钥（影响客户） | 通知客户与法务 |

## 8. 沟通模板

```text
【密钥轮换通知 · 内部】
因安全事件，我们将于 ____ 轮换 ____ 系统的访问密钥。
影响：____ 服务需重新部署，预计中断 ____ 分钟。
请各负责人在 ____ 前完成配置更新。
旧密钥将于 ____ 失效，请勿继续使用。
```

## 9. 取证与保全

| 证据 | 说明 |
|---|---|
| 泄露位置快照 | 页面/仓库/日志截图 + 哈希 |
| 密钥使用日志 | 云审计、数据库审计、API 网关 |
| 异常操作记录 | 创建用户、读取密钥、删除资源 |
| 轮换记录 | 时间、执行人、影响范围 |

## 10. 恢复与复盘

```text
1. 根因：硬编码？CI 日志？权限过宽？流程缺失？
2. 为何未在提交时拦截？secret scanning 是否覆盖？
3. 缩短密钥寿命（短期凭据/OIDC）
4. 建立密钥清单与 Owner 制度
5. 回写知识库：28/49 + 本 Runbook
```

## 11. 附录

```text
预防清单
- 禁止硬编码，使用 Secrets Manager / Vault
- pre-commit hook：gitleaks / trufflehog
- CI 中 secret scanning + 阻断
- 短期凭据优先（OIDC / STS）
- 最小权限 + 定期轮换
- 日志脱敏，禁止打印 Token
```

- 关联：`../28-supply-chain/`、`../49-credential-theft/`、`RB-002`、`RB-008`
