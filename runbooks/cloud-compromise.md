# RB-008 云账号失陷

| 项 | 内容 |
|---|---|
| Runbook ID | RB-008 |
| 版本 | v1.0 |
| 负责人 | 云平台安全负责人 |
| 最后演练 | 待定（建议每半年） |
| 默认级别 | **P1 紧急** |
| 关联 | `../50-cloud-container/`、`../31-ssrf/`、`../47-dns-attacks/` |

## 1. 触发条件

- GuardDuty / Security Hub / Defender for Cloud 高危告警
- CloudTrail 异常：关闭日志、创建新用户/密钥、修改信任策略
- 账单突增（挖矿、数据传出、快照）
- 陌生地域出现实例/函数/用户
- 密钥泄露（RB-007）后确认被使用
- 公开存储桶被写入/删除
- 安全组被改为 `0.0.0.0/0`

## 2. 分级与响应时限

| 情形 | 级别 | 首次响应 |
|---|---|---|
| 生产账号 / 根账号 / 管理员角色被控 | P1 | 15 分钟 |
| 单服务账号 / 沙箱账号 | P2 | 30 分钟 |
| 仅告警，未确认 | P3 | 2 小时 |

## 3. 角色与职责

| 角色 | 职责 |
|---|---|
| IC | 指挥、决策（是否断网/停服） |
| 云安全工程师 | 取证、遏制、清理 |
| 平台/运维 | 恢复实例与服务 |
| IAM | 轮换凭据、重建角色 |
| 法务/DPO | 数据影响评估（RB-003） |
| 云厂商 TAM | 紧急支持、日志协助 |

## 4. 前置准备

- [ ] 多账号结构（生产/安全/日志隔离）
- [ ] CloudTrail 全区域 + 组织级日志，投递到**独立账号**
- [ ] GuardDuty / Security Hub / Config 已开启
- [ ] 根账号 MFA + 无 AK，break-glass 流程
- [ ] 资产清单与业务影响分级
- [ ] 云厂商紧急联系人与支持级别

> 关键：**日志必须写到攻击者无法删除的地方**（独立账号 + 对象锁）。

## 5. 处置步骤

### Step 1 遏制（0–15 分钟）

```text
1. 禁用泄露/可疑的 AK
2. 吊销该主体的临时会话（Deny 策略）
3. 隔离受影响实例（安全组移出/隔离子网/停止实例——先取证再停）
4. 若攻击者在使用：阻断其源 IP、禁用其创建的用户/角色
5. 暂停高危自动化（避免自动扩缩容被利用）
6. ⚠️ 不要删除日志、不要立即删除攻击者资源（先取证）
```

```bash
# 只读：快速摸清身份与最近操作
aws sts get-caller-identity
aws cloudtrail lookup-events --max-results 50
aws iam list-users
aws iam list-access-keys --user-name <user>
```

```bash
# ⚠️ 双人确认：禁用 AK + 吊销会话
aws iam update-access-key --user-name <user> --access-key-id AKIA... --status Inactive
aws iam put-user-policy --user-name <user> --policy-name RevokeSessions \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"2026-01-01T00:00:00Z"}}}]}'
```

### Step 2 保全日志（15–45 分钟）

```bash
# 导出最近 30 天 CloudTrail 到独立位置（只读）
aws cloudtrail lookup-events --start-time 2025-12-01 --end-time 2026-01-01 > ct.json
shasum -a 256 ct.json > ct.sha256

# 确认组织级 trail 未被篡改
aws cloudtrail describe-trails --include-shadow-trails
aws cloudtrail get-trail-status --name org-trail
```

```text
重点确认：
- CloudTrail 是否被 StopLogging / DeleteTrail
- 是否有新的 trail 被创建到攻击者账号
- S3 日志桶是否被改策略
- GuardDuty 是否被禁用
```

### Step 3 界定范围（1–6 小时）

```text
1. 哪些身份被使用？（用户、角色、联邦、根）
2. 从哪些 IP/地域？是否仍活跃？
3. 创建了什么持久化？
   - 新 IAM 用户/角色/AK
   - 修改信任策略（跨账号）
   - Lambda / EC2 UserData / 容器
   - S3 桶策略、公共访问
   - 路由表、安全组、VPC Peering
   - 密钥管理（KMS）、Secret 读取
   - SSO/OAuth 应用
4. 是否访问了数据？→ 可能升级 RB-003
5. 是否扩散到其他账号/区域？
```

```bash
# 只读：枚举可疑资源（示例）
aws iam list-users --query 'Users[?CreateDate>=`2025-12-01`]'
aws iam list-roles --query 'Roles[?CreateDate>=`2025-12-01`]'
aws ec2 describe-instances --query 'Reservations[].Instances[?LaunchTime>=`2025-12-01`]'
aws lambda list-functions
aws s3api list-buckets
aws kms list-keys
```

### Step 4 清除（确认范围后）

```text
顺序：先切断访问 → 再删除资源 → 最后重建
1. 删除攻击者创建的用户/角色/AK/策略
2. 还原被修改的信任策略、桶策略、安全组
3. 终止恶意实例/函数/容器
4. 清理后门：SSH key、cron、UserData、镜像
5. 轮换所有可能暴露的密钥（见 RB-007）
```

```bash
# ⚠️ 双人确认：删除攻击者创建的用户
aws iam delete-user-policy --user-name attacker-user --policy-name X
aws iam delete-access-key --user-name attacker-user --access-key-id AKIA...
aws iam delete-user --user-name attacker-user
```

### Step 5 恢复

```text
1. 用干净镜像重建实例（不要修复被入侵的实例）
2. 从备份恢复数据（确认备份未被污染）
3. 重新部署应用，验证配置与权限
4. 恢复 DNS/流量，观察异常
5. 加强监控 30 天
```

### Step 6 通知

| 对象 | 时机 | 内容 |
|---|---|---|
| 管理层/CISO | 确认 P1 后 30 分钟 | 影响、已遏制、需决策 |
| 云厂商 | 立即 | 开紧急工单，请求日志协助 |
| 法务/DPO | 数据可能被访问 | 上报评估（RB-003） |
| 客户 | 若涉及其数据 | 统一口径 |
| 保险 | 按保单 | 保留费用凭证 |

## 6. 验证标准

- [ ] 攻击者身份全部失效（AK、会话、角色）
- [ ] 无新增 IAM 用户/角色/AK（连续 72 小时）
- [ ] 无异常 API 调用与账单增长
- [ ] 被修改的策略/安全组已还原
- [ ] 恶意资源已清除，后门已排查
- [ ] 日志完整性确认（无 StopLogging/DeleteTrail）
- [ ] 数据访问范围已评估，必要时应上报

## 7. 升级与通知

- 根账号/组织管理员被控 → 立即 P1，考虑联系云厂商安全团队
- 跨账号/跨区域扩散 → 升级 P1，通知所有账号 Owner
- 数据被访问/下载 → 升级 RB-003
- 供应链（CI/CD 被投毒）→ 升级 `../28-supply-chain/` 流程

## 8. 沟通模板

```text
【云安全事件 · 内部通告】
时间：____
范围：账号 ____ / 区域 ____ / 服务 ____
现状：已禁用可疑凭据，正在确认影响范围
已采取措施：吊销会话、隔离实例、保全日志
需决策：是否暂停相关业务、是否通知客户
下次更新：____
```

## 9. 取证与保全

| 证据 | 来源 | 注意 |
|---|---|---|
| API 调用记录 | CloudTrail | 独立账号存储，防删除 |
| 网络流量 | VPC Flow Logs | 保留 90 天+ |
| 资源配置历史 | AWS Config | 还原变更时间线 |
| 实例磁盘 | EBS 快照 | 只读副本 |
| 容器镜像 | 镜像仓库 | 保留 digest |
| 账单 | Cost Explorer | 异常资源与地域 |

## 10. 恢复与复盘

```text
1. 根因：AK 泄露？SSRF？IAM 过宽？公开桶？
2. 检测时延：GuardDuty 是否覆盖？告警是否被忽略？
3. 权限设计：是否可横向到组织管理账号？
4. 改进：SCP、权限边界、短期凭据、日志隔离、CSPM
5. 回写知识库：50/31 + 本 Runbook
```

## 11. 附录

```text
云上高危信号
- CreateUser / CreateAccessKey / AttachUserPolicy
- PutBucketPolicy（public）
- AuthorizeSecurityGroupIngress（0.0.0.0/0）
- StopLogging / DeleteTrail / DeleteDetector
- CreateFunction / UpdateFunctionCode
- ModifyInstanceAttribute（UserData）
- AssumeRole 跨账号异常
```

- 关联：`../50-cloud-container/`、`../31-ssrf/`、`RB-003`、`RB-007`
