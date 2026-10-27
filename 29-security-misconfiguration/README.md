# 安全配置错误 (Security Misconfiguration)

> 分类：配置 / 运维 | 风险：高 | CWE-16 | OWASP A05:2021

## 1. 攻击原理

系统在部署时保留了不安全的默认值或暴露了不必要的功能。它本身不是「一个漏洞」，而是漏洞的放大器，常见于：

| 类别 | 例子 |
|---|---|
| 调试信息 | 生产开启 `DEBUG=True`、堆栈回显、`/actuator/env` 暴露 |
| 默认凭据 | `admin/admin`、`root/root`、数据库空密码 |
| 暴露文件 | `.git/`、`.env`、`backup.zip`、`phpinfo.php`、源码映射 |
| 目录列表 | `autoindex on` |
| 不必要服务 | 测试接口、Swagger UI、JMX、Redis/Mongo 公网 |
| 云配置 | S3 公开读、安全组 0.0.0.0/0、IAM 过度授权 |
| 管理入口 | `/admin` 无 IP 限制、无 MFA |
| 容器 | root 运行、特权模式、挂载 docker.sock |
| 安全头缺失 | 无 CSP/HSTS/X-Frame-Options |

## 2. 攻击示例

```text
GET /.git/config           → 下载仓库，恢复源码
GET /.env                  → 数据库密码、API Key
GET /server-status         → 内部信息
GET /actuator/env          → Spring Boot 配置泄露（可能含密钥）
GET /swagger-ui.html       → 接口清单，辅助攻击
```

S3 公开桶：

```bash
aws s3 ls s3://company-backup --no-sign-request
```

默认口令登录 Jenkins / RabbitMQ 管理台 → 命令执行。

## 3. 影响

- 源码与密钥泄露，直接导致接管
- 攻击面暴露（接口、内网服务）
- 云资源被滥用（挖矿、数据外泄）
- 常与其他漏洞组成完整攻击链

## 4. 防御措施

1. **环境分离与基线**：开发/测试/生产配置分离，生产禁止 debug；用 IaC（Terraform/Helm）固化安全基线。
2. **配置扫描**：CIS Benchmark、`kube-bench`、`checkov`、`tfsec`、`docker-bench-security`。
3. **删除非必要组件**：示例应用、文档、测试端点、未使用模块。
4. **强制改默认口令**：首次启动强制设置，禁止空密码。
5. **敏感路径拦截**：
   ```nginx
   location ~ /\.(git|env|svn|hg) { deny all; }
   location ~ \.(bak|sql|zip|tar|gz|log)$ { deny all; }
   autoindex off;
   ```
6. **管理面收敛**：独立入口 + IP 白名单 + MFA + 审计；数据库/缓存不暴露公网。
7. **云安全**：S3 Block Public Access、最小 IAM、安全组默认拒绝、开启 CloudTrail/GuardDuty。
8. **容器加固**：非 root、只读 FS、drop capabilities、禁特权、不挂 docker.sock。
9. **错误处理**：统一异常处理，对外只返回 code + traceId。
10. **安全响应头**：HSTS、CSP、nosniff、Referrer-Policy、Permissions-Policy。
11. **持续巡检**：定期外部资产测绘（子域、端口、证书）与暴露面收敛。

## 5. 代码对比

```python
# ❌ Django 生产配置
DEBUG = True
ALLOWED_HOSTS = ['*']
SECRET_KEY = 'django-insecure-hardcoded'

# ✅
import os
DEBUG = os.environ.get('DJANGO_DEBUG') == '1'   # 生产为 False
ALLOWED_HOSTS = ['app.site.com']
SECRET_KEY = os.environ['DJANGO_SECRET_KEY']   # 来自 KMS
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 31536000
```

```yaml
# ✅ Spring Boot 生产
management:
  endpoints:
    web:
      exposure:
        include: health,info      # 不暴露 env/beans/heapdump
server:
  error:
    include-stacktrace: never
    include-message: never
```

```nginx
# ✅ 基础加固
server_tokens off;
autoindex off;
add_header X-Content-Type-Options nosniff always;
add_header Referrer-Policy strict-origin-when-cross-origin always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

```yaml
# ✅ K8s Pod
securityContext:
  runAsNonRoot: true
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities: { drop: ["ALL"] }
```

## 6. 自查清单

- [ ] 生产关闭 debug、详细错误、堆栈
- [ ] 无默认口令，无空密码服务
- [ ] `.git` / `.env` / 备份 / 日志不可公网访问
- [ ] 目录列表关闭，版本号隐藏
- [ ] Swagger / Actuator / 测试端点已关闭或鉴权
- [ ] 数据库、Redis、管理台不暴露公网
- [ ] 云存储非公开、IAM 最小权限、安全组收敛
- [ ] 容器非 root、只读 FS、无特权
- [ ] 安全响应头齐全
- [ ] 有配置基线扫描与定期资产测绘

## 7. 参考资料

- OWASP: Security Misconfiguration
- OWASP ASVS 第 14 章 Configuration
- CIS Benchmarks
- CWE-16: Configuration
