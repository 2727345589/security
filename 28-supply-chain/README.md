# 供应链 / 第三方依赖风险 (Supply Chain Security)

> 分类：供应链 | 风险：高 | CWE-1104 / CWE-829

## 1. 攻击原理

现代应用 70%–90% 的代码来自第三方。攻击面包括：

| 环节 | 攻击方式 |
|---|---|
| 依赖包 | 恶意包、抢注（typosquatting）、投毒（event-stream 式）、维护者账号被劫持 |
| 版本 | 依赖混淆（dependency confusion）、通配版本引入恶意更新 |
| CDN | 第三方脚本被篡改 → 全站 XSS / 挖矿 / 窃取表单 |
| 构建 | CI 密钥泄露、构建机被入侵、制品被替换 |
| 容器镜像 | 基础镜像含后门、过期漏洞 |
| 更新通道 | 自动更新被劫持 |

## 2. 攻击示例

### 依赖混淆

公司内部包 `@company/utils` 未在公共 npm 注册，攻击者抢注同名公开包 + 高版本号，构建时拉到恶意版本。

### 恶意 postinstall

```json
{
  "scripts": { "postinstall": "node ./scripts/collect.js" }
}
```

`collect.js` 读取 `~/.npmrc`、环境变量、SSH 密钥并外传。

### CDN 脚本篡改

```html
<!-- ❌ 无完整性校验 -->
<script src="https://cdn.example.com/lib.js"></script>
```

CDN 被入侵或域名过期被抢注 → 全站执行攻击者脚本。

### 事件流式攻击

合法包维护者被社工，发布含恶意代码的「正常更新」，下游自动升级中招。

## 3. 影响

- 远程代码执行、密钥与源码泄露
- 全站 XSS、数据窃取
- 构建产物被植入后门
- 合规与声誉风险

## 4. 防御措施

1. **锁定版本**：提交 lockfile（`package-lock.json` / `pnpm-lock.yaml` / `poetry.lock` / `go.sum`），CI 使用 `npm ci` 而非 `npm install`。
2. **SCA 扫描**：Dependabot / Renovate + `npm audit` / `osv-scanner` / Snyk / Trivy，阻断高危漏洞。
3. **私有源与作用域**：内部包使用私有 registry 与 `@scope`，配置 `registry` 映射，防依赖混淆。
4. **SRI（子资源完整性）**：
   ```html
   <script src="https://cdn.example.com/lib.js"
           integrity="sha384-..." crossorigin="anonymous"></script>
   ```
   并对第三方脚本设 CSP 白名单。
5. **减少第三方脚本**：能不引就不引；必须引时用 iframe 隔离或服务端代理。
6. **安装脚本管控**：`npm ci --ignore-scripts`（评估影响），pnpm 默认限制。
7. **新包审查**：检查下载量、维护者、发布时间、仓库、是否有混淆代码；设置依赖冷却期（新版本发布 N 天后再升级）。
8. **SBOM**：生成软件物料清单（CycloneDX / SPDX），便于漏洞响应。
9. **构建加固**：CI 最小权限、密钥短期化（OIDC）、制品签名（Sigstore/cosign）、可复现构建。
10. **镜像扫描与最小基础镜像**：distroless、定期重建。

## 5. 代码对比

```jsonc
// ✅ package.json：精确版本 + 私有作用域
{
  "dependencies": {
    "express": "4.21.2",
    "@company/auth": "1.4.0"
  },
  "overrides": {
    "minimist": "1.2.8"
  }
}
```

```yaml
# ✅ CI 中使用锁文件 + 审计 + 忽略脚本
- run: npm ci --ignore-scripts
- run: npx osv-scanner --lockfile=package-lock.json
- run: npx @cyclonedx/cyclonedx-npm --output-file sbom.json
```

```html
<!-- ✅ SRI -->
<script src="https://cdn.jsdelivr.net/npm/dompurify@3.1.6/dist/purify.min.js"
        integrity="sha384-<hash>"
        crossorigin="anonymous"></script>
```

```nginx
# ✅ CSP 限制脚本源
add_header Content-Security-Policy "script-src 'self' https://cdn.jsdelivr.net;" always;
```

## 6. 自查清单

- [ ] lockfile 已提交，CI 使用 `npm ci` 类命令
- [ ] SCA 扫描进 CI，高危漏洞阻断合并
- [ ] 内部包使用私有 registry 与作用域
- [ ] 第三方脚本有 SRI + CSP 白名单
- [ ] 安装脚本默认禁用或有审查
- [ ] 新依赖有审查流程与冷却期
- [ ] 已生成 SBOM，具备漏洞响应流程
- [ ] 容器镜像定期扫描与重建
- [ ] 构建密钥短期化，制品签名验证

## 7. 参考资料

- OWASP: Software Supply Chain Security Cheat Sheet
- CWE-1104: Use of Unmaintained Third Party Components
- CWE-829: Inclusion of Functionality from Untrusted Control Sphere
- SLSA / Sigstore / CycloneDX
