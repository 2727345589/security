# 深度伪造与 AI 社工 (Deepfake & AI-Enhanced Social Engineering)

> 分类：AI 驱动社工 | 风险：高 | MITRE T1566 / T1656 | 攻击链：投递 / 欺骗

## 1. 攻击原理

生成式 AI 让「冒充真人」的成本趋近于零：

| 能力 | 门槛 | 用途 |
|---|---|---|
| 语音克隆 | 数秒样本 | 冒充 CEO/CFO 打电话指令转账 |
| 实时换脸 | 消费级 GPU | 视频会议冒充同事/领导 |
| 文本生成 | 零门槛 | 无语法错误的钓鱼邮件、多语言社工 |
| 视频合成 | 分钟级 | 伪造高管声明、KYC 绕过 |
| 图像生成 | 零门槛 | 伪造证件、工牌、发票、截图 |

攻击特点：

- **绕过「眼见为实」**：视频/语音不再能作为身份凭证
- **规模化 + 个性化**：结合 OSINT（`54-osint` 预留）批量定制
- **常与 BEC 结合**：冒充领导/供应商，直接下指令
- **实时性**：视频会议中实时换脸，要求当场转账

## 2. 攻击示例

### 2.1 语音克隆 + 紧急指令

```text
攻击者从公开演讲/短视频提取 10 秒语音 → 克隆音色
→ 打电话给财务：「我在开会，马上付这笔款，别走流程了」
→ 财务听到「老板声音」，绕过复核
```

### 2.2 视频会议换脸

```text
真实案例（Arup，2024）：财务员工参加「高管视频会议」，
屏幕上多位「同事」均为深度伪造，被骗转账 2500 万美元。
```

### 2.3 KYC / 身份验证绕过

```text
用换脸 + 合成语音通过远程开户活体检测
→ 注册虚假身份 → 洗钱/诈骗/薅羊毛
```

### 2.4 AI 钓鱼文案

```text
结合泄露数据（姓名、职位、项目、供应商）
生成高度定制邮件，语法完美、上下文准确
→ 传统「拼写错误」识别法失效
```

### 2.5 伪造证据

```text
生成伪造的合同扫描件、转账截图、聊天记录
→ 用于内部欺诈、纠纷、舆论攻击
```

## 3. 影响

- 高额资金损失（BEC 升级版）
- 身份验证体系失效（KYC、远程开户）
- 高管声誉与股价受影响
- 员工对「视频/语音」信任崩塌，流程成本上升
- 伪造证据引发法律与公关危机

## 4. 防御措施

### 4.1 流程（最有效）

1. **不依赖单一通道确认**：任何转账/改账户指令，必须用**已知号码回拨**或第二通道确认。
2. **双人复核 + 金额分级审批**：大额交易至少两人独立审批。
3. **约定暗号/口令**：高敏感场景使用预共享验证短语。
4. **冷静期**：大额变更延迟生效（如 24 小时），留出核实窗口。
5. **供应商验证**：银行账户变更必须通过合同预留联系人 + 回拨确认。
6. **权限与限额**：单人可操作金额设上限；异常时段/异地交易触发人工复核。

### 4.2 技术

7. **内容凭证（C2PA）**：对官方发布的音视频签名，验证来源与完整性。
8. **水印与来源标注**：AI 生成内容加不可见水印（辅助，非绝对）。
9. **检测工具**：深度伪造检测作为**辅助信号**，不作为唯一依据（存在漏报/对抗）。
10. **活体检测升级**：KYC 增加动作挑战、深度信息、设备指纹、行为分析，多因子组合。
11. **邮件认证**：SPF/DKIM/DMARC + 外部发件人标识（见 `41-phishing`）。
12. **通话/会议安全**：高敏会议使用带身份认证的平台，开启等候室与参会者校验。

### 4.3 人员

13. **培训**：明确「视频/语音也可能是假的」，强化「流程高于直觉」。
14. **演练**：定期做深度伪造 BEC 演练（语音 + 视频）。
15. **举报通道**：员工可快速上报可疑指令，不因「怕得罪领导」而沉默。

### 4.4 组织

16. **高管数字资产治理**：减少公开的高清音视频素材，降低克隆样本来源。
17. **公关预案**：发现伪造内容后的辟谣、取证、下架流程。
18. **法律与保险**：明确欺诈损失的责任与保险覆盖。

## 5. 配置与检测对比

```yaml
# ✅ 付款审批流程（策略即代码示意）
payment_policy:
  - amount_lt: 10000
    approvals: 1
  - amount_gte: 10000
    approvals: 2
    require_callback: true          # 回拨已知号码
    cool_down_hours: 24
  - bank_account_change: true
    approvals: 2
    require_contract_contact: true
    cool_down_hours: 48
```

```js
// ✅ 敏感指令必须二次通道确认（伪代码）
async function approveTransfer(req, transfer) {
  if (transfer.amount >= 10000 || transfer.isBankChange) {
    const ok = await verifyViaKnownChannel(transfer.requesterId);  // 回拨登记号码
    if (!ok) throw new Error('second-channel verification failed');
    await requireDualApproval(transfer, { exclude: transfer.requesterId });
  }
  await audit.log('transfer.approved', { transfer, approver: req.user.id });
}
```

```js
// ✅ C2PA 内容凭证校验（伪代码）
import { Reader } from 'c2pa-node';
const reader = await Reader.fromAsset('./ceo-statement.mp4');
const manifest = reader.getActiveManifest();
if (!manifest || manifest.signatureInfo?.issuer !== 'Company Media Team') {
  console.warn('unverified media provenance');
}
```

```yaml
# ✅ 检测：异常会议/转账组合
- alert: HighValueTransferAfterVideoCall
  expr: |
    increase(transfer_amount_total{amount_gt="10000"}[10m]) > 0
    and increase(video_conference_join_total[15m]) > 0
  labels: { severity: high }
```

```yaml
# ✅ 培训/演练指标
- metric: phishing_simulation_report_rate
  target: "> 60%"
- metric: deepfake_drill_detection_rate
  target: "> 80%"
```

## 6. 自查清单

- [ ] 大额转账/改账户必须回拨已知号码确认
- [ ] 双人复核与金额分级审批已落地
- [ ] 高敏场景有预共享暗号
- [ ] 银行账户变更走合同联系人 + 48h 冷静期
- [ ] 单人可操作金额有上限
- [ ] 官方音视频使用 C2PA 等内容凭证
- [ ] KYC 活体检测多因子，非单一视频
- [ ] 邮件 SPF/DKIM/DMARC 完整，外部邮件有标识
- [ ] 深度伪造识别培训与演练常态化
- [ ] 有可疑指令快速上报通道
- [ ] 伪造内容公关与下架预案
- [ ] 高管公开音视频素材已收敛

## 7. 参考资料

- MITRE ATT&CK T1566: Phishing（深度伪造常作为投递/欺骗手段）
- MITRE ATT&CK T1656: Impersonation
- FBI IC3: Business Email Compromise 与 Deepfake 诈骗预警
- C2PA / Content Authenticity Initiative
- NIST AI 100-4: Reducing Risks Posed by Synthetic Content
- 真实案例：Arup 深度伪造视频会议诈骗（2024）
- 关联本库：`41-phishing`、`42-account-takeover`、`51-insider-threat`
