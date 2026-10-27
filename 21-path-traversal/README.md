# 目录穿越 / 任意文件读取 (Path Traversal)

> 分类：文件系统 | 风险：高 | CWE-22 / CWE-73

## 1. 攻击原理

应用用用户输入拼接文件路径，攻击者通过 `../`（及其编码变体）跳出预期目录，读取或覆盖任意文件。

常见入口：文件下载、图片/附件预览、模板加载、日志查看、备份导出、静态资源代理、`include`/`require` 动态路径。

编码变体（过滤器常被绕过）：

```text
../  ..%2f  ..%252f  ..%5c  ..\/  ....//  %2e%2e%2f
..%c0%af（Unicode 超长编码，旧版 IIS）
绝对路径：/etc/passwd、C:\Windows\win.ini
空字节截断：../../etc/passwd%00.png（旧版 PHP）
```

## 2. 攻击示例

```js
// ❌
app.get('/download', (req, res) => {
  res.sendFile(path.join(UPLOAD_DIR, req.query.file));
});
```

请求：

```http
GET /download?file=../../../../etc/passwd
GET /download?file=..%2f..%2f..%2fetc%2fpasswd
```

读取应用配置与密钥：

```text
GET /download?file=../.env
GET /download?file=../config/database.yml
```

写入型（配合上传/日志）：覆盖 `.htaccess`、cron、SSH `authorized_keys` → 提权/RCE。

## 3. 影响

- 读取源码、配置、密钥、系统文件
- 结合写入可导致 RCE
- 数据泄露与合规事故

## 4. 防御措施

1. **不要用用户输入直接拼路径（首选）**：用**文件 ID → 存储路径映射**（数据库记录），接口只接受 ID/UUID。
2. **规范化后校验前缀**：
   ```js
   const base = path.resolve(UPLOAD_DIR);
   const target = path.resolve(base, userPath);
   if (!target.startsWith(base + path.sep)) return res.sendStatus(400);
   ```
3. **只取文件名**：`path.basename(input)`，剥离目录部分。
4. **严格白名单**：文件名匹配 `^[a-zA-Z0-9_-]{1,64}\.(png|jpg|pdf)$`。
5. **解码后再校验**：先 URL 解码（可多次）再检查，防编码绕过；拒绝含 `..`、`/`、`\`、`%00` 的输入。
6. **符号链接防护**：`realpath` 后再次校验前缀；存储目录禁止软链接。
7. **权限最小化**：进程以非 root 运行，使用只读挂载；敏感文件不可达（chroot / 容器隔离）。
8. **对象存储**：文件放 S3/OSS，通过**签名 URL** 访问，逻辑层不带路径拼接。

## 5. 代码对比

```js
// ❌ 拼接
res.sendFile(path.join(UPLOAD_DIR, req.query.file));

// ✅ 规范化 + 前缀校验
const path = require('path');
const BASE = path.resolve(process.env.UPLOAD_DIR);

function safeResolve(userInput) {
  if (typeof userInput !== 'string') return null;
  const decoded = decodeURIComponent(userInput);
  const target = path.resolve(BASE, decoded);
  const rel = path.relative(BASE, target);
  if (rel.startsWith('..') || path.isAbsolute(rel)) return null;
  return target;
}

app.get('/download/:id', async (req, res) => {
  const file = await File.findByPk(req.params.id);   // ✅ ID 映射
  if (!file || file.ownerId !== req.user.id) return res.sendStatus(404);
  res.sendFile(safeResolve(file.storedName));
});
```

```python
# ✅ Python
import os
BASE = os.path.realpath(UPLOAD_DIR)
target = os.path.realpath(os.path.join(BASE, name))
if os.path.commonpath([BASE, target]) != BASE:
    abort(400)
```

```java
// ✅ Java
Path base = Paths.get(UPLOAD_DIR).toRealPath();
Path target = base.resolve(name).normalize().toRealPath();
if (!target.startsWith(base)) throw new SecurityException("invalid path");
```

## 6. 自查清单

- [ ] 文件访问使用 ID 映射，不拼用户路径
- [ ] 所有路径经过 `resolve` + `realpath` + 前缀校验
- [ ] URL 解码后校验，拒绝 `..`、`/`、`\`、`%00`
- [ ] 文件名使用 `basename` 或白名单
- [ ] 存储目录禁软链接，进程非 root、敏感目录只读
- [ ] 对象存储使用签名 URL
- [ ] 有自动化测试覆盖编码变体

## 7. 参考资料

- OWASP: Path Traversal
- OWASP: File Path Traversal Cheat Sheet
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory
- PortSwigger: Path traversal
