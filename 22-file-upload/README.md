# 恶意文件上传 (Unrestricted File Upload)

> 分类：文件系统 | 风险：严重 | CWE-434

## 1. 攻击原理

上传接口未充分校验文件类型/内容/存储方式，攻击者可上传：

- **Web Shell**（`.php`、`.jsp`、`.aspx`、`.phtml`、`.phar`）→ 直接 RCE
- **SVG / HTML**（含脚本）→ 存储型 XSS
- **超大文件 / 压缩炸弹** → DoS
- **双扩展名 / 解析漏洞**：`shell.php.jpg`、`shell.asp;.jpg`、`.htaccess` 覆盖
- **图片马**：合法图片 + 尾部 PHP 代码，配合解析漏洞或 LFI 执行
- **XML（docx/svg）**→ XXE
- 覆盖已有文件/路径穿越写入

## 2. 攻击示例

```php
// ❌ 只校验前端
if (in_array($_FILES['f']['type'], ['image/jpeg'])) move_uploaded_file($_FILES['f']['tmp_name'], "uploads/{$_FILES['f']['name']}");
```

`Content-Type` 由客户端伪造，攻击者上传 `shell.php` 并设置 `image/jpeg`：

```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=x

--x
Content-Disposition: form-data; name="f"; filename="shell.php"
Content-Type: image/jpeg

<?php system($_GET['c']); ?>
--x--
```

访问 `https://site.com/uploads/shell.php?c=id` → RCE。

其他技巧：

- `filename="shell.php%00.jpg"`（空字节，旧版）
- `filename=".htaccess"` 写入 `AddType application/x-httpd-php .jpg`
- 上传 SVG 含 `<script>` 造成 XSS
- 上传 zip 解压穿越（zip-slip）写出任意路径

## 3. 影响

- 远程代码执行，服务器失守
- 存储型 XSS、钓鱼页面托管
- 磁盘/带宽耗尽、数据泄露
- 作为恶意文件分发点

## 4. 防御措施

1. **扩展名白名单**（非黑名单）：只用允许的扩展名，大小写不敏感。
2. **MIME + 魔术字节双校验**：读取文件头判断真实类型（`file-type` 库 / `magic`），并与扩展名一致。
3. **重命名存储**：UUID + 正确扩展名，**不保留原始文件名**，原始名仅存数据库展示。
4. **存储与 Web 根分离**：上传目录不可执行（Nginx 关闭 PHP handler、对象存储独立域名 + `Content-Disposition: attachment`）。
5. **图片重编码**：用 sharp / ImageMagick 重新生成，剥离元数据与内嵌脚本，从根本上消除图片马。
6. **SVG 净化**：`DOMPurify` 或转 PNG；禁止直接内联渲染。
7. **限制大小、数量、频率**：单文件大小、总配额、每用户速率。
8. **安全的解压**：校验条目路径（防 zip-slip）、限制解压后总大小与文件数（防 zip 炸弹）。
9. **权限与隔离**：上传目录只写不执行，进程最小权限，病毒扫描（ClamAV）。
10. **下载安全**：`Content-Type: application/octet-stream` + `Content-Disposition: attachment` + `X-Content-Type-Options: nosniff`。

## 5. 代码对比

```js
// ✅ Node（multer + file-type + sharp）
import multer from 'multer';
import { fileTypeFromBuffer } from 'file-type';
import sharp from 'sharp';
import { randomUUID } from 'crypto';

const ALLOWED = new Map([
  ['image/jpeg', 'jpg'],
  ['image/png', 'png'],
  ['image/webp', 'webp'],
]);

const upload = multer({
  limits: { fileSize: 5 * 1024 * 1024, files: 1 },
  storage: multer.memoryStorage(),
});

app.post('/upload', auth, upload.single('file'), async (req, res) => {
  const type = await fileTypeFromBuffer(req.file.buffer);
  if (!type || !ALLOWED.has(type.mime)) return res.status(400).json({ error: 'unsupported' });

  const name = `${randomUUID()}.${ALLOWED.get(type.mime)}`;
  const out = await sharp(req.file.buffer).rotate().resize({ width: 2000, withoutEnlargement: true }).toBuffer();

  await storage.put(`private/${name}`, out, { contentType: type.mime });
  await File.create({ ownerId: req.user.id, storedName: name });
  res.json({ id: name });
});
```

```nginx
# ✅ 上传目录禁止执行
location /uploads/ {
    location ~ \.(php|jsp|asp|aspx|pl|py|sh)$ { deny all; }
    add_header Content-Disposition "attachment";
    add_header X-Content-Type-Options "nosniff";
}
```

## 6. 自查清单

- [ ] 扩展名白名单 + MIME + 魔术字节三重校验
- [ ] 文件重命名为 UUID，原始名不入路径
- [ ] 上传目录不可执行，与 Web 根分离
- [ ] 图片重编码，SVG 净化或禁用
- [ ] 大小/数量/频率限制，病毒扫描
- [ ] 解压做路径与大小校验（防 zip-slip / 炸弹）
- [ ] 下载强制 `attachment` + `nosniff`
- [ ] 存储使用私有对象存储 + 签名 URL

## 7. 参考资料

- OWASP: File Upload Cheat Sheet
- CWE-434: Unrestricted Upload of File with Dangerous Type
- PortSwigger: File upload vulnerabilities
