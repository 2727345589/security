# LDAP / XPath 注入 (LDAP & XPath Injection)

> 分类：注入类 | 风险：中高 | CWE-90 / CWE-643

## 1. 攻击原理

### LDAP 注入
应用把用户输入拼进 LDAP 过滤器，攻击者可用 `*`、`)(`、`|`、`&` 等元字符改变过滤逻辑。典型发生在企业登录、通讯录搜索、AD 集成。

### XPath 注入
应用把输入拼进 XPath 查询，攻击者用 `' or '1'='1` 绕过认证，或用 `count()`、`substring()` 做盲注提取 XML 文档全部内容。

## 2. 攻击示例

### LDAP：认证绕过

```java
// 原始实现
String filter = "(&(uid=" + user + ")(userPassword=" + pass + "))";
```

输入 `user = *)(uid=*))(|(uid=*`、`pass = anything`，过滤器被改写为恒真条件。

```text
(&(uid=*)(uid=*))(|(uid=*)(userPassword=anything))
```

### LDAP：信息枚举
`user = *` 返回全部条目；`user = a*` 逐字符探测。

### XPath：认证绕过

```java
String expr = "//user[name/text()='" + name + "' and password/text()='" + pass + "']";
```

输入 `name = ' or '1'='1`，表达式恒真。

### XPath：盲注

```text
' or substring(//user[1]/password,1,1)='a' and '1'='1
```

靠页面返回差异逐字符还原。

## 3. 影响

- 认证绕过，进入管理后台
- 泄露目录服务 / XML 中的全部敏感数据（含密码哈希、组织架构）
- 结合 AD 可进一步枚举域内账号，为横向移动铺路

## 4. 防御措施

1. **使用参数化 / 安全 API**
   - LDAP：`DirContext.search` 时用 `{0}` 占位 + `args`；或 JNDI `InitialDirContext` 的转义工具。
   - XPath：优先用 XPath 2.0 变量绑定（`$var`）；若无绑定能力，严格转义。
2. **转义特殊字符**（OWASP 建议的 LDAP 转义集）：

```java
// RFC 4515 转义
private static String escapeLDAP(String s) {
    StringBuilder sb = new StringBuilder();
    for (char c : s.toCharArray()) {
        switch (c) {
            case '\\': sb.append("\\5c"); break;
            case '*':  sb.append("\\2a"); break;
            case '(':  sb.append("\\28"); break;
            case ')':  sb.append("\\29"); break;
            case '\0': sb.append("\\00"); break;
            case '/':  sb.append("\\2f"); break;
            default:   sb.append(c);
        }
    }
    return sb.toString();
}
```

3. **白名单校验**：账号只允许 `^[a-zA-Z0-9._-]{1,64}$`。
4. **最小权限绑定账号**：查询账号仅有读权限，禁止匿名绑定。
5. **XPath 数据隔离**：不要把凭据存在 XML 中；用哈希 + 常量时间比较。
6. **错误收敛**：不回显解析异常与查询细节。

## 5. 代码对比

```java
// ❌ 拼接
String filter = "(&(uid=" + user + ")(userPassword=" + pass + "))";
ctx.search(base, filter, controls);

// ✅ 占位符 + 转义
String filter = "(&(uid={0})(userPassword={1}))";
ctx.search(base, filter, new Object[]{ escapeLDAP(user), escapeLDAP(pass) }, controls);
```

```java
// ✅ XPath 变量绑定（XPath 2.0）
XPathExpression expr = xpath.compile("//user[name/text()=$n and password/text()=$p]");
expr.setContext(ctx);
```

```python
# ✅ Python ldap3 转义
from ldap3.utils.conv import escape_filter_chars
flt = f"(&(uid={escape_filter_chars(user)})(objectClass=person))"
```

## 6. 自查清单

- [ ] 所有 LDAP 过滤器使用占位符或 `escape_filter_chars`
- [ ] 所有 XPath 使用变量绑定或严格转义
- [ ] 账号类输入有白名单正则
- [ ] LDAP 绑定账号最小权限，禁用匿名
- [ ] 认证失败响应无差异（防枚举）
- [ ] 凭据不存放在可被 XPath 遍历的 XML 中

## 7. 参考资料

- OWASP: LDAP Injection Prevention Cheat Sheet
- OWASP: XPath Injection
- CWE-90 / CWE-643
- RFC 4515: LDAP String Representation of Search Filters
