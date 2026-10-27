# SQL 注入 (SQL Injection)

> 分类：注入类 | 风险：严重 | CWE-89 | OWASP A03:2021

## 1. 攻击原理

应用程序把不可信输入拼接进 SQL 语句，改变了原有语义：攻击者可以绕过认证、读取任意表、写入/删除数据，甚至在数据库权限过高时执行系统命令（如 MySQL `INTO OUTFILE`、SQL Server `xp_cmdshell`、PostgreSQL `COPY ... PROGRAM`）。

三种常见形态：

| 类型 | 说明 | 例子 |
|---|---|---|
| 字符型 | 闭合引号后追加逻辑 | `' OR '1'='1` |
| 数字型 | 直接拼接数字 | `1 OR 1=1` |
| 盲注 | 无回显，靠布尔/时间差推测 | `AND SLEEP(5)`、`AND SUBSTR(...)='a'` |

二次注入：恶意数据先入库，后续被拼进另一条 SQL 时才触发。

## 2. 攻击示例

登录接口原始实现：

```js
const sql = `SELECT * FROM users WHERE email = '${email}' AND password = '${password}'`;
```

输入 `email = admin@x.com' -- `，密码任意：

```sql
SELECT * FROM users WHERE email = 'admin@x.com' -- ' AND password = '...'
```

`--` 注释掉密码条件，直接以 admin 身份登录。

UNION 拖库：

```sql
' UNION SELECT username, password_hash, 1 FROM users -- 
```

## 3. 影响

- 认证绕过、全量数据泄露、数据被篡改或删除
- 结合数据库特性升级为命令执行 / 文件读写
- 合规风险（等保、GDPR、PCI-DSS）

## 4. 防御措施

1. **参数化查询（首选）**：SQL 结构预编译，数据永不参与解析。
2. **存储过程 / ORM 查询构建器**：同样必须绑定参数，警惕 `raw()`、`whereRaw()`、`execute()`。
3. **白名单校验**：排序字段、表名、列名这类不能参数化的位置，用枚举映射。
4. **最小数据库权限**：业务账号只授予 DML，禁用 `FILE`、`SUPER`、`xp_cmdshell`；应用与 DDL 账号分离。
5. **错误信息收敛**：不回显 SQL 报错与堆栈，避免盲注加速。
6. **纵深防御**：WAF 仅作补充，不能替代参数化；开启审计日志。

## 5. 代码对比

```js
// ❌ 拼接
const rows = await db.query(`SELECT * FROM users WHERE email = '${email}'`);

// ✅ 位置占位符
const rows = await db.query('SELECT * FROM users WHERE email = ?', [email]);

// ✅ 命名占位符
const rows = await db.query('SELECT * FROM users WHERE email = :email', { email });

// ✅ 动态排序白名单
const SORT = { created: 'created_at', name: 'name' };
const col = SORT[req.query.sort] ?? 'created_at';
await db.query(`SELECT * FROM users ORDER BY ${col} LIMIT ? OFFSET ?`, [limit, offset]);
```

```python
# ✅ Python / psycopg
cur.execute("SELECT * FROM users WHERE email = %s", (email,))
```

```java
// ✅ JDBC
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE email = ?");
ps.setString(1, email);
```

## 6. 自查清单

- [ ] 全仓库搜索字符串拼接 SQL（`+`、`${}`、`%`、`f"..."`、`.format(`）
- [ ] ORM 的 raw / native 查询全部走绑定参数
- [ ] 动态表名 / 列名 / 排序字段使用白名单映射
- [ ] 生产环境关闭 SQL 详细报错
- [ ] 数据库账号权限已最小化，无 FILE / SUPER / xp_cmdshell
- [ ] CI 中集成 SAST（Semgrep / CodeQL）SQL 注入规则

## 7. 参考资料

- OWASP: SQL Injection Prevention Cheat Sheet
- CWE-89: Improper Neutralization of Special Elements used in an SQL Command
- PortSwigger Web Security Academy: SQL Injection
