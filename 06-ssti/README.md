# 服务端模板注入 SSTI (Server-Side Template Injection)

> 分类：注入类 | 风险：严重 | CWE-1336 | CWE-94

## 1. 攻击原理

应用把用户输入当作**模板内容**（而非模板变量）交给模板引擎编译执行。模板引擎通常能访问对象属性、调用方法，攻击者可沿对象链爬到 `os`/`process`/`Runtime`，最终实现远程代码执行。

易受影响的引擎：Jinja2（Python）、Twig（PHP）、Freemarker/Velocity（Java）、ERB（Ruby）、Handlebars/EJS/Pug（Node，部分场景）。

## 2. 攻击示例

```python
# ❌ 危险：把用户输入当模板
from jinja2 import Template
Template("Hello " + name).render()
```

输入 `{{7*7}}` → 返回 `Hello 49`，确认存在注入。进一步：

```jinja2
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ ''.__class__.__mro__[1].__subclasses__() }}
```

Node / EJS：

```js
// ❌
ejs.render(req.body.tpl, {});
// 输入 <%= process.mainModule.require('child_process').execSync('id') %>
```

Java Freemarker：

```text
<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
```

## 3. 影响

- 远程代码执行 → 服务器完全失守
- 读取环境变量、密钥、配置文件
- 内网探测与横向移动

## 4. 防御措施

1. **模板与数据分离**：用户输入只能作为**变量值**传入，绝不能被当作模板源码编译。
   - 正确做法：模板文件固定，`render({ name: userInput })`。
2. **无逻辑模板**：优先使用逻辑无关（logic-less）的模板引擎（Mustache），减少可调用面。
3. **沙箱化**：必须支持用户自定义模板时（如邮件模板、报表），使用受限沙箱（如 Jinja2 `SandboxedEnvironment`、Handlebars 白名单 helper），禁用危险全局对象。
4. **白名单语法**：自定义 DSL 时只解析允许的标签，不进入通用表达式求值。
5. **进程隔离**：模板渲染放在独立、无网、只读的 worker 中，限制 CPU/内存/时间。
6. **输入校验**：拒绝含 `{{`、`{%`、`${`、`<#` 等模板定界符的输入（仅作辅助）。
7. **最小权限**：渲染进程不挂载密钥，环境变量做隔离。

## 5. 代码对比

```python
# ❌ 模板来自用户输入
from jinja2 import Template
html = Template(user_tpl).render(data)

# ✅ 模板固定，数据作为变量
from jinja2 import Environment, FileSystemLoader, select_autoescape
env = Environment(loader=FileSystemLoader('templates'), autoescape=select_autoescape())
html = env.get_template('mail.html').render(name=user_name)

# ✅ 必须支持用户模板时使用沙箱
from jinja2.sandbox import SandboxedEnvironment
env = SandboxedEnvironment(autoescape=True)
```

```js
// ❌
res.send(ejs.render(req.body.template, locals));
// ✅
res.render('fixed-view', locals);
```

## 6. 自查清单

- [ ] 无任何 `render(userInput)` / `Template(userInput)` / `compile(userInput)` 调用
- [ ] 模板文件全部来自代码仓库，不可由用户上传覆盖
- [ ] 用户可自定义模板的场景使用沙箱环境
- [ ] 沙箱内无 `os`、`process`、`Runtime`、反射类可达
- [ ] 渲染服务独立部署，无密钥、无内网访问
- [ ] 模板定界符输入作为辅助拦截并记录告警

## 7. 参考资料

- PortSwigger: Server-side template injection
- OWASP: Server-Side Template Injection
- CWE-1336 / CWE-94
- Jinja2 SandboxedEnvironment 文档
