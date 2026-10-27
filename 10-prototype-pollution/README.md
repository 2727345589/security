# 原型污染 (Prototype Pollution)

> 分类：客户端/服务端注入 | 风险：高 | CWE-1321

## 1. 攻击原理

JavaScript 中所有对象共享 `Object.prototype`。若应用对用户输入做**递归合并、深拷贝、路径赋值**时未过滤 `__proto__`、`constructor`、`prototype` 键，攻击者就能修改原型，向所有对象注入属性。

后果从「逻辑绕过」到「远程代码执行」不等：

- 服务端：污染 `Object.prototype`，影响后续所有请求（Node 进程级），可导致鉴权绕过、RCE（借助 `child_process` 选项注入、模板引擎 gadget）。
- 客户端：污染后触发 DOM XSS（如污染 `innerHTML` 相关配置、`srcdoc`）。

高危函数：`lodash.merge`（旧版本）、`jQuery.extend(true, ...)`、`Object.assign` 的递归写法、自研 `deepMerge`、`set(obj, path, value)`、`JSON.parse` 后的递归赋值。

## 2. 攻击示例

```js
// ❌ 自研深合并
function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object') {
      target[key] = merge(target[key] ?? {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
merge({}, JSON.parse(req.body.config));
```

请求体：

```json
{ "__proto__": { "isAdmin": true } }
```

之后任何 `({}).isAdmin === true`，鉴权判断 `if (user.isAdmin)` 直接通过。

客户端：

```js
// URL: ?__proto__[src]=data:,alert(1)
const params = new URLSearchParams(location.search);
merge({}, Object.fromEntries(params));  // 污染后某些库读取 proto 属性
```

RCE 链（Node）：

```json
{ "__proto__": { "shell": "/bin/sh", "argv0": "x", "env": { "EVIL": "1" } } }
```

污染后调用 `child_process.spawn` 的选项对象可被劫持（视版本与调用方式）。

## 3. 影响

- 鉴权绕过（`isAdmin` / `role` 被注入）
- DoS（覆盖 `toString` 等方法导致崩溃）
- 客户端 DOM XSS
- 特定条件下服务端 RCE

## 4. 防御措施

1. **禁止危险键**：合并/赋值前过滤 `__proto__`、`constructor`、`prototype`（递归到每一层）。
2. **使用安全 API**：
   - 用 `Object.create(null)` 作为容器（无原型链）
   - 用 `Map` / `Set` 存用户键值
   - 用 `Object.hasOwn(obj, key)` 判断
   - 用 `structuredClone` 或经过审计的库（lodash ≥ 4.17.21、`deepmerge` 最新版）
3. **schema 校验 + 白名单字段**：不接收任意键的配置对象，只允许显式字段。
4. **冻结关键原型**：启动时 `Object.freeze(Object.prototype)`（Node 可行，注意兼容性）。
5. **`--disable-proto=throw`**：Node 启动参数直接让 `__proto__` 访问抛错。
6. **客户端防御**：`Object.freeze(Object.prototype)`、CSP、Trusted Types；升级依赖。
7. **代码扫描**：SAST 规则检测递归 merge 与动态路径赋值。

## 5. 代码对比

```js
// ✅ 安全深合并
const BLOCKED = new Set(['__proto__', 'constructor', 'prototype']);

function safeMerge(target, source) {
  if (source === null || typeof source !== 'object') return target;
  for (const key of Object.keys(source)) {
    if (BLOCKED.has(key)) continue;
    const val = source[key];
    if (val && typeof val === 'object' && !Array.isArray(val)) {
      const base = Object.hasOwn(target, key) && target[key] && typeof target[key] === 'object'
        ? target[key] : Object.create(null);
      target[key] = safeMerge(base, val);
    } else if (Array.isArray(val)) {
      target[key] = val.map((v) => (v && typeof v === 'object' ? safeMerge(Object.create(null), v) : v));
    } else {
      target[key] = val;
    }
  }
  return target;
}
```

```js
// ✅ 安全路径赋值
function setSafe(obj, path, value) {
  const parts = path.split('.');
  if (parts.some((p) => BLOCKED.has(p))) return obj;
  let cur = obj;
  for (const p of parts.slice(0, -1)) {
    if (!Object.hasOwn(cur, p) || typeof cur[p] !== 'object') cur[p] = Object.create(null);
    cur = cur[p];
  }
  cur[parts.at(-1)] = value;
  return obj;
}
```

```bash
# ✅ Node 启动参数
node --disable-proto=throw app.js
```

## 6. 自查清单

- [ ] 全仓库搜索 `merge(`、`extend(true`、`deepClone`、`set(obj, path`
- [ ] 所有递归合并过滤 `__proto__` / `constructor` / `prototype`
- [ ] 依赖版本已升级（lodash ≥ 4.17.21）
- [ ] Node 启用 `--disable-proto=throw` 或冻结 `Object.prototype`
- [ ] 接收配置对象时使用 schema 白名单
- [ ] 客户端同样校验 URL 参数合并逻辑

## 7. 参考资料

- OWASP: Prototype Pollution
- CWE-1321: Improperly Controlled Modification of Object Prototype Attributes
- PortSwigger: Prototype pollution
