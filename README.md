# 本地软件依赖扫描与策略阻断（spring-dependency-policy-audit-java）

发布前对依赖清单进行**本地归一 → 策略判定 → 阻断/审计**的 Spring Boot 服务。
不依赖任何外部服务、网络或真实凭据：清单只读本地文件，策略来自本地 JSON / classpath，
审计追加写本地文件，所有时间与输入在策略不变时产生**确定且可复现**的结论。

## 1. 支持范围

### 1.1 输入格式（两种，均为本地）

| manifestType | 格式 | 说明 |
|---|---|---|
| `manifest-json` | JSON 对象，`dependencies` 为数组，元素含 `group`/`name`/`version`/`scope` | 依赖清单 |
| `lock-file` | 行式文本，每行 `group:name:version:scope`，`#` 注释、空行忽略 | 锁定信息 |

- `scope` 取值：`COMPILE` / `RUNTIME` / `TEST` / `PROVIDED`；
  清单中缺省或无法识别时归一为 `UNKNOWN`（作用域匹配时不会误命中限定作用域的规则/例外）。
- 版本必须是**完整钉死**的 `MAJOR.MINOR.PATCH`（允许预发布/构建后缀，如 `1.2.3-rc1`）。
  `LATEST`/`RELEASE`/区间 `[1.0,2.0)`/缺段（`1.2`）一律判为版本不完整。
- 任何问题条目都不会被静默跳过，全部进入 `parseIssues`，并导致整体 `blocked=true`。

### 1.2 可区分的失败原因（`FailureReason`）

| 原因 | 触发场景 |
|---|---|
| `FORMAT_MALFORMED` | JSON 无法解析、根结构错误、条目不是对象、lock 行列数错、未知 scope |
| `UNSUPPORTED_FORMAT` | manifestType 为空或无解析器支持 |
| `FIELD_MISSING` | group/name 缺失或空白 |
| `VERSION_INCOMPLETE` | 版本缺失、动态版本、版本段不足三段或非数字 |
| `DUPLICATE_ENTRY` | 同一坐标重复且版本一致 |
| `VERSION_CONFLICT` | 同一坐标出现不一致版本 |
| `SCOPE_MISMATCH` | 唯一名单/例外因作用域不匹配而不适用 |
| `EXCEPTION_EXPIRED` | 匹配的例外已过期 |
| `POLICY_CONFLICT` | 同时命中 ALLOW 与 DENY（按 DENY 优先解决，依据中显式记录冲突双方） |
| `SEVERITY_THRESHOLD_EXCEEDED` | 本地咨询严重级别达到/超过阈值且无有效例外 |
| `DENIED_BY_RULE` | 命中 DENY 名单（且无 ALLOW 冲突） |
| `NO_APPLICABLE_POLICY` | 无任何规则/例外命中，落到默认 DENY |
| `IO_ERROR` | 本地文件不存在/不可读 |

## 2. 策略模型

策略为本地 JSON 文件（配置 `depaudit.policy.file`，留空则使用内置
`src/main/resources/default-policy.json`）。加载时严格校验：缺少
`policyVersion`、未知枚举、重复规则（同动作+名称+版本）、重复/残缺例外等都会快速失败。

```json
{
  "policyVersion": "demo-policy-v1",
  "defaultVerdict": "DENY",
  "severityThreshold": "HIGH",
  "rules": [
    {"action":"DENY","name":"com.knownbad:malware-lib","versionPattern":"*",
     "scopes":[],"reasonText":"known malicious package"},
    {"action":"ALLOW","name":"org.example:safe-*","versionPattern":"*","scopes":["COMPILE"]}
  ],
  "exceptions": [
    {"id":"EXC-1","name":"org.example:risky-cache","versionPattern":"2.3.*",
     "scopes":["RUNTIME"],"expiresAt":"2030-01-01T00:00:00Z",
     "approver":"release-manager@local","justification":"migration accepted"}
  ],
  "advisorySeverity": {"org.example:risky-cache":"CRITICAL"}
}
```

- `rules[].scopes` / `exceptions[].scopes` 为空数组表示**全作用域**。
- `name` 支持尾随 `*` 前缀通配（`org.example:safe-*`、`org.example:*`）；
  `versionPattern` 支持尾随 `*`（`2.3.*`），其余精确匹配。
- `advisorySeverity` 是**本地**咨询数据（坐标 → NONE/LOW/MODERATE/HIGH/CRITICAL），
  不联网查询。

### 2.1 判定优先级与冲突处理（从高到低，确定性）

1. **DENY 名单（安全优先，最高）**：命中即 `DENY`。
   同时命中 ALLOW 与 DENY 时 **DENY 胜出**，`failureReason=POLICY_CONFLICT`，
   `basis` 中记录两条规则的描述与 DENY 原因，结论可解释。
2. **生效中的例外**：未过期 **且** 作用域匹配的例外按 id 字典序取最小者，
   结论为 `CONDITIONAL_PASS`，可覆盖超阈值或默认 DENY。
3. **严重级别阈值**：咨询级别 ≥ 阈值且无有效例外 → `DENY`。
   - 唯一可救济的例外已过期 → `EXCEPTION_EXPIRED`；
   - 唯一可救济的例外作用域不符 → `SCOPE_MISMATCH`；
   - 否则 → `SEVERITY_THRESHOLD_EXCEEDED`。
4. **ALLOW 名单**：命中 → `PASS`。
5. **默认判定** `defaultVerdict`：为 DENY 时按过期/作用域/无策略分别给出
   `EXCEPTION_EXPIRED` / `SCOPE_MISMATCH` / `NO_APPLICABLE_POLICY`。

过期例外与作用域不匹配不会被静默忽略：即使不影响最终结论，也会写入 `basis` 的
`notes` 段（如 `exception EXC-1002 EXPIRED at ...`）。

### 2.2 确定性保证

判定只依赖 `(policy, dependency, clock)`；规则按声明顺序选取、例外按 id 排序选取。
策略在进程启动时加载一次并缓存。**同一输入 + 同一策略版本，重复执行结论一致**
（有测试用固定时钟连续判定 10 次做全字段比对）。

### 2.3 例外管理

- 每个例外必须有唯一 `id`、`approver`（操作者/批准人）、`expiresAt`（UTC Instant）。
- 到期后自动失效：不会放行，并在依据中标记过期。
- 作用域不符不生效：例如仅批准 `TEST` 的例外不能放行 `COMPILE` 依赖。
- 例外只产生 `CONDITIONAL_PASS`，审计中可追溯批准人、到期时间、理由与策略版本。

## 3. 判定结果含义（`Verdict`）

| 判定 | 含义 | 是否阻断发布 |
|---|---|---|
| `PASS` | 显式 ALLOW 或默认 PASS，无任何命中问题 | 否 |
| `CONDITIONAL_PASS` | 命中生效例外的有条件放行；已记录操作者、策略版本、依据、依赖指纹 | 否，但强制留审计 |
| `DENY` | 命中 DENY / 阈值超标 / 默认 DENY 等 | **是**（HTTP 403） |

扫描整体 `blocked = 存在任意 parseIssues 或 任意 DENY`。
解析阶段失败的条目不进入策略判定，但同样在响应中逐条给出原因。

## 4. 阻断、审计与并发语义

### 4.1 HTTP 入口

`POST /api/dependency-scans`，请求二选一：
- 内联：`{"manifestType":"manifest-json","sourceName":"m.json",
  "rawContent":"...","operator":"alice"}`
- 本地路径：`{"manifestType":"lock-file","manifestPath":"/abs/path.lock",
  "operator":"alice"}`（含 `://` 的路径一律拒绝，只允许本地文件）

响应：`200` 通过；`403` 阻断（响应体仍含每条可区分原因）；
`400` 请求错误；`415` 不支持的格式；`422` 本地 IO 错误；`500` 策略配置错误。

### 4.2 指纹与幂等

- 依赖指纹：`SHA256(格式 | group:name | version | scope)`；
  请求指纹：`SHA256(manifestType | sourceName | 原始清单文本)`；
  审计幂等键：`请求指纹:依赖指纹`。
- 同一批次内容重复提交（串行或并发）：
  - **不重复放行**：`AuditStore.putIfAbsent`（`ConcurrentHashMap` 原子抢占）保证每键只落一条；
  - **结论不覆盖**：存储 append-only，重复提交返回首次结论，响应标记 `duplicateSubmission=true`；
  - **审计不缺失**：审计写盘失败会回滚内存键，杜绝“已放行无审计”；
  - 写盘用 `FileLock` 串行化，启动时回放审计文件重建索引。
- 审计记录字段：幂等键、请求/依赖指纹、操作者、策略版本、判定、依据、失败原因、时间。

### 4.3 日志脱敏

`SafeLogger` 双层防护：字段白名单（未列入的键直接丢弃）+ 键名/值敏感词扫描
（`password/passwd/secret/token/credential/apikey/...` 命中即输出 `[REDACTED]`）。
每条判定日志都打印**输入指纹、命中的规则/例外、最终判定**，例如：

```
event=dependency-decision requestFingerprint=7461... matchedRule=ALLOW:org.example:safe-*:*
verdict=PASS failureReason= policyVersion=demo-policy-v1 name=org.example:safe-core ...
event=scan-summary blocked=false duplicateSubmission=false issueCount=0 decisionCount=1 ...
```

## 5. 本地配置

`application.properties`：

```properties
server.port=0
depaudit.audit.file=./target/depaudit-audit.log   # 本地追加审计文件
depaudit.policy.file=                             # 空=内置 default-policy.json
```

## 6. 本地复现与验证

要求：JDK 21+、Maven 3.9+（无需网络访问、无需任何凭据；首次构建由 Maven 解析依赖）。

```bash
# 1) 全量测试（37 个用例：畸形清单/版本冲突/过期例外/作用域/策略冲突/并发重复提交/脱敏/HTTP）
mvn clean test

# 2) 打包并以 demo 策略启动
mvn -DskipTests package
java -jar target/spring-dependency-policy-audit-java-1.0-SNAPSHOT.jar \
  --depaudit.policy.file=./demo/policies/policy-demo.json \
  --depaudit.audit.file=./target/smoke-audit.log
# 日志中查看实际端口（server.port=0 随机端口），然后：
curl -s --noproxy '*' -H 'Content-Type: application/json' -d '{
  "manifestType":"manifest-json","operator":"alice",
  "manifestPath":"'"$PWD"'/demo/manifests/good.json"
}' http://127.0.0.1:<端口>/api/dependency-scans

# 通过：demo/manifests/good.json（200 PASS）
# 条件放行：demo/manifests/exception.json（200 CONDITIONAL_PASS，依据含批准人与到期时间）
# 阻断：demo/manifests/blocked.lock（403，DENIED_BY_RULE + VERSION_INCOMPLETE 可区分）

# 3) 核对审计与脱敏
wc -l ./target/smoke-audit.log        # 每个唯一“请求:依赖”仅一条
grep -icE 'password|secret|token' ./target/smoke-audit.log   # 0
```

测试清单：

| 测试类 | 覆盖场景 |
|---|---|
| `ManifestParsingTest` | 畸形 JSON、字段缺失、动态/残缺版本、重复、版本冲突、lock 格式同类问题 |
| `PolicyEvaluationTest` | 阈值、ALLOW/DENY、冲突 DENY 优先、例外生效/过期/作用域、默认 DENY、确定性、策略加载校验 |
| `ScanConcurrencyTest` | 16 线程并发同批提交、串行重复提交、阻断、畸形清单、过期例外、重启回放 |
| `AuditStoreTest` | 原子去重、按请求查询、落盘格式、日志白名单与凭据脱敏 |
| `ScanControllerTest` | 200/403/400/415、拒绝远程路径、重复提交幂等标记 |

## 7. 代码结构

```
model/      枚举(FailureReason/Verdict/Severity/...) 与记录(NormalizedDependency/PolicySet/
            DependencyDecision/AuditRecord/ScanResult/ParseIssue...)
manifest/   LocalManifestReader、ManifestJsonParser、LockFileParser、ManifestFormatRegistry
policy/     LocalPolicyLoader、LocalPolicyProvider、PolicyEvaluator（确定性优先级链）
audit/      AuditStore、LocalFileAuditStore（去重+回放+FileLock）、SafeLogger（白名单脱敏）
scan/       Fingerprints(SHA-256)、ScanService（编排、幂等、审计、日志）
web/        ScanController、ApiExceptionHandler
config/     Clock Bean、AuditProperties、PolicyProperties
```
