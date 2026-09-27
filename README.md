# 本地软件依赖扫描与策略阻断（Spring Boot）

在发布前对**本地依赖清单/锁定文件**做统一归一、策略判定、阻断与审计留痕的服务。
**仅使用本地能力**：不访问任何外部漏洞库/网络服务，不需要真实凭据；JSON 解析为内置手写实现，
风险情报来自策略文件内的本地数据。

## 1. 能力范围

| 能力 | 说明 |
| --- | --- |
| 清单读取与归一 | 支持两种 JSON 形态：依赖清单（`dependencies`/`packages`）与锁定信息（`locked`/`packages`/`dependencies`）；支持生态 `maven` / `npm` / `pip` |
| 显式解析失败 | 格式异常、必填字段缺失、版本不完整、重复条目、不支持的生态——**全部显式失败并返回带定位的、彼此可区分的原因码**，绝不静默跳过 |
| 可配置策略 | 严重级别阈值、允许/拒绝名单、带到期时间与作用域的例外、生效作用域（scope） |
| 确定可解释决策 | 固定优先级 + 规则按 id 排序；同一输入在同一策略版本下重复执行结论一致 |
| 阻断 | 未通过策略的依赖阻止发布，HTTP 403，并给出每个依赖的明确原因 |
| 有条件放行（WARN） | 记录操作者、策略版本、决策依据与依赖指纹（SHA-256），可按批次/指纹追溯 |
| 幂等与并发 | 以幂等键去重；并发扫描/同批次重复提交不会重复放行、互相覆盖或漏审计 |
| 日志安全 | 日志只含指纹、命中策略、最终判定等安全字段；密码/token/URL 内嵌账密自动脱敏 |

不在范围内：不联网拉取漏洞数据、不做真正的制品仓库上传拦截（由调用方在发布流水线中依据
HTTP 状态码决定是否阻断）、审计存储为进程内存（重启清空，适合本地/CI 复现）。

## 2. 清单格式

```json
{
  "ecosystem": "maven",
  "dependencies": [
    {"group": "com.acme", "name": "lib", "version": "1.2.3", "scope": "compile"}
  ]
}
```

- `ecosystem`：`maven` / `npm` / `pip`（必填）。maven 条目必须有 `group`。
- `name`、`version`：必填。`version` 必须是完整版本；`LATEST`、`RELEASE`、`1.*`、
  `${...}`、`+`、空串均判为 `VERSION_INCOMPLETE`。
- `scope`：可空，归一默认值 `compile`。同坐标但 scope 不同不算重复。
- 锁文件顶层数组键可用 `locked`（见 `samples/lock-example.json`）。

解析失败原因码（HTTP 422，`issues[].reason`）：

| reason | 含义 |
| --- | --- |
| `FORMAT_ERROR` | JSON 语法/结构错误（带行列号），或依赖数组/条目类型错误 |
| `MISSING_FIELD` | 缺少 `ecosystem`、依赖数组、`name`、maven 的 `group` 等必填字段 |
| `VERSION_INCOMPLETE` | 版本缺失、为空或是动态/占位版本 |
| `DUPLICATE_ENTRY` | 同生态+group+name+version+scope 的重复条目 |
| `UNSUPPORTED_ECOSYSTEM` | 生态标识无法识别 |

一次解析会返回**全部**问题（含 `location` 与 `detail`），不是遇到第一个就中断。

## 3. 策略模型与优先级

策略文件见 `src/main/resources/default-policy.json`（内置默认）与
`samples/policy-example.json`。可通过启动参数 `--policy.file=/path/to/policy.json` 覆盖。
策略加载时做严格校验（未知动作/枚举、错误日期、非法 JSON 直接快速失败）。

字段：`policyVersion`、`maxSeverity`（阻断阈值）、`enforcedScopes`（生效作用域）、
`rules`（允许/拒绝名单）、`advisories`（本地风险情报，赋予严重级别）、
`exceptions`（例外：到期日 + 作用域 + 申请人 + 理由）。

**判定优先级（从高到低，固定不变）：**

1. **生效范围**：依赖 scope 不在 `enforcedScopes` 内 → `OUT_OF_SCOPE`，跳过风险判定，不产生风险审计。
2. **拒绝名单（DENY 规则）**：命中即 `DENY`，硬性阻断，**优先级高于一切豁免**。
3. **策略冲突**：同一依赖同时命中 DENY 与 ALLOW 规则 → 仍 `DENY`，原因码 `RULE_CONFLICT`，
   冲突双方规则 id 全部留痕，依据写明“安全优先”。这是确定且可解释的冲突处理。
4. **有效例外**：坐标/版本/作用域匹配且未到期的例外 → `WARN`（有条件放行，必须审计）。
   例外到期日**当天仍有效**，次日起失效。
5. **严重级别阈值**：命中情报且级别 ≥ `maxSeverity` → `DENY`（`SEVERITY_THRESHOLD`）；
   低于阈值 → `WARN`（`SEVERITY_BELOW_THRESHOLD`）。
6. **允许名单**：仅命中 ALLOW 且无情报 → `PASS`（原因码 `ALLOW_RULE`）。
7. 其余干净依赖 → `PASS`（原因码 `CLEAN`）。

边界情况的确定结论：

- **过期例外**：不再豁免；按底层规则/阈值判定，原因码带 `EXCEPTION_EXPIRED`，过期例外 id 仍留痕。
- **作用域不匹配的例外**：对该依赖无效，回落到阈值判定（不因其存在而放行）。
- 多条情报命中取**最高严重级别**；多个有效例外取**到期日最晚**者；规则/例外均按 id 排序，
  保证选择确定、结论可复现。

## 4. 判定结果含义

| decision | 含义 | 是否阻断发布 | 是否写审计 |
| --- | --- | --- | --- |
| `PASS` | 通过（干净或显式允许名单） | 否 | 否（仅汇总日志） |
| `WARN` | 有条件放行：低于阈值的风险，或持有效例外 | 否，但状态为 `PASSED_WITH_WARNINGS` | 是 |
| `DENY` | 阻断：拒绝名单/规则冲突/达到严重级别阈值（过期例外不豁免） | 是（HTTP 403） | 是 |
| `OUT_OF_SCOPE` | 不在策略生效作用域（如 test），不参与风险判定 | 否 | 否 |

每条判定包含：`coordinate`、`fingerprint`（生态|group|name|version|scope 的 SHA-256）、
`decision`、`severity`、`reasonCode`、人读 `reason`、`matchedRuleIds`、
`matchedAdvisoryId`、`matchedExceptionId`、`policyVersion`。

审计记录包含：审计 id（批次+依赖指纹+策略版本推导，天然幂等）、判定时间、批次、操作者、
策略版本、依赖指纹、坐标、严重级别、结论、原因码与决策依据。

## 5. HTTP 接口

- `POST /api/scans`
  - 请求：`{"manifestType":"manifest|lock","contents":"<清单原文>","operator":"...","batchId":"...","idempotencyKey":"..."}`
  - `idempotencyKey` 可空：缺省由 内容指纹+批次+操作者 推导。
  - `200`：全部通过（可能含 WARN）；`403`：存在 DENY；`422`：清单解析失败；`400`：请求非法。
- `GET /api/audits`：全部 WARN/DENY 审计。
- `GET /api/audits/batches/{batchId}`：按批次查询。

## 6. 本地复现与验证

前置：JDK 21+、Maven 3.9+（无需联网下载任何数据；首次构建由 Maven 拉取 Spring 依赖，
运行期不访问网络）。

```bash
# 1) 全量测试（69 个用例，纯本地、无外部服务、无真实凭据）
mvn test

# 2) 打包并启动（random.port 已在 application.properties 中关闭，这里显式指定）
mvn package
java -jar target/spring-dependency-policy-audit-java-1.0-SNAPSHOT.jar --server.port=8080
# 如需自定义策略：
#   --policy.file=$PWD/samples/policy-example.json

# 3) 提交一个干净清单 => 200 PASSED
curl -s -X POST http://127.0.0.1:8080/api/scans \
  -H 'Content-Type: application/json' \
  -d @<(python3 - <<'PY'
import json
print(json.dumps({
  "manifestType": "manifest",
  "contents": open("samples/manifest-example.json").read(),
  "operator": "local-dev", "batchId": "demo", "idempotencyKey": "demo-1"}))
PY
)

# 4) 畸形清单 => 422，返回彼此可区分的 reason/location/detail
# 5) 重复 POST 同一个 idempotencyKey => 返回同一结论，审计不增加
# 6) 查看审计
curl -s http://127.0.0.1:8080/api/audits/batches/demo
```

也可以直接在 IDE 中运行各测试类：

- `ManifestParserTest`：畸形清单、缺字段、版本不完整、重复条目；
- `PolicyEngineTest`：阈值、允许/拒绝名单、策略冲突（安全优先）、过期例外、作用域不匹配、同输入可重复；
- `DefaultScanServiceTest`：阻断/告警/范围外、幂等、24 线程并发去重、审计字段完整性；
- `AuditStoreTest`：并发重复写入只保留一条且结论不被覆盖；
- `SafeLogTest`：密码/token/Bearer/URL 账密脱敏；
- `ScanControllerIntegrationTest`：200/403/422/400 与重复提交的端到端 HTTP 行为。

## 7. 关键设计说明

- **确定性**：依赖解析后按坐标排序；规则/情报/例外按 id 与严重级别做有序选择；判定引擎是
  注入 `Clock` 的纯函数，测试中使用固定时钟（2026-09-28）。
- **并发**：幂等键 → `ConcurrentHashMap` 锁分段串行化首次计算，结果缓存后复用；
  审计存储为 `CopyOnWriteArrayList` 且按审计 id 幂等追加。
- **日志安全**：原始清单内容永不落日志，只记录其 SHA-256 指纹；所有字符串字段经脱敏处理。
