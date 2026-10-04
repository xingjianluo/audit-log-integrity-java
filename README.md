# 防篡改审计链路（Java / Spring Boot）

一条可本地验证的安全审计链路：事件顺序追加形成密码学完整性链，敏感字段落盘前按版本化策略
不可逆脱敏，支持按批次保留清理，并可向本地模拟接收端做幂等导出。在并发写入、策略变更、
存储异常与接收端故障下，结论保持一致且失败原因可区分、可解释。

## 1. 目录与运行

```bash
mvn spring-boot:run                       # 默认数据目录 ./audit-data
AUDIT_DATA_DIR=/tmp/audit mvn spring-boot:run   # 自定义数据目录
mvn test                                  # 54 个单测（含篡改/截断/重复/并发/存储异常/归档包）
```

数据目录包含三类文件：

| 文件 | 作用 |
| --- | --- |
| `events.jsonl` | 每行一条事件 JSON，仅追加（链本体） |
| `anchor.json` | 链头/链尾锚点（headSeq/headHash/tailSeq/tailHash/count），独立持久化 |
| `policy.json` | 当前脱敏策略（版本号 + 敏感字段集合 + 掩码 token） |
| `archive-signing.key` / `archive-signing.pub` | 本环境的归档签名密钥对（Ed25519，首次启动生成；私钥不出环境） |
| `compact.intent` / `*.tmp` | 按批次清理与原子写的崩溃恢复临时文件（正常运行后自动消失） |

## 2. 完整性校验方式

### 2.1 链式哈希

- 算法：SHA-256（64 位十六进制），首条事件的 `prevHash` 为 64 个 `0` 的创世哈希。
- 事件规范化串（字段顺序固定，payload 的 key 按字典序排序，UTF-8）：

```
seq \n timestamp \n eventId \n actor \n action \n resource \n policyVersion \n prevHash \n
k1=v1&k2=v2...
```

- `hash = SHA-256(规范化串)`。事件自身的 hash 字段不参与计算，因此落盘后可独立复算。

校验时逐条复算 hash 并核对 `prevHash == 上一条.hash`，同时将链头/链尾与独立锚点比对。

### 2.2 可区分的失败原因（`VerificationFailureReason`）

| 原因 | 触发手段 |
| --- | --- |
| `ENTRY_HASH_MISMATCH` | 篡改任一条目的字段或直接改写其 hash |
| `LINK_MISMATCH` | 断链（中间删除/插入导致 prevHash 接不上；首条 prevHash 非创世值） |
| `SEQUENCE_GAP` | 序号空洞、重排（交换行序） |
| `TRUNCATED` | 删头（链头 seq 晚于锚点 headSeq）、去尾（链尾 seq 早于锚点 tailSeq）、整体清空 |
| `ANCHOR_MISMATCH` | 锚点被篡改、条目数与锚点 count 不符等 |
| `MALFORMED_ENTRY` | 行无法解析为事件 JSON / 缺必要字段（文件损坏或手工破坏） |

校验结论 `VerificationReport{valid, scannedEntries, headSeq, tailSeq, issues[]}` 中每个 issue
都带有 reason、定位 seq/eventId 与人类可读 detail。所有判定依据同时写入服务日志。

### 2.3 崩溃一致性与自动对账

- 追加顺序：先写链文件行（强制 flush），再以“临时文件 + 原子移动”更新锚点。
- 启动恢复：链文件末尾没有换行符的半截行视为未落盘完成，截断到最后一个完整行。
- 合法崩溃窗口“行已落盘、锚点未更新”：当链头与锚点一致且链尾连续地晚于锚点尾时，
  识别为锚点落后（不是篡改），校验通过并自动把锚点前滚。除此之外锚点与链不一致即报错。
- 按批次清理采用 `compact.intent` 日志：写意图 → 重写链文件 → 刷新锚点 → 删意图，
  任一步崩溃后重启都会把压缩推进完成，不会留下“链已截断但锚点仍旧”的歧义状态。

## 3. 幂等追加与并发

- 以 `eventId` 幂等：相同 eventId 且 actor/action/resource 一致的重复提交返回已存在事件，
  不新增记录、序号与链节不变；eventId 相同但身份字段不同返回 409
  `DUPLICATE_EVENT_CONFLICT`。
- 进程内单写者锁串行化所有写操作：多线程并发下序号严格 1..N 连续、eventId 无重复。
- 链校验不通过时拒绝追加/清理（409 `INTEGRITY_FAILED`），不会在破损链上续写。

## 4. 脱敏与保留策略

### 4.1 脱敏

- 敏感字段值在落盘前整体替换为固定 token（默认 `***REDACTED***`），不可逆，
  且不保留长度等任何可反推特征；非敏感字段原样保留。
- 默认敏感字段：`password,idCard,phone,token`，可用 `audit.sensitive-fields` 配置。
- 策略带单调递增版本号，每条事件记录写入时的 `policyVersion`。

### 4.2 策略变更与历史可复现

- 更新策略只影响之后写入的事件；历史事件中的脱敏值与版本号永不改变，
  因而“当时校验通过”的历史结论在任何策略更新后仍可逐字节复现。
- 接口：`GET/POST /audit/policy`（敏感字段集合内容未变时不产生新版本）。

### 4.3 按批次保留

`POST /audit/retain?keepBatches=N&batchSize=B` 保留最新 N×B 条，其余按批次整体删除
（重写链文件并把保留段第一条锚定为新链头），清理完成后立即重新校验，失败则报错。
保留窗口大于现有量时为空操作。

## 5. 导出（本地模拟接收端）

导出前先做完整性校验，结论严格分为四类（`ExportOutcome`），两类失败互不混淆：

| 结论 | 含义 |
| --- | --- |
| `DELIVERED` | 有新事件投递成功且无失败 |
| `DUPLICATE_IGNORED` | 全部为接收端已收过的重复投递，幂等忽略 |
| `RECEIVER_FAILED` | 本地链完好，但接收端故障（`failedEventIds` 给出失败清单）；本地记录零改动，可直接重试 |
| `INTEGRITY_FAILED` | 本地链校验未通过，一条都不投递（携带 integrityIssues） |

- 接收端以 eventId 幂等，乱序、重复投递均安全（`POST /audit/export/order` 可指定投递顺序）。
- `POST /audit/receiver/failing?failing=true|false` 模拟接收端故障，`/receiver/reset` 清空幂等记忆。

## 6. 归档包（离线核验与跨环境导入）

把指定序号区间导出为一个**自包含、带签名**的归档包（单个 JSON 文件）。审计方拿到
“包 + 来源环境公钥”即可完全离线地判断这段记录是否完整、是否被改动；也可以把包导入
另一套（或已清空的）环境继续使用。

### 6.1 包格式与防伪造

```json
{
  "manifest": { "format": "audit-archive", "version": 1, "archiveId": "...",
                "environmentId": "env-...", "createdAt": 0,
                "fromSeq": 3, "toSeq": 7, "count": 5,
                "precedingHash": "...", "headHash": "...", "tailHash": "...",
                "policyVersions": [1] },
  "events":   [ /* 区间内事件本体，与落盘字节一致 */ ],
  "signature": "<Ed25519(清单规范化串)，Base64>"
}
```

- 每个环境持有一对 Ed25519 密钥（`archive-signing.key/.pub`，首次启动生成）。
  **environmentId = "env-" + SHA-256(公钥) 前 16 位十六进制**，完全由公钥派生。
- 签名只覆盖清单；事件本体由清单里的 `precedingHash/headHash/tailHash` 与事件自身的
  链式哈希共同绑定（改任一事件都会破坏哈希链或清单绑定）。
- 伪造者没有私钥就无法造出能通过核验的包；把别的环境的包拿来顶替，签名无法用
  本环境公钥核验通过。公钥带外交付（`GET /audit/archive/public-key`）。
- 包内事件即当时落盘的内容（含当时的脱敏值与 policyVersion），因此**之后调整脱敏
  策略、或来源环境做了保留期清理，都不会改变已导出包的核验结论**。

### 6.2 导出

`POST /audit/archive/export?fromSeq=3&toSeq=7[&out=/tmp/pkg.json]`
（不给 `out` 时响应里以 Base64 返回包字节）。导出前对整条链做单趟流式校验
（内存 O(1)，耗时随链规模线性），结论可区分：

| 结论 | 含义 |
| --- | --- |
| `EXPORTED` | 导出成功 |
| `EMPTY_CHAIN` | 链为空，无可导出记录（不产出包） |
| `RANGE_PRUNED` | 区间起点已被保留期清理 |
| `RANGE_NOT_FOUND` | 区间超出链尾 |
| `INTEGRITY_FAILED` | 本地链校验未通过，拒绝导出（携带 issues） |

### 6.3 离线核验

`POST /audit/archive/verify?path=<包文件>&keyPath=<来源公钥文件>`，或直接用
`ArchiveVerifier.verify(packageBytes, publicKey)`（不依赖本服务任何运行时数据）。
结论彼此可区分（`ArchiveConclusion`）：

| 结论 | 触发手段 |
| --- | --- |
| `VALID` | 签名有效，全部事件哈希/序号/链节/清单绑定复算一致 |
| `MALFORMED_PACKAGE` | 包文件被截断/损坏/格式版本不符 |
| `SIGNATURE_INVALID` | 掉包、伪造（含拿别的环境的包顶替） |
| `ENVIRONMENT_MISMATCH` | 签名有效但清单环境标识与公钥派生标识不符 |
| `CONTENT_TAMPERED` | 条目内容被改（含改后重算哈希、混入清单外记录、整体替换） |
| `RECORDS_DELETED` | 区间内有记录被删除（序号出现空洞） |
| `TAIL_TRUNCATED` | 尾部被截：现存部分是声明区间的合法前缀但数量不足 |
| `ORDER_SHUFFLED` | 记录一条不缺但顺序被打乱 |

### 6.4 导入

`POST /audit/archive/import?path=<包文件>&keyPath=<来源公钥文件>`。
每条源事件包装为一条本地事件追加到链尾（与本地已有记录并存于同一条链），
原始事件 JSON 逐字节保留在 payload 的 `_importOriginalEvent` 字段，
本地事件 id 为确定性的 `imp-<archiveId>-<原eventId>`。结论可区分（`ImportOutcome`）：

| 结论 | 含义 |
| --- | --- |
| `IMPORTED` | 有新记录导入 |
| `ALREADY_IMPORTED` | 幂等命中：包中记录此前已全部导入，零改动 |
| `PACKAGE_INVALID` | 包本身完整性有问题（核验未通过），本地零改动 |
| `LOCAL_CHAIN_INVALID` | 本地链当前不完整，拒绝导入，本地零改动 |
| `IMPORT_STORAGE_FAILED` | 接收/存储中途出错，已回滚到导入前状态，可安全重试 |

- **幂等**：同一包反复导入结果相同，不会多出记录，链保持有效。
- **原子**：整批导入先一次性校验本地链，然后批量追加并一次刷新锚点；中途存储失败
  用 `pruneAfter` 把链截回导入前状态并恢复锚点（与按批次清理共用同一套
  意图日志崩溃恢复机制），本地已有记录零影响。
- 包完整性问题（`PACKAGE_INVALID`）与本地接收/存储问题（`IMPORT_STORAGE_FAILED`）
  是两类不同结论：前者找对方核对，后者直接重试。

### 6.5 兼容范围

- 包格式 `format=audit-archive, version=1`；核验端只接受同格式同版本的包。
- 事件的哈希规范化算法与主链一致（SHA-256，见 2.1）；跨环境导入只要求双方运行
  同一版本的本服务，不要求共享存储、策略或密钥。
- 环境身份即密钥对：数据目录整体清空后重新初始化的环境是新身份，旧包仍可用
  旧公钥离线核验，但不会被误认为是新环境所出。

## 7. HTTP 接口一览

| 方法 路径 | 说明 |
| --- | --- |
| `POST /audit/events` | 追加事件（幂等） |
| `GET /audit/events` | 读取全部事件 |
| `GET /audit/verify` | 完整性校验，返回 VerificationReport |
| `POST /audit/retain?keepBatches=&batchSize=` | 按批次保留 |
| `POST /audit/export` / `POST /audit/export/order` | 导出（顺序导出/乱序重放） |
| `POST /audit/archive/export?fromSeq=&toSeq=[&out=]` | 导出区间为签名归档包 |
| `GET /audit/archive/public-key` | 查看本环境标识与归档公钥（带外交付） |
| `POST /audit/archive/verify?path=&keyPath=` | 离线核验归档包 |
| `POST /audit/archive/import?path=&keyPath=` | 导入归档包（幂等、原子） |
| `GET/POST /audit/policy` | 查看/更新脱敏策略 |
| `POST /audit/receiver/failing` / `/receiver/reset` | 模拟接收端控制 |

错误响应体含 `errorType`：`INTEGRITY_FAILED` / `DUPLICATE_EVENT_CONFLICT` /
`STORAGE_ERROR` / `BAD_REQUEST`，HTTP 状态码分别为 409/409/503/400。

## 7. 验证方法

### 7.1 单元测试

```bash
mvn test
```

覆盖（每个用例日志均打印“输入”与“判定依据”）：

- `ChainIntegrityTest`：正常链、字段篡改 → ENTRY_HASH_MISMATCH
- `TamperDetectionTest`：改 hash、删头、去尾、清空、交换行序、删中间行、损坏行、篡改锚点
- `DuplicateAndConcurrencyTest`：串行/并发重复提交幂等、16×25 并发写入序号连续
- `MaskingAndRetentionTest`：落盘无明文、策略变更只影响新事件、历史记录字节不变、
  按批次保留后校验通过、保留后重启续写
- `ExportTest`：首次投递/重复忽略、乱序重放、接收端故障与完整性失败严格区分且本地零改动
- `StorageFailureAndRecoveryTest`：不可写目录、半截行恢复、锚点落后自动对账、清理后崩溃恢复
- `ArchiveOfflineVerificationTest`：各类破坏的离线核验结论（改内容/删记录/截尾/乱序/
  伪造/跨环境顶替/标识不符/包截断）、空链/单条/区间已清理、策略变更与源端清理不影响旧包
- `ArchiveImportTest`：空环境导入、重复导入幂等、与本地记录并存、坏包零改动、
  导入中途存储故障回滚且可重试、本地链破损拒绝导入
- `ArchiveScaleTest`：2 万条链上导出 1 万条区间、离线核验与导入的耗时（秒级以内）

### 7.2 手工端到端

```bash
mvn spring-boot:run
curl -s -X POST localhost:8080/audit/events -H 'Content-Type: application/json' \
  -d '{"eventId":"e1","actor":"alice","action":"LOGIN","resource":"h1",
       "payload":{"password":"secret","ip":"10.0.0.1"}}'
curl -s localhost:8080/audit/verify
# 直接编辑 audit-data/events.jsonl 改一个字段后：
curl -s localhost:8080/audit/verify     # valid=false, issues 中给出具体原因与定位
```

### 7.3 归档包手工验证

```bash
# 1) 追加若干事件后，导出区间 [1,3] 到文件，并取本环境公钥
curl -s -X POST 'localhost:8080/audit/archive/export?fromSeq=1&toSeq=3&out=/tmp/pkg.json'
curl -s localhost:8080/audit/archive/public-key | jq -r .publicKeyBase64 > /tmp/env.pub

# 2) 离线核验（可换一台机器、或先停掉服务，只凭 包+公钥）
curl -s -X POST 'localhost:8080/audit/archive/verify?path=/tmp/pkg.json&keyPath=/tmp/env.pub'
#   -> conclusion=VALID；改包内任一字段再核验 -> CONTENT_TAMPERED 等具体结论

# 3) 导入到另一套环境（AUDIT_DATA_DIR=/tmp/audit-b 另起一个实例）
curl -s -X POST 'localhost:8081/audit/archive/import?path=/tmp/pkg.json&keyPath=/tmp/env.pub'
#   -> IMPORTED；再发一次 -> ALREADY_IMPORTED，记录数不变
curl -s localhost:8081/audit/verify     # 导入后的本地链校验通过
```
