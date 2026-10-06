# 防篡改审计链路（Java / Spring Boot）

一条可本地验证的安全审计链路：事件顺序追加形成密码学完整性链，敏感字段落盘前按版本化策略
不可逆脱敏，支持按批次保留清理，可向本地模拟接收端做幂等导出，并可把指定区间打包成
**自包含归档包**交给外部审计方离线核验、或幂等导入另一套环境——导入后记录即并入该环境
自己的链，可查询、参与整体校验、可继续往后写。在并发写入、策略变更、存储异常与接收端
故障下，结论保持一致且失败原因可区分、可解释。

## 1. 目录与运行

```bash
mvn spring-boot:run                       # 默认数据目录 ./audit-data
AUDIT_DATA_DIR=/tmp/audit mvn spring-boot:run   # 自定义数据目录
mvn test                                  # 60 个单测（含篡改/截断/重复/并发/存储异常/归档包）
```

数据目录包含三类文件：

| 文件 | 作用 |
| --- | --- |
| `events.jsonl` | 每行一条事件 JSON，仅追加（链本体；导入的记录也并入此链） |
| `anchor.json` | 链头/链尾锚点（headSeq/headHash/tailSeq/tailHash/count），独立持久化 |
| `policy.json` | 当前脱敏策略（版本号 + 敏感字段集合 + 掩码 token） |
| `compact.intent` / `merge.intent` / `*.tmp` | 按批次清理与合并导入的崩溃恢复意图、原子写临时文件（正常运行后自动消失） |
| `archives/` | 导出的自包含归档包（单文件 JSON） |
| `imports/` | 已导入归档包的副本（导入证据，可独立离线核验；记录本体已并入 `events.jsonl`） |

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


## 6. 归档包：导出、离线核验与导入

### 6.1 包格式与防伪造

归档包是单个自包含 JSON 文件（`archives/archive-<env>-<from>-<to>-<ts>.json`）：

```json
{
  "format": "audit-archive", "formatVersion": 1,
  "environmentId": "...", "exportedAt": 1234567890,
  "fromSeq": 3, "toSeq": 8, "count": 6,
  "prevHash": "...", "headHash": "...", "tailHash": "...",
  "events": [ /* 原样复制的事件（含当时脱敏值与 policyVersion） */ ],
  "manifestHash": "...", "signature": "..."
}
```

- `manifestHash = SHA-256(规范化元数据 || 逐条事件 hash)`；`signature = HMAC-SHA256(环境密钥, manifestHash)`。
- 每个环境有独立 `environmentId` 与密钥（`audit.environment-id` / `audit.archive-key`）。
  没有密钥的人无法为伪造/掉包的包算出合法签名；不同环境密钥不同，跨环境的包不能互相顶替。
- 包内事件是落盘时的原样复制（脱敏值与 policyVersion 已固定在哈希里），因此**之后调整脱敏
  策略、或来源环境做了保留期清理，都不影响该包的核验结论**，历史结论永远可按包内证据复现。
- 核验方只需要：包文件 + 对应环境的核验密钥（`audit.trusted-archive-keys.<env>`），
  不需要连接本服务，也不依赖本服务留存的任何运行时数据。

### 6.2 导出与交付

```bash
curl -s -X POST "localhost:8080/audit/archive/export?fromSeq=3&toSeq=8"
```

导出结论（`ArchiveExportOutcome`）：`EXPORTED`（生成成功，archiveFile 给出路径）、
`EMPTY_CHAIN`（空链，明确区别于"成功导出空包"）、`RANGE_UNAVAILABLE`（区间起点已被
保留期清理或尚未到达；上界自动裁剪到当前链尾）、`INTEGRITY_FAILED`（本地链校验未通过，
拒绝导出）、`STORAGE_FAILED`（写文件失败，可重试）、`CONFIG_MISSING`（归档所需配置缺失，
detail 指明是 `audit.environment-id` 还是 `audit.archive-key`，补齐后重试）、
`INTERNAL_ERROR`（未预料的内部错误，可重试，反复出现应排查环境）。把生成的单个 JSON
文件交给审计方即可。

### 6.3 离线核验

```bash
curl -s -X POST "localhost:8080/audit/archive/verify?path=/path/to/archive.json&expectedEnv=envA"
```

核验为流式实现（内存与包大小无关），结论按类别区分（`ArchiveFailureReason`），
不会混成一句"无效"：

| 原因 | 含义 |
| --- | --- |
| `PACKAGE_NOT_FOUND` | 包文件不存在/不可读（路径错误或包未送达），与包内容损坏区分开 |
| `ENTRY_HASH_MISMATCH` | 某条事件内容被改 |
| `SEQUENCE_GAP` | 中间记录被删 |
| `TRUNCATED` | 尾部被截（逻辑截尾或文件物理截断） |
| `ORDER_VIOLATION` | 顺序被打乱 |
| `LINK_MISMATCH` | 链节断裂（prevHash 接不上） |
| `MANIFEST_MISMATCH` | 清单被改但未重签 |
| `SIGNATURE_MISMATCH` | 伪造/掉包/非本信任域密钥签发 |
| `UNTRUSTED_ENVIRONMENT` | 没有该环境的核验密钥，来源不可信 |
| `ENVIRONMENT_MISMATCH` | 包来自其他环境（跨环境顶替） |
| `EMPTY_ARCHIVE` / `MALFORMED_PACKAGE` / `UNSUPPORTED_FORMAT` | 空包 / 结构损坏 / 不认识的格式版本 |

### 6.4 导入规则

```bash
curl -s -X POST "localhost:8080/audit/archive/import?path=/path/to/archive.json"
curl -s localhost:8080/audit/events                 # 导入的记录与本地记录一起可查
curl -s localhost:8080/audit/verify                 # 整体校验（含导入记录）照样通过
curl -s localhost:8080/audit/archive/imports        # 已留存的包副本列表（导入证据）
curl -s -X POST "localhost:8080/audit/archive/imports/verify?storedAs=imported-envA-1-4.json"
```

**导入后记录就是本环境自己的记录**：包内事件的内容（eventId、时间戳、actor/action/
resource、脱敏后的 payload、policyVersion）原样保留，seq/prevHash/hash 按本地链尾重新
编号与链接后并入 `events.jsonl`。因此导入后可以：

- 用 `GET /audit/events` 把导入记录与本地记录放在一起查询；
- 用 `GET /audit/verify` 对整条链（含导入记录）做整体校验，照样通过；
- 继续 `POST /audit/events` 往后追加，序号与链节接在导入记录之后。

跨环境导入时，落盘的 eventId 会自动加上 `来源环境/` 前缀（如 `envA/evt-3`）做命名空间
隔离，避免来源环境与本地环境的 eventId 撞车导致后续追加被误判冲突；前缀是确定性的，
同一包重复导入仍按同一 eventId 幂等。同环境回导（如清理后恢复自己的包）保持原 eventId。

导入规则：

- **先核验后并入**：包未通过离线核验，本地零改动，绝不并入。
- **幂等**：同一包（或区间重叠的包）重复导入任意次，结果与首次一致——已存在的记录按
  eventId+内容幂等跳过（`DUPLICATE_IGNORED`），不堆重复记录、不动链；并发导入同一个包
  由单写者锁串行化，只会真正并入一次。
- **清理后再导入**：该包此前导入过、记录后被保留期清理掉的，重新导入会再次并入，但结论
  明确给出 `REIMPORTED_AFTER_PRUNE`，不会悄悄判成普通成功。
- **原子**：合并是"写意图 → 重写链文件 → 刷新锚点 → 删意图"（`merge.intent`）的单步
  可恢复操作。接收/存储中途失败或进程崩溃：要么本地原有记录分毫不动，要么重启后把合并
  推进完成，不会留下半截状态。
- **证据留存**：包副本存于 `imports/` 下，可随时独立离线核验（核验的是包本身，与是否已
  并入本地链无关）。

导入结论（`ArchiveImportOutcome`）彼此可区分，各自对应不同处置：

| 结论 | 含义与处置 |
| --- | --- |
| `IMPORTED` | 记录已并入本地链（mergedCount 给出并入条数），可查询/校验/续写 |
| `REIMPORTED_AFTER_PRUNE` | 此前导入过、记录已被保留期清理，本次已重新并入（明确区别于首次导入） |
| `DUPLICATE_IGNORED` | 包内记录已全部在本地链中，幂等忽略，本地零改动 |
| `INTEGRITY_REJECTED` | 包本身有问题（核验未通过，primaryReason 给出类别），本地零改动；**找对方核对**，不要简单重试 |
| `UNTRUSTED_SOURCE` | 没有来源环境的核验密钥；把对方密钥配到 `audit.trusted-archive-keys.<env>` 或找对方确认来源 |
| `LOCAL_CHAIN_INVALID` | 包有效但本地链本身校验未通过，拒绝在破损链上合并；先处理本地链问题 |
| `STORAGE_FAILED` | 包有效但本地接收/存储失败，本地零改动，**可重试** |
| `INTERNAL_ERROR` | 未预料的内部错误，本地零改动，可重试；反复出现应排查环境 |

### 6.5 兼容范围

- `formatVersion` 当前为 1；不认识的格式或版本核验返回 `UNSUPPORTED_FORMAT`，不会误判通过。
- 跨环境导入要求接收方配置来源环境的核验密钥；未配置即 `UNTRUSTED_SOURCE`。
- 归档包只依赖 SHA-256 与 HMAC-SHA256，核验方可用任意技术栈独立实现核验。

## 7. HTTP 接口一览

| 方法 路径 | 说明 |
| --- | --- |
| `POST /audit/events` | 追加事件（幂等） |
| `GET /audit/events` | 读取全部事件 |
| `GET /audit/verify` | 完整性校验，返回 VerificationReport |
| `POST /audit/retain?keepBatches=&batchSize=` | 按批次保留 |
| `POST /audit/export` / `POST /audit/export/order` | 导出（顺序导出/乱序重放） |
| `GET/POST /audit/policy` | 查看/更新脱敏策略 |
| `POST /audit/receiver/failing` / `/receiver/reset` | 模拟接收端控制 |
| `POST /audit/archive/export?fromSeq=&toSeq=` | 导出区间为自包含归档包 |
| `POST /audit/archive/verify?path=&expectedEnv=` | 离线核验归档包 |
| `POST /audit/archive/import?path=` | 幂等导入归档包（记录并入本地链） |
| `GET /audit/archive/imports` / `POST /audit/archive/imports/verify?storedAs=` | 已留存包副本列表 / 独立核验 |

错误响应体含 `errorType`：`INTEGRITY_FAILED` / `DUPLICATE_EVENT_CONFLICT` /
`STORAGE_ERROR` / `BAD_REQUEST`，HTTP 状态码分别为 409/409/503/400。

## 8. 验证方法

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
- `StorageFailureAndRecoveryTest`：不可写目录、半截行恢复、锚点落后自动对账、清理后崩溃恢复、
  合并导入崩溃（链已重写则重启推进完成、未重写则旧链分毫不动）
- `ArchiveVerifyTest`：离线核验面对内容被改/记录被删/截尾/物理截断/重排/伪造签名/清单被改/
  自洽假包/跨环境顶替各自的结论；空链与单条链；区间已被清理；策略变更+清理后历史结论可复现
- `ArchiveImportTest`：导入后记录并入本地链（可查询/整体校验/续写）、空环境导入、
  重复导入幂等、重叠区间去重、清理后再导入给出 REIMPORTED_AFTER_PRUNE、篡改包拒绝且
  本地零改动、未信任来源指向该补的配置、包文件缺失与包损坏区分、存储故障可重试且零改动、
  本地链破损与包问题区分、8 线程并发导入同一包只并入一次
- `ArchiveConfigAndErrorTest`：导出缺配置（archive-key / environment-id）给出 CONFIG_MISSING、
  导出/导入遇未预料内部错误归类为 INTERNAL_ERROR 而非笼统异常、核验缺失包文件为
  PACKAGE_NOT_FOUND
- `ArchiveScaleTest`：5000 条链上导出/核验耗时与内存（流式，核验侧 O(1) 内存）

### 7.2 手工端到端

```bash
mvn spring-boot:run
curl -s -X POST localhost:8080/audit/events -H 'Content-Type: application/json' \
  -d '{"eventId":"e1","actor":"alice","action":"LOGIN","resource":"h1",
       "payload":{"password":"secret","ip":"10.0.0.1"}}'
curl -s localhost:8080/audit/verify
# 直接编辑 audit-data/events.jsonl 改一个字段后：
curl -s localhost:8080/audit/verify     # valid=false, issues 中给出具体原因与定位

# 归档包手工验证：
curl -s -X POST "localhost:8080/audit/archive/export?fromSeq=1&toSeq=1"
#   -> archiveFile 给出包路径（audit-data/archives/ 下）
curl -s -X POST "localhost:8080/audit/archive/verify?path=<包路径>"
#   -> valid=true；手工改包内任一字段后再次核验，可见对应类别的失败结论
curl -s -X POST "localhost:8080/audit/archive/import?path=<包路径>"
#   -> 首次 IMPORTED（mergedCount=并入条数），再次执行 DUPLICATE_IGNORED（幂等）
curl -s localhost:8080/audit/events
#   -> 导入的记录与本地记录一起可查（跨环境导入的 eventId 带 "来源环境/" 前缀）
curl -s localhost:8080/audit/verify
#   -> 含导入记录的整体校验照样通过；继续 POST /audit/events 可接着往后写
```
