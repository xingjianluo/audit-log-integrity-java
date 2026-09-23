# 防篡改审计链路（audit-log-integrity-java）

一条可在本地验证的、只追加（append-only）的安全审计链路：事件顺序追加并形成
SHA-256 完整性链，任何篡改、删除、重排、截断或损坏都会被检测到，并以**可区分的
原因**报告；敏感字段落盘前按版本化策略**不可逆脱敏**；保留期清理**按批次**进行，
清理后剩余数据仍可校验；向本地模拟接收端的导出在接收端异常、重复/乱序投递下
**幂等**，且“接收端失败”与“完整性校验失败”是两类明确可区分的结果。

## 1. 目录结构

```
src/main/java/com/github/xingjianluo/auditlogintegrityjava/
├── crypto/      HashService / SHA-256 实现
├── model/       AuditEvent、StoredRecord、VerificationResult、
│                FailureReason、ExportResult/Status、CleanupResult、ChainAnchor
├── masking/     不可逆脱敏策略（版本化）、脱敏字段策略（版本化）、保留策略
├── store/       FileAuditLogStore（只追加文件存储 + 锚点 + 尾指针 + 游标）
├── service/     ChainIntegrityVerifier（链校验）、AuditService（记录/校验/清理）
├── export/      AuditEventReceiver（本地模拟接收端）、AuditExporter（导出）
└── config/      AuditProperties、AuditConfig
src/test/...     28 个测试：篡改/截断/重排/损坏/重复/并发/清理/策略更新/导出
```

## 2. 完整性校验方式

### 2.1 链式结构

- 每条记录 `StoredRecord` 含：`seq`（无间隙递增）、业务字段、`policyVersion`、
  `prevHash`、`hash`。
- 内容哈希：
  `hash = SHA-256(规范化拼接(seq, eventId, timestamp, actor, action, resource,
  policyVersion, prevHash, detail 按 key 排序后的全部键值))`
  字段采用“长度前缀”编码，detail 的键先排序，保证序列化无歧义、与 Map 迭代顺序无关。
- 链头：首条记录的 `prevHash = "GENESIS"`；之后每条的 `prevHash` 等于上一条的
  `hash`。
- 落盘：`audit.log` 每行一条 JSON；追加写入后 `fsync`。另有：
  - `audit.tail`：持久化的“最后一条记录 seq/hash”尾指针；
  - `anchor`：保留期清理后链头锚点（`seq/hash/updatedAt`）；
  - `export-cursor`：已导出到接收端的最后 seq。

校验时**只依据磁盘上的记录内容重新计算哈希**，不依赖当前脱敏策略，因此历史结论
可稳定复现。

### 2.2 可区分的失败原因（`FailureReason`）

`ChainIntegrityVerifier.verify(...)` 按固定顺序检查并返回结构化结果
（是否有效、原因、出问题的 seq、期望值/实际值、判定依据说明）：

| 原因 | 触发情形 |
| --- | --- |
| `CONTENT_TAMPERED` | 某条记录字段被改，但存储哈希未同步重算（内容哈希不一致） |
| `CHAIN_BROKEN` | 记录被“自洽伪造”替换：自身哈希重算了，但下一条的 prevHash 对不上 |
| `SEQUENCE_GAP_OR_REORDER` | seq 缺失、重复或乱序（中间删除、两行交换等） |
| `TRUNCATED_AT_HEAD` | 头部记录被非法删除：首条现存记录的 seq/prevHash 对不上 GENESIS 或锚点 |
| `TRUNCATED_AT_TAIL` | 尾部记录被删：日志实际结尾早于 `audit.tail` 持久化尾指针 |
| `CORRUPTED_RECORD` | 日志中存在无法解析的行 |

合法的保留期清理不会被判为篡改：清理以原子重写 + 锚点前移完成，剩余首条记录的
`prevHash` 正好指向新锚点；若有人不经锚点直接删头部，即得到
`TRUNCATED_AT_HEAD`。

### 2.3 并发与一致性

- 存储的所有变更由同一把锁串行化；记录、锚点、尾指针组成不可变 `ChainState`
  原子替换，读操作不会看到“新记录 + 旧尾指针”之类的混合状态。
- 追加前在同一临界区内完成“eventId 是否存在 → 分配 seq/prevHash → 落盘”，
  因此重复提交与并发写入都是安全的。

## 3. 幂等的重复提交

- 幂等键为调用方提供的 `eventId`。相同 `eventId` 再次提交（即使内容不同、或多线程
  同时提交）只会返回**已存在的那条记录**，不会追加第二条，链的连续性不受影响。

## 4. 脱敏与保留策略

### 4.1 不可逆脱敏

- 敏感字段（默认 `password,token,idCard`，可配置）在落盘前替换为
  `mask:<strategyVersion>:<salted SHA-256 前 8 位>`。
- 加盐单向摘要：明文不可由落盘值恢复（不可逆），但相同明文的脱敏值一致，便于
  审计关联分析。非敏感字段保持明文。
- **版本化**：字段策略版本 = 策略版本 + “敏感字段集合排序后摘要”。每条记录持久化
  写入时的 `policyVersion`。策略变更只影响此后写入的记录；校验只重算哈希、不重新
  脱敏，所以策略更新后历史记录依旧校验通过、历史结论可复现。新记录自动携带新版本
  与新脱敏结果，一条链中可并存不同策略版本的记录。

### 4.2 保留期清理（仅按批次）

- 超过 `now - audit.retention-days` 的头部连续记录可被清理；
- 每批最多删除 `audit.cleanup-batch-size` 条（不存在“超大最后一批”）；
- 每批是一次原子重写：保留剩余记录、把锚点前移到“最后一条被删记录”，随后立即对
  剩余链重新校验；删除全部记录时链重置为 GENESIS，之后可正常继续追加。
- 清理同步把导出游标前推到锚点位置，避免导出引用已不存在的 seq。

## 5. 导出与模拟接收端

- `InMemoryAuditEventReceiver` 是本地内存模拟的接收端，以 `seq` 为键：重复投递、
  乱序投递都是幂等 no-op；可用 `setFailing(true)` 模拟接收端故障。
- 导出流程 `AuditExporter`：
  1. **先做本地完整性校验**，失败则返回 `INTEGRITY_CHECK_FAILED`（携带原因），
     完全不投递；
  2. 校验通过后按 seq 顺序投递，每成功一条推进一次导出游标；
  3. 接收端抛错返回 `RECEIVER_FAILED`：游标停在故障记录之前、本地审计数据零改动，
     故障恢复后重试仍然幂等。
- 结果枚举 `ExportStatus` 明确区分：`DELIVERED / NOTHING_TO_EXPORT /
  INTEGRITY_CHECK_FAILED / RECEIVER_FAILED / STORAGE_FAILED`。

## 6. 配置（`application.properties`）

```properties
audit.storage-dir=${java.io.tmpdir}/audit-chain-default   # 存储目录
audit.masking-salt=local-dev-salt                         # 脱敏盐
audit.sensitive-fields=password,token,idCard              # 敏感字段
audit.retention-days=30                                   # 保留期（天）
audit.cleanup-batch-size=2                                # 清理批次大小
```

## 7. 本地验证方法

要求 JDK 21+、Maven 3.9+（仓库已具备离线依赖）。

### 7.1 运行全部测试

```bash
mvn test
```

覆盖场景（28 个用例）：

- `ChainIntegrityVerifierTest`：内容篡改、自洽伪造（断链）、中间删除、重排、尾截断、
  头截断、损坏行——逐一断言**不同** `FailureReason`；
- `AuditServiceTest`：顺序/并发写入（16 线程 × 25）、同 eventId 并发重复提交只落一条、
  敏感字段不可逆脱敏、按批清理（断言批次数与锚点）、清空后重置、策略更新后历史可复现；
- `FileAuditLogStoreTest`：直接改磁盘文件（无重启/重启后）检测篡改、头删、尾指针伪造、
  损坏行容错加载、清理后重启锚点合法；
- `AuditExporterTest`：导出幂等、重复/乱序投递、`RECEIVER_FAILED` 不动本地数据且可
  重试、篡改/截断时 `INTEGRITY_CHECK_FAILED` 与接收端失败可区分；
- `EndToEndAuditChainTest`：并发写入 → 重复提交 → 导出 → 接收端故障 → 篡改 →
  修复后导出 → 截断 → 策略更新 的完整链路。

测试日志对每个场景打印 `[input]`（构造的输入）与 `[decision]`（判定结果、原因与
判定依据），例如：

```
[input] seq=2 actor/action modified, stored hash left unchanged
 -> [decision] valid=false reason=CONTENT_TAMPERED offendingSeq=2 ...
    basis=stored hash of seq=2 differs from hash recomputed over its fields ...
```

### 7.2 运行本地演示

```bash
mvn package -DskipTests
rm -rf "${TMPDIR:-/tmp}/audit-chain-demo"
java -jar target/audit-log-integrity-java-1.0-SNAPSHOT.jar \
     --spring.profiles.active=demo --audit.demo
```

演示会打印：追加与重复提交去重 → 整链校验通过 → 导出成功 → 接收端故障
（`RECEIVER_FAILED`）→ 磁盘篡改 + 尾截断后校验报 `CONTENT_TAMPERED` 且导出被阻断
（`INTEGRITY_CHECK_FAILED`）。

## 8. 设计要点小结

- **可解释**：所有失败都返回结构化原因、问题 seq、期望/实际值与文字依据。
- **可复现**：记录自描述（含 policyVersion），校验不依赖现行策略配置。
- **故障隔离**：导出路径绝不修改本地记录；接收端失败与完整性失败互不混淆。
- **最小可信**：合法的删除只有“经锚点的按批保留清理”一条路径，其余头部缺失一律
  视为攻击。
