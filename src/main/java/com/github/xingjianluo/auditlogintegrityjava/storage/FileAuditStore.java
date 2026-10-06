package com.github.xingjianluo.auditlogintegrityjava.storage;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.xingjianluo.auditlogintegrityjava.chain.AuditEvent;
import com.github.xingjianluo.auditlogintegrityjava.config.AuditProperties;
import org.springframework.stereotype.Component;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;

/**
 * 基于本地目录的存储：
 * <ul>
 *   <li>{@code events.jsonl}：每行一条事件 JSON，仅追加；</li>
 *   <li>{@code anchor.json}：链头/链尾锚点，临时文件 + 原子移动写入；</li>
 *   <li>{@code compact.intent}：按批次清理（压缩）的崩溃恢复日志。</li>
 * </ul>
 *
 * <p>崩溃恢复（构造时执行）：
 * <ol>
 *   <li>末尾不完整行（无换行符结尾）视为未落盘完成，截断到最后一个完整行；</li>
 *   <li>存在 compact.intent 时，把“重写链文件 + 刷新锚点”这一压缩动作推进到完成。</li>
 * </ol>
 */
@Component
public class FileAuditStore implements AuditStore {

    private record CompactIntent(long keepBeforeSeq) {
    }

    /** 合并导入的崩溃恢复意图：记录合并完成后链应有的条目数与尾部哈希。 */
    private record MergeIntent(int expectedCount, String expectedTailHash) {
    }

    private final Path dir;
    private final Path eventsFile;
    private final Path anchorFile;
    private final Path intentFile;
    private final Path mergeIntentFile;
    private final ObjectMapper mapper;

    public FileAuditStore(AuditProperties properties, ObjectMapper objectMapper) {
        this.dir = Path.of(properties.getDataDir());
        this.eventsFile = dir.resolve("events.jsonl");
        this.anchorFile = dir.resolve("anchor.json");
        this.intentFile = dir.resolve("compact.intent");
        this.mergeIntentFile = dir.resolve("merge.intent");
        this.mapper = objectMapper;
        try {
            Files.createDirectories(dir);
            truncatePartialLastLine();
            recoverCompaction();
            recoverMerge();
        } catch (IOException e) {
            throw new AuditStoreException("初始化审计存储失败: " + dir, e);
        }
    }

    @Override
    public synchronized void append(AuditEvent event) {
        try {
            String line = mapper.writeValueAsString(event);
            try (BufferedWriter w = Files.newBufferedWriter(eventsFile,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND)) {
                w.write(line);
                w.write('\n');
                w.flush();
            }
        } catch (IOException e) {
            throw new AuditStoreException("追加审计事件失败: seq=" + event.seq(), e);
        }
    }

    @Override
    public synchronized List<AuditEvent> readAll() {
        if (!Files.exists(eventsFile)) {
            return List.of();
        }
        List<String> lines;
        try {
            lines = Files.readAllLines(eventsFile);
        } catch (IOException e) {
            throw new AuditStoreException("读取审计链文件失败", e);
        }
        List<AuditEvent> events = new ArrayList<>(lines.size());
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            if (line.isBlank()) {
                throw new AuditStoreException("审计链文件第 " + (i + 1) + " 行为空，疑似损坏");
            }
            try {
                AuditEvent event = mapper.readValue(line, AuditEvent.class);
                if (event.eventId() == null || event.hash() == null) {
                    throw new AuditStoreException("审计链文件第 " + (i + 1) + " 行缺少必要字段");
                }
                events.add(event);
            } catch (IOException e) {
                throw new AuditStoreException("审计链文件第 " + (i + 1) + " 行无法解析，疑似损坏/篡改", e);
            }
        }
        return events;
    }

    @Override
    public synchronized Anchor readAnchor() {
        if (!Files.exists(anchorFile)) {
            return Anchor.empty();
        }
        try {
            return mapper.readValue(Files.readAllBytes(anchorFile), Anchor.class);
        } catch (IOException e) {
            throw new AuditStoreException("读取锚点文件失败", e);
        }
    }

    @Override
    public synchronized void writeAnchor(Anchor anchor) {
        try {
            atomicWriteJson(anchorFile, anchor);
        } catch (IOException e) {
            throw new AuditStoreException("写入锚点失败", e);
        }
    }

    /**
     * 按批次清理：删除 seq &lt; keepBeforeSeq 的事件，整体重写链文件并刷新锚点。
     * 借助 compact.intent 使“重写 + 锚点更新”可崩溃恢复，中途失败不会留下
     * “链已截断但锚点仍旧”这种无法区分的状态。
     *
     * @return 保留的事件
     */
    @Override
    public synchronized List<AuditEvent> pruneBefore(long keepBeforeSeq) {
        List<AuditEvent> all = readAll();
        if (all.isEmpty() || all.get(0).seq() >= keepBeforeSeq) {
            return all;
        }
        try {
            atomicWriteJson(intentFile, new CompactIntent(keepBeforeSeq));
            return finishCompaction();
        } catch (IOException e) {
            throw new AuditStoreException("按批次清理失败", e);
        }
    }

    // ---- 崩溃恢复 ----

    /**
     * 原子合并一批事件到链尾并刷新锚点。
     * 崩溃窗口与恢复：
     * <ol>
     *   <li>意图写入后、链文件替换前崩溃：旧链分毫不动，重启删除临时文件与意图；</li>
     *   <li>链文件已替换、锚点未刷新崩溃：重启按链内容重算锚点，把合并推进完成。</li>
     * </ol>
     * 本次调用内若 IO 失败且尚未替换链文件，则立即清理意图与临时文件，
     * 保证“失败即本地零改动”，调用方可安全重试。
     */
    @Override
    public synchronized void mergeAppend(List<AuditEvent> batch, Anchor anchor) {
        if (batch == null || batch.isEmpty()) {
            return;
        }
        List<AuditEvent> current = readAll();
        List<AuditEvent> merged = new ArrayList<>(current.size() + batch.size());
        merged.addAll(current);
        merged.addAll(batch);
        AuditEvent newTail = merged.get(merged.size() - 1);
        Path tmp = dir.resolve("events.jsonl.merge.tmp");
        boolean moved = false;
        try {
            atomicWriteJson(mergeIntentFile, new MergeIntent(merged.size(), newTail.hash()));
            writeEvents(tmp, merged);
            moveAtomically(tmp, eventsFile);
            moved = true;
            atomicWriteJson(anchorFile, anchor);
            Files.deleteIfExists(mergeIntentFile);
        } catch (IOException e) {
            if (!moved) {
                // 链文件尚未被替换：清理本次痕迹，旧链保持原样
                deleteIfRegularFile(tmp);
                deleteIfRegularFile(dir.resolve("merge.intent.tmp"));
                deleteIfRegularFile(mergeIntentFile);
            }
            // 已替换链文件但锚点写失败：保留 merge.intent，重启恢复会把合并推进完成
            throw new AuditStoreException("合并导入事件失败（本地原有记录未受影响）", e);
        }
    }

    private void truncatePartialLastLine() throws IOException {
        if (!Files.exists(eventsFile) || Files.size(eventsFile) == 0) {
            return;
        }
        byte[] bytes = Files.readAllBytes(eventsFile);
        if (bytes[bytes.length - 1] == (byte) '\n') {
            return;
        }
        int cut = bytes.length - 1;
        while (cut >= 0 && bytes[cut] != (byte) '\n') {
            cut--;
        }
        long keep = cut < 0 ? 0 : cut + 1L;
        try (FileChannel ch = FileChannel.open(eventsFile, StandardOpenOption.WRITE)) {
            ch.truncate(keep);
        }
    }

    private void recoverCompaction() throws IOException {
        if (!Files.exists(intentFile)) {
            return;
        }
        finishCompaction();
    }

    /**
     * 合并导入的崩溃恢复（幂等）：
     * 链已是合并后形态（条目数与尾哈希都吻合意图）则按链重算锚点推进完成；
     * 否则说明崩溃发生在链文件替换之前，旧链完好，丢弃临时文件与意图即可。
     */
    private void recoverMerge() throws IOException {
        if (!Files.exists(mergeIntentFile)) {
            return;
        }
        MergeIntent intent = mapper.readValue(Files.readAllBytes(mergeIntentFile), MergeIntent.class);
        List<AuditEvent> all = Files.exists(eventsFile) ? readAll() : List.of();
        boolean rolledForward = all.size() == intent.expectedCount()
                && !all.isEmpty()
                && all.get(all.size() - 1).hash().equals(intent.expectedTailHash());
        if (rolledForward) {
            AuditEvent head = all.get(0);
            AuditEvent tail = all.get(all.size() - 1);
            atomicWriteJson(anchorFile,
                    new Anchor(head.seq(), head.hash(), tail.seq(), tail.hash(), all.size()));
        } else {
            deleteIfRegularFile(dir.resolve("events.jsonl.merge.tmp"));
        }
        Files.deleteIfExists(mergeIntentFile);
    }

    private static void deleteIfRegularFile(Path p) {
        try {
            if (Files.isRegularFile(p)) {
                Files.deleteIfExists(p);
            }
        } catch (IOException ignored) {
            // 清理临时文件失败不影响结论
        }
    }

    /**
     * 依据 intent 把压缩推进到完成（幂等）：
     * 链文件未重写则重写；链文件已重写而锚点仍旧（崩溃发生在两次原子移动之间），
     * 则按保留事件重算锚点。
     */
    private List<AuditEvent> finishCompaction() throws IOException {
        CompactIntent intent = mapper.readValue(Files.readAllBytes(intentFile), CompactIntent.class);
        long keepBeforeSeq = intent.keepBeforeSeq();

        List<AuditEvent> all = Files.exists(eventsFile) ? readAll() : List.of();
        boolean alreadyRewritten = all.stream().allMatch(e -> e.seq() >= keepBeforeSeq);

        List<AuditEvent> retained;
        if (alreadyRewritten) {
            retained = all;
        } else {
            retained = all.stream().filter(e -> e.seq() >= keepBeforeSeq).toList();
            Path tmp = dir.resolve("events.jsonl.tmp");
            writeEvents(tmp, retained);
            moveAtomically(tmp, eventsFile);
        }

        Anchor anchor;
        if (retained.isEmpty()) {
            anchor = Anchor.empty();
        } else {
            AuditEvent head = retained.get(0);
            AuditEvent tail = retained.get(retained.size() - 1);
            anchor = new Anchor(head.seq(), head.hash(), tail.seq(), tail.hash(), retained.size());
        }
        atomicWriteJson(anchorFile, anchor);
        Files.deleteIfExists(intentFile);
        return retained;
    }

    // ---- 工具 ----

    private void writeEvents(Path target, List<AuditEvent> events) throws IOException {
        try (BufferedWriter w = Files.newBufferedWriter(target,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
            for (AuditEvent e : events) {
                w.write(mapper.writeValueAsString(e));
                w.write('\n');
            }
            w.flush();
        }
    }

    private void atomicWriteJson(Path target, Object value) throws IOException {
        Path tmp = target.resolveSibling(target.getFileName() + ".tmp");
        try (BufferedWriter w = Files.newBufferedWriter(tmp,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
            w.write(mapper.writeValueAsString(value));
            w.flush();
        }
        moveAtomically(tmp, target);
    }

    private static void moveAtomically(Path src, Path dst) throws IOException {
        try {
            Files.move(src, dst, java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException atomicFailed) {
            Files.move(src, dst, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        }
    }
}
