package com.github.xingjianluo.auditlogintegrityjava.store;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.xingjianluo.auditlogintegrityjava.config.AuditProperties;
import com.github.xingjianluo.auditlogintegrityjava.crypto.HashService;
import com.github.xingjianluo.auditlogintegrityjava.model.ChainAnchor;
import com.github.xingjianluo.auditlogintegrityjava.model.StoredRecord;
import com.github.xingjianluo.auditlogintegrityjava.service.ChainIntegrityVerifier;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Repository;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Append-only file store:
 * <ul>
 *   <li>{@code audit.log}: one JSON record per line; appends are fsynced,</li>
 *   <li>{@code audit.tail}: persisted {@code seq/hash} of the last record,
 *       used to detect tail truncation,</li>
 *   <li>{@code anchor}: {@code seq/hash/updatedAt} head anchor after pruning,</li>
 *   <li>{@code export-cursor}: last seq already exported.</li>
 * </ul>
 * Every public method is guarded by one monitor. Mutations build a new
 * immutable {@link ChainState} (records + anchor + tail pointer) and replace
 * it atomically, while {@link #readSnapshot()} always reads record content
 * back from disk so tampering/deletion/reordering by an external actor is
 * visible even within a running process.
 */
@Repository
public class FileAuditLogStore implements AuditLogStore {

    private final AuditProperties properties;
    private final ObjectMapper mapper = new ObjectMapper();

    private Path dir;
    private Path logFile;
    private Path tailFile;
    private Path anchorFile;
    private Path cursorFile;

    private ChainState state = ChainState.genesis();
    private long exportCursor;

    public FileAuditLogStore(AuditProperties properties, HashService hashService) {
        this.properties = properties;
    }

    @PostConstruct
    public void init() {
        try {
            dir = Path.of(properties.getStorageDir());
            Files.createDirectories(dir);
            logFile = dir.resolve("audit.log");
            tailFile = dir.resolve("audit.tail");
            anchorFile = dir.resolve("anchor");
            cursorFile = dir.resolve("export-cursor");
            if (Files.notExists(logFile)) {
                Files.createFile(logFile);
            }
            ChainAnchor anchor = loadAnchor();
            List<StoredRecord> records = parseLogRecords();
            long tailSeq;
            String tailHash;
            if (!records.isEmpty()) {
                StoredRecord last = records.get(records.size() - 1);
                tailSeq = readLong(tailFile, last.seq());
                tailHash = readText(tailFile, last.hash());
            } else if (anchor != null) {
                tailSeq = readLong(tailFile, anchor.seq());
                tailHash = readText(tailFile, anchor.hash());
            } else {
                tailSeq = 0L;
                tailHash = ChainIntegrityVerifier.GENESIS;
            }
            state = new ChainState(List.copyOf(records), anchor, tailSeq, tailHash);
            exportCursor = readLong(cursorFile, anchor == null ? 0L : anchor.seq());
        } catch (IOException e) {
            throw new AuditStorageException("failed to initialize audit store at "
                    + properties.getStorageDir(), e);
        }
    }

    private List<StoredRecord> parseLogRecords() throws IOException {
        // Tolerant load: malformed lines are skipped rather than crashing the
        // process on restart. They remain on disk and readSnapshot() reports
        // them as CORRUPTED_RECORD during verification.
        List<StoredRecord> parsed = new ArrayList<>();
        for (String line : Files.readAllLines(logFile, StandardCharsets.UTF_8)) {
            if (line.isBlank()) {
                continue;
            }
            try {
                parsed.add(mapper.readValue(line, StoredRecord.class));
            } catch (IOException malformed) {
                // skip; verification will flag the corrupt line number
            }
        }
        return parsed;
    }

    private ChainAnchor loadAnchor() throws IOException {
        if (Files.notExists(anchorFile)) {
            return null;
        }
        List<String> lines = Files.readAllLines(anchorFile, StandardCharsets.UTF_8);
        long seq = -1;
        String hash = null;
        long updatedAt = 0;
        for (String line : lines) {
            if (line.startsWith("seq=")) {
                seq = Long.parseLong(line.substring(4).trim());
            } else if (line.startsWith("hash=")) {
                hash = line.substring(5).trim();
            } else if (line.startsWith("updatedAt=")) {
                updatedAt = Long.parseLong(line.substring(10).trim());
            }
        }
        if (seq < 0 || hash == null) {
            throw new AuditStorageException("invalid anchor file: " + anchorFile, null);
        }
        return new ChainAnchor(seq, hash, updatedAt);
    }

    @Override
    public synchronized void append(StoredRecord record) {
        List<StoredRecord> current = state.records();
        long expectedSeq = nextSeq();
        String expectedPrev = headHash();
        if (record.seq() != expectedSeq) {
            throw new AuditStorageException(
                    "append rejected: seq=" + record.seq() + " expected=" + expectedSeq, null);
        }
        if (!expectedPrev.equals(record.prevHash())) {
            throw new AuditStorageException(
                    "append rejected: prevHash does not match current head hash", null);
        }
        for (StoredRecord r : current) {
            if (r.eventId().equals(record.eventId())) {
                throw new AuditStorageException(
                        "append rejected: duplicate eventId " + record.eventId(), null);
            }
        }
        try {
            appendLineFsync(mapper.writeValueAsString(record));
            List<StoredRecord> next = new ArrayList<>(current.size() + 1);
            next.addAll(current);
            next.add(record);
            state = new ChainState(List.copyOf(next), state.anchor(),
                    record.seq(), record.hash());
            writeTail();
        } catch (IOException e) {
            throw new AuditStorageException("failed to append record seq=" + record.seq(), e);
        }
    }

    private void appendLineFsync(String json) throws IOException {
        try (java.io.FileOutputStream fos = new java.io.FileOutputStream(logFile.toFile(), true);
             var out = new java.io.BufferedOutputStream(fos)) {
            out.write(json.getBytes(StandardCharsets.UTF_8));
            out.write('\n');
            out.flush();
            fos.getFD().sync();
        }
    }

    private void writeTail() throws IOException {
        writeAtomic(tailFile, "seq=" + state.tailSeq() + "\nhash=" + state.tailHash() + "\n");
    }

    @Override
    public synchronized LogSnapshot readSnapshot() {
        // Content is read from disk (to catch external tampering); the tail
        // pointer comes from the authoritative in-memory state that moves
        // atomically with appends/prunes (to catch truncation and avoid
        // mixed-version reads). Corrupt disk lines are reported separately.
        try {
            List<StoredRecord> parsed = new ArrayList<>();
            List<Integer> corrupt = new ArrayList<>();
            int lineNo = 0;
            for (String line : Files.readAllLines(logFile, StandardCharsets.UTF_8)) {
                lineNo++;
                if (line.isBlank()) {
                    continue;
                }
                try {
                    parsed.add(mapper.readValue(line, StoredRecord.class));
                } catch (IOException parseFailure) {
                    corrupt.add(lineNo);
                }
            }
            return new LogSnapshot(List.copyOf(parsed), List.copyOf(corrupt),
                    state.tailSeq(), state.tailHash());
        } catch (IOException e) {
            throw new AuditStorageException("failed to read audit log", e);
        }
    }

    @Override
    public synchronized boolean existsByEventId(String eventId) {
        for (StoredRecord r : state.records()) {
            if (r.eventId().equals(eventId)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public synchronized long nextSeq() {
        List<StoredRecord> records = state.records();
        if (!records.isEmpty()) {
            return records.get(records.size() - 1).seq() + 1;
        }
        return state.anchor() == null ? 1L : state.anchor().seq() + 1;
    }

    @Override
    public synchronized String headHash() {
        List<StoredRecord> records = state.records();
        if (!records.isEmpty()) {
            return records.get(records.size() - 1).hash();
        }
        return state.anchor() == null ? ChainIntegrityVerifier.GENESIS : state.anchor().hash();
    }

    @Override
    public synchronized ChainAnchor getAnchor() {
        return state.anchor();
    }

    @Override
    public synchronized void pruneHead(List<StoredRecord> survivors, ChainAnchor newAnchor) {
        try {
            StringBuilder sb = new StringBuilder();
            for (StoredRecord r : survivors) {
                sb.append(mapper.writeValueAsString(r)).append('\n');
            }
            long newTailSeq;
            String newTailHash;
            if (survivors.isEmpty()) {
                if (newAnchor != null) {
                    throw new AuditStorageException(
                            "prune rejected: no survivors requires a null (GENESIS) anchor", null);
                }
                newTailSeq = 0L;
                newTailHash = ChainIntegrityVerifier.GENESIS;
            } else {
                StoredRecord last = survivors.get(survivors.size() - 1);
                newTailSeq = last.seq();
                newTailHash = last.hash();
            }
            writeAtomic(logFile, sb.toString());
            state = new ChainState(List.copyOf(survivors), newAnchor, newTailSeq, newTailHash);
            writeTail();

            if (newAnchor == null) {
                Files.deleteIfExists(anchorFile);
            } else {
                writeAtomic(anchorFile, "seq=" + newAnchor.seq()
                        + "\nhash=" + newAnchor.hash()
                        + "\nupdatedAt=" + newAnchor.updatedAt() + "\n");
            }
            long minimumCursor = newAnchor == null ? 0L : newAnchor.seq();
            if (exportCursor < minimumCursor) {
                exportCursor = minimumCursor;
                writeCursor();
            }
        } catch (IOException e) {
            throw new AuditStorageException("failed to prune audit log head", e);
        }
    }

    @Override
    public synchronized long getExportCursor() {
        return exportCursor;
    }

    @Override
    public synchronized void updateExportCursor(long seq) {
        if (seq < exportCursor) {
            return;
        }
        exportCursor = seq;
        try {
            writeCursor();
        } catch (IOException e) {
            throw new AuditStorageException("failed to persist export cursor", e);
        }
    }

    private void writeCursor() throws IOException {
        writeAtomic(cursorFile, Long.toString(exportCursor));
    }

    private void writeAtomic(Path target, String content) throws IOException {
        Path tmp = target.resolveSibling(target.getFileName() + ".tmp");
        // Write and fsync on the SAME open channel, then atomically rename.
        // Reopening the temp file with a truncating FileOutputStream (as a
        // naive separate fsync step would) empties the file.
        try (java.nio.channels.FileChannel ch = java.nio.channels.FileChannel.open(tmp,
                StandardOpenOption.CREATE, StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING)) {
            java.nio.ByteBuffer buf = java.nio.ByteBuffer.wrap(
                    content.getBytes(StandardCharsets.UTF_8));
            while (buf.hasRemaining()) {
                ch.write(buf);
            }
            ch.force(true);
        }
        Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    private long readLong(Path file, long fallback) throws IOException {
        if (Files.notExists(file)) {
            return fallback;
        }
        String s = Files.readString(file, StandardCharsets.UTF_8).trim();
        if (s.isEmpty()) {
            return fallback;
        }
        String firstLine = s.split("\\R")[0];
        if (firstLine.startsWith("seq=")) {
            return Long.parseLong(firstLine.substring(4).trim());
        }
        return Long.parseLong(firstLine.trim());
    }

    private String readText(Path file, String fallback) throws IOException {
        if (Files.notExists(file)) {
            return fallback;
        }
        for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
            if (line.startsWith("hash=")) {
                return line.substring(5).trim();
            }
        }
        return fallback;
    }
}
