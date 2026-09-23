package com.github.xingjianluo.auditlogintegrityjava.web;

import com.github.xingjianluo.auditlogintegrityjava.service.DuplicateEventException;
import com.github.xingjianluo.auditlogintegrityjava.service.IntegrityException;
import com.github.xingjianluo.auditlogintegrityjava.storage.AuditStoreException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

/**
 * 把不同类型失败映射为可区分的 HTTP 错误类别。
 */
@RestControllerAdvice
public class AuditExceptionHandler {

    @ExceptionHandler(IntegrityException.class)
    public ResponseEntity<Map<String, Object>> integrity(IntegrityException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of(
                "errorType", "INTEGRITY_FAILED",
                "message", ex.getMessage(),
                "report", ex.getReport()));
    }

    @ExceptionHandler(DuplicateEventException.class)
    public ResponseEntity<Map<String, Object>> duplicate(DuplicateEventException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of(
                "errorType", "DUPLICATE_EVENT_CONFLICT",
                "message", ex.getMessage()));
    }

    @ExceptionHandler(AuditStoreException.class)
    public ResponseEntity<Map<String, Object>> store(AuditStoreException ex) {
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(Map.of(
                "errorType", "STORAGE_ERROR",
                "message", ex.getMessage()));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> badRequest(IllegalArgumentException ex) {
        return ResponseEntity.badRequest().body(Map.of(
                "errorType", "BAD_REQUEST",
                "message", ex.getMessage()));
    }
}
