package com.github.xingjianluo.auditlogintegrityjava.store;

/**
 * Raised when the local audit store cannot be read or written. Callers must
 * treat this differently from an integrity verification failure.
 */
public class AuditStorageException extends RuntimeException {
    public AuditStorageException(String message, Throwable cause) {
        super(message, cause);
    }
}
