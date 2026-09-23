package com.github.xingjianluo.auditlogintegrityjava.storage;

/**
 * 存储层异常（磁盘 IO、文件损坏等）。
 */
public class AuditStoreException extends RuntimeException {
    public AuditStoreException(String message) {
        super(message);
    }

    public AuditStoreException(String message, Throwable cause) {
        super(message, cause);
    }
}
