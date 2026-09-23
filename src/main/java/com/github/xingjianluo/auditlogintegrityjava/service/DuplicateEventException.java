package com.github.xingjianluo.auditlogintegrityjava.service;

/**
 * 同一 eventId 以不同内容重复提交。
 */
public class DuplicateEventException extends RuntimeException {
    public DuplicateEventException(String message) {
        super(message);
    }
}
