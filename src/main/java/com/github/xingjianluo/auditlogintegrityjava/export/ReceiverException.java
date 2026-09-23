package com.github.xingjianluo.auditlogintegrityjava.export;

/**
 * 接收端故障（与完整性失败是两类不同结果）。
 */
public class ReceiverException extends RuntimeException {
    public ReceiverException(String message) {
        super(message);
    }
}
