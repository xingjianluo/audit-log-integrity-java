package com.github.xingjianluo.auditlogintegrityjava.export;

/** Receiver-side failure; must stay distinguishable from integrity failure. */
public class ReceiverException extends Exception {
    public ReceiverException(String message) {
        super(message);
    }
}
