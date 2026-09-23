package com.github.xingjianluo.auditlogintegrityjava.storage;

import com.fasterxml.jackson.annotation.JsonIgnore;

/**
 * 锚点：链头/链尾状态，单独持久化，用于检测截断与重写。
 * headSeq/headHash 指当前存储中最老一条；tailSeq/tailHash 指最新一条。
 */
public record Anchor(
        long headSeq,
        String headHash,
        long tailSeq,
        String tailHash,
        int count) {

    public static Anchor empty() {
        return new Anchor(0, "", 0, "", 0);
    }

    @JsonIgnore
    public boolean isEmpty() {
        return count == 0;
    }
}
