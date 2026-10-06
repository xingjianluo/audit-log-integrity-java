package com.github.xingjianluo.auditlogintegrityjava.service;

/**
 * 一次并入操作的结果。
 *
 * @param outcome     并入结论
 * @param mergedCount 本次新并入的记录条数（幂等忽略/拒绝时为 0）
 * @param totalEvents 操作完成后本地链总条数（失败时为操作前条数）
 * @param detail      人类可读的判定依据
 */
public record ImportMergeResult(
        ImportMergeOutcome outcome,
        int mergedCount,
        int totalEvents,
        String detail) {
}
