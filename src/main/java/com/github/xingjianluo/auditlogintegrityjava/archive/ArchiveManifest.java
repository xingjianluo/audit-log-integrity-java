package com.github.xingjianluo.auditlogintegrityjava.archive;

import java.util.List;

/**
 * 归档包清单（被签名的部分）。签名覆盖本清单的规范化串，
 * 清单中的 headHash/tailHash/precedingHash 与事件链哈希共同绑定包内容。
 *
 * @param environmentId 来源环境标识（由环境公钥派生，环境间不可顶替）
 * @param precedingHash 区间前一条事件的 hash（区间从 1 开始时为创世哈希），
 *                      把区间锚定在源链位置上，防止跨区间拼接
 */
public record ArchiveManifest(
        String format,
        int version,
        String archiveId,
        String environmentId,
        long createdAt,
        long fromSeq,
        long toSeq,
        int count,
        String precedingHash,
        String headHash,
        String tailHash,
        List<Integer> policyVersions) {
}
