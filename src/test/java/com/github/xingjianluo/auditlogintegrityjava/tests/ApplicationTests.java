package com.github.xingjianluo.auditlogintegrityjava.tests;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.nio.file.Files;

/**
 * 上下文冒烟测试。数据目录指向临时目录，避免在工程根产生运行时文件。
 */
@SpringBootTest(properties = "audit.data-dir=${java.io.tmpdir}/audit-context-test")
public class ApplicationTests {

    @BeforeAll
    static void init() throws Exception {
        Files.createDirectories(java.nio.file.Path.of(System.getProperty("java.io.tmpdir"), "audit-context-test"));
    }

    @Test
    public void contentLoad() {
    }
}
