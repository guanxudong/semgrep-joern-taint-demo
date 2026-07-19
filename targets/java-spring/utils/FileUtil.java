package com.baddemo.utils;

import java.io.File;
import java.nio.file.Files;

/** Filesystem helper (deep-chain path traversal sink). */
public class FileUtil {

    public static String read(String baseDir, String name) throws Exception {
        File f = new File(baseDir + File.separator + name);
        return new String(Files.readAllBytes(f.toPath()));
    }
}
