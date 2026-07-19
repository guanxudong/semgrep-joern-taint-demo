package com.baddemo.services;

import java.util.Set;

import com.baddemo.config.AppConfig;
import com.baddemo.utils.FileUtil;

/** File retrieval logic. */
public class FileService {

    private static final Set<String> ALLOWED = Set.of("readme.txt", "help.txt");

    /** Passes user-controlled name down to the filesystem helper (sink hop). */
    public String readUserFile(String name) throws Exception {
        return FileUtil.read(AppConfig.UPLOAD_DIR, name);
    }

    public String readWhitelisted(String name) throws Exception {
        if (!ALLOWED.contains(name)) {
            throw new IllegalArgumentException("file not allowed");
        }
        return FileUtil.read(AppConfig.UPLOAD_DIR, name);
    }
}
