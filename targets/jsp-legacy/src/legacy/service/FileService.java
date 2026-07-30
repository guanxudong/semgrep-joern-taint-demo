package legacy.service;

import java.util.Set;

import legacy.config.AppConfig;
import legacy.util.FileUtil;

/** File retrieval logic. */
public class FileService {

    private static final Set<String> ALLOWED = Set.of("readme.txt", "help.txt");

    // VULN: jsp-path-traversal-01 (path-traversal, cwe-22) - passes user-controlled name down to the filesystem helper (sink hop)
    public String readUserFile(String name) throws Exception {
        return FileUtil.read(AppConfig.UPLOAD_DIR, name);
    }

    // SAFE: jsp-safe-04 (mimics path-traversal) - allow-list validation before reading
    public String readWhitelisted(String name) throws Exception {
        if (!ALLOWED.contains(name)) {
            throw new IllegalArgumentException("file not allowed");
        }
        return FileUtil.read(AppConfig.UPLOAD_DIR, name);
    }
}
