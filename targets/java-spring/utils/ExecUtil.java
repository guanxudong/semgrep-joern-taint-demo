package com.baddemo.utils;

/** Shell execution helper. */
public class ExecUtil {

    public static int run(String cmd) throws Exception {
        Process p = Runtime.getRuntime().exec(cmd);
        return p.waitFor();
    }
}
