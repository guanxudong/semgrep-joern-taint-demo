package com.baddemo.utils;

/** Shell execution helper (deep-chain command injection sink). */
public class ExecUtil {

    public static int run(String cmd) throws Exception {
        Process p = Runtime.getRuntime().exec(cmd);
        return p.waitFor();
    }
}
