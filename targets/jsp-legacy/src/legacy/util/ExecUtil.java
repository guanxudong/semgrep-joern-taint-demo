package legacy.util;

/** Shell execution helper (deep-chain command injection sink). */
public class ExecUtil {

    // VULN: jsp-cmdi-02 (cmdi, cwe-78) - sink: Runtime.exec on a caller-built command
    public static int run(String cmd) throws Exception {
        Process p = Runtime.getRuntime().exec(cmd);
        return p.waitFor();
    }
}
