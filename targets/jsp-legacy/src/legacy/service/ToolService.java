package legacy.service;

import legacy.util.ExecUtil;

/** Diagnostic command logic; taint stored in a field between calls. */
public class ToolService {

    /** Tainted value staged by the page (taint via field). */
    private String target;

    public void stageTarget(String host) {
        this.target = host;
    }

    // VULN: jsp-cmdi-02 (cmdi, cwe-78) - reads the staged field and reaches the shell sink (deep chain end)
    public int runStagedDiag() throws Exception {
        return ExecUtil.run("ping -c 1 " + this.target);
    }
}
