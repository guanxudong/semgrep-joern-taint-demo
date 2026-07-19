package com.baddemo.services;

import com.baddemo.utils.ExecUtil;

/** Diagnostic command logic; taint stored in a field between calls. */
public class ToolService {

    /** Tainted value staged by the controller (taint via field). */
    private String target;

    public void stageTarget(String host) {
        this.target = host;
    }

    /** Reads the staged field and reaches the shell sink (deep chain end). */
    public int runStagedDiag() throws Exception {
        return ExecUtil.run("ping -c 1 " + this.target);
    }
}
