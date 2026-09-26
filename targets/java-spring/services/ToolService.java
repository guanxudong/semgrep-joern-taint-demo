package com.baddemo.services;

import com.baddemo.utils.ExecUtil;

/** Diagnostic command logic. */
public class ToolService {

    /** Value staged by the controller. */
    private String target;

    public void stageTarget(String host) {
        this.target = host;
    }

    /** Reads the staged field and runs the diagnostic. */
    public int runStagedDiag() throws Exception {
        return ExecUtil.run("ping -c 1 " + this.target);
    }
}
