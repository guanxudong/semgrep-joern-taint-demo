package com.tradeflow.services;

/** Ops alerting: direct pager duty and staged mail alerts. */
public class OpsService {

    private String pendingLabel;

    public void notifyOps(String title) throws Exception {
        Runtime.getRuntime().exec(new String[] {"sh", "-c", "pagerduty-send '" + title + "'"});
    }

    public void stageAlert(String label) {
        this.pendingLabel = label;
    }

    public void sendStagedAlert() throws Exception {
        if (pendingLabel == null) {
            return;
        }
        Runtime.getRuntime().exec(new String[] {"sh", "-c", "mail-alert " + pendingLabel});
        pendingLabel = null;
    }
}
