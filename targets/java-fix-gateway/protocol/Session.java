package com.tradeflow.protocol;

/** Session state for one connected counterparty. */
public class Session {
    private final String compId;
    private String role = "trader";
    private long lastSeqNum = 0;

    public Session(String compId) {
        this.compId = compId;
    }

    public String getCompId() {
        return compId;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public long getLastSeqNum() {
        return lastSeqNum;
    }

    public void setLastSeqNum(long lastSeqNum) {
        this.lastSeqNum = lastSeqNum;
    }
}
