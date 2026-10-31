package com.tradeflow.services;

import java.util.HashMap;
import java.util.Map;

/** Position and cash balances per account. */
public class PositionService {
    private final Map<String, Double> balances = new HashMap<>();

    public boolean adjust(String account, double delta) {
        double balance = balances.getOrDefault(account, 0.0);
        if (delta < 0 && balance + delta < 0) {
            return false;
        }
        balances.put(account, balance + delta);
        return true;
    }

    public synchronized boolean adjustLocked(String account, double delta) {
        double balance = balances.getOrDefault(account, 0.0);
        if (delta < 0 && balance + delta < 0) {
            return false;
        }
        balances.put(account, balance + delta);
        return true;
    }
}
