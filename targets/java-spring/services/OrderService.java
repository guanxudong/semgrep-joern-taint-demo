package com.baddemo.services;

import java.util.HashMap;
import java.util.Map;

/** Order / wallet logic with deliberate business-logic and race flaws. */
public class OrderService {

    private static final Map<String, Double> BALANCES = new HashMap<>();
    static {
        BALANCES.put("alice", 1000.0);
        BALANCES.put("bob", 1000.0);
    }

    /** No validation of amount sign -> negative amount steals money. */
    public double transfer(String src, String dst, double amount) {
        BALANCES.put(src, BALANCES.getOrDefault(src, 0.0) - amount);
        BALANCES.put(dst, BALANCES.getOrDefault(dst, 0.0) + amount);
        return BALANCES.get(src);
    }

    /** Coupon is never marked as used -> unlimited reuse. */
    public boolean applyCoupon(String user, String coupon) {
        if ("SAVE50".equals(coupon)) {
            BALANCES.put(user, BALANCES.getOrDefault(user, 0.0) + 50.0);
            return true;
        }
        return false;
    }

    /** Check-then-act without any lock -> race condition (TOCTOU). */
    public boolean withdraw(String user, double amount) {
        double balance = BALANCES.getOrDefault(user, 0.0);
        if (balance >= amount) {
            // attacker fires many concurrent requests here
            BALANCES.put(user, balance - amount);
            return true;
        }
        return false;
    }

    private final Object lock = new Object();

    public boolean withdrawSafe(String user, double amount) {
        synchronized (lock) {
            double balance = BALANCES.getOrDefault(user, 0.0);
            if (balance >= amount) {
                BALANCES.put(user, balance - amount);
                return true;
            }
            return false;
        }
    }
}
