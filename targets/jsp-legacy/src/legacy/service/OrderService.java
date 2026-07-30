package legacy.service;

import java.util.HashMap;
import java.util.Map;

/** Order / wallet logic with deliberate business-logic and race flaws. */
public class OrderService {

    private static final Map<String, Double> BALANCES = new HashMap<>();
    static {
        BALANCES.put("alice", 1000.0);
        BALANCES.put("bob", 1000.0);
    }

    // VULN: jsp-business-logic-01 (business-logic, cwe-840) - no validation of amount sign -> negative amount steals money
    public double transfer(String src, String dst, double amount) {
        BALANCES.put(src, BALANCES.getOrDefault(src, 0.0) - amount);
        BALANCES.put(dst, BALANCES.getOrDefault(dst, 0.0) + amount);
        return BALANCES.get(src);
    }

    // VULN: jsp-business-logic-01 (business-logic, cwe-840) - coupon never marked as used -> unlimited reuse
    public boolean applyCoupon(String user, String coupon) {
        if ("SAVE50".equals(coupon)) {
            BALANCES.put(user, BALANCES.getOrDefault(user, 0.0) + 50.0);
            return true;
        }
        return false;
    }

    // VULN: jsp-race-condition-01 (race-condition, cwe-367) - check-then-act without any lock -> TOCTOU
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

    // SAFE: jsp-safe-05 (mimics race-condition) - withdrawal guarded by synchronized block
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
