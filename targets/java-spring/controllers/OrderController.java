package com.baddemo.controllers;

import java.util.Map;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.baddemo.services.OrderService;

@RestController
@RequestMapping("/orders")
public class OrderController {

    private final OrderService orderService = new OrderService();

    // VULN: java-business-logic-01 (business-logic, cwe-840) - negative amount accepted
    @PostMapping("/transfer")
    public String transfer(@RequestBody Map<String, Object> body) {
        double balance = orderService.transfer(
                (String) body.get("src"), (String) body.get("dst"),
                Double.parseDouble(body.get("amount").toString()));
        return "balance=" + balance;
    }

    // VULN: java-business-logic-01 (business-logic, cwe-840) - coupon never invalidated
    @PostMapping("/coupon")
    public String coupon(@RequestBody Map<String, String> body) {
        boolean ok = orderService.applyCoupon(body.get("user"), body.get("coupon"));
        return "applied=" + ok;
    }

    // VULN: java-race-condition-01 (race-condition, cwe-367)
    @PostMapping("/withdraw")
    public String withdraw(@RequestBody Map<String, Object> body) {
        boolean ok = orderService.withdraw(
                (String) body.get("user"), Double.parseDouble(body.get("amount").toString()));
        return "ok=" + ok;
    }

    // SAFE: java-safe-05 (mimics race-condition) - synchronized withdraw
    @PostMapping("/withdraw_safe")
    public String withdrawSafe(@RequestBody Map<String, Object> body) {
        boolean ok = orderService.withdrawSafe(
                (String) body.get("user"), Double.parseDouble(body.get("amount").toString()));
        return "ok=" + ok;
    }
}
