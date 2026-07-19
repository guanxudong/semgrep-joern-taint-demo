package com.baddemo.controllers;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.baddemo.services.ToolService;

@RestController
@RequestMapping("/tools")
public class ToolController {

    private final ToolService toolService = new ToolService();

    // VULN: java-cmdi-01 (cmdi, cwe-78) [shallow]
    @GetMapping("/ping")
    public String ping(@RequestParam String host) throws Exception {
        Process p = Runtime.getRuntime().exec("ping -c 1 " + host);
        return "rc=" + p.waitFor();
    }

    // VULN: java-cmdi-02 (cmdi, cwe-78) [deep, taint via instance field]
    @GetMapping("/diagnose")
    public String diagnose(@RequestParam String host) throws Exception {
        toolService.stageTarget(host);
        return "rc=" + toolService.runStagedDiag();
    }

    // VULN: java-rce-01 (rce, cwe-94) [shallow]
    @PostMapping("/calc")
    public String calc(@RequestBody String expr) throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("JavaScript");
        Object result = engine.eval(expr);
        return String.valueOf(result);
    }
}
