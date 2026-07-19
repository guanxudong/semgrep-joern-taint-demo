package com.baddemo.controllers;

import java.io.StringWriter;
import java.util.HashMap;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import freemarker.template.Configuration;
import freemarker.template.Template;

@RestController
@RequestMapping("/render")
public class RenderController {

    // VULN: java-ssti-01 (ssti, cwe-1336) [medium]
    @PostMapping("/preview")
    public String preview(@RequestBody String tpl) throws Exception {
        Configuration cfg = new Configuration(Configuration.VERSION_2_3_31);
        Template template = new Template("user-tpl", tpl, cfg);
        StringWriter out = new StringWriter();
        template.process(new HashMap<String, Object>(), out);
        return out.toString();
    }

    // VULN: java-xss-01 (xss, cwe-79) [shallow]
    @GetMapping("/hello")
    public String hello(@RequestParam String name) {
        return "<h1>Hello " + name + "</h1>";
    }
}
