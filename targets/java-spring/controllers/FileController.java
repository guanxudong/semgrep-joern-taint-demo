package com.baddemo.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.baddemo.services.FileService;

@RestController
@RequestMapping("/files")
public class FileController {

    private final FileService fileService = new FileService();

    // VULN: java-path-traversal-01 (path-traversal, cwe-22) [medium]
    @GetMapping("/download")
    public String download(@RequestParam String name) throws Exception {
        return fileService.readUserFile(name);
    }

    // SAFE: java-safe-04 (mimics path-traversal) - whitelist validation
    @GetMapping("/download_safe")
    public String downloadSafe(@RequestParam String name) throws Exception {
        return fileService.readWhitelisted(name);
    }
}
