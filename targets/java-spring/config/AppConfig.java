package com.baddemo.config;

/** Application configuration. Secrets are hardcoded on purpose (demo target). */
public class AppConfig {
    public static final String JWT_SECRET = "secret";
    public static final String DB_URL = "jdbc:mysql://localhost:3306/baddemo";
    public static final String DB_USER = "admin";
    public static final String DB_PASSWORD = "admin123";
    public static final String UPLOAD_DIR = "/var/www/uploads";
}
