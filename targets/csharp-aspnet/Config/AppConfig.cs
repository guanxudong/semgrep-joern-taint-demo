namespace BadDemo.Config
{
    /// <summary>Application configuration. Secrets are hardcoded on purpose (demo target).</summary>
    public static class AppConfig
    {
        public const string JwtSecret = "secret";
        public const string ConnectionString = "Server=localhost;Database=baddemo;User=admin;Password=admin123;";
        public const string UploadDir = "/var/www/uploads";
    }
}
