using System.Collections.Generic;
using System.IO;
using BadDemo.Config;

namespace BadDemo.Services
{
    /// <summary>File retrieval logic.</summary>
    public class FileService
    {
        private static readonly HashSet<string> Allowed = new HashSet<string> { "readme.txt", "help.txt" };

        /// <summary>Concatenates user-controlled name into a filesystem path (sink).</summary>
        public string ReadUserFile(string name)
        {
            var path = Path.Combine(AppConfig.UploadDir, name);
            return File.ReadAllText(path);
        }

        public string ReadWhitelisted(string name)
        {
            if (!Allowed.Contains(name))
            {
                throw new InvalidDataException("file not allowed");
            }
            return File.ReadAllText(Path.Combine(AppConfig.UploadDir, name));
        }
    }
}
