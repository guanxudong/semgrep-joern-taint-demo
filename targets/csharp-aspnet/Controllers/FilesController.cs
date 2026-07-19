using BadDemo.Services;
using Microsoft.AspNetCore.Mvc;

namespace BadDemo.Controllers
{
    [ApiController]
    [Route("files")]
    public class FilesController : ControllerBase
    {
        private readonly FileService _fileService = new FileService();

        // VULN: cs-path-traversal-01 (path-traversal, cwe-22) [medium]
        [HttpGet("download")]
        public IActionResult Download([FromQuery] string name)
        {
            return Ok(_fileService.ReadUserFile(name));
        }

        // SAFE: cs-safe-04 (mimics path-traversal) - whitelist validation
        [HttpGet("download_safe")]
        public IActionResult DownloadSafe([FromQuery] string name)
        {
            try
            {
                return Ok(_fileService.ReadWhitelisted(name));
            }
            catch
            {
                return BadRequest("file not allowed");
            }
        }
    }
}
