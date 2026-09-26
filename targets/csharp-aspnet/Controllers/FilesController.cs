using BadDemo.Services;
using Microsoft.AspNetCore.Mvc;

namespace BadDemo.Controllers
{
    [ApiController]
    [Route("files")]
    public class FilesController : ControllerBase
    {
        private readonly FileService _fileService = new FileService();

        [HttpGet("download")]
        public IActionResult Download([FromQuery] string name)
        {
            return Ok(_fileService.ReadUserFile(name));
        }

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
