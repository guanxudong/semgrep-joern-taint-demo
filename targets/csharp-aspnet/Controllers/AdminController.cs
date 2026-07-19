using BadDemo.Data;
using Microsoft.AspNetCore.Mvc;

namespace BadDemo.Controllers
{
    [ApiController]
    [Route("admin")]
    public class AdminController : ControllerBase
    {
        private readonly UserRepository _repo = new UserRepository();

        // VULN: cs-broken-access-control-01 (broken-access-control, cwe-862)
        [HttpGet("users")]
        public IActionResult ListAllUsers()
        {
            return Ok(_repo.QueryUnsafe("SELECT id, username, email, role FROM users"));
        }

        // VULN: cs-broken-access-control-01 (broken-access-control, cwe-862)
        [HttpDelete("users/{id}")]
        public IActionResult DeleteUser(string id)
        {
            _repo.ExecuteUnsafe("DELETE FROM users WHERE id = " + id);
            return Ok("deleted " + id);
        }
    }
}
