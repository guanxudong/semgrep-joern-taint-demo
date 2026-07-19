using System.Data.SqlClient;
using BadDemo.Data;
using BadDemo.Services;
using Microsoft.AspNetCore.Mvc;

namespace BadDemo.Controllers
{
    [ApiController]
    [Route("users")]
    public class UsersController : ControllerBase
    {
        private readonly UserRepository _repo = new UserRepository();
        private readonly UserService _userService = new UserService();

        // VULN: cs-sqli-01 (sqli, cwe-89) [shallow]
        [HttpGet("search")]
        public IActionResult Search([FromQuery] string q)
        {
            SqlDataReader rows = _repo.QueryUnsafe("SELECT id, username FROM users WHERE username LIKE '%" + q + "%'");
            return Ok(rows);
        }

        // VULN: cs-sqli-02 (sqli, cwe-89) [deep, taint via instance field]
        [HttpGet("lookup")]
        public IActionResult Lookup([FromQuery] string name)
        {
            _userService.StageName(name);
            SqlDataReader rows = _userService.FindStaged();
            return Ok(rows);
        }

        // VULN: cs-idor-01 (idor, cwe-639)
        [HttpGet("{id}")]
        public IActionResult GetUser(string id)
        {
            return Ok(_userService.FindById(id));
        }

        // SAFE: cs-safe-01 (mimics sqli) - parameterized query
        [HttpGet("search_safe")]
        public IActionResult SearchSafe([FromQuery] string q)
        {
            SqlDataReader rows = _repo.QuerySafe("SELECT id, username FROM users WHERE username LIKE @p1", "%" + q + "%");
            return Ok(rows);
        }

        // SAFE: cs-safe-02 (mimics idor) - ownership checked against caller identity
        [HttpGet("me/{id}")]
        public IActionResult GetOwnProfile(string id, [FromHeader(Name = "X-User-Id")] string sessionUser)
        {
            if (sessionUser != id)
            {
                return Forbid();
            }
            return Ok(_userService.FindByIdSafe(id));
        }
    }
}
