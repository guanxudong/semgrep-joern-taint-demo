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

        [HttpGet("search")]
        public IActionResult Search([FromQuery] string q)
        {
            SqlDataReader rows = _repo.QueryUnsafe("SELECT id, username FROM users WHERE username LIKE '%" + q + "%'");
            return Ok(rows);
        }

        [HttpGet("lookup")]
        public IActionResult Lookup([FromQuery] string name)
        {
            _userService.StageName(name);
            SqlDataReader rows = _userService.FindStaged();
            return Ok(rows);
        }

        [HttpGet("{id}")]
        public IActionResult GetUser(string id)
        {
            return Ok(_userService.FindById(id));
        }

        [HttpGet("search_safe")]
        public IActionResult SearchSafe([FromQuery] string q)
        {
            SqlDataReader rows = _repo.QuerySafe("SELECT id, username FROM users WHERE username LIKE @p1", "%" + q + "%");
            return Ok(rows);
        }

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
