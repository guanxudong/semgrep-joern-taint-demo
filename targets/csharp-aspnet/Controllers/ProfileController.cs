using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using Microsoft.AspNetCore.Mvc;

namespace BadDemo.Controllers
{
    [ApiController]
    [Route("profile")]
    public class ProfileController : ControllerBase
    {
        [Serializable]
        public class User
        {
            public string Username = "";
            public string Email = "";
            public string Role = "user";
        }

        /// <summary>Profile update request data.</summary>
        public class UpdateProfileRequest
        {
            public string Username { get; set; } = "";
            public string Email { get; set; } = "";
            public string Role { get; set; } = "user";
        }

        private static readonly Dictionary<string, User> Users = new Dictionary<string, User>();

        [HttpPost("update")]
        public IActionResult UpdateProfile([FromBody] UpdateProfileRequest req)
        {
            if (!Users.TryGetValue(req.Username, out var user))
            {
                user = new User();
                Users[req.Username] = user;
            }
            user.Email = req.Email;
            user.Role = req.Role;
            return Ok(user);
        }

        [HttpPost("import")]
        public IActionResult ImportProfile([FromBody] string b64)
        {
            byte[] data = Convert.FromBase64String(b64);
            var formatter = new BinaryFormatter();
            using var ms = new MemoryStream(data);
            var user = (User)formatter.Deserialize(ms);
            Users[user.Username] = user;
            return Ok("imported " + user.Username);
        }
    }
}
