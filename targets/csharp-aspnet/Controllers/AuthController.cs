using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using BadDemo.Config;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace BadDemo.Controllers
{
    [ApiController]
    [Route("auth")]
    public class AuthController : ControllerBase
    {
        // VULN: cs-auth-flaws-01 (auth-flaws, cwe-287)
        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginRequest req)
        {
            // no lockout / rate limiting; any credentials issue a token
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(AppConfig.JwtSecret.PadRight(32, 'x')));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(
                claims: new[] { new Claim("sub", req.Username), new Claim("role", "user") },
                expires: DateTime.UtcNow.AddYears(1),
                signingCredentials: creds);
            return Ok(new JwtSecurityTokenHandler().WriteToken(token));
        }

        // VULN: cs-auth-flaws-01 (auth-flaws, cwe-287) - predictable reset token
        [HttpPost("reset")]
        public IActionResult RequestReset([FromBody] LoginRequest req)
        {
            var rng = new Random();
            return Ok(new { reset_token = rng.Next(100000, 999999).ToString() });
        }

        public class LoginRequest
        {
            public string Username { get; set; } = "";
            public string Password { get; set; } = "";
        }
    }
}
