using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using trpo_8.Models;

namespace trpo_8.Controllers
{
    [ApiController]
    [Route("api/v1/auth")]
    public class Auth : ControllerBase
    {
        private readonly KardashinDbContext _context = new();
        private readonly IPasswordHasher<User> _hasher;
        private readonly IConfiguration _configuration;

        public Auth(IPasswordHasher<User> hasher, IConfiguration configuration)
        {
            _hasher = hasher;
            _configuration = configuration;
        }

        public record AuthRequest(string Login, string Password);

        [HttpPost("register")]
        public IActionResult Register(AuthRequest request)
        {
            if (_context.Users.ToList().Any(u => u.Login == request.Login))
                return Conflict("Логин уже существует");

            var user = new User { Login = request.Login };

            user.PasswordHash = _hasher.HashPassword(user, request.Password);

            user.Role = "User";

            _context.Users.Add(user);

            _context.SaveChanges();

            return Ok("Пользователь создан");
        }

        [HttpPost("login")]
        public IActionResult Login (AuthRequest request)
        {
            var user = _context.Users.ToList().Find(u => u.Login == request.Login);

            if (user == null)
                return Unauthorized("Неверная пара логин/пароль");

            var result = _hasher.VerifyHashedPassword(
                user,
                user.PasswordHash,
                request.Password
            );

            if (result == PasswordVerificationResult.Failed)
                return Unauthorized("Неверная пара логин/пароль");

            var token = GenerateJwtToken(user);

            return Ok(new
            {
                access_token = token
            });
        }

        private string GenerateJwtToken(User user)
        {
            var claims = new[]
            {
                new Claim(ClaimTypes.Name, user.Login),
                new Claim(ClaimTypes.Role, user.Role)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!));

            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: "ExampleApi",
                audience: "ExampleApiClient",
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(30),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
