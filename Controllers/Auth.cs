using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using trpo_8.DI_interfaces;
using trpo_8.Models;

namespace trpo_8.Controllers
{
    [ApiController]
    [Route("api/v1/auth")]
    public class Auth : ControllerBase
    {
        private readonly IUser _user;
        private readonly IPasswordHasher<User> _hasher;
        private readonly IConfiguration _configuration;
        private readonly IRefreshToken _refreshToken;

        public Auth(IUser user, IPasswordHasher<User> hasher, IConfiguration configuration, IRefreshToken refreshToken)
        {
            _user = user;
            _hasher = hasher;
            _configuration = configuration;
            _refreshToken = refreshToken;
        }

        public record AuthRequest(string Login, string Password);

        [HttpPost("register")]
        public IActionResult Register(AuthRequest request)
        {
            //if (_user.Any(u => u.Login == request.Login))
            //    return Conflict("Логин уже существует");

            var user = new User { Login = request.Login };

            user.PasswordHash = _hasher.HashPassword(user, request.Password);

            user.Role = "User";

            //_users.Add(user);

            return Ok("Пользователь создан");
        }

        /*[HttpPost("login")]
        public IActionResult Login(AuthRequest request)
        {
            var user = _users.Find(u => u.Login == request.Login);

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
            var ref_token = GenerateRefreshToken(user);

            return Ok(new
            {
                access_token = token,
                refresh_token = ref_token
            });
        }*/

        private string GenerateJwtToken(User user)
        {
            var claims = new[] // утверждения
            {
                new Claim(ClaimTypes.Name, user.Login),
                new Claim(ClaimTypes.Role, user.Role),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!));

            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: "ExampleApi",
                audience: "ExampleApiClient",
                claims: claims,
                expires: DateTime.UtcNow.AddSeconds(60),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private string GenerateRefreshToken(User user)
        {
            var rnd_num = RandomNumberGenerator.GetBytes(32);

            var tok_hash = SHA256.HashData(rnd_num);

            var ref_token = new RefreshToken
            {
                UserId = user.Id,
                TokenHash = Convert.ToHexString(tok_hash),
                ExpiresAt = DateTime.UtcNow.AddDays(7)
            };

            //_refreshTokens.Add(ref_token);

            return Convert.ToBase64String(rnd_num);
        }
    }
}
