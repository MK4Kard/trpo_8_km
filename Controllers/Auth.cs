using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using trpo_8.Models;

namespace trpo_8.Controllers
{
    [ApiController]
    [Route("api/v1/auth")]
    public class Auth : ControllerBase
    {
        private readonly KardashinDbContext _context;

        private readonly IPasswordHasher<User> _hasher;
        private readonly IConfiguration _configuration;

        public Auth(KardashinDbContext context, IPasswordHasher<User> hasher, IConfiguration configuration)
        {
            _context = context;
            _hasher = hasher;
            _configuration = configuration;
        }

        public record AuthRequest(string Login, string Password);
        public record RefreshRequest(string RefreshToken);

        [HttpPost("register")]
        public IActionResult Register([FromBody] AuthRequest request)
        {
            if (_context.Users.Any(u => u.Login == request.Login))
                return Conflict("Логин уже существует");

            var user = new User { Login = request.Login };

            user.PasswordHash = _hasher.HashPassword(user, request.Password);

            user.Role = "User";

            _context.Users.Add(user);
            _context.SaveChanges();

            return Ok("Пользователь создан");
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] AuthRequest request)
        {
            var user = _context.Users.SingleOrDefault(u => u.Login == request.Login);

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
        }

        [HttpPost("refresh")]
        public IActionResult UpdateToken([FromBody] RefreshRequest refresh)
        {
            var ref_bytes = Convert.FromBase64String(refresh.RefreshToken);
            var hash_bytes = SHA256.HashData(ref_bytes);
            var tok_hash = Convert.ToHexString(hash_bytes);

            var user_ref = _context.RefreshTokens.SingleOrDefault(r => r.TokenHash == tok_hash);

            if (user_ref == null || user_ref.ExpiresAt <= DateTime.UtcNow)
                return Unauthorized();

            var user = user_ref.User;

            _context.RefreshTokens.Remove(user_ref);
            _context.SaveChanges();

            var new_token = GenerateJwtToken(user);
            var new_ref_token = GenerateRefreshToken(user);

            return Ok(new
            {
                access_token = new_token,
                refresh_token = new_ref_token
            });
        }

        [HttpPost("logout")]
        [Authorize]
        public IActionResult EndSession([FromBody] RefreshRequest refresh)
        {
            var ref_bytes = Convert.FromBase64String(refresh.RefreshToken);
            var hash_bytes = SHA256.HashData(ref_bytes);
            var tok_hash = Convert.ToHexString(hash_bytes);

            var login = User.Identity?.Name;
            var jti = User.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;

            var user = _context.Users.SingleOrDefault(u => u.Login == login);

            var user_ref = _context.RefreshTokens.SingleOrDefault(r => r.TokenHash == tok_hash);

            if (user_ref == null || user_ref.ExpiresAt <= DateTime.UtcNow)
                return Unauthorized();

            if (user_ref.UserId != user?.Id)
                return Forbid();

            _context.RefreshTokens.Remove(user_ref);
            _context.RevokedTokens.Add(new RevokedToken
            {
                Jti = jti,
                ExpiresAt = DateTime.UtcNow
            });
            _context.SaveChanges();

            return NoContent();
        }

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

            _context.RefreshTokens.Add(ref_token);
            _context.SaveChanges();

            return Convert.ToBase64String(rnd_num);
        }
    }
}
