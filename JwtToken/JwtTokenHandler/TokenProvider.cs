using AuthorizationService.JwtToken.JwtTokenHandler;
using DatabaseService;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text;

namespace AuthorizationService.JwtToken.Security.JwtTokenHandler
{
    public class TokenProvider(IConfiguration configuration) : ITokenProvider
    {
        public string GenerateToken(User request)
        {
            string secretKey = configuration["Jwt:Secret"];
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim> {
                        new Claim(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Sub, request.Email),
                        new Claim("email_verified", request.Email),
                        new Claim(ClaimTypes.Name, request.Email),
                        new Claim(ClaimTypes.Role, request.Role)
                    };


            if (request.Permissions != null)
            {
                claims.AddRange(request.Permissions.Select(p => new Claim("permission", p.Permission)));
            }

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(configuration.GetValue<int>("Jwt:ExpirationInMinutes")),
                SigningCredentials = credentials,
                Issuer = configuration["Jwt:Issuer"],
                Audience = configuration["Jwt:Audience"]
            };

            var handler = new JsonWebTokenHandler();
            string token = handler.CreateToken(tokenDescriptor);

            return token;
        }
    }
}
