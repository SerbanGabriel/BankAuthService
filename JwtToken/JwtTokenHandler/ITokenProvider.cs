using DatabaseService;

namespace AuthorizationService.JwtToken.JwtTokenHandler
{
    public interface ITokenProvider
    {
        public string GenerateToken(User user);
    }
}
