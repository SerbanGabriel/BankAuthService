using Microsoft.AspNetCore.Authorization;

namespace AuthorizationService.JwtToken.Security.PermissionHandler
{
    public class PermissionRequirement : IAuthorizationRequirement
    {
        public string Permission { get; }

        public PermissionRequirement(string permission)
        {
            Permission = permission;
        }
    }
}
