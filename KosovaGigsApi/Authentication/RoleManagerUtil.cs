using Microsoft.AspNetCore.Identity;

namespace KosovaGigsApi.Authentication  
{
    public static class RoleManagerUtil
    {
        public static async Task CreateRoles(IServiceProvider serviceProvider)
        {
            var RoleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole>>();
            string[] roles = { UserRoles.Freelancer, UserRoles.Client, UserRoles.Moderator, UserRoles.Admin };

            foreach (var role in roles)
            {
                if (!await RoleManager.RoleExistsAsync(role))
                {
                    await RoleManager.CreateAsync(new IdentityRole(role));
                }
            }
        }
    }
}