using KosovaGigsApi.Authentication;
using KosovaGigsApi.Data.Models; 
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System;
using System.Threading.Tasks;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.AspNetCore.Authorization;

namespace KosovaGigsApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly IConfiguration _configuration;

        public AuthenticationController(UserManager<ApplicationUser> userManager,RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            this.userManager = userManager;
            this.roleManager = roleManager;
            _configuration = configuration;
        }
        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model, string role)
        {
            if (string.IsNullOrEmpty(role))
            {
                return BadRequest("Please specify the desired role.");
            }

            var userExist = await userManager.FindByNameAsync(model.Username);
            if (userExist != null)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error" });
            }

            ApplicationUser user = new ApplicationUser()
            {
                UserName = model.Username,
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString()
            };

            var result = await userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Messages ="Hello" });
            }

            // Check if the specified role exists
            if (!await roleManager.RoleExistsAsync(role))
            {
                return BadRequest("Invalid role specified.");
            }

            // Assign the requested role to the newly created user
            await userManager.AddToRoleAsync(user, role);

            return Ok(new Response { Status = "Success", Messages = "User created successfully" });
        }
        [HttpPost]
        [Route("Register/Freelancer")]
        public async Task<IActionResult> RegisterFreelancer([FromBody] RegisterModel model)
        {
            return await Register(model, UserRoles.Freelancer);
        }

        [HttpPost]
        [Route("Register/Client")]
        public async Task<IActionResult> RegisterClient([FromBody] RegisterModel model)
        {
            return await Register(model, UserRoles.Client);
        }
        [Authorize(Roles = "Admin")]
        [HttpPost]
        [Route("Register/Moderator")]
        public async Task<IActionResult> RegisterModerator([FromBody] RegisterModel model)
        {
            return await Register(model, UserRoles.Moderator);
        }
        [HttpPost]
        [Route("Register/Admin")]
        public async Task<IActionResult> RegisterAdmin([FromBody] RegisterModel model)
        {
            return await Register(model, UserRoles.Admin);
        }

        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var user = await userManager.FindByNameAsync(model.Username);
            if (user != null && await userManager.CheckPasswordAsync(user, model.Password))
            {
                var userRoles = await userManager.GetRolesAsync(user);
                var authClaims = new List<Claim>
                {
                    new Claim (ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };
                foreach(var userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }
                Console.WriteLine($"JWT Secret Key: {_configuration["JWT:SecretKey"]}");

                var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:SecretKey"]));
                var token = new JwtSecurityToken(
                    issuer: _configuration["JWT:ValidIssuer"],
                    audience: _configuration["JWT:ValidAudience"],
                    expires: DateTime.Now.AddHours(3),
                    claims: authClaims,
                    signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                    );
                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    expiration = token.ValidTo,
                    User = user.UserName
                });
            }

            return Unauthorized();
        }

    }
}
