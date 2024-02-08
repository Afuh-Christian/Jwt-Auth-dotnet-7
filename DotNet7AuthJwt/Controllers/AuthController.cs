using BCrypt.Net;
using DotNet7AuthJwt.Models;
using DotNet7AuthJwt.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace DotNet7AuthJwt.Controllers
{
    [Route("api/[controller]/[action]")]
    [ApiController]
 
    public class AuthController : ControllerBase
    {
        public static User user = new User();


        public AuthController(IConfiguration configuration
            , IUserServiceApp userService
            )
        {
            this._configuration = configuration;
           this.userService = userService;
        }
        private readonly IUserServiceApp userService;
        private readonly IConfiguration _configuration;

        [HttpPost]
        public ActionResult<User> Register(UserDto request)
        {
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(request.Password);

            user.PasswordHash = passwordHash;
            user.Username = request.Username;

            return  Ok(user);
        }


        [HttpPost]
        public ActionResult<User> Login(UserDto request)
        {
            if(request.Username != user.Username)
            {
                return BadRequest("User not found"); 
            }

            if(!BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
            {
                return BadRequest("Wrong Password");
            }

            string token = CreateToken(user); 

            return Ok(token);
        }



        [HttpGet , Authorize]
        public ActionResult<string> GetName()
        {
            return Ok(this.userService.GetName());
        }


        
        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>
            {
                    new (ClaimTypes.Name , user.Username),
                    new Claim(ClaimTypes.Role , "User") ,  //// New role added ... Or we can do this in the user models itself ... 
                    new Claim(ClaimTypes.Role , "Admin") , 
                };

            /// Get key fron appsettings.json and encode . 
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetSection("AppSettings:Token").Value!));
            
            // To get signing credentials 
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);

            // Generate Token 
            var token = new JwtSecurityToken(
                claims: claims , 
                expires:DateTime.Now.AddDays(1), //one day from now
                signingCredentials: creds 
                );


            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
                
        }
    }
}
