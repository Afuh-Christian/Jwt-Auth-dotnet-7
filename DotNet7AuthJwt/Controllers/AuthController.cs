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
using System.Security.Cryptography;
using System.Text;

namespace DotNet7AuthJwt.Controllers
{
    [Route("api/[controller]/[action]")]
    [ApiController]
 
    public class AuthController : ControllerBase
    {
        private  User user = new();


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
            var refreshToken = GenerateRefreshToken();
            SetRefreshToken(refreshToken);

            return Ok(token);
        }



        [HttpGet , Authorize]
        public ActionResult<string> GetName()
        {
            return Ok(this.userService.GetName());
        }



        // To Generate a new refresh token .... 
        [HttpPost("refresh-token")]
        public async Task<ActionResult<string>> RefreshToken()
        {

            var refreshToken = Request.Cookies["refreshToken"];
            if (!user.RefreshToken.Equals(refreshToken))
            {
                return (Unauthorized("Invalid Refresh Token"));
            }
            else if (user.TokenExpires < DateTime.Now)
            {
                return (Unauthorized("Token expired"));
            }

            string token = CreateToken(user);
            var newRefreshToken = GenerateRefreshToken();
            SetRefreshToken(newRefreshToken);

            return Ok(token);
        }



























    
        // Create access token 
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
                expires:DateTime.Now.AddHours(1), //one day from now
                signingCredentials: creds 
                );


            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
                
        }







        // Generate Refresh Token 
       
        private  RefreshToken GenerateRefreshToken()
        {


            var refreshToken = new RefreshToken
            {
                // RandomNumberGenerator from system.Cryptography
                Token =  Convert.ToBase64String(RandomNumberGenerator.GetBytes(64))
                , Expires = DateTime.Now.AddDays(1)
            };

            return refreshToken;


        }







        // Store refresh token in cookies . 
        private void SetRefreshToken(RefreshToken newRefreshToken)
        {
            // Cookie option ... httponly  = true . 
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = newRefreshToken.Expires
            };
            Response.Cookies.Append("refreshToken" , newRefreshToken.Token , cookieOptions);

            user.RefreshToken = newRefreshToken.Token;
            user.TokenCreated = newRefreshToken.Created; 
            user.TokenExpires = newRefreshToken.Expires;

            // This code will store the refresh token in the cookies . 
        }

    
    }
}
