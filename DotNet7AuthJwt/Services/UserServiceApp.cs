using System.Security.Claims;

namespace DotNet7AuthJwt.Services
{
    public class UserServiceApp : IUserServiceApp
    {
   
        public readonly IHttpContextAccessor _contextAccessor = new HttpContextAccessor();

        public string GetName()
        {

            var result = string.Empty;
            if (_contextAccessor.HttpContext is not null)
            { 
                result =  _contextAccessor.HttpContext.User.FindFirstValue(ClaimTypes.Name) ; 
            
            }
            return result?? "no user";

        }
    }
}
