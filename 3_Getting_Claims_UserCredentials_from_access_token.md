

# METHOD 1 

```User``` comes frome ClaimsPrincipal

```C# 
// AuthControllers ... 



        [HttpGet , Authorize]
        public ActionResult<string> GetUserCredentials()
        {
            var username = User?.Identity?.Name;
            var roles = User?.FindAll(ClaimTypes.Role)?.Select(x => x.Value).ToList();
            var roles2 = User?.Claims.Where(c => c.Type == ClaimTypes.Role).Select(x => x.Value).ToList();
            return Ok(new { username  , roles , roles2});
        }



```












# METHOD 2  

- Create a services to handle this action ... 
- we'll need to use  ```HttpContextAccessor```  and also add in the Program.cs   . 
- Also add the services too ..  


```c# 
// Program.cs 

builder.Services.AddHttpContextAccessor(); 
builder.Services.AddScoped<IUserService, UserService>();

```



```c# 
// Services/UserService.cs


```


### Service 

```c# 

// Services/UserServiceApp





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

```



#### Controller .... 

```c# 

// AuthController ... 



       [HttpGet , Authorize]
        public ActionResult<string> GetName()
        {
            return Ok(this.userService.GetName());
        }




```   