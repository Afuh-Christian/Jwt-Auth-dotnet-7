

### 

We'll use the   

``` 
dotnet user-jwt <command> 
``` 

for testing ... 


### Program.cs 

```c# 
// Program.cs 


builder.Services.AddSwaggerGen(
    options =>
    {
        options.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
        {
            In = ParameterLocation.Header,
            Name = "Authorization",
            Type = SecuritySchemeType.ApiKey
        });

        options.OperationFilter<SecurityRequirementsOperationFilter>();
    }
    );

//builder.Services.AddAuthentication(JwtBearerDefaults).AddJwtBearer();
 builder.Services.AddAuthentication().AddJwtBearer();



```

### weather Controller . 

```c# 


    [ApiController]
    [Route("[controller]")]
    [Authorize(Roles = "Admin")]
    public class WeatherForecastController : ControllerBase { }

```   

### User the "dotnet user-jwt <command> " to create the roles .. so you can access the endpoint else you get a 403 



###  Enable [Authorize] to be used  on controllers and actions . 

```c# 

//Program.cs 

// to add the Bearer auth to the controller ..............................................................
builder.Services.AddAuthentication().AddJwtBearer(
    options => {
        options.TokenValidationParameters = new TokenValidationParameters
        {
          ValidateIssuerSigningKey = true,
            ValidateAudience = false,
            ValidateIssuer = false,
          IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration.GetSection("AppSettings:Token").Value!))
        };
    }
   )  ;
// ............................................................................................................
```




### To Authorize by roles ... 

e.g we've added roles in the weather controller . .

    [Authorize(Roles ="Admin,User")]

- Add new claim for the user when creating the token .... 

```c# 

//AuthController .. 



        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>
            {
                    new Claim(ClaimTypes.Name , user.Username),
                    new Claim(ClaimTypes.Role , "User") //// New role added ... Or we can do this in the user models itself ... You can add multiple roles 
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

```









- 






