using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authorization;

var builder = WebApplication.CreateBuilder(args);

// For demo purposes: hardcoded JWT key (store securely in production!)
var jwtKey = "YourSuperSecretKey_ChangeThisInProduction!";
var key = Encoding.ASCII.GetBytes(jwtKey);

// Configure Authentication with JWT Bearer
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = true;
    options.SaveToken = true;
    options.TokenValidationParameters = new TokenValidationParameters
    {
         ValidateIssuerSigningKey = true,
         IssuerSigningKey = new SymmetricSecurityKey(key),
         ValidateIssuer = false,
         ValidateAudience = false,
         ClockSkew = TimeSpan.Zero
    };
});

builder.Services.AddAuthorization();

// Configure CORS to allow only trusted origins (e.g., your React app)
builder.Services.AddCors(options =>
{
    options.AddPolicy("CorsPolicy", policy =>
    {
         policy.WithOrigins("http://localhost:3000") // Change as needed.
               .AllowAnyHeader()
               .AllowAnyMethod();
    });
});

var app = builder.Build();

app.UseHttpsRedirection();
app.UseCors("CorsPolicy");
app.UseAuthentication();
app.UseAuthorization();

// Secure endpoint: accessible only with valid JWT.
app.MapGet("/api/secure", [Authorize] () =>
    Results.Ok(new { Message = "This is a secure endpoint" })
);

// Login endpoint: for demo, uses fixed credentials.
app.MapPost("/api/login", (UserCredentials credentials) =>
{
    // In production, validate credentials against a user store.
    if (credentials.Username == "test" && credentials.Password == "password")
    {
         var tokenHandler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
         var tokenDescriptor = new SecurityTokenDescriptor
         {
             Expires = DateTime.UtcNow.AddHours(1),
             SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
         };
         var token = tokenHandler.CreateToken(tokenDescriptor);
         var tokenString = tokenHandler.WriteToken(token);
         return Results.Ok(new { Token = tokenString });
    }
    return Results.Unauthorized();
});

app.Run();

// Record type for user credentials.
public record UserCredentials(string Username, string Password);
