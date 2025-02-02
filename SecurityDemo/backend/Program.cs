using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authorization;
using System.Threading.RateLimiting;

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

// Configure CORS to allow only trusted origins (e.g., our React app)
builder.Services.AddCors(options =>
{
    options.AddPolicy("CorsPolicy", policy =>
    {
         policy.WithOrigins("http://localhost:3000")
               .AllowAnyHeader()
               .AllowAnyMethod();
    });
});

// Configure Rate Limiting using the built‑in RateLimiter
builder.Services.AddRateLimiter(options =>
{
    // Create a global limiter that limits all clients to 10 requests per minute.
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
    {
        // Here you can partition by IP address, for example. For simplicity, we use a single partition.
        return RateLimitPartition.GetFixedWindowLimiter("GlobalLimiter", _ =>
            new FixedWindowRateLimiterOptions
            {
                PermitLimit = 10,
                Window = TimeSpan.FromMinutes(1),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 2
            });
    });
    options.RejectionStatusCode = 429; // HTTP 429 Too Many Requests
});

var app = builder.Build();

// Add a middleware to inject security headers into every response.
app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["X-XSS-Protection"] = "1; mode=block";
    // A basic Content Security Policy. Customize as needed.
    context.Response.Headers["Content-Security-Policy"] = "default-src 'self'";
    await next();
});

app.UseHttpsRedirection();
app.UseCors("CorsPolicy");
app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();

// Secure endpoint: accessible only with a valid JWT.
app.MapGet("/api/secure", [Authorize] () =>
    Results.Ok(new { message = "This is a secure endpoint" })
);

// Login endpoint: for demo purposes, uses fixed credentials.
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
         return Results.Ok(new { token = tokenString });
    }
    return Results.Unauthorized();
});

// New endpoint to demonstrate using UUIDs for resource IDs.
// This replaces traditional incremental IDs with a UUID.
app.MapPost("/api/resource", () =>
{
    var resource = new
    {
        Id = Guid.NewGuid(), // Use a UUID
        Name = "New Resource",
        CreatedAt = DateTime.UtcNow
    };
    return Results.Ok(resource);
});

app.Run();

// Record type for user credentials.
public record UserCredentials(string Username, string Password);
