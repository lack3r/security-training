using System.Text;
using System.Collections.Concurrent;
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

// Add middleware to inject security headers into every response.
app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["X-XSS-Protection"] = "1; mode=block";
    // A basic Content Security Policy. We can customize as needed.
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

// In-memory storage for resources, for demo purposes (just to avoid having to create a database).
var resources = new ConcurrentDictionary<Guid, Resource>();

// Endpoint to create a new resource with a UUID (POST)
app.MapPost("/api/resource", () =>
{
    var resource = new Resource
    {
        Id = Guid.NewGuid(), // Use a UUID
        Name = "New Resource",
        CreatedAt = DateTime.UtcNow
    };

    resources[resource.Id] = resource;
    return Results.Ok(resource);
});

// Endpoint to retrieve a resource by UUID (GET)
app.MapGet("/api/resource/{id:guid}", (Guid id) =>
{
    if (resources.TryGetValue(id, out var resource))
    {
        return Results.Ok(resource);
    }
    return Results.NotFound();
});

app.Run();

// Record type for user credentials.
public record UserCredentials(string Username, string Password);

// Model for a resource.
public record Resource
{
    public Guid Id { get; init; }
    public string Name { get; init; } = string.Empty;
    public DateTime CreatedAt { get; init; }
}
