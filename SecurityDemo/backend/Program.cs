using System.Text;
using System.Collections.Concurrent;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authorization;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

// --------------------
// Load configuration settings
// --------------------

// JWT settings
var jwtSection = builder.Configuration.GetSection("Jwt");
var jwtKey = jwtSection["Key"] ?? throw new Exception("JWT key not found in configuration.");
var issuer = jwtSection["Issuer"];
var audience = jwtSection["Audience"];
var tokenExpiryHours = jwtSection.GetValue<int>("TokenExpiryHours", 1);
var key = Encoding.ASCII.GetBytes(jwtKey);

// CORS settings
var allowedOrigins = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>() 
                     ?? new string[] { "https://localhost:3000" };

// Rate limiting settings
var rateLimitSection = builder.Configuration.GetSection("RateLimiting:Global");
int permitLimit = rateLimitSection.GetValue<int>("PermitLimit", 10);
int windowInMinutes = rateLimitSection.GetValue<int>("WindowInMinutes", 1);
int queueLimit = rateLimitSection.GetValue<int>("QueueLimit", 2);

// Security Headers settings
var securityHeaders = builder.Configuration.GetSection("SecurityHeaders");
string contentSecurityPolicy = securityHeaders["ContentSecurityPolicy"] ?? "default-src 'self'";
string xContentTypeOptions = securityHeaders["XContentTypeOptions"] ?? "nosniff";
string xFrameOptions = securityHeaders["XFrameOptions"] ?? "DENY";

// --------------------
// Service Configuration
// --------------------

// Configure JWT Bearer Authentication
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
         ValidateIssuer = !string.IsNullOrEmpty(issuer),
         ValidIssuer = issuer,
         ValidateAudience = !string.IsNullOrEmpty(audience),
         ValidAudience = audience,
         ClockSkew = TimeSpan.Zero
    };
});

builder.Services.AddAuthorization();

// Configure CORS
builder.Services.AddCors(options =>
{
    options.AddPolicy("CorsPolicy", policy =>
    {
         policy.WithOrigins(allowedOrigins)
               .AllowAnyHeader()
               .AllowAnyMethod();
    });
});

// Configure Rate Limiting (global: based on configuration)
builder.Services.AddRateLimiter(options =>
{
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
    {
        // For simplicity, using a single partition; in production, you might partition by IP address or user.
        return RateLimitPartition.GetFixedWindowLimiter("GlobalLimiter", _ =>
            new FixedWindowRateLimiterOptions
            {
                PermitLimit = permitLimit,
                Window = TimeSpan.FromMinutes(windowInMinutes),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = queueLimit
            });
    });
    options.RejectionStatusCode = 429; // HTTP 429 Too Many Requests
});

var app = builder.Build();

// --------------------
// Middleware Configuration
// --------------------

// Add security headers to every response.
app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = xContentTypeOptions;
    context.Response.Headers["X-Frame-Options"] = xFrameOptions;
    context.Response.Headers["Content-Security-Policy"] = contentSecurityPolicy;
    await next();
});

app.UseHttpsRedirection();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseCors("CorsPolicy");
app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();

// --------------------
// Endpoint Configuration
// --------------------

// Secure endpoint: requires a valid JWT.
app.MapGet("/api/secure", [Authorize] () =>
    Results.Ok(new { message = "This is a secure endpoint" })
);

// Login endpoint: demo fixed credentials ("test"/"password")
app.MapPost("/api/login", (UserCredentials credentials) =>
{
    if (credentials.Username == "test" && credentials.Password == "password")
    {
         var tokenHandler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
         var tokenDescriptor = new SecurityTokenDescriptor
         {
             Expires = DateTime.UtcNow.AddHours(tokenExpiryHours),
             Issuer = issuer,         // Added Issuer from configuration
             Audience = audience,     // Added Audience from configuration
             SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
         };
         var token = tokenHandler.CreateToken(tokenDescriptor);
         var tokenString = tokenHandler.WriteToken(token);
         return Results.Ok(new { token = tokenString });
    }
    return Results.Unauthorized();
});


// In-memory storage for resources (using UUIDs)
var resources = new ConcurrentDictionary<Guid, Resource>();

// Create a new resource (POST) – uses a UUID as ID.
app.MapPost("/api/resource", () =>
{
    var resource = new Resource
    {
        Id = Guid.NewGuid(),
        Name = "New Resource",
        CreatedAt = DateTime.UtcNow
    };

    resources[resource.Id] = resource;
    return Results.Ok(resource);
});

// Retrieve a resource by UUID (GET)
app.MapGet("/api/resource/{id:guid}", (Guid id) =>
{
    if (resources.TryGetValue(id, out var resource))
    {
        return Results.Ok(resource);
    }
    return Results.NotFound();
});

app.Run();

// --------------------
// Record Types
// --------------------
public record UserCredentials(string Username, string Password);
public record Resource
{
    public Guid Id { get; init; }
    public string Name { get; init; } = string.Empty;
    public DateTime CreatedAt { get; init; }
}
