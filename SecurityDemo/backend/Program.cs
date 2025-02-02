using System.Text;
using System.Collections.Concurrent;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authorization;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

// Load JWT key from configuration (appsettings.json or environment)
var jwtKey = builder.Configuration["Jwt:Key"] ?? throw new Exception("JWT key not found in configuration.");
var key = Encoding.ASCII.GetBytes(jwtKey);

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
         ValidateIssuer = false,
         ValidateAudience = false,
         ClockSkew = TimeSpan.Zero
    };
});

builder.Services.AddAuthorization();

// Configure CORS for our trusted frontend (adjust URL as needed)
builder.Services.AddCors(options =>
{
    options.AddPolicy("CorsPolicy", policy =>
    {
         policy.WithOrigins("https://localhost:3000")
               .AllowAnyHeader()
               .AllowAnyMethod();
    });
});

// Configure Rate Limiting (global: 10 requests per minute)
builder.Services.AddRateLimiter(options =>
{
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
    {
        // For simplicity, using a single partition; in production, partition by IP or user
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

// Middleware: Add security headers to every response.
app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff"; // Prevent MIME type sniffing. https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-content-type-options
    context.Response.Headers["X-Frame-Options"] = "DENY"; // Prevent clickjacking. https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-frame-options
    // A basic Content Security Policy. We can customize as needed.
    // Content Security Policy (CSP) is a security feature that is used to specify the origin of content that is allowed to be 
    // loaded on a website or in a web applications. 
    // It is an added layer of security that helps to detect and mitigate certain types of attacks, 
    // including Cross-Site Scripting (XSS) and data injection attacks. 
    // These attacks are used for everything from data theft to site defacement to distribution of malware.
    // Cross site scripting attacks are a type of injection attack that injects malicious code into a web page.
    context.Response.Headers["Content-Security-Policy"] = "default-src 'self'"; // https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#content-security-policy
    await next();
});

app.UseHttpsRedirection();
app.UseCors("CorsPolicy");
app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();

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
             Expires = DateTime.UtcNow.AddHours(1),
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

// Record types
public record UserCredentials(string Username, string Password);
public record Resource
{
    public Guid Id { get; init; }
    public string Name { get; init; } = string.Empty;
    public DateTime CreatedAt { get; init; }
}
