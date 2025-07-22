using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using InsecureAppWebNet8.Data;
using Serilog;

Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Debug()
    .WriteTo.Console() // Pour debug console
    .WriteTo.File("wwwroot/logs/log.txt")
    .CreateLogger();

var builder = WebApplication.CreateBuilder(args);

builder.Host.UseSerilog();

// !!! DEBUG MODE activé en prod
builder.WebHost.UseSetting("detailedErrors", "true");

// !!! CORS ultra-permissif
builder.Services.AddCors(options =>
{
    options.AddPolicy("OpenCorsPolicy", policy =>
    {
        policy
            .AllowAnyOrigin()
            .AllowAnyMethod()
            .AllowAnyHeader()
            .WithExposedHeaders("*"); // Pas recommandé
    });
});

// Add services to the container.
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") 
    ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));

builder.Services.AddDatabaseDeveloperPageExceptionFilter();

builder.Services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = true)
    .AddEntityFrameworkStores<ApplicationDbContext>();

// postGreSql
var npgConnectionString = builder.Configuration.GetConnectionString("NpgConnection") 
    ?? throw new InvalidOperationException("Connection string 'NpgConnection' not found.");
builder.Services.AddDbContext<ProductDbContext>(options =>
    options.UseNpgsql(npgConnectionString));

builder.Services.AddControllersWithViews();

builder.Services.AddHttpClient();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    // !!!! app.UseHsts();
}

// !!! Active toutes les erreurs, même en prod
app.UseDeveloperExceptionPage();

// !!! CORS activé globalement
app.UseCors("OpenCorsPolicy");

// !!! Ne pas oublier ces headers
//app.Use(async (context, next) =>
//{
//    context.Response.Headers.Append("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
//    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
//    context.Response.Headers.Append("X-Frame-Options", "DENY");
//    context.Response.Headers.Append("Referrer-Policy", "no-referrer");
//    context.Response.Headers.Append("Permissions-Policy", "geolocation=(), microphone=()");
//    context.Response.Headers.Append("Content-Security-Policy", "default-src 'self'; script-src 'self'");
//    await next();
//});

// !!! app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");
app.MapRazorPages();

app.Run();
