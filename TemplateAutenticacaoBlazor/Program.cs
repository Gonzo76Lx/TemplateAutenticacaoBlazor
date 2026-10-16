using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth.Claims;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.HttpOverrides;
using TemplateAutenticacaoBlazor.Components;
using TemplateAutenticacaoBlazor.Middleware;
using TemplateAutenticacaoBlazor.Services;

var builder = WebApplication.CreateBuilder(args);

// 1. Configuração para Kubernetes / AKS Ingress (X-Forwarded-For, X-Forwarded-Host, X-Forwarded-Proto)
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost;
    options.KnownIPNetworks.Clear();
    options.KnownProxies.Clear();
});

// 2. Serviços de UI e Controllers (para endpoints REST de autenticação)
builder.Services.AddControllers();
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// 3. Cascata de estado de autenticação para componentes Blazor
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddHttpContextAccessor();

// 4. Injeção de Dependências dos Serviços de Autenticação, Claims e Roteamento de Domínios (AKS / Ingress)
builder.Services.AddScoped<IAuthClaimsEnricher, AuthClaimsEnricher>();
builder.Services.AddScoped<IUserAuthenticationService, FormsAuthenticationService>();

var domainOptions = builder.Configuration.GetSection("DomainRouting").Get<DomainRoutingOptions>() ?? new DomainRoutingOptions();
builder.Services.AddSingleton(domainOptions);
builder.Services.AddSingleton<IDomainRoutingService, DomainRoutingService>();

// 5. Configuração de Autenticação (Cookie Primário + OpenID Connect / Entra ID)
var authBuilder = builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
})
.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
{
    var cookieName = builder.Configuration.GetValue<string>("AuthSettings:CookieName") ?? "TemplateBlazor_AuthCookie";
    var expireHours = builder.Configuration.GetValue<int>("AuthSettings:ExpireHours", 8);
    var sliding = builder.Configuration.GetValue<bool>("AuthSettings:SlidingExpiration", true);

    options.Cookie.Name = cookieName;
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    options.LoginPath = "/externo/login";
    options.AccessDeniedPath = "/access-denied";
    options.SlidingExpiration = sliding;
    options.ExpireTimeSpan = TimeSpan.FromHours(expireHours);
});

// Configuração do Microsoft Entra ID (OpenID Connect) se configurado no appsettings
var entraIdClientId = builder.Configuration["AzureAd:ClientId"];
var entraIdClientSecret = builder.Configuration["AzureAd:ClientSecret"];
var isEntraIdConfigured = !string.IsNullOrWhiteSpace(entraIdClientId) && 
                          !entraIdClientId.Contains("YOUR_ENTRA_ID_CLIENT_ID");

if (isEntraIdConfigured)
{
    authBuilder.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
    {
        var instance = builder.Configuration["AzureAd:Instance"] ?? "https://login.microsoftonline.com/";
        var tenantId = builder.Configuration["AzureAd:TenantId"] ?? "common";
        options.Authority = $"{instance}{tenantId}/v2.0";
        options.ClientId = entraIdClientId;
        if (!string.IsNullOrWhiteSpace(entraIdClientSecret) && !entraIdClientSecret.Contains("YOUR_ENTRA_ID_CLIENT_SECRET"))
        {
            options.ClientSecret = entraIdClientSecret;
        }
        options.ResponseType = "code";
        options.ResponseMode = "query";
        options.UsePkce = true;
        options.CallbackPath = builder.Configuration["AzureAd:CallbackPath"] ?? "/signin-oidc";
        options.SignedOutCallbackPath = builder.Configuration["AzureAd:SignedOutCallbackPath"] ?? "/signout-callback-oidc";
        options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.SaveTokens = true;
        options.GetClaimsFromUserInfoEndpoint = true;

        options.Scope.Add("openid");
        options.Scope.Add("profile");
        options.Scope.Add("email");
        options.Scope.Add("offline_access");

        // Mapeia claims de grupos e funções de diretório do Entra ID
        options.ClaimActions.MapUniqueJsonKey("groups", "groups");
        options.ClaimActions.MapUniqueJsonKey("roles", "roles");
        options.ClaimActions.MapUniqueJsonKey("wids", "wids");
        options.ClaimActions.MapUniqueJsonKey("upn", "upn");
        options.ClaimActions.MapUniqueJsonKey("unique_name", "unique_name");
        options.ClaimActions.MapUniqueJsonKey("oid", "oid");
        options.ClaimActions.MapUniqueJsonKey("tid", "tid");

        options.Events = new OpenIdConnectEvents
        {
            OnTokenValidated = async context =>
            {
                if (context.Principal != null)
                {
                    // Enriquece os dados do utilizador interno com claims personalizadas
                    var enricher = context.HttpContext.RequestServices.GetRequiredService<IAuthClaimsEnricher>();
                    var internalClaims = enricher.BuildClaimsForInternalUser(context.Principal);
                    var appIdentity = new ClaimsIdentity(internalClaims, CookieAuthenticationDefaults.AuthenticationScheme);
                    
                    context.Principal.AddIdentity(appIdentity);
                }
                await Task.CompletedTask;
            }
        };
    });
}

// 5. Políticas de Autorização (Políticas por Ponto de Entrada / Tipo de Utilizador)
builder.Services.AddAuthorization(options =>
{
    // Política para ponto de entrada interno (/interno)
    options.AddPolicy("InternoPolicy", policy =>
        policy.RequireAuthenticatedUser()
              .RequireClaim("UserType", "Interno"));

    // Política para ponto de entrada externo (/externo)
    options.AddPolicy("ExternoPolicy", policy =>
        policy.RequireAuthenticatedUser()
              .RequireClaim("UserType", "Externo"));

    // Política administrativa opcional
    options.AddPolicy("AdminPolicy", policy =>
        policy.RequireRole("AdministradorInterno"));
});

var app = builder.Build();

// 7. Pipeline HTTP e suporte a Reverse Proxy / Ingress do AKS
app.UseForwardedHeaders();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseRouting();

// Middleware de Autenticação e Autorização
app.UseAuthentication();
app.UseAuthorization();

// Middleware de Roteamento e Forçamento de Autenticação por Domínio DNS (Interno vs Externo)
app.UseMiddleware<DomainAuthenticationMiddleware>();

app.UseAntiforgery();

app.MapStaticAssets();

// Mapeamento dos Controllers REST de Autenticação
app.MapControllers();

// Mapeamento dos Componentes Blazor com Server-Side Rendering
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
