using Microsoft.AspNetCore.Http;
using TemplateAutenticacaoBlazor.Services;

namespace TemplateAutenticacaoBlazor.Middleware;

public class DomainAuthenticationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<DomainAuthenticationMiddleware> _logger;

    public DomainAuthenticationMiddleware(RequestDelegate next, ILogger<DomainAuthenticationMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context, IDomainRoutingService domainService)
    {
        var path = context.Request.Path.Value?.ToLowerInvariant() ?? string.Empty;

        // Ignora recursos estáticos (.css, .js, imagens, fontes, etc.), endpoints de callback OIDC, APIs de autenticação, login e logout
        if (path.StartsWith("/_") ||
            path.StartsWith("/lib/") ||
            path.StartsWith("/auth/") ||
            path.StartsWith("/api/auth/") ||
            path.StartsWith("/externo/login") ||
            path.StartsWith("/login") ||
            path.StartsWith("/access-denied") ||
            path.StartsWith("/signin-oidc") ||
            path.StartsWith("/signout-callback-oidc") ||
            path.EndsWith(".css") ||
            path.EndsWith(".js") ||
            path.EndsWith(".png") ||
            path.EndsWith(".jpg") ||
            path.EndsWith(".jpeg") ||
            path.EndsWith(".svg") ||
            path.EndsWith(".ico") ||
            path.EndsWith(".woff") ||
            path.EndsWith(".woff2") ||
            path.EndsWith(".ttf") ||
            path.EndsWith(".map"))
        {
            await _next(context);
            return;
        }

        var host = context.Request.Host.Value;
        var isAuthenticated = context.User.Identity?.IsAuthenticated ?? false;
        var userType = context.User.FindFirst("UserType")?.Value;

        var isInternalRequest = domainService.IsInternalDomain(host) || path.Equals("/interno") || path.StartsWith("/interno/");

        // Se o utilizador não estiver autenticado, força o redirecionamento para o método de login adequado
        if (!isAuthenticated)
        {
            var returnUrl = $"{context.Request.Path}{context.Request.QueryString}";
            if (string.IsNullOrWhiteSpace(returnUrl) || returnUrl == "/")
            {
                returnUrl = isInternalRequest ? "/interno" : "/externo";
            }

            var loginRedirect = domainService.GetLoginPathForHost(host, returnUrl);
            _logger.LogInformation("Utilizador anónimo detetado (Host: {Host}, Path: {Path}). A redirecionar para login ({LoginPath})", host, path, loginRedirect);
            context.Response.Redirect(loginRedirect);
            return;
        }

        // Se o utilizador estiver autenticado mas for de tipo externo a tentar aceder a recurso/domínio interno
        if (isInternalRequest && userType != null && !userType.Equals("Interno", StringComparison.OrdinalIgnoreCase))
        {
            var returnUrl = $"{context.Request.Path}{context.Request.QueryString}";
            _logger.LogWarning("Utilizador externo a aceder a recurso interno (Host: {Host}, Path: {Path}). A redirecionar para Entra ID.", host, path);
            context.Response.Redirect($"/auth/login-entra?returnUrl={Uri.EscapeDataString(returnUrl)}");
            return;
        }

        await _next(context);
    }
}
