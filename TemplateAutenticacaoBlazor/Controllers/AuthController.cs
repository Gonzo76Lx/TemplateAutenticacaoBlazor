using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using TemplateAutenticacaoBlazor.Models;
using TemplateAutenticacaoBlazor.Services;

namespace TemplateAutenticacaoBlazor.Controllers;

[ApiController]
public class AuthController : ControllerBase
{
    private readonly IUserAuthenticationService _authService;
    private readonly IAuthClaimsEnricher _claimsEnricher;
    private readonly IConfiguration _configuration;
    private readonly ILogger<AuthController> _logger;

    public AuthController(
        IUserAuthenticationService authService,
        IAuthClaimsEnricher claimsEnricher,
        IConfiguration configuration,
        ILogger<AuthController> logger)
    {
        _authService = authService;
        _claimsEnricher = claimsEnricher;
        _configuration = configuration;
        _logger = logger;
    }

    /// <summary>
    /// Endpoint para autenticação de utilizadores externos via submissão de formulário HTML.
    /// Valida as credenciais, cria o HttpCookie de autenticação e redireciona para o ReturnUrl.
    /// </summary>
    [HttpPost]
    [Route("api/auth/login")]
    [Route("auth/login-forms")]
    [Consumes("application/x-www-form-urlencoded", "multipart/form-data")]
    public async Task<IActionResult> LoginFromForm([FromForm] LoginViewModel formModel)
    {
        return await ProcessLoginAsync(formModel, isFormPost: true);
    }

    /// <summary>
    /// Endpoint REST / JSON para autenticação programática de utilizadores externos.
    /// Valida as credenciais, cria o HttpCookie de autenticação e devolve resposta JSON.
    /// </summary>
    [HttpPost]
    [Route("api/auth/login")]
    [Consumes("application/json")]
    public async Task<IActionResult> LoginFromJson([FromBody] LoginViewModel jsonModel)
    {
        return await ProcessLoginAsync(jsonModel, isFormPost: false);
    }

    private async Task<IActionResult> ProcessLoginAsync(LoginViewModel model, bool isFormPost)
    {
        if (model == null || string.IsNullOrWhiteSpace(model.Username) || string.IsNullOrWhiteSpace(model.Password))
        {
            if (isFormPost)
            {
                return Redirect($"/externo/login?error=missing_credentials&returnUrl={Uri.EscapeDataString(model?.ReturnUrl ?? "/externo")}");
            }
            return BadRequest(new { success = false, message = "Nome de utilizador e palavra-passe são obrigatórios." });
        }

        var user = await _authService.ValidateUserCredentialsAsync(model.Username, model.Password);
        if (user == null)
        {
            _logger.LogWarning("Tentativa de login falhada para o utilizador externo: {Username}", model.Username);
            if (isFormPost)
            {
                return Redirect($"/externo/login?error=invalid_credentials&returnUrl={Uri.EscapeDataString(model.ReturnUrl ?? "/externo")}");
            }
            return Unauthorized(new { success = false, message = "Credenciais inválidas. Verifique os dados introduzidos." });
        }

        // 1. Gera a lista de Claims enriquecida para utilizador externo
        var claims = _claimsEnricher.BuildClaimsForExternalUser(user);
        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        // 2. Configura as propriedades do Cookie de autenticação
        var expireHours = _configuration.GetValue("AuthSettings:ExpireHours", 8);
        var authProperties = new AuthenticationProperties
        {
            IsPersistent = model.RememberMe,
            IssuedUtc = DateTimeOffset.UtcNow,
            ExpiresUtc = DateTimeOffset.UtcNow.AddHours(expireHours),
            AllowRefresh = true
        };

        // 3. Emite o HttpCookie de autenticação
        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            principal,
            authProperties);

        _logger.LogInformation("Utilizador externo '{Username}' autenticado com sucesso via Forms.", user.Username);

        var targetUrl = string.IsNullOrWhiteSpace(model.ReturnUrl) ? "/externo" : model.ReturnUrl;
        if (!Url.IsLocalUrl(targetUrl))
        {
            targetUrl = "/externo";
        }

        if (isFormPost)
        {
            return Redirect(targetUrl);
        }

        return Ok(new
        {
            success = true,
            message = "Autenticação efetuada com sucesso.",
            redirectUrl = targetUrl,
            user = new
            {
                user.Id,
                user.Username,
                user.Email,
                user.FullName,
                user.Role,
                user.UserType,
                user.AuthenticationProvider
            }
        });
    }

    /// <summary>
    /// Despoleta o desafio de autenticação via Microsoft Entra ID (OpenID Connect).
    /// </summary>
    [HttpGet("auth/login-entra")]
    public IActionResult LoginEntra([FromQuery] string? returnUrl)
    {
        var targetUrl = string.IsNullOrWhiteSpace(returnUrl) || !Url.IsLocalUrl(returnUrl) ? "/interno" : returnUrl;

        // Se o Entra ID estiver configurado, desafia o OpenID Connect
        var isAzureAdConfigured = !string.IsNullOrWhiteSpace(_configuration["AzureAd:ClientId"]) && 
                                  !_configuration["AzureAd:ClientId"]!.Contains("YOUR_ENTRA_ID_CLIENT_ID");

        if (isAzureAdConfigured)
        {
            var props = new AuthenticationProperties
            {
                RedirectUri = targetUrl
            };
            return Challenge(props, OpenIdConnectDefaults.AuthenticationScheme);
        }

        // Em modo de desenvolvimento sem Azure AD real configurado, simula o login Entra ID para conveniência
        return Redirect($"/auth/login-entra-demo?returnUrl={Uri.EscapeDataString(targetUrl)}");
    }

    /// <summary>
    /// Endpoint utilitário para demonstração e desenvolvimento do fluxo Entra ID sem necessidade de tenant real.
    /// Grava o cookie com o mesmo formato e claims que o Entra ID real geraria.
    /// </summary>
    [HttpGet("auth/login-entra-demo")]
    public async Task<IActionResult> LoginEntraDemo([FromQuery] string? returnUrl)
    {
        var demoInternalPrincipal = new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()),
            new(ClaimTypes.Name, "Carlos Silva (Colaborador Interno)"),
            new(ClaimTypes.Email, "carlos.silva@empresa.pt"),
            new("preferred_username", "carlos.silva@empresa.pt"),
            new("oid", Guid.NewGuid().ToString()),
            new("tid", "tenant-demo-empresa-123"),
            new(ClaimTypes.Role, "AdministradorInterno"),
            new("roles", "TI.Engenharia"),
            new("roles", "Gestao.Acessos"),
            new("groups", "8c91d1e4-3b2a-4f5c-9123-abc123def456"),
            new("groups", "f47ac10b-58cc-4372-a567-0e02b2c3d479"),
            new("groups", "3fa85f64-5717-4562-b3fc-2c963f66afa6")
        }, "EntraID-Demo"));

        var claims = _claimsEnricher.BuildClaimsForInternalUser(demoInternalPrincipal);
        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        var expireHours = _configuration.GetValue("AuthSettings:ExpireHours", 8);
        var authProperties = new AuthenticationProperties
        {
            IsPersistent = false,
            IssuedUtc = DateTimeOffset.UtcNow,
            ExpiresUtc = DateTimeOffset.UtcNow.AddHours(expireHours),
            AllowRefresh = true
        };

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            principal,
            authProperties);

        _logger.LogInformation("Login interno simulado (Entra ID Demo) realizado com sucesso.");

        var targetUrl = string.IsNullOrWhiteSpace(returnUrl) || !Url.IsLocalUrl(returnUrl) ? "/interno" : returnUrl;
        return Redirect(targetUrl);
    }

    /// <summary>
    /// Termina a sessão do utilizador, apagando o HttpCookie de autenticação.
    /// </summary>
    [HttpGet("auth/logout")]
    [HttpPost("api/auth/logout")]
    public async Task<IActionResult> Logout([FromQuery] string? returnUrl)
    {
        var authProvider = User.FindFirst("AuthenticationProvider")?.Value;

        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        var targetUrl = string.IsNullOrWhiteSpace(returnUrl) || !Url.IsLocalUrl(returnUrl) ? "/" : returnUrl;

        // Se o utilizador autenticou via Entra ID real e o OpenID Connect estiver ativo
        var isAzureAdConfigured = !string.IsNullOrWhiteSpace(_configuration["AzureAd:ClientId"]) && 
                                  !_configuration["AzureAd:ClientId"]!.Contains("YOUR_ENTRA_ID_CLIENT_ID");

        if (authProvider == "EntraID" && isAzureAdConfigured)
        {
            return SignOut(new AuthenticationProperties { RedirectUri = targetUrl }, OpenIdConnectDefaults.AuthenticationScheme);
        }

        if (Request.HasFormContentType || HttpContext.Request.Method == "GET")
        {
            return Redirect(targetUrl);
        }

        return Ok(new { success = true, message = "Sessão terminada com sucesso.", redirectUrl = targetUrl });
    }

    /// <summary>
    /// Endpoint REST para verificar o estado de autenticação atual e listar todas as claims do utilizador.
    /// </summary>
    [HttpGet("api/auth/me")]
    [Authorize]
    public IActionResult GetCurrentUser()
    {
        var claims = User.Claims.Select(c => new { c.Type, c.Value }).ToList();
        return Ok(new
        {
            isAuthenticated = User.Identity?.IsAuthenticated ?? false,
            authType = User.Identity?.AuthenticationType,
            userName = User.Identity?.Name,
            userType = User.FindFirst("UserType")?.Value,
            provider = User.FindFirst("AuthenticationProvider")?.Value,
            claims
        });
    }
}
