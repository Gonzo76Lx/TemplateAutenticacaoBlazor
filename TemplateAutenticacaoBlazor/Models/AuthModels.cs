namespace TemplateAutenticacaoBlazor.Models;

public class LoginViewModel
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public bool RememberMe { get; set; } = false;
    public string? ReturnUrl { get; set; }
}

public class UserInfoModel
{
    public string Id { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string FullName { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty;
    public string UserType { get; set; } = string.Empty; // "Interno" ou "Externo"
    public string AuthenticationProvider { get; set; } = string.Empty; // "EntraID" ou "Forms"
    public Dictionary<string, string> CustomAttributes { get; set; } = new();
}

public class AuthSettings
{
    public string CookieName { get; set; } = "TemplateBlazorAuthCookie";
    public int ExpireHours { get; set; } = 8;
    public bool SlidingExpiration { get; set; } = true;
}

public class DemoUser
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string FullName { get; set; } = string.Empty;
    public string Role { get; set; } = "ClienteExterno";
    public Dictionary<string, string> CustomClaims { get; set; } = new();
}
