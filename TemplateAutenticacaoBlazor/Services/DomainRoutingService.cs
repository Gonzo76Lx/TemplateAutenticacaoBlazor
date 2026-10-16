namespace TemplateAutenticacaoBlazor.Services;

public class DomainRoutingOptions
{
    public string InternalDomainPattern { get; set; } = "interno";
    public string ExternalDomainPattern { get; set; } = "externo";
    public string InternalLoginPath { get; set; } = "/auth/login-entra";
    public string ExternalLoginPath { get; set; } = "/externo/login";
    public bool AutoEnforceByDomain { get; set; } = true;

    /// <summary>
    /// Modo de simulação para depuração / desenvolvimento local (ex.: localhost).
    /// Valores suportados:
    /// - "Auto" (padrão): avalia pelo DNS/Host do pedido (ex.: aplicacao-interno... vs aplicacao-externo...).
    /// - "Interno": força o comportamento de domínio interno (força autenticação Entra ID).
    /// - "Externo": força o comportamento de domínio externo (força Forms Authentication).
    /// </summary>
    public string DebugOverrideMode { get; set; } = "Auto";
}

public interface IDomainRoutingService
{
    bool IsInternalDomain(string? host);
    bool IsExternalDomain(string? host);
    string GetLoginPathForHost(string? host, string? returnUrl = null);
    string GetEffectiveMode(string? host);
}

public class DomainRoutingService : IDomainRoutingService
{
    private readonly DomainRoutingOptions _options;

    public DomainRoutingService(DomainRoutingOptions? options = null)
    {
        _options = options ?? new DomainRoutingOptions();
    }

    public bool IsInternalDomain(string? host)
    {
        if (!string.IsNullOrWhiteSpace(_options.DebugOverrideMode) &&
            !_options.DebugOverrideMode.Equals("Auto", StringComparison.OrdinalIgnoreCase))
        {
            return _options.DebugOverrideMode.Equals("Interno", StringComparison.OrdinalIgnoreCase);
        }

        if (string.IsNullOrWhiteSpace(host)) return false;
        var cleanHost = host.Split(':')[0];
        return cleanHost.Contains(_options.InternalDomainPattern, StringComparison.OrdinalIgnoreCase);
    }

    public bool IsExternalDomain(string? host)
    {
        if (!string.IsNullOrWhiteSpace(_options.DebugOverrideMode) &&
            !_options.DebugOverrideMode.Equals("Auto", StringComparison.OrdinalIgnoreCase))
        {
            return _options.DebugOverrideMode.Equals("Externo", StringComparison.OrdinalIgnoreCase);
        }

        if (string.IsNullOrWhiteSpace(host)) return false;
        var cleanHost = host.Split(':')[0];
        return cleanHost.Contains(_options.ExternalDomainPattern, StringComparison.OrdinalIgnoreCase);
    }

    public string GetEffectiveMode(string? host)
    {
        if (IsInternalDomain(host)) return "Interno";
        if (IsExternalDomain(host)) return "Externo";
        return "Auto / Híbrido";
    }

    public string GetLoginPathForHost(string? host, string? returnUrl = null)
    {
        var target = string.IsNullOrWhiteSpace(returnUrl) ? "/" : returnUrl;
        if (IsInternalDomain(host))
        {
            return $"{_options.InternalLoginPath}?returnUrl={Uri.EscapeDataString(target)}";
        }

        return $"{_options.ExternalLoginPath}?returnUrl={Uri.EscapeDataString(target)}";
    }
}
