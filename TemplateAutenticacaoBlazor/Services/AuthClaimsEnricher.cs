using System.Security.Claims;
using TemplateAutenticacaoBlazor.Models;

namespace TemplateAutenticacaoBlazor.Services;

public interface IAuthClaimsEnricher
{
    /// <summary>
    /// Enriquece e gera a lista de Claims para utilizadores externos (Forms Authentication)
    /// </summary>
    List<Claim> BuildClaimsForExternalUser(UserInfoModel user);

    /// <summary>
    /// Enriquece e gera a lista de Claims para utilizadores internos (Entra ID)
    /// </summary>
    List<Claim> BuildClaimsForInternalUser(ClaimsPrincipal principal);
}

public class AuthClaimsEnricher : IAuthClaimsEnricher
{
    public List<Claim> BuildClaimsForExternalUser(UserInfoModel user)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id),
            new(ClaimTypes.Name, string.IsNullOrWhiteSpace(user.FullName) ? user.Username : user.FullName),
            new(ClaimTypes.Email, user.Email),
            new(ClaimTypes.Role, string.IsNullOrWhiteSpace(user.Role) ? "UtilizadorExterno" : user.Role),
            
            // Custom Claims requeridas pela aplicação
            new("UserType", "Externo"),
            new("AuthenticationProvider", "Forms"),
            new("AuthTimestamp", DateTimeOffset.UtcNow.ToString("O")),
            new("AccessScope", "PortalExterno")
        };

        // Adiciona quaisquer atributos customizados adicionais configurados
        foreach (var (key, value) in user.CustomAttributes)
        {
            claims.Add(new Claim(key, value));
        }

        return claims;
    }

    public List<Claim> BuildClaimsForInternalUser(ClaimsPrincipal principal)
    {
        var claims = new List<Claim>();

        // 1. Copia e preserva TODAS as claims originais recebidas do Entra ID (groups, roles, wids, oid, tid, etc.)
        foreach (var claim in principal.Claims)
        {
            if (!claims.Any(c => c.Type == claim.Type && c.Value == claim.Value))
            {
                claims.Add(new Claim(claim.Type, claim.Value, claim.ValueType, claim.Issuer));
            }
        }

        // 2. Extrai e normaliza identificadores essenciais caso não existam com a tipagem padrão
        var userId = claims.FirstOrDefault(c => c.Type == "oid" || c.Type == "http://schemas.microsoft.com/identity/claims/objectidentifier" || c.Type == ClaimTypes.NameIdentifier)?.Value
                     ?? Guid.NewGuid().ToString();

        var name = claims.FirstOrDefault(c => c.Type == "name" || c.Type == ClaimTypes.Name)?.Value
                   ?? claims.FirstOrDefault(c => c.Type == "preferred_username")?.Value
                   ?? "Utilizador Interno";

        var email = claims.FirstOrDefault(c => c.Type == ClaimTypes.Email || c.Type == "email" || c.Type == "preferred_username" || c.Type == "upn")?.Value
                    ?? "interno@empresa.pt";

        if (!claims.Any(c => c.Type == ClaimTypes.NameIdentifier))
        {
            claims.Add(new Claim(ClaimTypes.NameIdentifier, userId));
        }

        if (!claims.Any(c => c.Type == ClaimTypes.Name))
        {
            claims.Add(new Claim(ClaimTypes.Name, name));
        }

        if (!claims.Any(c => c.Type == ClaimTypes.Email))
        {
            claims.Add(new Claim(ClaimTypes.Email, email));
        }

        if (!claims.Any(c => c.Type == ClaimTypes.Role))
        {
            var existingRole = claims.FirstOrDefault(c => c.Type == "roles" || c.Type == "role")?.Value;
            claims.Add(new Claim(ClaimTypes.Role, existingRole ?? "FuncionarioInterno"));
        }

        // 3. Custom Claims específicas para a aplicação
        if (!claims.Any(c => c.Type == "UserType"))
            claims.Add(new Claim("UserType", "Interno"));

        if (!claims.Any(c => c.Type == "AuthenticationProvider"))
            claims.Add(new Claim("AuthenticationProvider", "EntraID"));

        if (!claims.Any(c => c.Type == "AuthTimestamp"))
            claims.Add(new Claim("AuthTimestamp", DateTimeOffset.UtcNow.ToString("O")));

        if (!claims.Any(c => c.Type == "AccessScope"))
            claims.Add(new Claim("AccessScope", "PortalInterno"));

        if (!claims.Any(c => c.Type == "Departamento"))
            claims.Add(new Claim("Departamento", "Operações e Desenvolvimento"));

        if (!claims.Any(c => c.Type == "NivelAcesso"))
            claims.Add(new Claim("NivelAcesso", "Nivel-3-Colaborador"));

        var tenantId = claims.FirstOrDefault(c => c.Type == "http://schemas.microsoft.com/identity/claims/tenantid" || c.Type == "tid")?.Value;
        if (!string.IsNullOrEmpty(tenantId) && !claims.Any(c => c.Type == "TenantId"))
        {
            claims.Add(new Claim("TenantId", tenantId));
        }

        return claims;
    }
}
