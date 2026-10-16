using System.Security.Claims;
using Microsoft.Extensions.Configuration;
using TemplateAutenticacaoBlazor.Models;
using TemplateAutenticacaoBlazor.Services;

namespace TemplateAutenticacaoBlazor.Tests;

public class AuthTests
{
    [Fact]
    public void BuildClaimsForExternalUser_ShouldContainExpectedClaims()
    {
        // Arrange
        var enricher = new AuthClaimsEnricher();
        var user = new UserInfoModel
        {
            Id = "ext-123",
            Username = "cliente@empresa.pt",
            Email = "cliente@empresa.pt",
            FullName = "Cliente de Teste",
            Role = "ClientePremium",
            CustomAttributes = new Dictionary<string, string>
            {
                { "NIF", "500123456" },
                { "Empresa", "Acme Portugal" }
            }
        };

        // Act
        var claims = enricher.BuildClaimsForExternalUser(user);

        // Assert
        Assert.Contains(claims, c => c.Type == ClaimTypes.NameIdentifier && c.Value == "ext-123");
        Assert.Contains(claims, c => c.Type == ClaimTypes.Name && c.Value == "Cliente de Teste");
        Assert.Contains(claims, c => c.Type == ClaimTypes.Email && c.Value == "cliente@empresa.pt");
        Assert.Contains(claims, c => c.Type == ClaimTypes.Role && c.Value == "ClientePremium");
        Assert.Contains(claims, c => c.Type == "UserType" && c.Value == "Externo");
        Assert.Contains(claims, c => c.Type == "AuthenticationProvider" && c.Value == "Forms");
        Assert.Contains(claims, c => c.Type == "NIF" && c.Value == "500123456");
        Assert.Contains(claims, c => c.Type == "Empresa" && c.Value == "Acme Portugal");
    }

    [Fact]
    public void BuildClaimsForInternalUser_ShouldContainEntraIdAndInternalClaims()
    {
        // Arrange
        var enricher = new AuthClaimsEnricher();
        var incomingClaims = new List<Claim>
        {
            new("oid", "entra-guid-999"),
            new("name", "Colaborador Interno"),
            new("preferred_username", "colaborador@empresa.pt"),
            new("tid", "tenant-entra-123"),
            new("groups", "group-guid-111"),
            new("groups", "group-guid-222"),
            new("roles", "TI.Admin"),
            new("wids", "directory-role-wid-123"),
            new("ipaddr", "192.168.1.50")
        };
        var incomingPrincipal = new ClaimsPrincipal(new ClaimsIdentity(incomingClaims, "OpenIdConnect"));

        // Act
        var claims = enricher.BuildClaimsForInternalUser(incomingPrincipal);

        // Assert
        Assert.Contains(claims, c => c.Type == ClaimTypes.NameIdentifier && c.Value == "entra-guid-999");
        Assert.Contains(claims, c => c.Type == ClaimTypes.Name && c.Value == "Colaborador Interno");
        Assert.Contains(claims, c => c.Type == ClaimTypes.Email && c.Value == "colaborador@empresa.pt");
        Assert.Contains(claims, c => c.Type == "UserType" && c.Value == "Interno");
        Assert.Contains(claims, c => c.Type == "AuthenticationProvider" && c.Value == "EntraID");
        Assert.Contains(claims, c => c.Type == "TenantId" && c.Value == "tenant-entra-123");
        Assert.Contains(claims, c => c.Type == "Departamento" && c.Value == "Operações e Desenvolvimento");
        
        // Valida que TODOS os grupos e claims adicionais do Entra ID foram preservados
        Assert.Contains(claims, c => c.Type == "groups" && c.Value == "group-guid-111");
        Assert.Contains(claims, c => c.Type == "groups" && c.Value == "group-guid-222");
        Assert.Contains(claims, c => c.Type == "roles" && c.Value == "TI.Admin");
        Assert.Contains(claims, c => c.Type == "wids" && c.Value == "directory-role-wid-123");
        Assert.Contains(claims, c => c.Type == "ipaddr" && c.Value == "192.168.1.50");
    }

    [Fact]
    public async Task FormsAuthenticationService_ValidateUserCredentials_ShouldSucceedForValidUser()
    {
        // Arrange
        var configuration = new ConfigurationBuilder().Build();
        var service = new FormsAuthenticationService(configuration);

        // Act
        var user = await service.ValidateUserCredentialsAsync("cliente@externo.pt", "Password123!");

        // Assert
        Assert.NotNull(user);
        Assert.Equal("cliente@externo.pt", user.Username);
        Assert.Equal("Externo", user.UserType);
        Assert.True(user.CustomAttributes.ContainsKey("NIF"));
    }

    [Fact]
    public async Task FormsAuthenticationService_ValidateUserCredentials_ShouldFailForInvalidPassword()
    {
        // Arrange
        var configuration = new ConfigurationBuilder().Build();
        var service = new FormsAuthenticationService(configuration);

        // Act
        var user = await service.ValidateUserCredentialsAsync("cliente@externo.pt", "WrongPassword!");

        // Assert
        Assert.Null(user);
    }

    [Theory]
    [InlineData("aplicacao-interno.dominio.com", true, false)]
    [InlineData("interno.empresa.pt:443", true, false)]
    [InlineData("aplicacao-externo.dominio.com", false, true)]
    [InlineData("externo.empresa.pt", false, true)]
    [InlineData("outro-servico.dominio.com", false, false)]
    public void DomainRoutingService_ShouldDetectInternalAndExternalDomainsCorrectly(string host, bool expectedInternal, bool expectedExternal)
    {
        // Arrange
        var service = new DomainRoutingService(new DomainRoutingOptions
        {
            InternalDomainPattern = "interno",
            ExternalDomainPattern = "externo"
        });

        // Act
        var isInternal = service.IsInternalDomain(host);
        var isExternal = service.IsExternalDomain(host);

        // Assert
        Assert.Equal(expectedInternal, isInternal);
        Assert.Equal(expectedExternal, isExternal);
    }

    [Theory]
    [InlineData("Interno", "localhost:5001", true, false, "Interno")]
    [InlineData("Externo", "localhost:5001", false, true, "Externo")]
    [InlineData("Auto", "aplicacao-interno.dominio.com", true, false, "Interno")]
    [InlineData("Auto", "aplicacao-externo.dominio.com", false, true, "Externo")]
    [InlineData("Auto", "localhost:5001", false, false, "Auto / Híbrido")]
    public void DomainRoutingService_DebugOverrideMode_ShouldControlRoutingBehavior(
        string debugMode,
        string host,
        bool expectedInternal,
        bool expectedExternal,
        string expectedEffectiveMode)
    {
        // Arrange
        var service = new DomainRoutingService(new DomainRoutingOptions
        {
            InternalDomainPattern = "interno",
            ExternalDomainPattern = "externo",
            DebugOverrideMode = debugMode
        });

        // Act
        var isInternal = service.IsInternalDomain(host);
        var isExternal = service.IsExternalDomain(host);
        var effectiveMode = service.GetEffectiveMode(host);

        // Assert
        Assert.Equal(expectedInternal, isInternal);
        Assert.Equal(expectedExternal, isExternal);
        Assert.Equal(expectedEffectiveMode, effectiveMode);
    }

    [Fact]
    public void DomainRoutingService_GetLoginPathForHost_ShouldReturnCorrectLoginUrl()
    {
        // Arrange
        var service = new DomainRoutingService(new DomainRoutingOptions
        {
            InternalDomainPattern = "interno",
            ExternalDomainPattern = "externo",
            DebugOverrideMode = "Auto"
        });

        // Act
        var internalLogin = service.GetLoginPathForHost("aplicacao-interno.dominio.com", "/dashboard");
        var externalLogin = service.GetLoginPathForHost("aplicacao-externo.dominio.com", "/dashboard");

        // Assert
        Assert.Contains("/auth/login-entra", internalLogin);
        Assert.Contains("/externo/login", externalLogin);
        Assert.Contains(Uri.EscapeDataString("/dashboard"), internalLogin);
        Assert.Contains(Uri.EscapeDataString("/dashboard"), externalLogin);
    }
}
