using TemplateAutenticacaoBlazor.Models;

namespace TemplateAutenticacaoBlazor.Services;

public interface IUserAuthenticationService
{
    Task<UserInfoModel?> ValidateUserCredentialsAsync(string username, string password);
    Task<List<DemoUser>> GetAvailableDemoUsersAsync();
}

public class FormsAuthenticationService : IUserAuthenticationService
{
    private readonly IConfiguration _configuration;
    private readonly List<DemoUser> _demoUsers;

    public FormsAuthenticationService(IConfiguration configuration)
    {
        _configuration = configuration;
        _demoUsers = _configuration.GetSection("FormsAuthDemoUsers").Get<List<DemoUser>>() ?? new List<DemoUser>
        {
            new()
            {
                Username = "cliente@externo.pt",
                Password = "Password123!",
                Email = "cliente@externo.pt",
                FullName = "Maria Fernandes (Cliente Externo)",
                Role = "ClienteExterno",
                CustomClaims = new Dictionary<string, string>
                {
                    { "NIF", "123456789" },
                    { "Empresa", "Soluções Digitais Lda" },
                    { "PlanoSubscricao", "Premium" }
                }
            },
            new()
            {
                Username = "fornecedor@parceiro.pt",
                Password = "Password123!",
                Email = "fornecedor@parceiro.pt",
                FullName = "João Santos (Parceiro Externo)",
                Role = "FornecedorExterno",
                CustomClaims = new Dictionary<string, string>
                {
                    { "NIF", "987654321" },
                    { "Empresa", "Logística Express SA" },
                    { "PlanoSubscricao", "Enterprise" }
                }
            }
        };
    }

    public Task<UserInfoModel?> ValidateUserCredentialsAsync(string username, string password)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
        {
            return Task.FromResult<UserInfoModel?>(null);
        }

        // Validação contra os utilizadores demo (substituir por base de dados / Entity Framework em produção)
        var user = _demoUsers.FirstOrDefault(u => 
            (u.Username.Equals(username, StringComparison.OrdinalIgnoreCase) || 
             u.Email.Equals(username, StringComparison.OrdinalIgnoreCase)) &&
            u.Password == password);

        if (user == null)
        {
            return Task.FromResult<UserInfoModel?>(null);
        }

        var userInfo = new UserInfoModel
        {
            Id = Guid.NewGuid().ToString(),
            Username = user.Username,
            Email = user.Email,
            FullName = user.FullName,
            Role = user.Role,
            UserType = "Externo",
            AuthenticationProvider = "Forms",
            CustomAttributes = new Dictionary<string, string>(user.CustomClaims)
        };

        return Task.FromResult<UserInfoModel?>(userInfo);
    }

    public Task<List<DemoUser>> GetAvailableDemoUsersAsync()
    {
        return Task.FromResult(_demoUsers);
    }
}
