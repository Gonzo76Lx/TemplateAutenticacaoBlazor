# Template de Autenticação Blazor Web App (SSR) - AKS / Kubernetes / Ingress / Multi-Domain

Template de referência em **C# / .NET 10 (Blazor Web App)** com **Server-Side Rendering (SSR)** para copiar e colar em novos projetos alojados no mesmo Pod/Serviço (ex.: Azure Kubernetes Service - AKS com Ingress / NGINX / Cloudflare ou IIS).

Este template implementa autenticação híbrida por **Domínio DNS (Host)** e por **Caminho (`/interno` e `/externo`)** na mesma aplicação, armazenando os dados da sessão e claims personalizadas num **HttpCookie seguro**:

### 🌐 Cenário de Roteamento por DNS (Dois URLs / Mesma Aplicação em AKS)
1. **Domínio Interno (`aplicacao-interno.dominio.com` ou `/interno`)**:
   - Destinado a colaboradores internos da organização.
   - Força automaticamente o desafio de autenticação via **Microsoft Entra ID** (OpenID Connect / Azure AD).
   - Injeta claims corporativas (ex.: `UserType = "Interno"`, `Departamento`, `NivelAcesso`, `TenantId`).
   - Persiste a sessão no HttpCookie.

2. **Domínio Externo (`aplicacao-externo.dominio.com` ou `/externo`)**:
   - Destinado a utilizadores, clientes ou parceiros externos.
   - Redireciona utilizadores não autenticados para a página de login (`/externo/login`).
   - O formulário submete via `POST` para o endpoint REST `AuthController` (`/api/auth/login`).
   - Valida credenciais (Forms Authentication), injeta claims externas (ex.: `UserType = "Externo"`, `NIF`, `Empresa`, `PlanoSubscricao`) e grava o HttpCookie.
   - Redireciona o utilizador para a página pretendida.

---

## 🚀 Como Executar o Projeto

```powershell
# Restaurar e compilar a solução
dotnet build

# Executar a aplicação
dotnet run --project TemplateAutenticacaoBlazor/TemplateAutenticacaoBlazor.csproj
```

Abra o browser no endereço indicado (por defeito `https://localhost:5001` ou porta configurada em `Properties/launchSettings.json`).

### 🛠️ Configuração de Modo em Debug / Localhost (`DebugOverrideMode`)

Ao executar e depurar localmente em `localhost`, pode forçar e testar o comportamento Interno ou Externo através do `appsettings.Development.json` (ou `appsettings.json`):

```json
"DomainRouting": {
  "DebugOverrideMode": "Auto" 
}
```

- `"Auto"` (padrão): avalia pelo DNS/Host do pedido (ex: `aplicacao-interno...` vs `aplicacao-externo...`). Em `localhost`, permite navegar livremente em ambos os caminhos.
- `"Interno"`: simula que qualquer acesso ao `localhost` é um domínio interno, forçando automaticamente o fluxo de Microsoft Entra ID.
- `"Externo"`: simula que qualquer acesso ao `localhost` é um domínio externo, forçando o redirecionamento automático para a página de login Forms (`/externo/login`).

---

## 🔑 Credenciais Demo para Testes Rápidos (Forms Auth)

Para testar o fluxo externo imediatamente, o template vem com utilizadores pré-configurados:

| Utilizador / Email | Palavra-passe | Perfil / Tipo | Claims de Exemplo |
| :--- | :--- | :--- | :--- |
| `cliente@externo.pt` | `Password123!` | `ClienteExterno` / `Externo` | `NIF: 123456789`, `Empresa: Soluções Digitais Lda`, `Plano: Premium` |
| `fornecedor@parceiro.pt` | `Password123!` | `FornecedorExterno` / `Externo` | `NIF: 987654321`, `Empresa: Logística Express SA`, `Plano: Enterprise` |

---

## ⚙️ Configuração do Microsoft Entra ID (Azure AD) e Obtenção de Grupos / Claims

No ficheiro `TemplateAutenticacaoBlazor/appsettings.json`, configure a secção `AzureAd`:

```json
"AzureAd": {
  "Instance": "https://login.microsoftonline.com/",
  "Domain": "suaempresa.onmicrosoft.com",
  "TenantId": "00000000-0000-0000-0000-000000000000",
  "ClientId": "11111111-1111-1111-1111-111111111111",
  "ClientSecret": "",
  "CallbackPath": "/signin-oidc",
  "SignedOutCallbackPath": "/signout-callback-oidc"
}
```

### 👥 Como Ativar a Emissão de Grupos no Azure Portal (Entra ID)
Para que o Microsoft Entra ID envie os **Grupos de Segurança (Security Groups)** e **Funções de Diretório (Roles)** no token de autenticação:
1. No [Portal Microsoft Entra ID](https://entra.microsoft.com/) ou [Azure Portal](https://portal.azure.com/), aceda a **App registrations** > selecione a sua aplicação.
2. No menu lateral, clique em **Token configuration** > **Add groups claim**.
3. Selecione os tipos de grupo pretendidos:
   - **Security groups** (Grupos de segurança)
   - **Directory roles** (Funções administrativas do Entra ID)
   - ou **All groups** (Todos os grupos).
4. Em **Customize ID token claim properties by group type**, selecione o formato do identificador pretendido (por defeito é o `Group ID` / GUID).
5. O template .NET já se encontra configurado no `Program.cs` e `AuthClaimsEnricher.cs` para mapear automaticamente todas as claims (`groups`, `roles`, `wids`, `oid`, `tid`, etc.) e gravá-las no `HttpCookie` de sessão.

> **Nota de Desenvolvimento:** Se os identificadores ainda contiverem os placeholders (`YOUR_ENTRA_ID_...`), a aplicação ativa automaticamente um modo de simulação/demo seguro para permitir testar o fluxo de `/interno` com grupos de exemplo. Quando colocar as credenciais reais do seu Tenant, a autenticação obterá os grupos e claims reais da organização.

---

## 🛠️ Estrutura do Projeto

```text
TemplateAutenticacaoBlazor/
├── Controllers/
│   └── AuthController.cs          # Endpoints REST de login forms, desafio Entra ID, logout e inspeção de claims (/api/auth/me)
├── Middleware/
│   └── DomainAuthenticationMiddleware.cs # Middleware que deteta o Host DNS e força Entra ID ou Forms Login
├── Models/
│   └── AuthModels.cs              # Modelos de Login, Utilizador, Configurações de Cookie e Demo Users
├── Services/
│   ├── IDomainRoutingService.cs   # Interface de deteção e resolução de domínios internos/externos
│   ├── DomainRoutingService.cs    # Lógica de correspondência de domínios DNS (AKS / Ingress)
│   ├── IAuthClaimsEnricher.cs     # Interface para injeção de claims personalizadas
│   ├── AuthClaimsEnricher.cs      # Construtor de claims para utilizadores Internos e Externos
│   ├── IUserAuthenticationService.cs # Interface de validação de credenciais
│   └── FormsAuthenticationService.cs # Serviço de validação de credenciais externas
├── Components/
│   ├── Layout/
│   │   ├── MainLayout.razor       # Layout com barra superior e identificador de sessão
│   │   ├── NavMenu.razor          # Menu de navegação lateral
│   │   └── UserClaimsBadge.razor  # Componente que exibe em tempo real o utilizador, tipo e botão de logout
│   ├── Pages/
│   │   ├── Home.razor             # Dashboard explicativo com visualizador de claims ativas
│   │   ├── Interno.razor          # Ponto de entrada /interno (Microsoft Entra ID)
│   │   ├── Externo.razor          # Ponto de entrada /externo (Forms Authentication)
│   │   ├── ExternoLogin.razor     # Formulário de login SSR com submissão POST
│   │   └── AccessDenied.razor     # Página amigável de Acesso Negado (403)
│   ├── Routes.razor               # Roteamento Blazor com AuthorizeRouteView
│   └── App.razor                  # Raiz HTML da aplicação
├── Program.cs                     # Registo de Cookie, OpenID Connect, Políticas e Pipeline
└── appsettings.json               # Configurações de Cookie, AzureAd e Utilizadores
```

---

## 🍪 Personalização de Claims no HttpCookie

Para adicionar ou modificar as claims guardadas no cookie, edite a classe `AuthClaimsEnricher.cs`:

```csharp
// Exemplo para utilizadores externos (Forms Auth)
public List<Claim> BuildClaimsForExternalUser(UserInfoModel user)
{
    var claims = new List<Claim>
    {
        new(ClaimTypes.NameIdentifier, user.Id),
        new(ClaimTypes.Name, user.FullName),
        new(ClaimTypes.Email, user.Email),
        new("UserType", "Externo"),
        new("AuthenticationProvider", "Forms"),
        new("NIF", user.CustomAttributes["NIF"]),
        new("Empresa", user.CustomAttributes["Empresa"])
    };
    return claims;
}
```

---

## 🛡️ Proteger Páginas e Componentes

Para restringir o acesso a páginas Blazor, utilize o atributo `@attribute [Authorize(Policy = "...")]`:

```razor
@page "/minha-pagina-interna"
@attribute [Authorize(Policy = "InternoPolicy")]

<h3>Área exclusiva a colaboradores internos (Entra ID)</h3>
```

```razor
@page "/minha-pagina-externa"
@attribute [Authorize(Policy = "ExternoPolicy")]

<h3>Área exclusiva a clientes externos</h3>
```

---

## 📡 Endpoints REST Disponíveis

- `POST /api/auth/login`: Submissão de credenciais (suporta Form URL Encoded e JSON). Valida dados e emite o HttpCookie.
- `GET /auth/login-entra`: Despoleta o desafio de login corporativo via Microsoft Entra ID.
- `GET /auth/logout` & `POST /api/auth/logout`: Limpa o cookie de autenticação e termina a sessão.
- `GET /api/auth/me`: Retorna um JSON com o estado da sessão e todas as claims do utilizador autenticado.
