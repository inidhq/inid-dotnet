# InID for .NET

Sign-in with InID for ASP.NET Core and any .NET 8 server: the routes that sign people in and out, the session in its cookies (renewed before it ends), protected paths with roles and permissions, webhooks, bearer tokens from native apps, and the app API.

| Package | What it is |
|---|---|
| `InID` | The core: no framework, only `HttpClient`, `System.Security.Cryptography` and `System.Text.Json` |
| `InID.AspNetCore` | `AddInID`, the `UseInID` middleware, authorization policies and HTML helpers |

## Install

```sh
dotnet add package InID.AspNetCore
```

Set your keys (from InID's panel) in `appsettings.json` or as environment variables:

```json
{
  "InID": {
    "PublishableKey": "pk_test_...",
    "SecretKey": "sk_test_...",
    "WebhookSecret": "whsec_..."
  }
}
```

| Setting | Env var | Default |
|---|---|---|
| `PublishableKey` | `INID_PUBLISHABLE_KEY` | required (`pk_...`) |
| `SecretKey` | `INID_SECRET_KEY` | required (`sk_...`) |
| `Issuer` | `INID_ISSUER` | `https://id.inid.co` |
| `AppUrl` | `INID_APP_URL` | the request's origin (set it behind a proxy) |
| `ApiPath` | | `/api/inid` |
| `Scope` | | `openid profile email phone` |
| `WebhookSecret` | `INID_WEBHOOK_SECRET` | only to verify webhooks |

Missing or malformed keys fail at startup.

## Minimal API (`Program.cs`)

```csharp
using InID;
using InID.AspNetCore;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddInID();
builder.Services.AddAuthorization(o => o.AddPolicy("admin", p => p.RequireInIDRole("admin")));

var app = builder.Build();

// InID's routes (/api/inid/signin, /callback, /signout, /session, /sessions), the session
// renewed before it ends, and who may see each path
app.UseInID(o => o
    .Protect("/dashboard")                                     // signed in (and its subpaths)
    .Protect("/billing", permission: "invoices:read")          // a permission
    .Protect("/staff", role: "staff", entrance: "team"));      // a role, through the "team" entrance

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", (HttpContext http) => Results.Content($"""
    <!doctype html>
    {InIDHtml.Script()}
    {InIDHtml.SignIn(appName: "Acme")}
    <inid-user-button></inid-user-button>
    """, "text/html"));

app.MapGet("/dashboard", (HttpContext http) =>
{
    var auth = http.GetInID();
    return $"Hello {auth.User!.Name}, admin: {auth.Has(role: "admin")}";
});

// A role through an authorization policy (unsigned: sent to sign in; without the role: 403)
app.MapGet("/admin", () => "Admins only").RequireAuthorization("admin");

// A native app's backend: Authorization: Bearer <id_token>
app.MapGet("/api/me", async (HttpContext http) =>
{
    var auth = await http.VerifyInIDBearerAsync();
    return auth.IsSignedIn ? Results.Ok(auth.User) : Results.Unauthorized();
});

// Webhooks: the raw body and the InID-Signature header (throws InIDException if forged)
app.MapPost("/webhooks/inid", async (HttpRequest request) =>
{
    var e = await request.VerifyInIDWebhookAsync();
    if (e.Type == "user.deleted") { /* forget e.Sub */ }
    return Results.Ok();
});

app.Run();
```

## MVC

```csharp
// Program.cs
builder.Services.AddControllersWithViews();
builder.Services.AddInID();
builder.Services.AddAuthorization(o =>
{
    o.AddPolicy("admin", p => p.RequireInIDRole("admin"));
    o.AddPolicy("invoices", p => p.RequireInIDPermission("invoices:read"));
    o.AddPolicy("signedIn", p => p.RequireInIDSignedIn());
});
// ...
app.UseInID(o => o.Protect("/account"));
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.MapDefaultControllerRoute();
```

```csharp
public class AdminController : Controller
{
    private readonly InIDClient _inid;
    public AdminController(InIDClient inid) => _inid = inid;

    [Authorize(Policy = "admin")]
    public IActionResult Index() => View(HttpContext.GetInID().User);

    [Authorize(Policy = "admin")]
    [HttpPost]
    public async Task<IActionResult> Promote(string id)
    {
        await _inid.SetRoleAsync(id, "admin");   // arrives with the person's next renewal
        return RedirectToAction(nameof(Index));
    }
}
```

The signed-in person is also `User` (a `ClaimsPrincipal`: `sub`, name, email, a role claim per role and a `permission` claim per permission), so `User.IsInRole("admin")` works.

In a view (`_ViewImports.cshtml`: `@addTagHelper *, InID.AspNetCore`):

```cshtml
@using InID.AspNetCore
<inid-script />                 @* or @Html.InIDScript() *@
@Html.InIDSignIn(appName: "Acme")
<inid-user-button></inid-user-button>
```

## Without ASP.NET Core

```csharp
var inid = new InIDClient();   // INID_PUBLISHABLE_KEY, INID_SECRET_KEY…
var gate = await inid.GateAsync(new InIDRequest("GET", requestUrl, cookieHeader), new ProtectRule[] { "/dashboard" });
if (gate.Response is { } response) { /* send response.Status, response.Headers, response.Body */ }
// else: gate.Auth.User, gate.Auth.Has(role: "admin"); add gate.SetCookies to your response
```

`InIDClient` also has `HandleAsync` (the routes alone), `ReadSessionAsync`, `VerifyIdTokenAsync`, `VerifyBearerAsync`, `VerifyWebhook`, and the app API: `GetUserAsync`, `SetRoleAsync`, `UpdateMetadataAsync`, `GetRolesAsync`, `InviteAsync`, `ApiAsync`.

## Tests

```sh
docker run --rm -v "$PWD":/app -w /app mcr.microsoft.com/dotnet/sdk:8.0 dotnet test
```

## License

MIT
