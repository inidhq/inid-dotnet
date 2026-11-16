using System.Security.Claims;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.DependencyInjection;

namespace InID.AspNetCore;

/// <summary>Which paths need someone signed in (and maybe a role or permission).</summary>
public sealed class InIDMiddlewareOptions
{
    public List<ProtectRule> Rules { get; } = new();
    /// <summary>Protect whatever this says (on top of the rules).</summary>
    public Func<HttpContext, bool>? When { get; set; }
    /// <summary>Answer InID's routes under the api path here (default true).</summary>
    public bool Routes { get; set; } = true;

    /// <summary>Paths ("/dashboard"), patterns (new Regex("^/reports")) or ProtectRule.For("/admin", role: "admin").</summary>
    public InIDMiddlewareOptions Protect(params ProtectRule[] rules)
    {
        Rules.AddRange(rules);
        return this;
    }

    public InIDMiddlewareOptions Protect(string path, string? role = null, string? permission = null, string? entrance = null) =>
        Protect(ProtectRule.For(path, role, permission, entrance));

    public InIDMiddlewareOptions Protect(Regex pattern, string? role = null, string? permission = null, string? entrance = null) =>
        Protect(ProtectRule.For(pattern, role, permission, entrance));

    public InIDMiddlewareOptions Protect(Func<HttpContext, bool> when)
    {
        When = when;
        return this;
    }
}

public sealed class InIDMiddleware
{
    private readonly RequestDelegate _next;
    private readonly InIDClient _client;
    private readonly InIDMiddlewareOptions _options;

    public InIDMiddleware(RequestDelegate next, InIDClient client, InIDMiddlewareOptions options)
    {
        _next = next;
        _client = client;
        _options = options;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var request = context.ToInIDRequest();
        var when = _options.When;
        var gate = await _client.GateAsync(request, _options.Rules, when is null ? null : _ => when(context), _options.Routes, context.RequestAborted);
        if (gate.Response is not null)
        {
            await context.WriteAsync(gate.Response);
            return;
        }
        context.Items[InIDDefaults.ItemKey] = gate.Auth;
        if (gate.Auth.IsSignedIn) context.User = InIDPrincipal.From(gate.Auth);
        foreach (var cookie in gate.SetCookies) context.Response.Headers.Append("Set-Cookie", cookie);
        // The rest of this request sees the renewed cookies
        if (gate.CookieHeader is not null) context.Request.Headers.Cookie = gate.CookieHeader;
        await _next(context);
    }
}

public static class InIDHttpContextExtensions
{
    /// <summary>Who is signed in (set by UseInID; anonymous without it).</summary>
    public static InIDAuth GetInID(this HttpContext context) =>
        context.Items.TryGetValue(InIDDefaults.ItemKey, out var auth) && auth is InIDAuth a ? a : InIDAuth.Anonymous;

    /// <summary>The request as InID's core sees it.</summary>
    public static InIDRequest ToInIDRequest(this HttpContext context) =>
        new(context.Request.Method, new Uri(context.Request.GetEncodedUrl()), context.Request.Headers.Cookie.ToString() is { Length: > 0 } c ? c : null);

    /// <summary>Sends an answer from InID's core.</summary>
    public static async Task WriteAsync(this HttpContext context, InIDResponse response)
    {
        context.Response.StatusCode = response.Status;
        foreach (var (name, value) in response.Headers)
        {
            if (string.Equals(name, "content-type", StringComparison.OrdinalIgnoreCase)) context.Response.ContentType = value;
            else context.Response.Headers.Append(name, value);
        }
        if (response.Body is not null) await context.Response.WriteAsync(response.Body, context.RequestAborted);
    }

    /// <summary>For a native app's backend: the person behind "Authorization: Bearer &lt;id_token&gt;".</summary>
    public static Task<InIDAuth> VerifyInIDBearerAsync(this HttpContext context) =>
        context.RequestServices.GetRequiredService<InIDClient>().VerifyBearerAsync(context.Request.Headers.Authorization.ToString(), context.RequestAborted);

    /// <summary>Verifies a webhook request: reads the raw body and checks the InID-Signature header.</summary>
    public static async Task<InIDWebhookEvent> VerifyInIDWebhookAsync(this HttpRequest request)
    {
        using var reader = new StreamReader(request.Body);
        var body = await reader.ReadToEndAsync(request.HttpContext.RequestAborted);
        return request.HttpContext.RequestServices.GetRequiredService<InIDClient>().VerifyWebhook(body, request.Headers["InID-Signature"].ToString());
    }
}

public static class InIDApplicationBuilderExtensions
{
    /// <summary>
    /// InID's routes under the api path, the session (renewed before it ends) and the protect rules.
    /// Put it before routing/authorization. Keys are checked here, at startup.
    /// </summary>
    public static IApplicationBuilder UseInID(this IApplicationBuilder app, Action<InIDMiddlewareOptions>? configure = null)
    {
        var options = new InIDMiddlewareOptions();
        configure?.Invoke(options);
        var client = app.ApplicationServices.GetRequiredService<InIDClient>();
        return app.UseMiddleware<InIDMiddleware>(client, options);
    }
}

/// <summary>A ClaimsPrincipal for the signed-in person: sub, name, email, a role claim per role, a "permission" claim per permission.</summary>
public static class InIDPrincipal
{
    public const string PermissionClaim = "permission";

    public static ClaimsPrincipal From(InIDAuth auth)
    {
        if (auth.User is not { } user) return new ClaimsPrincipal(new ClaimsIdentity());
        var claims = new List<Claim> { new(ClaimTypes.NameIdentifier, user.Id), new("sub", user.Id) };
        if (user.Name is not null) claims.Add(new Claim(ClaimTypes.Name, user.Name));
        if (user.Email is not null) claims.Add(new Claim(ClaimTypes.Email, user.Email));
        claims.AddRange(user.Roles.Select(r => new Claim(ClaimTypes.Role, r)));
        claims.AddRange(user.Permissions.Select(p => new Claim(PermissionClaim, p)));
        return new ClaimsPrincipal(new ClaimsIdentity(claims, InIDDefaults.AuthenticationScheme));
    }
}
