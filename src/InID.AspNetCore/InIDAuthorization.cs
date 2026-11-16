using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace InID.AspNetCore;

/// <summary>
/// The "InID" scheme: authenticates from what UseInID found (or the session cookie), challenges by
/// sending the person to sign in and forbids with a 403.
/// </summary>
public sealed class InIDAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly InIDClient _client;

    public InIDAuthenticationHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, InIDClient client)
        : base(options, logger, encoder) => _client = client;

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var auth = Context.Items.ContainsKey(InIDDefaults.ItemKey)
            ? Context.GetInID()
            : await _client.AuthAsync(Request.Headers.Cookie.ToString(), Context.RequestAborted);
        if (!auth.IsSignedIn) return AuthenticateResult.NoResult();
        return AuthenticateResult.Success(new AuthenticationTicket(InIDPrincipal.From(auth), Scheme.Name));
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        var returnTo = $"{Request.PathBase}{Request.Path}{Request.QueryString}";
        Response.StatusCode = 307;
        Response.Headers.Location = $"{_client.ApiPath}/signin?return_to={Uri.EscapeDataString(returnTo)}";
        Response.Headers.CacheControl = "no-store";
        return Task.CompletedTask;
    }

    protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = 403;
        return Task.CompletedTask;
    }
}

public static class InIDAuthorizationPolicyBuilderExtensions
{
    /// <summary>Someone signed in with InID.</summary>
    public static AuthorizationPolicyBuilder RequireInIDSignedIn(this AuthorizationPolicyBuilder builder) =>
        builder.AddAuthenticationSchemes(InIDDefaults.AuthenticationScheme).RequireAuthenticatedUser();

    /// <summary>Someone signed in with InID who has this app role.</summary>
    public static AuthorizationPolicyBuilder RequireInIDRole(this AuthorizationPolicyBuilder builder, string role) =>
        builder.RequireInIDSignedIn().RequireRole(role);

    /// <summary>Someone signed in with InID who has this app permission.</summary>
    public static AuthorizationPolicyBuilder RequireInIDPermission(this AuthorizationPolicyBuilder builder, string permission) =>
        builder.RequireInIDSignedIn().RequireClaim(InIDPrincipal.PermissionClaim, permission);
}
