using System.Net;
using System.Security.Cryptography;
using System.Text;
using InID.AspNetCore;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace InID.Tests;

public sealed class AspNetCoreTests : IDisposable
{
    private readonly FakeInID _fake = new() { Now = DateTimeOffset.UtcNow.ToUnixTimeSeconds() };
    private readonly IHost _host;
    private readonly HttpClient _client;

    public AspNetCoreTests()
    {
        _host = new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureAppConfiguration(c => c.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["InID:PublishableKey"] = FakeInID.Pk,
                    ["InID:SecretKey"] = FakeInID.Sk,
                    ["InID:Issuer"] = FakeInID.Issuer,
                    ["InID:WebhookSecret"] = "whsec_test",
                }))
                .ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddInID(httpClient: new HttpClient(_fake));
                    services.AddAuthorization(o => o.AddPolicy("admin", p => p.RequireInIDRole("admin")));
                })
                .Configure(app =>
                {
                    app.UseInID(o => o.Protect("/dashboard").Protect("/staff", role: "staff", entrance: "team"));
                    app.UseRouting();
                    app.UseAuthentication();
                    app.UseAuthorization();
                    app.UseEndpoints(e =>
                    {
                        e.MapGet("/", (HttpContext c) => c.GetInID().IsSignedIn ? "in" : "out");
                        e.MapGet("/dashboard", (HttpContext c) => c.GetInID().User!.Name);
                        e.MapGet("/staff", () => "staff");
                        e.MapGet("/cookies", (HttpContext c) => c.Request.Cookies["__inid_refresh"] ?? "");
                        e.MapGet("/admin", () => "admin").RequireAuthorization("admin");
                        e.MapGet("/whoami", (HttpContext c) => c.User.Identity?.IsAuthenticated == true ? c.User.FindFirst("sub")!.Value : "nobody");
                        e.MapGet("/app/me", async (HttpContext c) => (await c.VerifyInIDBearerAsync()).UserId ?? "nobody");
                        e.MapPost("/webhooks/inid", async (HttpContext c) => (await c.Request.VerifyInIDWebhookAsync()).Type);
                    });
                }))
            .Start();
        _client = _host.GetTestClient();
    }

    public void Dispose()
    {
        _client.Dispose();
        _host.Dispose();
    }

    private Task<HttpResponseMessage> Get(string path, string? cookie = null)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, path);
        if (cookie is not null) req.Headers.Add("Cookie", cookie);
        return _client.SendAsync(req);
    }

    private string Signed(string[]? roles = null, long? exp = null) => $"__inid_session={_fake.IdToken(exp: exp, roles: roles)}";

    [Fact]
    public async Task Answers_the_signin_route()
    {
        var res = await Get("/api/inid/signin?return_to=%2Fdashboard");
        Assert.Equal(HttpStatusCode.Found, res.StatusCode);
        Assert.StartsWith(FakeInID.Issuer + "/oauth/authorize?", res.Headers.Location!.ToString());
        Assert.Contains("redirect_uri=http%3A%2F%2Flocalhost%2Fapi%2Finid%2Fcallback", res.Headers.Location!.ToString());
        var cookie = res.Headers.GetValues("Set-Cookie").Single();
        Assert.StartsWith("__inid_flow_", cookie);
        Assert.DoesNotContain("Secure", cookie);
    }

    [Fact]
    public async Task Answers_the_session_route()
    {
        var res = await Get("/api/inid/session", Signed());
        Assert.Equal("application/json", res.Content.Headers.ContentType!.MediaType);
        Assert.Contains("\"firstName\":\"Ana\"", await res.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.NotFound, (await Get("/api/inid/unknown")).StatusCode);
    }

    [Fact]
    public async Task Protected_path_sends_to_sign_in()
    {
        var res = await Get("/dashboard/reports?x=1");
        Assert.Equal(HttpStatusCode.TemporaryRedirect, res.StatusCode);
        Assert.Equal("/api/inid/signin?return_to=%2Fdashboard%2Freports%3Fx%3D1", res.Headers.Location!.ToString());
    }

    [Fact]
    public async Task Protected_path_with_entrance()
    {
        var res = await Get("/staff");
        Assert.Equal("/api/inid/signin?return_to=%2Fstaff&entrance=team", res.Headers.Location!.ToString());
    }

    [Fact]
    public async Task Signed_in_sees_the_page()
    {
        var res = await Get("/dashboard", Signed());
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        Assert.Equal("Ana Pérez", await res.Content.ReadAsStringAsync());
        Assert.Equal("user_1", await (await Get("/whoami", Signed())).Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Missing_role_is_403()
    {
        Assert.Equal(HttpStatusCode.Forbidden, (await Get("/staff", Signed())).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Get("/staff", Signed(new[] { "staff" }))).StatusCode);
    }

    [Fact]
    public async Task Unprotected_path_is_open()
    {
        Assert.Equal("out", await (await Get("/")).Content.ReadAsStringAsync());
        Assert.Equal("in", await (await Get("/", Signed())).Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Renews_the_session_for_this_request_and_the_browser()
    {
        var res = await Get("/cookies", $"{Signed(exp: _fake.Now + 20)}; __inid_refresh=rt_old");
        Assert.Equal("rt_new", await res.Content.ReadAsStringAsync());
        var cookies = res.Headers.GetValues("Set-Cookie").ToList();
        Assert.Contains(cookies, c => c.StartsWith("__inid_session="));
        Assert.Contains(cookies, c => c.StartsWith("__inid_refresh=rt_new"));
    }

    [Fact]
    public async Task Google_answer_goes_on_to_inid()
    {
        var res = await Get("/?state=inidg_1&error=access_denied");
        Assert.Equal(HttpStatusCode.TemporaryRedirect, res.StatusCode);
        Assert.Equal(FakeInID.Issuer + "/oauth/google/callback?state=inidg_1&error=access_denied", res.Headers.Location!.ToString());
    }

    [Fact]
    public async Task Role_policy_challenges_forbids_and_allows()
    {
        var anonymous = await Get("/admin");
        Assert.Equal(HttpStatusCode.TemporaryRedirect, anonymous.StatusCode);
        Assert.Equal("/api/inid/signin?return_to=%2Fadmin", anonymous.Headers.Location!.ToString());
        Assert.Equal(HttpStatusCode.Forbidden, (await Get("/admin", Signed())).StatusCode);
        Assert.Equal("admin", await (await Get("/admin", Signed(new[] { "admin" }))).Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Bearer_token_for_native_apps()
    {
        var req = new HttpRequestMessage(HttpMethod.Get, "/app/me");
        req.Headers.Add("Authorization", "Bearer " + _fake.IdToken());
        Assert.Equal("user_1", await (await _client.SendAsync(req)).Content.ReadAsStringAsync());
        Assert.Equal("nobody", await (await Get("/app/me")).Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Webhook_endpoint_verifies_the_signature()
    {
        const string body = "{\"type\":\"user.created\",\"sub\":\"user_1\",\"created_at\":\"2026-11-16T00:00:00Z\"}";
        var t = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var v1 = Convert.ToHexString(HMACSHA256.HashData(Encoding.UTF8.GetBytes("whsec_test"), Encoding.UTF8.GetBytes($"{t}.{body}"))).ToLowerInvariant();
        var req = new HttpRequestMessage(HttpMethod.Post, "/webhooks/inid") { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        req.Headers.Add("InID-Signature", $"t={t},v1={v1}");
        Assert.Equal("user.created", await (await _client.SendAsync(req)).Content.ReadAsStringAsync());
    }

    [Fact]
    public void Missing_keys_fail_at_startup()
    {
        var builder = new HostBuilder().ConfigureWebHost(web => web
            .UseTestServer()
            .ConfigureAppConfiguration(c => c.AddInMemoryCollection(new Dictionary<string, string?> { ["InID:PublishableKey"] = "", ["InID:SecretKey"] = "" }))
            .ConfigureServices(s => s.AddInID())
            .Configure(app => app.UseInID()));
        var error = Assert.ThrowsAny<Exception>(() => builder.Start());
        Assert.Contains("INID_PUBLISHABLE_KEY", error.ToString());
    }

    [Fact]
    public void Html_renders_the_sign_in_element_and_script()
    {
        Assert.Equal("<script src=\"https://cdn.jsdelivr.net/npm/@inid/js@0.1/dist/inid.global.js\" defer></script>", InIDHtml.Script());
        Assert.Equal("<inid-sign-in app-name=\"Acme &amp; Co\" entrance=\"team\"></inid-sign-in>", InIDHtml.SignIn(appName: "Acme & Co", entrance: "team", apiPath: "/api/inid"));
        Assert.Equal("<inid-sign-in api-path=\"/auth\" redirect></inid-sign-in>", InIDHtml.SignIn(redirect: true, apiPath: "/auth"));
    }
}
