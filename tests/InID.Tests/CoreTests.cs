using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Xunit;

namespace InID.Tests;

public class CoreTests
{
    private readonly FakeInID _fake = new();
    private const string App = "https://app.test";

    private static InIDRequest Req(string method, string pathAndQuery, string? cookie = null) => new(method, new Uri(App + pathAndQuery), cookie);

    private static Dictionary<string, string> Query(string url) =>
        new Uri(url).Query.TrimStart('?').Split('&').Select(p => p.Split('=')).ToDictionary(p => p[0], p => Uri.UnescapeDataString(p[1]));

    private static string? CookieValue(InIDResponse r, string name)
    {
        var c = r.SetCookies.FirstOrDefault(x => x.StartsWith(name + "="));
        return c is null ? null : Uri.UnescapeDataString(c[(name.Length + 1)..c.IndexOf(';')]);
    }

    private static string? SetCookie(InIDResponse r, string name) => r.SetCookies.FirstOrDefault(x => x.StartsWith(name + "="));

    // ---------- 1. signin ----------

    [Fact]
    public async Task Signin_redirects_with_every_parameter_pkce_and_flow_cookie()
    {
        var r = await _fake.Client().HandleAsync(Req("GET", "/api/inid/signin?return_to=%2Fdashboard%3Ftab%3D1&ui_locales=es&login_hint=ana%40x.co&entrance=team"));
        Assert.Equal(302, r.Status);
        Assert.Equal("no-store", r.Header("cache-control"));
        var location = r.Header("location")!;
        Assert.StartsWith(FakeInID.Issuer + "/oauth/authorize?", location);
        var q = Query(location);
        Assert.Equal(FakeInID.Pk, q["client_id"]);
        Assert.Equal(App + "/api/inid/callback", q["redirect_uri"]);
        Assert.Equal("code", q["response_type"]);
        Assert.Equal("openid profile email phone", q["scope"]);
        Assert.Equal("S256", q["code_challenge_method"]);
        Assert.Equal("es", q["ui_locales"]);
        Assert.Equal("ana@x.co", q["login_hint"]);
        Assert.Equal("team", q["entrance"]);
        Assert.False(q.ContainsKey("prompt"));
        Assert.False(q.ContainsKey("display"));

        var cookie = SetCookie(r, "__inid_flow_" + q["state"])!;
        Assert.Contains("Path=/api/inid", cookie);
        Assert.Contains("Max-Age=600", cookie);
        Assert.Contains("HttpOnly", cookie);
        Assert.Contains("SameSite=Lax", cookie);
        Assert.Contains("Secure", cookie);
        var flow = JsonDocument.Parse(Convert.FromBase64String(Pad(CookieValue(r, "__inid_flow_" + q["state"])!))).RootElement;
        Assert.Equal(q["state"], flow.GetProperty("state").GetString());
        Assert.Equal(q["nonce"], flow.GetProperty("nonce").GetString());
        Assert.Equal("/dashboard?tab=1", flow.GetProperty("returnTo").GetString());
        var verifier = flow.GetProperty("verifier").GetString()!;
        Assert.Equal(FakeInID.B64(SHA256.HashData(Encoding.UTF8.GetBytes(verifier))), q["code_challenge"]);
    }

    private static string Pad(string b64url)
    {
        var s = b64url.Replace('-', '+').Replace('_', '/');
        return s + new string('=', (4 - s.Length % 4) % 4);
    }

    [Theory]
    [InlineData("https://evil.com", "/")]
    [InlineData("//evil.com", "/")]
    [InlineData("/\\evil.com", "/")]
    [InlineData("/ok", "/ok")]
    public async Task Signin_sanitizes_return_to(string given, string expected)
    {
        var r = await _fake.Client().HandleAsync(Req("GET", "/api/inid/signin?return_to=" + Uri.EscapeDataString(given)));
        var state = Query(r.Header("location")!)["state"];
        var flow = JsonDocument.Parse(Convert.FromBase64String(Pad(CookieValue(r, "__inid_flow_" + state)!))).RootElement;
        Assert.Equal(expected, flow.GetProperty("returnTo").GetString());
    }

    [Fact]
    public async Task Signin_after_signing_out_asks_to_log_in()
    {
        var r = await _fake.Client().HandleAsync(Req("GET", "/api/inid/signin", "__inid_out=1"));
        Assert.Equal("login", Query(r.Header("location")!)["prompt"]);
    }

    [Fact]
    public async Task Signin_embed_adds_display_and_prompt_and_keeps_the_page()
    {
        var r = await _fake.Client().HandleAsync(Req("GET", "/api/inid/signin?display=embed&return_to=%2Fapp&page=%2Flogin"));
        var q = Query(r.Header("location")!);
        Assert.Equal("embed", q["display"]);
        Assert.Equal("login", q["prompt"]);
        var flow = JsonDocument.Parse(Convert.FromBase64String(Pad(CookieValue(r, "__inid_flow_" + q["state"])!))).RootElement;
        Assert.True(flow.GetProperty("embed").GetBoolean());
        Assert.Equal("/login", flow.GetProperty("page").GetString());
    }

    [Fact]
    public async Task Signin_resume_after_google_continues_at_inid()
    {
        var resume = Uri.EscapeDataString("request=rq1&session=s1&from=google&lang=es&junk=1");
        var r = await _fake.Client().HandleAsync(Req("GET", "/api/inid/signin?display=embed&continue=" + resume));
        Assert.Equal(FakeInID.Issuer + "/oauth/authorize/continue?request=rq1&session=s1&from=google&lang=es&display=embed", r.Header("location"));
        Assert.Empty(r.SetCookies);
    }

    // ---------- 2. callback ----------

    private async Task<(InIDClient client, string state, string cookie)> StartFlow(string query = "return_to=%2Fdashboard")
    {
        var client = _fake.Client();
        var r = await client.HandleAsync(Req("GET", "/api/inid/signin?" + query));
        var q = Query(r.Header("location")!);
        _fake.NextNonce = q["nonce"];
        var name = "__inid_flow_" + q["state"];
        return (client, q["state"], $"{name}={Uri.EscapeDataString(CookieValue(r, name)!)}; __inid_out=1");
    }

    [Fact]
    public async Task Callback_exchanges_the_code_and_signs_in()
    {
        var (client, state, cookie) = await StartFlow();
        var r = await client.HandleAsync(Req("GET", $"/api/inid/callback?code=c1&state={state}", cookie));
        Assert.Equal(302, r.Status);
        Assert.Equal("/dashboard", r.Header("location"));

        var token = _fake.Requests.Single(x => x.Url.AbsolutePath == "/oauth/token");
        Assert.Equal("Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"{FakeInID.Pk}:{FakeInID.Sk}")), token.Authorization);
        var form = FakeInID.Form(token.Body);
        Assert.Equal("authorization_code", form["grant_type"]);
        Assert.Equal("c1", form["code"]);
        Assert.Equal(App + "/api/inid/callback", form["redirect_uri"]);
        Assert.False(string.IsNullOrEmpty(form["code_verifier"]));

        Assert.NotNull(CookieValue(r, "__inid_session"));
        Assert.Equal("rt_new", CookieValue(r, "__inid_refresh"));
        Assert.Contains("Max-Age=2592000", SetCookie(r, "__inid_session"));
        Assert.Contains("Max-Age=0", SetCookie(r, "__inid_out"));
        Assert.Contains("Max-Age=0", SetCookie(r, "__inid_flow_" + state));
    }

    [Fact]
    public async Task Callback_with_a_wrong_nonce_fails()
    {
        var (client, state, cookie) = await StartFlow();
        _fake.NextNonce = "other";
        var r = await client.HandleAsync(Req("GET", $"/api/inid/callback?code=c1&state={state}", cookie));
        Assert.Equal(400, r.Status);
        Assert.Null(CookieValue(r, "__inid_session"));
    }

    [Fact]
    public async Task Callback_state_mismatch_goes_home()
    {
        var (client, _, cookie) = await StartFlow();
        var r = await client.HandleAsync(Req("GET", "/api/inid/callback?code=c1&state=forged", cookie));
        Assert.Equal(302, r.Status);
        Assert.Equal("/", r.Header("location"));
        Assert.DoesNotContain(_fake.Requests, x => x.Url.AbsolutePath == "/oauth/token");
    }

    [Fact]
    public async Task Callback_for_an_embedded_flow_leaves_the_frame()
    {
        var (client, state, cookie) = await StartFlow("display=embed&return_to=%2Fapp%3Fx%3D%3Cy%3E");
        var r = await client.HandleAsync(Req("GET", $"/api/inid/callback?code=c1&state={state}", cookie));
        Assert.Equal(200, r.Status);
        Assert.StartsWith("text/html", r.Header("content-type"));
        Assert.Equal("<!doctype html><meta charset=\"utf-8\"><script>(window.top || window).location.replace(\"/app?x=\\u003Cy\\u003E\")</script>", r.Body);
        Assert.NotNull(CookieValue(r, "__inid_session"));
    }

    [Fact]
    public async Task Callback_back_from_google_resumes_on_the_page()
    {
        var (client, state, cookie) = await StartFlow("display=embed&return_to=%2Fapp&page=%2Flogin%3Fa%3D1");
        var r = await client.HandleAsync(Req("GET", $"/api/inid/callback?state={state}&inid_continue=abc", cookie));
        Assert.Equal("/login?a=1&inid_continue=abc", r.Header("location"));
    }

    // ---------- 3. session renewal ----------

    [Fact]
    public async Task Session_near_expiry_is_renewed_with_the_refresh_token()
    {
        var client = _fake.Client();
        var old = _fake.IdToken(exp: _fake.Now + 30);
        var result = await client.ReadSessionAsync($"__inid_session={old}; __inid_refresh=rt_old; other=1", refresh: true);
        Assert.NotNull(result.Session);
        Assert.Equal(_fake.Now + 600, result.Session!.ExpiresAt);
        var form = FakeInID.Form(_fake.Requests.Single(x => x.Url.AbsolutePath == "/oauth/token").Body);
        Assert.Equal("refresh_token", form["grant_type"]);
        Assert.Equal("rt_old", form["refresh_token"]);
        Assert.Equal(2, result.SetCookies.Count);
        Assert.Contains("__inid_refresh=rt_new", result.CookieHeader);
        Assert.Contains("other=1", result.CookieHeader);
    }

    [Fact]
    public async Task Session_far_from_expiry_is_not_renewed()
    {
        var result = await _fake.Client().ReadSessionAsync($"__inid_session={_fake.IdToken()}; __inid_refresh=rt", refresh: true);
        Assert.NotNull(result.Session);
        Assert.Empty(result.SetCookies);
        Assert.DoesNotContain(_fake.Requests, x => x.Url.AbsolutePath == "/oauth/token");
    }

    [Fact]
    public async Task Session_refresh_answered_4xx_clears_the_cookies()
    {
        _fake.Token = _ => new HttpResponseMessage(HttpStatusCode.BadRequest) { Content = new StringContent("{\"error\":\"invalid_grant\"}") };
        var result = await _fake.Client().ReadSessionAsync($"__inid_session={_fake.IdToken(exp: _fake.Now + 30)}; __inid_refresh=rt", refresh: true);
        Assert.Null(result.Session);
        Assert.Contains(result.SetCookies, c => c.StartsWith("__inid_session=;") && c.Contains("Max-Age=0"));
        Assert.Contains(result.SetCookies, c => c.StartsWith("__inid_refresh=;") && c.Contains("Max-Age=0"));
        Assert.DoesNotContain("__inid_session", result.CookieHeader);
    }

    [Fact]
    public async Task Session_with_inid_down_keeps_what_is_still_valid()
    {
        _fake.Token = _ => throw new HttpRequestException("down");
        var client = _fake.Client();
        var result = await client.ReadSessionAsync($"__inid_session={_fake.IdToken(exp: _fake.Now + 30)}; __inid_refresh=rt", refresh: true);
        Assert.NotNull(result.Session);
        Assert.Empty(result.SetCookies);

        _fake.Token = _ => new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
        var expired = await client.ReadSessionAsync($"__inid_session={_fake.IdToken(exp: _fake.Now - 5)}; __inid_refresh=rt", refresh: true);
        Assert.Null(expired.Session);
        Assert.Empty(expired.SetCookies);
    }

    [Fact]
    public async Task Expired_session_without_refresh_is_signed_out()
    {
        var result = await _fake.Client().ReadSessionAsync($"__inid_session={_fake.IdToken(exp: _fake.Now - 5)}");
        Assert.Null(result.Session);
    }

    // ---------- 4. signout ----------

    [Fact]
    public async Task Signout_revokes_clears_and_marks_signed_out()
    {
        var r = await _fake.Client().HandleAsync(Req("POST", "/api/inid/signout", "__inid_session=x; __inid_refresh=rt_1"));
        Assert.Equal(200, r.Status);
        Assert.Equal("{\"ok\":true}", r.Body);
        Assert.Equal("no-store", r.Header("cache-control"));
        var revoke = _fake.Requests.Single(x => x.Url.AbsolutePath == "/oauth/revoke");
        Assert.StartsWith("Basic ", revoke.Authorization);
        var form = FakeInID.Form(revoke.Body);
        Assert.Equal("rt_1", form["token"]);
        Assert.Equal("refresh_token", form["token_type_hint"]);
        Assert.Contains("Max-Age=0", SetCookie(r, "__inid_session"));
        Assert.Contains("Max-Age=0", SetCookie(r, "__inid_refresh"));
        Assert.Equal("1", CookieValue(r, "__inid_out"));
        Assert.Contains("Max-Age=2592000", SetCookie(r, "__inid_out"));
    }

    // ---------- 5. /session ----------

    [Fact]
    public async Task Session_route_answers_the_user_in_camelCase()
    {
        var r = await _fake.Client().HandleAsync(Req("GET", "/api/inid/session", $"__inid_session={_fake.IdToken()}"));
        Assert.Equal(200, r.Status);
        Assert.Equal("no-store", r.Header("cache-control"));
        var body = JsonDocument.Parse(r.Body!).RootElement;
        Assert.Equal($"{FakeInID.Issuer}/account?client_id={FakeInID.Pk}", body.GetProperty("accountUrl").GetString());
        var user = body.GetProperty("user");
        Assert.Equal("user_1", user.GetProperty("id").GetString());
        Assert.Equal("Ana", user.GetProperty("firstName").GetString());
        Assert.Equal("Pérez", user.GetProperty("lastName").GetString());
        Assert.Equal("Ana Pérez", user.GetProperty("name").GetString());
        Assert.Equal("ana@example.com", user.GetProperty("email").GetString());
        Assert.True(user.GetProperty("emailVerified").GetBoolean());
        Assert.Equal("+573001234567", user.GetProperty("phone").GetString());
        Assert.Equal("member", user.GetProperty("roles")[0].GetString());
        Assert.Equal("invoices:read", user.GetProperty("permissions")[0].GetString());
        Assert.Equal("pro", user.GetProperty("publicMetadata").GetProperty("plan").GetString());
        Assert.Equal(10, user.EnumerateObject().Count());
    }

    [Fact]
    public async Task Session_route_without_session_answers_null_user()
    {
        var r = await _fake.Client().HandleAsync(Req("GET", "/api/inid/session"));
        Assert.Equal(JsonValueKind.Null, JsonDocument.Parse(r.Body!).RootElement.GetProperty("user").ValueKind);
    }

    [Fact]
    public void User_has_role_and_permission()
    {
        var user = new InIDUser { Roles = new[] { "admin" }, Permissions = new[] { "a:b" } };
        Assert.True(user.Has(role: "admin"));
        Assert.True(user.Has(permission: "a:b"));
        Assert.True(user.Has("admin", "a:b"));
        Assert.False(user.Has("admin", "x"));
        Assert.False(user.Has(role: "x"));
        Assert.True(user.Has());
        Assert.False(InIDAuth.Anonymous.Has());
        Assert.False(InIDAuth.Anonymous.Has(role: "admin"));
    }

    [Fact]
    public async Task Gate_path_only_rule_lets_any_signed_in_user_through()
    {
        var gate = await _fake.Client().GateAsync(Req("GET", "/dashboard", $"__inid_session={_fake.IdToken(roles: Array.Empty<string>())}"), new ProtectRule[] { "/dashboard" });
        Assert.Null(gate.Response);
        Assert.True(gate.Auth.Has());
    }

    [Fact]
    public async Task Sessions_routes_list_and_end()
    {
        var client = _fake.Client();
        var cookie = $"__inid_session={_fake.IdToken()}";
        Assert.Equal(401, (await client.HandleAsync(Req("GET", "/api/inid/sessions"))).Status);

        var list = JsonDocument.Parse((await client.HandleAsync(Req("GET", "/api/inid/sessions", cookie))).Body!).RootElement.GetProperty("sessions");
        Assert.True(list[0].GetProperty("current").GetBoolean());
        Assert.False(list[1].GetProperty("current").GetBoolean());
        Assert.Equal("Bearer " + FakeInID.Sk, _fake.Requests.Last().Authorization);

        var others = await client.HandleAsync(Req("DELETE", "/api/inid/sessions?others=1", cookie));
        Assert.Equal("{\"ended\":1}", others.Body);
        Assert.Contains(_fake.Requests, x => x.Method == HttpMethod.Delete && x.Url.AbsolutePath == "/v1/users/user_1/sessions/sid_2");

        var one = await client.HandleAsync(Req("DELETE", "/api/inid/sessions/sid_9", cookie));
        Assert.Equal("{\"ended\":1}", one.Body);
    }

    [Fact]
    public async Task Unknown_route_is_404()
    {
        var r = await _fake.Client().HandleAsync(Req("GET", "/api/inid/nope"));
        Assert.Equal(404, r.Status);
        Assert.Equal("{\"error\":\"not_found\"}", r.Body);
    }

    // ---------- 6. gate ----------

    [Fact]
    public async Task Gate_redirects_to_sign_in_with_return_to_and_entrance()
    {
        var gate = await _fake.Client().GateAsync(Req("GET", "/admin/users?page=2"), new[] { ProtectRule.For("/admin", role: "admin", entrance: "team") });
        Assert.Equal(307, gate.Response!.Status);
        Assert.Equal("/api/inid/signin?return_to=%2Fadmin%2Fusers%3Fpage%3D2&entrance=team", gate.Response.Header("location"));
    }

    [Fact]
    public async Task Gate_forbids_without_the_role()
    {
        var gate = await _fake.Client().GateAsync(Req("GET", "/admin", $"__inid_session={_fake.IdToken()}"), new[] { ProtectRule.For("/admin", role: "admin") });
        Assert.Equal(403, gate.Response!.Status);
        Assert.Equal("Forbidden", gate.Response.Body);
    }

    [Fact]
    public async Task Gate_lets_in_with_the_role()
    {
        var gate = await _fake.Client().GateAsync(Req("GET", "/admin", $"__inid_session={_fake.IdToken(roles: new[] { "admin" })}"), new[] { ProtectRule.For("/admin", role: "admin") });
        Assert.Null(gate.Response);
        Assert.True(gate.Auth.IsSignedIn);
        Assert.Equal("user_1", gate.Auth.UserId);
        Assert.True(gate.Auth.Has(role: "admin"));
    }

    [Theory]
    [InlineData("/dashboard", true)]
    [InlineData("/dashboard/x/y", true)]
    [InlineData("/dashboardx", false)]
    [InlineData("/", false)]
    public async Task Gate_matches_subpaths(string path, bool protectedPath)
    {
        var gate = await _fake.Client().GateAsync(Req("GET", path), new ProtectRule[] { "/dashboard" });
        Assert.Equal(protectedPath, gate.Response is not null);
    }

    [Fact]
    public async Task Gate_matches_regex_rules()
    {
        var gate = await _fake.Client().GateAsync(Req("GET", "/reports/2026"), new ProtectRule[] { new System.Text.RegularExpressions.Regex("^/reports/\\d+$") });
        Assert.Equal(307, gate.Response!.Status);
    }

    [Fact]
    public async Task Gate_sends_google_answers_on_to_inid()
    {
        var gate = await _fake.Client().GateAsync(Req("GET", "/?state=inidg_abc&code=xyz"));
        Assert.Equal(307, gate.Response!.Status);
        Assert.Equal(FakeInID.Issuer + "/oauth/google/callback?state=inidg_abc&code=xyz", gate.Response.Header("location"));
        var notOurs = await _fake.Client().GateAsync(Req("GET", "/?state=other&code=xyz"));
        Assert.Null(notOurs.Response);
    }

    [Fact]
    public async Task Gate_renews_and_hands_back_cookies()
    {
        var gate = await _fake.Client().GateAsync(Req("GET", "/page", $"__inid_session={_fake.IdToken(exp: _fake.Now + 10)}; __inid_refresh=rt"));
        Assert.Null(gate.Response);
        Assert.True(gate.Auth.IsSignedIn);
        Assert.Equal(2, gate.SetCookies.Count);
        Assert.Contains("__inid_refresh=rt_new", gate.CookieHeader);
    }

    [Fact]
    public async Task Gate_answers_routes_under_the_api_path()
    {
        var gate = await _fake.Client().GateAsync(Req("GET", "/api/inid/session"));
        Assert.Equal(200, gate.Response!.Status);
        var skipped = await _fake.Client().GateAsync(Req("GET", "/api/inid/session"), routes: false);
        Assert.True(skipped.Skipped);
        Assert.Null(skipped.Response);
    }

    // ---------- 7. webhooks ----------

    private static string Signature(string secret, long t, string body) =>
        $"t={t},v1={Convert.ToHexString(HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes($"{t}.{body}"))).ToLowerInvariant()}";

    private const string Event = "{\"type\":\"session.ended\",\"sub\":\"user_1\",\"sid\":\"sid_1\",\"created_at\":\"2026-11-16T00:00:00Z\"}";

    [Fact]
    public void Webhook_valid_signature_returns_the_event()
    {
        var e = InIDWebhooks.Verify(Event, Signature("whsec_test", 1000, Event), "whsec_test", now: 1100);
        Assert.Equal("session.ended", e.Type);
        Assert.Equal("user_1", e.Sub);
        Assert.Equal("sid_1", e.Sid);
        Assert.Equal("2026-11-16T00:00:00Z", e.CreatedAt);
    }

    [Fact]
    public void Webhook_via_client_uses_the_configured_secret()
    {
        var e = _fake.Client().VerifyWebhook(Event, Signature("whsec_test", _fake.Now, Event));
        Assert.Equal("session.ended", e.Type);
    }

    [Fact]
    public void Webhook_wrong_secret_is_rejected() =>
        Assert.Equal("invalid_signature", Assert.Throws<InIDException>(() => InIDWebhooks.Verify(Event, Signature("whsec_other", 1000, Event), "whsec_test", now: 1000)).Code);

    [Fact]
    public void Webhook_too_old_is_rejected() =>
        Assert.Throws<InIDException>(() => InIDWebhooks.Verify(Event, Signature("whsec_test", 1000, Event), "whsec_test", now: 1000 + 301));

    [Fact]
    public void Webhook_tampered_body_is_rejected() =>
        Assert.Throws<InIDException>(() => InIDWebhooks.Verify(Event.Replace("user_1", "user_2"), Signature("whsec_test", 1000, Event), "whsec_test", now: 1000));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("garbage")]
    [InlineData("t=1000")]
    [InlineData("v1=abcd")]
    [InlineData("t=abc,v1=abcd")]
    [InlineData("t=1000,v1=zz")]
    public void Webhook_malformed_header_is_rejected(string? header) =>
        Assert.Throws<InIDException>(() => InIDWebhooks.Verify(Event, header, "whsec_test", now: 1000));

    // ---------- 8. ID token verification ----------

    private Task<VerifiedToken?> Verify(InIDClient client, object claims, string kid = FakeInID.Kid, RSA? key = null) =>
        client.VerifyIdTokenAsync(_fake.Sign(claims, kid, key));

    [Fact]
    public async Task Token_valid_verifies()
    {
        var v = await Verify(_fake.Client(), _fake.Claims());
        Assert.NotNull(v);
        Assert.False(v!.Expired);
    }

    [Fact]
    public async Task Token_wrong_audience_fails()
    {
        var claims = _fake.Claims();
        claims["aud"] = "pk_test_other";
        Assert.Null(await Verify(_fake.Client(), claims));
    }

    [Fact]
    public async Task Token_wrong_issuer_fails()
    {
        var claims = _fake.Claims();
        claims["iss"] = "https://evil.test";
        Assert.Null(await Verify(_fake.Client(), claims));
    }

    [Fact]
    public async Task Token_bad_signature_fails()
    {
        using var other = RSA.Create(2048);
        Assert.Null(await Verify(_fake.Client(), _fake.Claims(), key: other));
        var token = _fake.IdToken();
        Assert.Null(await _fake.Client().VerifyIdTokenAsync(token[..^4] + (token.EndsWith("AAAA") ? "BBBB" : "AAAA")));
    }

    [Fact]
    public async Task Token_other_algorithm_fails()
    {
        Assert.Null(await _fake.Client().VerifyIdTokenAsync(_fake.Sign(_fake.Claims(), alg: "HS256")));
        Assert.Null(await _fake.Client().VerifyIdTokenAsync("not.a.jwt"));
        Assert.Null(await _fake.Client().VerifyIdTokenAsync("garbage"));
    }

    [Fact]
    public async Task Token_unknown_kid_fails_and_is_looked_up_once()
    {
        var client = _fake.Client();
        Assert.NotNull(await Verify(client, _fake.Claims()));
        Assert.Equal(1, _fake.JwksFetches);
        _fake.Now += 2;
        Assert.Null(await Verify(client, _fake.Claims(), kid: "unknown"));
        Assert.Equal(2, _fake.JwksFetches);
        // A different unknown kid within the same second isn't fetched
        Assert.Null(await Verify(client, _fake.Claims(), kid: "unknown-2"));
        Assert.Equal(2, _fake.JwksFetches);
        _fake.Now += 2;
        // Missed kids are remembered: no new fetch, even later
        Assert.Null(await Verify(client, _fake.Claims(), kid: "unknown"));
        Assert.Equal(2, _fake.JwksFetches);
    }

    [Fact]
    public async Task Token_expired_verifies_as_expired_and_never_signs_in()
    {
        var client = _fake.Client();
        var v = await Verify(client, _fake.Claims(exp: _fake.Now - 1));
        Assert.NotNull(v);
        Assert.True(v!.Expired);
        Assert.False((await client.VerifyBearerAsync("Bearer " + _fake.IdToken(exp: _fake.Now - 1))).IsSignedIn);
    }

    [Fact]
    public async Task Token_wrong_nonce_fails()
    {
        Assert.Null(await _fake.Client().VerifyIdTokenAsync(_fake.IdToken(nonce: "n1"), "n2"));
        Assert.NotNull(await _fake.Client().VerifyIdTokenAsync(_fake.IdToken(nonce: "n1"), "n1"));
    }

    [Fact]
    public async Task Bearer_verifies_a_native_apps_token()
    {
        var auth = await _fake.Client().VerifyBearerAsync("Bearer " + _fake.IdToken());
        Assert.True(auth.IsSignedIn);
        Assert.Equal("user_1", auth.UserId);
        Assert.False((await _fake.Client().VerifyBearerAsync(null)).IsSignedIn);
        Assert.False((await _fake.Client().VerifyBearerAsync("Bearer nope")).IsSignedIn);
    }

    // ---------- configuration and the app API ----------

    [Fact]
    public void Config_fails_clearly_without_keys()
    {
        var empty = (string _) => (string?)null;
        Assert.Contains("INID_PUBLISHABLE_KEY", Assert.Throws<InIDException>(() => new InIDConfig().Resolve(empty)).Message);
        Assert.Contains("INID_SECRET_KEY", Assert.Throws<InIDException>(() => new InIDConfig { PublishableKey = "pk_x" }.Resolve(empty)).Message);
        Assert.Throws<InIDException>(() => new InIDConfig { PublishableKey = "key", SecretKey = "sk_x" }.Resolve(empty));
    }

    [Fact]
    public void Config_reads_env_and_defaults()
    {
        var env = new Dictionary<string, string> { ["INID_PUBLISHABLE_KEY"] = "pk_env", ["INID_SECRET_KEY"] = "sk_env", ["INID_ISSUER"] = "https://id.local/", ["INID_APP_URL"] = "https://app.local/" };
        var c = new InIDConfig().Resolve(k => env.GetValueOrDefault(k));
        Assert.Equal("pk_env", c.PublishableKey);
        Assert.Equal("https://id.local", c.Issuer);
        Assert.Equal("https://app.local", c.AppUrl);
        Assert.Equal("/api/inid", c.ApiPath);
        Assert.Equal("openid profile email phone", c.Scope);
        var d = new InIDConfig { PublishableKey = "pk_a", SecretKey = "sk_a" }.Resolve(_ => null);
        Assert.Equal("https://id.inid.co", d.Issuer);
    }

    [Fact]
    public async Task App_api_helpers_use_the_secret_key()
    {
        var client = _fake.Client();
        Assert.Equal("member", (await client.GetUserAsync("user_1")).GetProperty("role").GetString());
        await client.SetRoleAsync("user_1", "admin");
        Assert.Equal("{\"role\":\"admin\"}", _fake.Requests.Last().Body);
        Assert.Equal(HttpMethod.Put, _fake.Requests.Last().Method);
        await client.UpdateMetadataAsync("user_1", publicMetadata: new { plan = "pro" });
        Assert.Equal("{\"publicMetadata\":{\"plan\":\"pro\"}}", _fake.Requests.Last().Body);
        await client.GetRolesAsync();
        await client.InviteAsync("a@b.co", "admin");
        Assert.All(_fake.Requests, r => Assert.Equal("Bearer " + FakeInID.Sk, r.Authorization));
        var error = await Assert.ThrowsAsync<InIDException>(() => client.GetUserAsync("missing"));
        Assert.Equal(404, error.Status);
    }

    [Fact]
    public async Task Cookies_are_not_secure_on_http()
    {
        var r = await _fake.Client().HandleAsync(new InIDRequest("POST", new Uri("http://localhost:5000/api/inid/signout")));
        Assert.DoesNotContain(r.SetCookies, c => c.Contains("Secure"));
        var behindProxy = await _fake.Client(appUrl: "https://app.test").HandleAsync(new InIDRequest("POST", new Uri("http://localhost:5000/api/inid/signout")));
        Assert.All(behindProxy.SetCookies, c => Assert.Contains("Secure", c));
    }
}
