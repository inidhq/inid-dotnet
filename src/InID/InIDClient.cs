// Sign-in with InID for an app's server. The app is an OpenID Connect client of InID (publishable
// key = client id, secret key = client secret). Signing in is the authorization code flow with PKCE;
// the session is InID's signed ID token in a cookie, checked with InID's public keys and never with
// a call to InID. It lasts ten minutes; the refresh token (another cookie) renews it.
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace InID;

public sealed class InIDClient
{
    private const int SignedOutSeconds = 30 * 24 * 3600;
    private const int RefreshMaxAge = 30 * 86_400;
    // A session with less than this left is renewed now, not in the middle of the next request
    private const int RenewBeforeSeconds = 60;

    private readonly HttpClient _http;
    private readonly Func<DateTimeOffset> _clock;
    private readonly string _basic;
    private readonly Jwks _jwks;

    /// <summary>The resolved settings (every value filled).</summary>
    public InIDConfig Config { get; }
    public string Issuer => Config.Issuer!;
    public string ApiPath => Config.ApiPath!;
    public string PublishableKey => Config.PublishableKey!;

    /// <param name="config">Settings; null ones come from INID_* environment variables or defaults.</param>
    /// <param name="http">The HttpClient to reach InID with (a new one if null).</param>
    /// <param name="clock">The current time (tests).</param>
    public InIDClient(InIDConfig? config = null, HttpClient? http = null, Func<DateTimeOffset>? clock = null)
    {
        Config = (config ?? new InIDConfig()).Resolve();
        _http = http ?? new HttpClient();
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
        _basic = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{Util.Esc(Config.PublishableKey!)}:{Util.Esc(Config.SecretKey!)}"));
        _jwks = new Jwks(this);
    }

    private long Now => _clock().ToUnixTimeSeconds();

    // ---------- ID tokens ----------

    /// <summary>An ID token InID signed for this app, or null. An expired one still comes back (Expired = true).</summary>
    public async Task<VerifiedToken?> VerifyIdTokenAsync(string token, string? nonce = null, CancellationToken ct = default)
    {
        var parts = token.Split('.');
        if (parts.Length != 3) return null;
        try
        {
            using var header = JsonDocument.Parse(Util.FromB64Url(parts[0]));
            var h = header.RootElement;
            if (!h.TryGetProperty("alg", out var alg) || alg.ValueKind != JsonValueKind.String || alg.GetString() != "RS256") return null;
            if (!h.TryGetProperty("kid", out var kid) || kid.ValueKind != JsonValueKind.String) return null;
            var key = await _jwks.KeyFor(kid.GetString()!, ct).ConfigureAwait(false);
            if (key is null) return null;
            var data = Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}");
            if (!key.VerifyData(data, Util.FromB64Url(parts[2]), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)) return null;

            using var body = JsonDocument.Parse(Util.FromB64Url(parts[1]));
            if (body.RootElement.ValueKind != JsonValueKind.Object) return null;
            var claims = body.RootElement.EnumerateObject().ToDictionary(p => p.Name, p => p.Value.Clone());
            bool Is(string name, string expected) => claims.TryGetValue(name, out var v) && v.ValueKind == JsonValueKind.String && v.GetString() == expected;
            if (!Is("iss", Issuer) || !Is("aud", PublishableKey)) return null;
            if (!claims.TryGetValue("sub", out var sub) || sub.ValueKind != JsonValueKind.String) return null;
            if (!claims.TryGetValue("exp", out var expEl) || expEl.ValueKind != JsonValueKind.Number) return null;
            if (nonce is not null && !Is("nonce", nonce)) return null;
            var exp = (long)Math.Floor(expEl.GetDouble());
            return new VerifiedToken(claims, exp, exp <= Now);
        }
        catch (InIDException) { throw; }
        catch (Exception) { return null; }
    }

    /// <summary>
    /// For a native app's backend: the person behind "Authorization: Bearer &lt;id_token&gt;" (the header
    /// or the bare token). Signed in only if the token verifies and hasn't expired.
    /// </summary>
    public async Task<InIDAuth> VerifyBearerAsync(string? authorization, CancellationToken ct = default)
    {
        var token = (authorization ?? "").Trim();
        if (token.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) token = token[7..].Trim();
        if (token.Length == 0) return InIDAuth.Anonymous;
        var checkedToken = await VerifyIdTokenAsync(token, null, ct).ConfigureAwait(false);
        return checkedToken is null || checkedToken.Expired ? InIDAuth.Anonymous : new InIDAuth(SessionOf(checkedToken));
    }

    private static InIDSession SessionOf(VerifiedToken t) => new() { User = InIDUser.FromClaims(t.Claims), ExpiresAt = t.Exp, Claims = t.Claims };

    // ---------- tokens ----------

    private sealed record Tokens(
        [property: JsonPropertyName("id_token")] string? IdToken,
        [property: JsonPropertyName("refresh_token")] string? RefreshToken);

    private async Task<Tokens> TokenAsync(Dictionary<string, string> form, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, $"{Issuer}/oauth/token") { Content = new FormUrlEncodedContent(form) };
        req.Headers.Authorization = new AuthenticationHeaderValue("Basic", _basic);
        using var res = await _http.SendAsync(req, ct).ConfigureAwait(false);
        var text = await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        JsonElement body = default;
        try { body = JsonDocument.Parse(text).RootElement; } catch (JsonException) { }
        string? Field(string name) => body.ValueKind == JsonValueKind.Object && body.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
        if (!res.IsSuccessStatusCode) throw new InIDException(Field("error") ?? "token_failed", (int)res.StatusCode);
        return new Tokens(Field("id_token") ?? "", Field("refresh_token") ?? "");
    }

    private static List<string> SessionCookies(Tokens tokens, bool secure) => new()
    {
        Util.Cookie(InIDCookies.Session, tokens.IdToken ?? "", RefreshMaxAge, secure),
        Util.Cookie(InIDCookies.Refresh, tokens.RefreshToken ?? "", RefreshMaxAge, secure),
    };

    private static List<string> ClearCookies(bool secure) => new()
    {
        Util.Cookie(InIDCookies.Session, "", 0, secure),
        Util.Cookie(InIDCookies.Refresh, "", 0, secure),
    };

    // ---------- the session ----------

    /// <summary>
    /// The session in these cookies. With refresh, one that ends within a minute is renewed: SetCookies go
    /// back to the browser, CookieHeader is what this same request should see.
    /// </summary>
    public async Task<SessionResult> ReadSessionAsync(string? cookieHeader, bool refresh = false, bool secure = true, CancellationToken ct = default)
    {
        var jar = Util.ParseCookies(cookieHeader);
        var current = jar.TryGetValue(InIDCookies.Session, out var idToken) && idToken.Length > 0 ? await VerifyIdTokenAsync(idToken, null, ct).ConfigureAwait(false) : null;
        if (current is not null && current.Exp - Now > RenewBeforeSeconds) return new SessionResult { Session = SessionOf(current) };
        var stillGood = current is { Expired: false } ? SessionOf(current) : null;
        if (!refresh || !jar.TryGetValue(InIDCookies.Refresh, out var refreshToken) || refreshToken.Length == 0)
            return new SessionResult { Session = stillGood };
        try
        {
            var tokens = await TokenAsync(new() { ["grant_type"] = "refresh_token", ["refresh_token"] = refreshToken }, ct).ConfigureAwait(false);
            var renewed = await VerifyIdTokenAsync(tokens.IdToken ?? "", null, ct).ConfigureAwait(false)
                ?? throw new InIDException("invalid_id_token", 400);
            jar[InIDCookies.Session] = tokens.IdToken!;
            jar[InIDCookies.Refresh] = tokens.RefreshToken!;
            return new SessionResult { Session = SessionOf(renewed), SetCookies = SessionCookies(tokens, secure), CookieHeader = Util.SerializeJar(jar) };
        }
        catch (InIDException e) when (e.Status is < 500)
        {
            // InID said no (signed out elsewhere, authorization taken back): the session is over
            jar.Remove(InIDCookies.Session);
            jar.Remove(InIDCookies.Refresh);
            return new SessionResult { SetCookies = ClearCookies(secure), CookieHeader = Util.SerializeJar(jar) };
        }
        catch (Exception) when (!ct.IsCancellationRequested)
        {
            // InID couldn't be reached: what's still valid stays
            return new SessionResult { Session = stillGood };
        }
    }

    /// <summary>Who is signed in, from a Cookie header (reads only; the gate is what renews).</summary>
    public async Task<InIDAuth> AuthAsync(string? cookieHeader, CancellationToken ct = default) =>
        new((await ReadSessionAsync(cookieHeader, false, true, ct).ConfigureAwait(false)).Session);

    private bool IsSecure(Uri url) => (Config.AppUrl ?? $"{url.Scheme}://").StartsWith("https://", StringComparison.Ordinal);

    // ---------- the routes under the api path ----------

    private sealed class Flow
    {
        [JsonPropertyName("state")] public string State { get; set; } = "";
        [JsonPropertyName("nonce")] public string Nonce { get; set; } = "";
        [JsonPropertyName("verifier")] public string Verifier { get; set; } = "";
        [JsonPropertyName("returnTo")] public string ReturnTo { get; set; } = "/";
        [JsonPropertyName("embed")] public bool? Embed { get; set; }
        [JsonPropertyName("page")] public string? Page { get; set; }
    }

    private static readonly JsonSerializerOptions FlowJson = new() { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };

    private static InIDResponse Redirect(string to, IEnumerable<string>? cookies = null)
    {
        var r = new InIDResponse { Status = 302 };
        r.Headers.Add(new("location", to));
        r.Headers.Add(new("cache-control", "no-store"));
        return r.With(cookies ?? Array.Empty<string>());
    }

    // A tiny page that sends the whole window on (the app's own address, same origin)
    private static InIDResponse LeaveFrame(string to, IEnumerable<string>? cookies = null)
    {
        // The default encoder escapes "<" as <, so the string can't close the script
        var target = JsonSerializer.Serialize(to);
        var r = new InIDResponse { Status = 200, Body = $"<!doctype html><meta charset=\"utf-8\"><script>(window.top || window).location.replace({target})</script>" };
        r.Headers.Add(new("content-type", "text/html; charset=utf-8"));
        r.Headers.Add(new("cache-control", "no-store"));
        return r.With(cookies ?? Array.Empty<string>());
    }

    private static InIDResponse Json(object body, int status = 200)
    {
        var r = new InIDResponse { Status = status, Body = body is JsonNode node ? node.ToJsonString() : JsonSerializer.Serialize(body) };
        r.Headers.Add(new("content-type", "application/json"));
        r.Headers.Add(new("cache-control", "no-store"));
        return r;
    }

    /// <summary>The app's routes under the api path: signin, callback, signout, session, sessions.</summary>
    public async Task<InIDResponse> HandleAsync(InIDRequest request, CancellationToken ct = default)
    {
        var url = request.Url;
        var path = url.AbsolutePath;
        var origin = Config.AppUrl ?? url.GetLeftPart(UriPartial.Authority);
        var secure = origin.StartsWith("https://", StringComparison.Ordinal);
        var action = path.StartsWith(ApiPath + "/", StringComparison.Ordinal) ? path[(ApiPath.Length + 1)..] : "";
        var redirectUri = $"{origin}{ApiPath}/callback";
        var query = Util.ParseQuery(url.Query);
        var method = request.Method.ToUpperInvariant();
        var cookies = Util.ParseCookies(request.Cookie);

        if (method == "GET" && action == "signin")
        {
            // display=embed: InID's form inside the app's own page (<inid-sign-in>)
            var embed = query.Get("display") == "embed";
            // Back from Google, the frame goes on with the same sign-in (its flow cookie stays)
            var resume = query.Get("continue");
            if (embed && resume is not null)
            {
                var q = Util.ParseQuery(resume);
                var kept = new List<KeyValuePair<string, string>>();
                foreach (var k in new[] { "request", "session", "from", "lang" })
                    if (q.Get(k) is { Length: > 0 } v) kept.Add(new(k, v));
                kept.Add(new("display", "embed"));
                return Redirect($"{Issuer}/oauth/authorize/continue?{Util.Query(kept)}");
            }
            var flow = new Flow { State = Util.Random(16), Nonce = Util.Random(16), Verifier = Util.Random(32), ReturnTo = Util.SafeReturn(query.Get("return_to")) };
            if (embed)
            {
                // page: where the form is, to go on there after Google
                flow.Embed = true;
                flow.Page = Util.SafeReturn(query.Get("page") is { Length: > 0 } p ? p : query.Get("return_to"));
            }
            var authorize = new Dictionary<string, string>
            {
                ["client_id"] = PublishableKey,
                ["redirect_uri"] = redirectUri,
                ["response_type"] = "code",
                ["scope"] = Config.Scope!,
                ["state"] = flow.State,
                ["nonce"] = flow.Nonce,
                ["code_challenge"] = Util.Sha256(flow.Verifier),
                ["code_challenge_method"] = "S256",
            };
            foreach (var passed in new[] { "ui_locales", "login_hint", "prompt", "entrance" })
                if (query.Get(passed) is { Length: > 0 } v) authorize[passed] = v;
            // In the page, someone InID knows still clicks to go in: never signed in by just loading it
            if (embed)
            {
                authorize["display"] = "embed";
                authorize["prompt"] = "login";
            }
            // Right after signing out of the app InID asks too: they chose to leave
            if (cookies.ContainsKey(InIDCookies.SignedOut)) authorize["prompt"] = "login";
            // One cookie per sign-in (named by its state): two at once don't overwrite each other
            var flowCookie = Util.Cookie($"{InIDCookies.Flow}_{flow.State}", Util.B64Url(JsonSerializer.SerializeToUtf8Bytes(flow, FlowJson)), 600, secure, ApiPath);
            return Redirect($"{Issuer}/oauth/authorize?{Util.Query(authorize)}", new[] { flowCookie });
        }

        if (method == "GET" && action == "callback")
        {
            var state = query.Get("state") ?? "";
            var flowName = System.Text.RegularExpressions.Regex.IsMatch(state, @"^[\w-]{1,64}$", System.Text.RegularExpressions.RegexOptions.ECMAScript)
                ? $"{InIDCookies.Flow}_{state}" : InIDCookies.Flow;
            var clearFlow = Util.Cookie(flowName, "", 0, secure, ApiPath);
            Flow? flow = null;
            try
            {
                if (cookies.TryGetValue(flowName, out var raw)) flow = JsonSerializer.Deserialize<Flow>(Util.FromB64Url(raw), FlowJson);
            }
            catch (Exception) { flow = null; }
            var embedded = flow?.Embed == true;

            // Back from Google, a sign-in that started in the app's page goes on in it
            var resume = query.Get("inid_continue");
            if (resume is not null && embedded && query.Get("state") == flow!.State)
            {
                var page = Util.SafeReturn(flow.Page);
                var hash = page.IndexOf('#');
                if (hash >= 0) page = page[..hash];
                var qAt = page.IndexOf('?');
                var pagePath = qAt < 0 ? page : page[..qAt];
                var pageQuery = qAt < 0 ? new() : Util.ParseQuery(page[qAt..]);
                pageQuery.RemoveAll(kv => kv.Key == "inid_continue");
                pageQuery.Add(new("inid_continue", resume));
                return Redirect($"{pagePath}?{Util.Query(pageQuery)}");
            }

            var code = query.Get("code");
            // From InID's form inside the page, the whole page goes on (not just its frame)
            Func<string, IEnumerable<string>?, InIDResponse> go = embedded ? LeaveFrame : Redirect;
            if (flow is null || string.IsNullOrEmpty(code) || query.Get("state") != flow.State)
                return go(Util.SafeReturn(flow?.ReturnTo), new[] { clearFlow });
            try
            {
                var tokens = await TokenAsync(new()
                {
                    ["grant_type"] = "authorization_code",
                    ["code"] = code,
                    ["redirect_uri"] = redirectUri,
                    ["code_verifier"] = flow.Verifier,
                }, ct).ConfigureAwait(false);
                if (await VerifyIdTokenAsync(tokens.IdToken ?? "", flow.Nonce, ct).ConfigureAwait(false) is null)
                    throw new InIDException("invalid_id_token", 400);
                var set = new List<string> { clearFlow };
                set.AddRange(SessionCookies(tokens, secure));
                set.Add(Util.Cookie(InIDCookies.SignedOut, "", 0, secure));
                return go(Util.SafeReturn(flow.ReturnTo), set);
            }
            catch (InIDException e)
            {
                return Json(new { error = e.Code }, e.Status is >= 400 and < 500 ? 400 : 502).With(new[] { clearFlow });
            }
        }

        if (method == "POST" && action == "signout")
        {
            // The sign-in ends at InID too (best effort); the person's InID stays signed in (that's theirs)
            if (cookies.TryGetValue(InIDCookies.Refresh, out var refreshToken) && refreshToken.Length > 0)
            {
                try
                {
                    using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    timeout.CancelAfter(TimeSpan.FromSeconds(3));
                    using var req = new HttpRequestMessage(HttpMethod.Post, $"{Issuer}/oauth/revoke")
                    {
                        Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["token"] = refreshToken, ["token_type_hint"] = "refresh_token" }),
                    };
                    req.Headers.Authorization = new AuthenticationHeaderValue("Basic", _basic);
                    using var _ = await _http.SendAsync(req, timeout.Token).ConfigureAwait(false);
                }
                catch (Exception) { }
            }
            var set = ClearCookies(secure);
            set.Add(Util.Cookie(InIDCookies.SignedOut, "1", SignedOutSeconds, secure));
            return Json(new { ok = true }).With(set);
        }

        // The person's own sessions at this app, and ending them: one (DELETE sessions/{id}) or all
        // but this one (DELETE sessions?others=1)
        if (action == "sessions" || action.StartsWith("sessions/", StringComparison.Ordinal))
        {
            var current = (await ReadSessionAsync(request.Cookie, false, secure, ct).ConfigureAwait(false)).Session;
            if (current is null) return Json(new { error = "not_signed_in" }, 401);
            var baseUrl = $"{Issuer}/v1/users/{Util.Esc(current.User.Id)}/sessions";
            var sid = current.SessionId;
            try
            {
                if (method == "GET")
                {
                    var list = await ListSessions(baseUrl, ct).ConfigureAwait(false);
                    foreach (var s in list) s["current"] = s["id"]?.GetValue<string>() == sid;
                    return Json(new JsonObject { ["sessions"] = new JsonArray(list.Cast<JsonNode>().ToArray()) });
                }
                if (method == "DELETE")
                {
                    var one = action.StartsWith("sessions/", StringComparison.Ordinal) ? Uri.UnescapeDataString(action["sessions/".Length..]) : "";
                    var ending = one.Length > 0 ? new List<string> { one }
                        : query.Get("others") is { Length: > 0 }
                            ? (await ListSessions(baseUrl, ct).ConfigureAwait(false)).Select(s => s["id"]?.GetValue<string>()).Where(id => id is not null && id != sid).Select(id => id!).ToList()
                            : new List<string>();
                    foreach (var id in ending)
                    {
                        using var req = AppRequest(HttpMethod.Delete, $"{baseUrl}/{Util.Esc(id)}");
                        using var _ = await _http.SendAsync(req, ct).ConfigureAwait(false);
                    }
                    return Json(new { ended = ending.Count });
                }
            }
            catch (Exception e) when (e is InIDException or HttpRequestException)
            {
                return Json(new { error = "sessions_unavailable" }, 502);
            }
        }

        if (method == "GET" && action == "session")
        {
            var result = await ReadSessionAsync(request.Cookie, true, secure, ct).ConfigureAwait(false);
            return Json(new { user = result.Session?.User, accountUrl = $"{Issuer}/account?client_id={Util.Esc(PublishableKey)}" }).With(result.SetCookies);
        }

        var notFound = new InIDResponse { Status = 404, Body = "{\"error\":\"not_found\"}" };
        notFound.Headers.Add(new("content-type", "application/json"));
        return notFound;
    }

    private async Task<List<JsonObject>> ListSessions(string url, CancellationToken ct)
    {
        using var req = AppRequest(HttpMethod.Get, url);
        using var res = await _http.SendAsync(req, ct).ConfigureAwait(false);
        if (!res.IsSuccessStatusCode) throw new InIDException("sessions_unavailable", 502);
        var body = JsonNode.Parse(await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
        return (body?["sessions"] as JsonArray)?.OfType<JsonObject>().Select(o => (JsonObject)o.DeepClone()).ToList() ?? new();
    }

    // ---------- the gate ----------

    /// <summary>
    /// What a middleware does with each request: InID's routes, back from Google, the session (renewed),
    /// and the protect rules. When the result has a Response, answer with it.
    /// </summary>
    public async Task<GateResult> GateAsync(InIDRequest request, IEnumerable<ProtectRule>? protect = null, Func<InIDRequest, bool>? protectWhen = null, bool routes = true, CancellationToken ct = default)
    {
        var url = request.Url;
        var path = url.AbsolutePath;
        if (path == ApiPath || path.StartsWith(ApiPath + "/", StringComparison.Ordinal))
            return routes ? new GateResult { Response = await HandleAsync(request, ct).ConfigureAwait(false) } : new GateResult { Skipped = true };

        // Back from Google on the app's own domain: Google's answer is for InID, so the person goes
        // straight on there, before any page renders
        var query = Util.ParseQuery(url.Query);
        var state = query.Get("state") ?? "";
        if (state.StartsWith("inidg_", StringComparison.Ordinal) && query.Any(kv => kv.Key is "code" or "error"))
        {
            var google = new InIDResponse { Status = 307 };
            google.Headers.Add(new("location", $"{Issuer}/oauth/google/callback{url.Query}"));
            return new GateResult { Response = google };
        }

        var secure = IsSecure(url);
        var session = await ReadSessionAsync(request.Cookie, true, secure, ct).ConfigureAwait(false);
        var rules = new List<ProtectRule>();
        if (protectWhen is not null && protectWhen(request)) rules.Add("/");
        if (protect is not null) rules.AddRange(protect.Where(r => r.Matches(path)));

        if (session.Session is null && rules.Count > 0)
        {
            var to = new List<KeyValuePair<string, string>> { new("return_to", path + url.Query) };
            if (rules.FirstOrDefault(r => !string.IsNullOrEmpty(r.Entrance))?.Entrance is { } entrance) to.Add(new("entrance", entrance));
            var signIn = new InIDResponse { Status = 307 };
            signIn.Headers.Add(new("location", $"{ApiPath}/signin?{Util.Query(to)}"));
            signIn.Headers.Add(new("cache-control", "no-store"));
            return new GateResult { Response = signIn.With(session.SetCookies) };
        }
        var auth = new InIDAuth(session.Session);
        if (session.Session is not null && rules.Any(r => !session.Session.User.Allows(r.Role, r.Permission)))
        {
            // Signed in, without the role or permission the path needs
            var forbidden = new InIDResponse { Status = 403, Body = "Forbidden" };
            forbidden.Headers.Add(new("content-type", "text/plain; charset=utf-8"));
            return new GateResult { Response = forbidden.With(session.SetCookies), Auth = auth };
        }
        return new GateResult { Auth = auth, SetCookies = session.SetCookies, CookieHeader = session.CookieHeader };
    }

    // ---------- webhooks ----------

    /// <summary>Verifies a webhook with the configured webhook secret (INID_WEBHOOK_SECRET).</summary>
    public InIDWebhookEvent VerifyWebhook(string rawBody, string? signature) =>
        InIDWebhooks.Verify(rawBody, signature, Config.WebhookSecret ?? "", Now);

    // ---------- the app API (secret key) ----------

    private HttpRequestMessage AppRequest(HttpMethod method, string url, object? body = null)
    {
        var req = new HttpRequestMessage(method, url);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Config.SecretKey);
        if (body is not null) req.Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
        return req;
    }

    /// <summary>Any call to InID's app API with the secret key; the parsed JSON answer. Throws InIDException on errors.</summary>
    public async Task<JsonElement> ApiAsync(HttpMethod method, string path, object? body = null, CancellationToken ct = default)
    {
        using var req = AppRequest(method, $"{Issuer}{path}", body);
        using var res = await _http.SendAsync(req, ct).ConfigureAwait(false);
        var text = await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        JsonElement parsed = default;
        try { if (text.Length > 0) parsed = JsonDocument.Parse(text).RootElement.Clone(); } catch (JsonException) { }
        if (!res.IsSuccessStatusCode)
        {
            var code = parsed.ValueKind == JsonValueKind.Object && parsed.TryGetProperty("error", out var e) && e.ValueKind == JsonValueKind.String ? e.GetString()! : "request_failed";
            throw new InIDException(code, (int)res.StatusCode);
        }
        return parsed;
    }

    /// <summary>GET /v1/users/{sub}: the person as the app sees them (with private metadata).</summary>
    public Task<JsonElement> GetUserAsync(string sub, CancellationToken ct = default) =>
        ApiAsync(HttpMethod.Get, $"/v1/users/{Util.Esc(sub)}", null, ct);

    /// <summary>PUT /v1/users/{sub}/role; null returns them to the role for new users.</summary>
    public Task<JsonElement> SetRoleAsync(string sub, string? role, CancellationToken ct = default) =>
        ApiAsync(HttpMethod.Put, $"/v1/users/{Util.Esc(sub)}/role", new Dictionary<string, object?> { ["role"] = role }, ct);

    /// <summary>PATCH /v1/users/{sub}/metadata: each given one replaces the previous.</summary>
    public Task<JsonElement> UpdateMetadataAsync(string sub, object? publicMetadata = null, object? privateMetadata = null, CancellationToken ct = default)
    {
        var body = new Dictionary<string, object?>();
        if (publicMetadata is not null) body["publicMetadata"] = publicMetadata;
        if (privateMetadata is not null) body["privateMetadata"] = privateMetadata;
        return ApiAsync(HttpMethod.Patch, $"/v1/users/{Util.Esc(sub)}/metadata", body, ct);
    }

    /// <summary>GET /v1/roles: the app's roles, default role and entrances.</summary>
    public Task<JsonElement> GetRolesAsync(CancellationToken ct = default) => ApiAsync(HttpMethod.Get, "/v1/roles", null, ct);

    /// <summary>POST /v1/invitations: lets someone in by email (with a role, if given).</summary>
    public Task<JsonElement> InviteAsync(string email, string? role = null, CancellationToken ct = default)
    {
        var body = new Dictionary<string, object?> { ["email"] = email };
        if (role is not null) body["role"] = role;
        return ApiAsync(HttpMethod.Post, "/v1/invitations", body, ct);
    }

    // ---------- InID's public keys, kept an hour ----------

    // A key it doesn't know (InID just rotated its signing key) is looked for at once, but once per key
    // and at most once a second: tokens with made-up key ids can't make it ask InID again and again.
    private sealed class Jwks
    {
        private readonly InIDClient _owner;
        private readonly SemaphoreSlim _lock = new(1, 1);
        private Dictionary<string, RSA>? _keys;
        private long _at;
        private long _askedAt;
        private readonly HashSet<string> _missed = new();

        public Jwks(InIDClient owner) => _owner = owner;

        public async Task<RSA?> KeyFor(string kid, CancellationToken ct)
        {
            await _lock.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                var now = _owner._clock().ToUnixTimeMilliseconds();
                var known = _keys is not null && now - _at < 3_600_000;
                if (known)
                {
                    if (_keys!.TryGetValue(kid, out var key)) return key;
                    if (_missed.Contains(kid) || now - _askedAt < 1000) return null;
                    _missed.Add(kid);
                    if (_missed.Count > 100) _missed.Clear();
                    // Only lookups for unknown keys count toward "once a second"
                    _askedAt = now;
                }
                using var res = await _owner._http.GetAsync($"{_owner.Issuer}/.well-known/jwks.json", ct).ConfigureAwait(false);
                if (!res.IsSuccessStatusCode) throw new InIDException("jwks_unavailable", (int)res.StatusCode);
                using var doc = JsonDocument.Parse(await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
                var keys = new Dictionary<string, RSA>();
                foreach (var jwk in doc.RootElement.GetProperty("keys").EnumerateArray())
                {
                    if (!jwk.TryGetProperty("kty", out var kty) || kty.GetString() != "RSA") continue;
                    if (!jwk.TryGetProperty("kid", out var id) || id.ValueKind != JsonValueKind.String) continue;
                    var rsa = RSA.Create();
                    rsa.ImportParameters(new RSAParameters
                    {
                        Modulus = Util.FromB64Url(jwk.GetProperty("n").GetString()!),
                        Exponent = Util.FromB64Url(jwk.GetProperty("e").GetString()!),
                    });
                    keys[id.GetString()!] = rsa;
                }
                _keys = keys;
                _at = now;
                return keys.TryGetValue(kid, out var found) ? found : null;
            }
            finally { _lock.Release(); }
        }
    }
}
