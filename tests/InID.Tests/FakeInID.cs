using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace InID.Tests;

// InID as the SDK sees it: a JWKS, a token endpoint, revocation and the sessions API, signing ID
// tokens with an RSA key made for the test
public sealed class FakeInID : HttpMessageHandler
{
    public const string Issuer = "https://id.test";
    public const string Pk = "pk_test_app";
    public const string Sk = "sk_test_secret";

    public readonly RSA Key = RSA.Create(2048);
    public const string Kid = "key-1";
    public long Now = 1_800_000_000;

    public sealed record Seen(HttpMethod Method, Uri Url, string? Authorization, string Body);
    public readonly List<Seen> Requests = new();
    public int JwksFetches;

    // How /oauth/token answers; by default a fresh token pair
    public Func<Dictionary<string, string>, HttpResponseMessage>? Token;
    public string? NextNonce;
    public readonly List<JsonObject> Sessions = new()
    {
        new() { ["id"] = "sid_1", ["createdAt"] = "2026-11-01T00:00:00Z", ["lastActiveAt"] = "2026-11-02T00:00:00Z", ["device"] = "Chrome" },
        new() { ["id"] = "sid_2", ["createdAt"] = "2026-11-01T00:00:00Z", ["lastActiveAt"] = "2026-11-02T00:00:00Z", ["device"] = null },
    };

    public InIDClient Client(string? appUrl = null) =>
        new(new InIDConfig { PublishableKey = Pk, SecretKey = Sk, Issuer = Issuer, AppUrl = appUrl, WebhookSecret = "whsec_test" },
            new HttpClient(this), () => DateTimeOffset.FromUnixTimeSeconds(Now));

    public static string B64(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public string Sign(object claims, string kid = Kid, RSA? key = null, string alg = "RS256")
    {
        var head = B64(JsonSerializer.SerializeToUtf8Bytes(new { alg, kid, typ = "JWT" }));
        var body = B64(JsonSerializer.SerializeToUtf8Bytes(claims));
        var sig = (key ?? Key).SignData(Encoding.ASCII.GetBytes($"{head}.{body}"), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return $"{head}.{body}.{B64(sig)}";
    }

    public Dictionary<string, object?> Claims(long? exp = null, string? nonce = null, string[]? roles = null) => new()
    {
        ["iss"] = Issuer,
        ["aud"] = Pk,
        ["sub"] = "user_1",
        ["sid"] = "sid_1",
        ["exp"] = exp ?? Now + 600,
        ["iat"] = Now,
        ["nonce"] = nonce,
        ["given_name"] = "Ana",
        ["family_name"] = "Pérez",
        ["email"] = "ana@example.com",
        ["email_verified"] = true,
        ["phone_number"] = "+573001234567",
        ["roles"] = roles ?? new[] { "member" },
        ["permissions"] = new[] { "invoices:read" },
        ["public_metadata"] = new Dictionary<string, object> { ["plan"] = "pro" },
    };

    public string IdToken(long? exp = null, string? nonce = null, string[]? roles = null) => Sign(Claims(exp, nonce, roles));

    public static Dictionary<string, string> Form(string body) =>
        body.Split('&', StringSplitOptions.RemoveEmptyEntries).Select(p => p.Split('=')).ToDictionary(p => Uri.UnescapeDataString(p[0].Replace('+', ' ')), p => Uri.UnescapeDataString(p.Length > 1 ? p[1].Replace('+', ' ') : ""));

    private static HttpResponseMessage Json(object body, HttpStatusCode status = HttpStatusCode.OK) =>
        new(status) { Content = new StringContent(body is JsonNode n ? n.ToJsonString() : JsonSerializer.Serialize(body), Encoding.UTF8, "application/json") };

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(ct);
        Requests.Add(new(request.Method, request.RequestUri!, request.Headers.Authorization?.ToString(), body));
        var path = request.RequestUri!.AbsolutePath;

        if (path == "/.well-known/jwks.json")
        {
            JwksFetches++;
            var p = Key.ExportParameters(false);
            return Json(new { keys = new[] { new { kty = "RSA", kid = Kid, alg = "RS256", use = "sig", n = B64(p.Modulus!), e = B64(p.Exponent!) } } });
        }
        if (path == "/oauth/token")
        {
            var form = Form(body);
            if (Token is not null) return Token(form);
            return Json(new { id_token = IdToken(nonce: NextNonce), refresh_token = "rt_new", access_token = "at", expires_in = 600 });
        }
        if (path == "/oauth/revoke") return new HttpResponseMessage(HttpStatusCode.OK);
        if (path == "/v1/users/user_1/sessions" && request.Method == HttpMethod.Get)
            return Json(new JsonObject { ["sessions"] = new JsonArray(Sessions.Select(s => (JsonNode)s.DeepClone()).ToArray()) });
        if (path.StartsWith("/v1/users/user_1/sessions/") && request.Method == HttpMethod.Delete) return Json(new { ended = 1 });
        if (path == "/v1/users/user_1") return Json(new { id = "user_1", role = "member" });
        if (path == "/v1/roles") return Json(new { roles = Array.Empty<object>(), defaultRole = (string?)null });
        if (path == "/v1/users/user_1/role" || path == "/v1/users/user_1/metadata" || path == "/v1/invitations") return Json(new { ok = true });
        return Json(new { error = "not_found" }, HttpStatusCode.NotFound);
    }
}
