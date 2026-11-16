using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace InID;

/// <summary>The parts of a request InID needs, whatever the framework.</summary>
/// <param name="Method">GET, POST…</param>
/// <param name="Url">The full request URL (scheme, host, path and query).</param>
/// <param name="Cookie">The Cookie header, if any.</param>
public sealed record InIDRequest(string Method, Uri Url, string? Cookie = null);

/// <summary>An answer from InID's routes or the gate, for the framework to send.</summary>
public sealed class InIDResponse
{
    public int Status { get; init; }
    /// <summary>Headers in order; Set-Cookie may repeat.</summary>
    public List<KeyValuePair<string, string>> Headers { get; } = new();
    public string? Body { get; init; }

    public string? Header(string name) =>
        Headers.FirstOrDefault(h => string.Equals(h.Key, name, StringComparison.OrdinalIgnoreCase)).Value;

    public IEnumerable<string> SetCookies =>
        Headers.Where(h => string.Equals(h.Key, "set-cookie", StringComparison.OrdinalIgnoreCase)).Select(h => h.Value);

    internal InIDResponse With(IEnumerable<string> cookies)
    {
        foreach (var c in cookies) Headers.Add(new("set-cookie", c));
        return this;
    }
}

/// <summary>Cookie names every InID SDK shares (the browser components rely on them).</summary>
public static class InIDCookies
{
    public const string Session = "__inid_session";
    public const string Refresh = "__inid_refresh";
    public const string Flow = "__inid_flow";
    // This browser signed out of the app: its next sign-in asks instead of going in by itself
    public const string SignedOut = "__inid_out";
}

internal static class Util
{
    public static string B64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] FromB64Url(string text)
    {
        var s = text.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(s + new string('=', (4 - s.Length % 4) % 4));
    }

    public static string Random(int size) => B64Url(RandomNumberGenerator.GetBytes(size));

    public static string Sha256(string text) => B64Url(SHA256.HashData(Encoding.UTF8.GetBytes(text)));

    public static string Esc(string value) => Uri.EscapeDataString(value);

    public static Dictionary<string, string> ParseCookies(string? header)
    {
        var jar = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var part in Regex.Split(header ?? "", @";\s*"))
        {
            var at = part.IndexOf('=');
            if (at > 0) jar[part[..at]] = Unescape(part[(at + 1)..]);
        }
        return jar;
    }

    public static string SerializeJar(IEnumerable<KeyValuePair<string, string>> jar) =>
        string.Join("; ", jar.Select(kv => $"{kv.Key}={Esc(kv.Value)}"));

    public static string Cookie(string name, string value, int maxAge, bool secure, string path = "/") =>
        $"{name}={Esc(value)}; Path={path}; Max-Age={maxAge}; HttpOnly; SameSite=Lax{(secure ? "; Secure" : "")}";

    private static readonly Regex SafePath = new(@"^/(?![/\\])", RegexOptions.Compiled);

    // Only somewhere in the app itself: a path, never another site
    public static string SafeReturn(string? to) => to is not null && SafePath.IsMatch(to) ? to : "/";

    // application/x-www-form-urlencoded, as URLSearchParams reads it
    public static List<KeyValuePair<string, string>> ParseQuery(string? query)
    {
        var list = new List<KeyValuePair<string, string>>();
        var q = query ?? "";
        if (q.StartsWith('?')) q = q[1..];
        foreach (var part in q.Split('&'))
        {
            if (part.Length == 0) continue;
            var at = part.IndexOf('=');
            var key = at < 0 ? part : part[..at];
            var value = at < 0 ? "" : part[(at + 1)..];
            list.Add(new(Unescape(key.Replace('+', ' ')), Unescape(value.Replace('+', ' '))));
        }
        return list;
    }

    public static string? Get(this List<KeyValuePair<string, string>> query, string key)
    {
        foreach (var kv in query) if (kv.Key == key) return kv.Value;
        return null;
    }

    public static string Query(IEnumerable<KeyValuePair<string, string>> pairs) =>
        string.Join("&", pairs.Select(kv => $"{Esc(kv.Key)}={Esc(kv.Value)}"));

    private static string Unescape(string value)
    {
        try { return Uri.UnescapeDataString(value); }
        catch { return value; }
    }
}
