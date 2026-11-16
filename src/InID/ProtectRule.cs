using System.Text.RegularExpressions;

namespace InID;

/// <summary>
/// A path (matching itself and its subpaths: "/admin" matches "/admin" and "/admin/x", not "/adminx")
/// or a pattern that needs someone signed in, and optionally a role or permission.
/// Entrance: the door its sign-in goes through.
/// </summary>
public sealed class ProtectRule
{
    public string? Path { get; init; }
    public Regex? Pattern { get; init; }
    public string? Role { get; init; }
    public string? Permission { get; init; }
    public string? Entrance { get; init; }

    public static implicit operator ProtectRule(string path) => new() { Path = path };
    public static implicit operator ProtectRule(Regex pattern) => new() { Pattern = pattern };

    public static ProtectRule For(string path, string? role = null, string? permission = null, string? entrance = null) =>
        new() { Path = path, Role = role, Permission = permission, Entrance = entrance };

    public static ProtectRule For(Regex pattern, string? role = null, string? permission = null, string? entrance = null) =>
        new() { Pattern = pattern, Role = role, Permission = permission, Entrance = entrance };

    public bool Matches(string path)
    {
        if (Pattern is not null) return Pattern.IsMatch(path);
        if (Path is null) return false;
        return path == Path || path.StartsWith(Path.EndsWith('/') ? Path : Path + "/", StringComparison.Ordinal);
    }
}

/// <summary>What the gate decided for a request.</summary>
public sealed class GateResult
{
    /// <summary>When set, answer with it: InID's routes, a sign-in, back from Google, a 403.</summary>
    public InIDResponse? Response { get; init; }
    public InIDAuth Auth { get; init; } = InIDAuth.Anonymous;
    /// <summary>Cookies the page's own response must carry (a renewed session).</summary>
    public IReadOnlyList<string> SetCookies { get; init; } = Array.Empty<string>();
    /// <summary>The request's cookies as they are now (renewed), for the rest of this same request.</summary>
    public string? CookieHeader { get; init; }
    /// <summary>Under the api path with routes off: nothing was done.</summary>
    public bool Skipped { get; init; }
}

/// <summary>The session read from cookies, plus what renewing it changed.</summary>
public sealed class SessionResult
{
    public InIDSession? Session { get; init; }
    public IReadOnlyList<string> SetCookies { get; init; } = Array.Empty<string>();
    public string? CookieHeader { get; init; }
}
