using System.Text.Json;
using System.Text.Json.Serialization;

namespace InID;

/// <summary>The signed-in person, from InID's ID token. Serializes with the same camelCase names as every InID SDK.</summary>
public sealed class InIDUser
{
    /// <summary>The person's id at this app (InID gives each app its own).</summary>
    [JsonPropertyName("id")] public string Id { get; init; } = "";
    [JsonPropertyName("firstName")] public string? FirstName { get; init; }
    [JsonPropertyName("lastName")] public string? LastName { get; init; }
    [JsonPropertyName("name")] public string? Name { get; init; }
    [JsonPropertyName("email")] public string? Email { get; init; }
    [JsonPropertyName("emailVerified")] public bool EmailVerified { get; init; }
    /// <summary>E.164 ("+573001234567").</summary>
    [JsonPropertyName("phone")] public string? Phone { get; init; }
    /// <summary>The app's roles for this person; empty when the app has no roles.</summary>
    [JsonPropertyName("roles")] public IReadOnlyList<string> Roles { get; init; } = Array.Empty<string>();
    [JsonPropertyName("permissions")] public IReadOnlyList<string> Permissions { get; init; } = Array.Empty<string>();
    [JsonPropertyName("publicMetadata")] public IReadOnlyDictionary<string, JsonElement> PublicMetadata { get; init; } = new Dictionary<string, JsonElement>();

    /// <summary>Whether the person has the role and/or the permission (both, if both are given; true with neither: being signed in is enough).</summary>
    public bool Has(string? role = null, string? permission = null) => Allows(role, permission);

    // Also the gate's check: a rule with only a path lets anyone signed in through
    internal bool Allows(string? role, string? permission) =>
        (role is null || Roles.Contains(role)) && (permission is null || Permissions.Contains(permission));

    public static InIDUser FromClaims(IReadOnlyDictionary<string, JsonElement> claims)
    {
        string? Text(string key) =>
            claims.TryGetValue(key, out var v) && v.ValueKind == JsonValueKind.String && v.GetString() is { Length: > 0 } s ? s : null;
        IReadOnlyList<string> Strings(string key) =>
            claims.TryGetValue(key, out var v) && v.ValueKind == JsonValueKind.Array
                ? v.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!).ToList()
                : Array.Empty<string>();

        var first = Text("given_name");
        var last = Text("family_name");
        var joined = string.Join(" ", new[] { first, last }.Where(x => x is not null));
        var metadata = new Dictionary<string, JsonElement>();
        if (claims.TryGetValue("public_metadata", out var meta) && meta.ValueKind == JsonValueKind.Object)
            foreach (var p in meta.EnumerateObject()) metadata[p.Name] = p.Value.Clone();

        return new InIDUser
        {
            Id = claims.TryGetValue("sub", out var sub) ? sub.GetString() ?? "" : "",
            FirstName = first,
            LastName = last,
            Name = joined.Length > 0 ? joined : Text("name"),
            Email = Text("email"),
            EmailVerified = claims.TryGetValue("email_verified", out var ev) && ev.ValueKind == JsonValueKind.True,
            Phone = Text("phone_number"),
            Roles = Strings("roles"),
            Permissions = Strings("permissions"),
            PublicMetadata = metadata,
        };
    }
}

/// <summary>A verified session: the person, when its token ends, and the token's claims.</summary>
public sealed class InIDSession
{
    public required InIDUser User { get; init; }
    /// <summary>Seconds since 1970; renewed before then.</summary>
    public required long ExpiresAt { get; init; }
    public required IReadOnlyDictionary<string, JsonElement> Claims { get; init; }

    /// <summary>InID's id for this sign-in (the "sid" claim), when present.</summary>
    public string? SessionId => Claims.TryGetValue("sid", out var sid) && sid.ValueKind == JsonValueKind.String ? sid.GetString() : null;
}

/// <summary>Who is signed in, for a page or an API route.</summary>
public sealed class InIDAuth
{
    public static readonly InIDAuth Anonymous = new(null);

    public InIDAuth(InIDSession? session) => Session = session;

    public InIDSession? Session { get; }
    public bool IsSignedIn => Session is not null;
    public string? UserId => Session?.User.Id;
    public InIDUser? User => Session?.User;

    /// <summary>Has(role: "admin"), Has(permission: "invoices:read").</summary>
    public bool Has(string? role = null, string? permission = null) => User?.Has(role, permission) ?? false;
}

/// <summary>An ID token InID signed for this app. An ended one still verifies (Expired), so the session can be renewed from it.</summary>
public sealed record VerifiedToken(IReadOnlyDictionary<string, JsonElement> Claims, long Exp, bool Expired);
