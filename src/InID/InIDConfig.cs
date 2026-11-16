namespace InID;

/// <summary>An app's InID settings. Anything left null comes from the environment (INID_*) or the defaults.</summary>
public sealed class InIDConfig
{
    public const string DefaultIssuer = "https://id.inid.co";
    public const string DefaultApiPath = "/api/inid";
    public const string DefaultScope = "openid profile email phone";

    /// <summary>pk_test_… or pk_live_… (the OAuth client id). Env: INID_PUBLISHABLE_KEY.</summary>
    public string? PublishableKey { get; set; }

    /// <summary>sk_… (the OAuth client secret). Env: INID_SECRET_KEY.</summary>
    public string? SecretKey { get; set; }

    /// <summary>InID itself. Env: INID_ISSUER. Default https://id.inid.co.</summary>
    public string? Issuer { get; set; }

    /// <summary>Where the sign-in routes live. Default /api/inid.</summary>
    public string? ApiPath { get; set; }

    /// <summary>What the app asks the person for.</summary>
    public string? Scope { get; set; }

    /// <summary>The app's own origin, when the requests it sees don't say it (behind proxies). Env: INID_APP_URL.</summary>
    public string? AppUrl { get; set; }

    /// <summary>whsec_…, only to verify webhooks. Env: INID_WEBHOOK_SECRET.</summary>
    public string? WebhookSecret { get; set; }

    /// <summary>
    /// A copy with every setting filled (given, else environment, else default) and checked:
    /// missing or malformed keys fail here, at startup, not on the first sign-in.
    /// </summary>
    public InIDConfig Resolve(Func<string, string?>? env = null)
    {
        env ??= Environment.GetEnvironmentVariable;
        var appUrl = (AppUrl ?? env("INID_APP_URL"))?.TrimEnd('/');
        var config = new InIDConfig
        {
            PublishableKey = PublishableKey ?? env("INID_PUBLISHABLE_KEY") ?? "",
            SecretKey = SecretKey ?? env("INID_SECRET_KEY") ?? "",
            Issuer = TrimOne(Issuer ?? env("INID_ISSUER") ?? DefaultIssuer),
            ApiPath = TrimOne(ApiPath ?? DefaultApiPath),
            Scope = Scope ?? DefaultScope,
            AppUrl = string.IsNullOrEmpty(appUrl) ? null : appUrl,
            WebhookSecret = WebhookSecret ?? env("INID_WEBHOOK_SECRET"),
        };
        if (!config.PublishableKey.StartsWith("pk_", StringComparison.Ordinal))
            throw new InIDException("INID_PUBLISHABLE_KEY is missing: set it to your publishable key (pk_...)");
        if (!config.SecretKey.StartsWith("sk_", StringComparison.Ordinal))
            throw new InIDException("INID_SECRET_KEY is missing: set it to your secret key (sk_...)");
        return config;
    }

    private static string TrimOne(string value) => value.EndsWith('/') ? value[..^1] : value;
}

/// <summary>An InID error: a code (invalid_signature, token_failed…) and, from InID, its HTTP status.</summary>
public sealed class InIDException : Exception
{
    public string Code { get; }
    public int? Status { get; }

    public InIDException(string code, int? status = null) : base(code)
    {
        Code = code;
        Status = status;
    }
}
