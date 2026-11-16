using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace InID;

/// <summary>
/// A verified webhook event. Type is one of user.created, user.updated, user.deleted, session.created,
/// session.ended, subscription.cancel_requested, customer.logged_out, customer.registered, checkout.abandoned.
/// </summary>
public sealed class InIDWebhookEvent
{
    public required string Type { get; init; }
    public string? CreatedAt { get; init; }
    public string? Sub { get; init; }
    /// <summary>One-time token (customer.registered, checkout.abandoned; user.deleted may carry one).</summary>
    public string? Token { get; init; }
    /// <summary>session.created / session.ended.</summary>
    public string? Sid { get; init; }
    /// <summary>subscription.cancel_requested: the app's own subscription id.</summary>
    public string? Subscription { get; init; }
    /// <summary>The whole event as sent.</summary>
    public required JsonElement Data { get; init; }
}

public static class InIDWebhooks
{
    private const int ToleranceSeconds = 5 * 60;

    /// <summary>
    /// Checks the InID-Signature header ("t=…,v1=…") against the raw body (exactly as received, before any
    /// JSON parsing) and returns the event. Throws InIDException("invalid_signature") if forged or stale.
    /// </summary>
    public static InIDWebhookEvent Verify(string rawBody, string? signature, string webhookSecret, long? now = null)
    {
        if (string.IsNullOrEmpty(webhookSecret)) throw new InIDException("webhook_secret_missing");
        var parts = new Dictionary<string, string>();
        foreach (var piece in (signature ?? "").Split(','))
        {
            var kv = piece.Split('=');
            if (kv.Length >= 2) parts[kv[0].Trim()] = kv[1].Trim();
        }
        var at = parts.TryGetValue("t", out var t) && long.TryParse(t, NumberStyles.None, CultureInfo.InvariantCulture, out var v) ? v : 0;
        var current = now ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (at == 0 || !parts.TryGetValue("v1", out var given) || given.Length == 0 || Math.Abs(current - at) > ToleranceSeconds)
            throw new InIDException("invalid_signature");

        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(webhookSecret));
        var expected = hmac.ComputeHash(Encoding.UTF8.GetBytes($"{at}.{rawBody}"));
        byte[] givenBytes;
        try { givenBytes = Convert.FromHexString(given); }
        catch (FormatException) { throw new InIDException("invalid_signature"); }
        if (!CryptographicOperations.FixedTimeEquals(givenBytes, expected)) throw new InIDException("invalid_signature");

        JsonElement data;
        try { data = JsonDocument.Parse(rawBody).RootElement.Clone(); }
        catch (JsonException) { throw new InIDException("invalid_body"); }
        string? Text(string key) => data.ValueKind == JsonValueKind.Object && data.TryGetProperty(key, out var x) && x.ValueKind == JsonValueKind.String ? x.GetString() : null;
        return new InIDWebhookEvent
        {
            Type = Text("type") ?? "",
            CreatedAt = Text("created_at"),
            Sub = Text("sub"),
            Token = Text("token"),
            Sid = Text("sid"),
            Subscription = Text("subscription"),
            Data = data,
        };
    }
}
