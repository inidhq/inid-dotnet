using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace InID.AspNetCore;

public static class InIDDefaults
{
    /// <summary>The authentication scheme the policies use (challenge = sign in, forbid = 403).</summary>
    public const string AuthenticationScheme = "InID";
    /// <summary>The configuration section read by AddInID.</summary>
    public const string ConfigurationSection = "InID";
    internal const string ItemKey = "InID.Auth";
}

public static class InIDServiceCollectionExtensions
{
    /// <summary>
    /// Registers InID: settings from the "InID" configuration section (PublishableKey, SecretKey, Issuer,
    /// AppUrl, ApiPath, Scope, WebhookSecret), else INID_* environment variables, then <paramref name="configure"/>.
    /// Also adds the "InID" authentication scheme for [Authorize] policies.
    /// </summary>
    public static IServiceCollection AddInID(this IServiceCollection services, Action<InIDConfig>? configure = null, HttpClient? httpClient = null)
    {
        services.TryAddSingleton(sp =>
        {
            var config = new InIDConfig();
            var configuration = sp.GetService<IConfiguration>();
            if (configuration is not null)
            {
                var section = configuration.GetSection(InIDDefaults.ConfigurationSection);
                config.PublishableKey = section["PublishableKey"] ?? configuration["INID_PUBLISHABLE_KEY"];
                config.SecretKey = section["SecretKey"] ?? configuration["INID_SECRET_KEY"];
                config.Issuer = section["Issuer"] ?? configuration["INID_ISSUER"];
                config.AppUrl = section["AppUrl"] ?? configuration["INID_APP_URL"];
                config.WebhookSecret = section["WebhookSecret"] ?? configuration["INID_WEBHOOK_SECRET"];
                config.ApiPath = section["ApiPath"];
                config.Scope = section["Scope"];
            }
            configure?.Invoke(config);
            return new InIDClient(config, httpClient);
        });
        AddScheme(services);
        return services;
    }

    /// <summary>Registers an InIDClient you built yourself (custom HttpClient or clock).</summary>
    public static IServiceCollection AddInID(this IServiceCollection services, InIDClient client)
    {
        services.TryAddSingleton(client);
        AddScheme(services);
        return services;
    }

    private static void AddScheme(IServiceCollection services)
    {
        services.AddAuthentication().AddScheme<AuthenticationSchemeOptions, InIDAuthenticationHandler>(InIDDefaults.AuthenticationScheme, null);
        services.AddAuthorization();
    }
}
