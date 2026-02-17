using System.Security.Cryptography;
using Krutaka.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Krutaka.Telegram;

/// <summary>
/// Extension methods for registering Telegram bot services.
/// </summary>
public static class ServiceExtensions
{
    /// <summary>
    /// Adds Telegram bot services to the dependency injection container.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">The configuration.</param>
    /// <returns>The service collection for chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when services or configuration is null.</exception>
    /// <exception cref="InvalidOperationException">Thrown when configuration validation fails.</exception>
    public static IServiceCollection AddTelegramBot(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        // Bind TelegramSecurityConfig from configuration section "Telegram"
        var telegramSection = configuration.GetSection("Telegram");
        var config = telegramSection.Get<TelegramSecurityConfig>();

        if (config is null)
        {
            throw new InvalidOperationException(
                "Telegram configuration section is missing or invalid. " +
                "Please ensure 'Telegram' section is present in appsettings.json with valid configuration.");
        }

        // Validate configuration at startup (fail-fast)
        TelegramConfigValidator.Validate(config);

        // Register validated config as singleton
        services.AddSingleton(config);

        // Register ITelegramAuthGuard as singleton
        // Note: This is a stateful singleton managing rate limiting and lockout state
        // across all sessions, which is correct for Telegram auth guard
        services.AddSingleton<ITelegramAuthGuard, TelegramAuthGuard>();

        // Register ITelegramResponseStreamer as singleton
        // Note: Stateless streamer that can be safely shared across all sessions
        services.AddSingleton<ITelegramResponseStreamer, TelegramResponseStreamer>();

        // Register ITelegramCommandRouter as singleton (implemented in issue #139)
        // Note: Stateless router that can be safely shared across all sessions  
        services.AddSingleton<ITelegramCommandRouter, TelegramCommandRouter>();

        // Generate HMAC secret for callback signing (once per application lifetime)
        var hmacSecret = RandomNumberGenerator.GetBytes(32);
        services.AddSingleton(new CallbackDataSigner(hmacSecret));

        // Register ITelegramApprovalHandler as singleton
        // Note: Stateless handler (nonce tracking is thread-safe) that can be safely shared across all sessions
        services.AddSingleton<ITelegramApprovalHandler, TelegramApprovalHandler>();

        // Register ITelegramSessionBridge as singleton (implemented in issue #141)
        // Note: Stateless bridge that delegates session management to ISessionManager
        services.AddSingleton<ITelegramSessionBridge, TelegramSessionBridge>();

        return services;
    }
}
