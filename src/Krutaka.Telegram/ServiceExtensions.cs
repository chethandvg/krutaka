using System.Security.Cryptography;
using Krutaka.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Telegram.Bot;

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

        // Register ITelegramFileHandler as singleton (implemented in issue #145)
        // Note: Stateless handler that can be safely shared across all sessions
        services.AddSingleton<ITelegramFileHandler, TelegramFileHandler>();

        // Register ITelegramHealthMonitor as singleton (implemented in issue #147)
        // Note: Stateful monitor (in-memory rate limiting + notification tracking) with thread-safe access,
        //       intentionally registered as a singleton so health/rate state is shared across all sessions
        services.AddSingleton<ITelegramHealthMonitor, TelegramHealthMonitor>();

        // Register ITelegramBotClient as singleton
        // Note: The TelegramBotService creates its own client instance, but TelegramResponseStreamer
        // and TelegramApprovalHandler need a shared client instance for sending messages/edits.
        // We use a factory pattern to create the client with the same secure HttpClient configuration.
#pragma warning disable CA5398 // TLS 1.2+ is explicitly required per security spec (T14 mitigation in TELEGRAM.md)
#pragma warning disable CA2000 // TelegramBotClient takes ownership of HttpClient
        services.AddSingleton<ITelegramBotClient>(sp =>
        {
            var secretsProvider = sp.GetRequiredService<ISecretsProvider>();
            var botToken = secretsProvider.GetSecret("KRUTAKA_TELEGRAM_BOT_TOKEN")
                ?? Environment.GetEnvironmentVariable("KRUTAKA_TELEGRAM_BOT_TOKEN")
                ?? throw new InvalidOperationException(
                    "Telegram bot token not found. " +
                    "Please store it in Windows Credential Manager (key: KRUTAKA_TELEGRAM_BOT_TOKEN) " +
                    "or set the KRUTAKA_TELEGRAM_BOT_TOKEN environment variable.");

            // Create secure HttpClient with TLS 1.2+ and cert revocation checking
            var handler = new System.Net.Http.HttpClientHandler
            {
                SslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13,
                CheckCertificateRevocationList = true
            };

            return new TelegramBotClient(botToken, new System.Net.Http.HttpClient(handler));
        });
#pragma warning restore CA2000
#pragma warning restore CA5398

        // Register TelegramBotService as hosted service
        services.AddHostedService<TelegramBotService>();

        return services;
    }
}
