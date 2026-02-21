using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using Krutaka.Core;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Telegram.Bot;

#pragma warning disable CA1848 // Use LoggerMessage delegates for improved performance
#pragma warning disable CA1873 // Evaluation of logging arguments may be expensive when logging is disabled

namespace Krutaka.Telegram;

/// <summary>
/// Background service that orchestrates the Telegram bot lifecycle with dual-mode transport support.
/// Supports long polling (hardened with security mitigations) and webhook modes.
/// </summary>
public sealed partial class TelegramBotService : BackgroundService
{
    private readonly ITelegramBotClient _botClient;
    private readonly TelegramSecurityConfig _config;
    private readonly ITelegramAuthGuard _authGuard;
    private readonly ITelegramCommandRouter _router;
    private readonly ITelegramSessionBridge _sessionBridge;
    // Note: _streamer will be wired into HandleSessionCommandAsync in future work
    // Currently, session command handling sends placeholder acknowledgments
    #pragma warning disable IDE0052 // Remove unread private members - will be used for response streaming
    private readonly ITelegramResponseStreamer _streamer;
    #pragma warning restore IDE0052
    private readonly ISessionManager _sessionManager;
    private readonly IHostApplicationLifetime _hostLifetime;
    private readonly ILogger<TelegramBotService> _logger;
    private readonly PollingLockFile? _pollingLock;

    // Long polling configuration
    private const int InitialBackoffSeconds = 5;
    private const int MaxRetryBackoffSeconds = 120;
    private const int MaxConsecutiveFailures = 10;

    private int _consecutiveFailures;
    private int _currentBackoffSeconds = InitialBackoffSeconds;
    private int _lastProcessedUpdateId;

    /// <summary>
    /// Initializes a new instance of the <see cref="TelegramBotService"/> class.
    /// </summary>
    /// <param name="config">The Telegram security configuration.</param>
    /// <param name="authGuard">The authentication guard for validating updates.</param>
    /// <param name="router">The command router for routing updates.</param>
    /// <param name="sessionBridge">The session bridge for managing Telegram sessions.</param>
    /// <param name="streamer">The response streamer for sending responses to Telegram.</param>
    /// <param name="sessionManager">The session manager for lifecycle operations.</param>
    /// <param name="hostLifetime">The host application lifetime for shutdown coordination.</param>
    /// <param name="secretsProvider">The secrets provider for loading the bot token.</param>
    /// <param name="logger">The logger.</param>
    /// <exception cref="InvalidOperationException">Thrown when bot token is not found in ISecretsProvider or environment variable.</exception>
    public TelegramBotService(
        TelegramSecurityConfig config,
        ITelegramAuthGuard authGuard,
        ITelegramCommandRouter router,
        ITelegramSessionBridge sessionBridge,
        ITelegramResponseStreamer streamer,
        ISessionManager sessionManager,
        IHostApplicationLifetime hostLifetime,
        ISecretsProvider secretsProvider,
        ILogger<TelegramBotService> logger)
    {
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(authGuard);
        ArgumentNullException.ThrowIfNull(router);
        ArgumentNullException.ThrowIfNull(sessionBridge);
        ArgumentNullException.ThrowIfNull(streamer);
        ArgumentNullException.ThrowIfNull(sessionManager);
        ArgumentNullException.ThrowIfNull(hostLifetime);
        ArgumentNullException.ThrowIfNull(secretsProvider);
        ArgumentNullException.ThrowIfNull(logger);

        _config = config;
        _authGuard = authGuard;
        _router = router;
        _sessionBridge = sessionBridge;
        _streamer = streamer;
        _sessionManager = sessionManager;
        _hostLifetime = hostLifetime;
        _logger = logger;

        // Load bot token from ISecretsProvider or environment variable (fail-fast)
        var botToken = LoadBotToken(secretsProvider);

        // Create bot client with TLS 1.2+ enforcement (T14 mitigation)
        // Note: HttpClient ownership is transferred to TelegramBotClient
#pragma warning disable CA2000 // TelegramBotClient takes ownership of HttpClient and will dispose it
        _botClient = new TelegramBotClient(botToken, CreateSecureHttpClient());
#pragma warning restore CA2000

        // Acquire single-instance lock for long polling mode (T15 mitigation)
        if (_config.Mode == TelegramTransportMode.LongPolling)
        {
            _pollingLock = new PollingLockFile();
            if (!_pollingLock.TryAcquire())
            {
                _pollingLock.Dispose();
                throw new InvalidOperationException(
                    "Another instance of the Telegram bot is already running and polling. " +
                    "Only one instance can poll the same bot token simultaneously. " +
                    "Stop the other instance or use webhook mode instead.");
            }

            _logger.LogInformation("Acquired single-instance polling lock");
        }
    }

    /// <summary>
    /// Executes the Telegram bot service lifecycle.
    /// </summary>
    /// <param name="stoppingToken">Cancellation token to signal shutdown.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Telegram bot service starting in {Mode} mode", _config.Mode);

        try
        {
            if (_config.Mode == TelegramTransportMode.LongPolling)
            {
                await RunLongPollingLoopAsync(stoppingToken).ConfigureAwait(false);
            }
            else if (_config.Mode == TelegramTransportMode.Webhook)
            {
                await RunWebhookModeAsync(stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogInformation("Telegram bot service stopped due to cancellation");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Telegram bot service encountered an unhandled exception");
            throw;
        }
        finally
        {
            _pollingLock?.Release();
            _logger.LogInformation("Telegram bot service stopped");
        }
    }

    /// <summary>
    /// Runs webhook mode (placeholder for initial implementation).
    /// </summary>
    private Task RunWebhookModeAsync(CancellationToken cancellationToken)
    {
        _logger.LogWarning("Webhook mode is not yet implemented. The bot will not process updates.");
        
        // Placeholder: keep service running but do nothing
        return Task.Delay(Timeout.Infinite, cancellationToken);
    }

    /// <summary>
    /// Loads the bot token from ISecretsProvider or environment variable.
    /// </summary>
    /// <param name="secretsProvider">The secrets provider.</param>
    /// <returns>The bot token.</returns>
    /// <exception cref="InvalidOperationException">Thrown when token is not found in either source.</exception>
    private string LoadBotToken(ISecretsProvider secretsProvider)
    {
        // Try ISecretsProvider first (Windows Credential Manager)
        var token = secretsProvider.GetSecret("KRUTAKA_TELEGRAM_BOT_TOKEN");

        // Fall back to environment variable
        token ??= Environment.GetEnvironmentVariable("KRUTAKA_TELEGRAM_BOT_TOKEN");

        if (string.IsNullOrWhiteSpace(token))
        {
            throw new InvalidOperationException(
                "Telegram bot token not found. " +
                "Please store it in Windows Credential Manager (key: KRUTAKA_TELEGRAM_BOT_TOKEN) " +
                "or set the KRUTAKA_TELEGRAM_BOT_TOKEN environment variable.");
        }

        _logger.LogInformation("Bot token loaded successfully");
        return token;
    }

    /// <summary>
    /// Creates an HttpClient with TLS 1.2+ enforcement (T14 mitigation).
    /// </summary>
#pragma warning disable CA5398 // TLS 1.2+ is explicitly required per security spec (T14 mitigation in TELEGRAM.md)
#pragma warning disable CA2000 // HttpClient ownership is transferred to TelegramBotClient, which will dispose it
    private static HttpClient CreateSecureHttpClient()
    {
        var handler = new HttpClientHandler
        {
            SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            CheckCertificateRevocationList = true // CA5399: Enable certificate revocation checking
        };

        // TelegramBotClient takes ownership of HttpClient and will dispose the handler
        return new HttpClient(handler);
    }
#pragma warning restore CA2000
#pragma warning restore CA5398

    /// <summary>
    /// Disposes the service and releases the polling lock.
    /// </summary>
    public override void Dispose()
    {
        _pollingLock?.Dispose();
        base.Dispose();
    }
}
