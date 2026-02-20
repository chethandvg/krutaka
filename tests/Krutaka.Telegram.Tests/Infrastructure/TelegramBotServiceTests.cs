using FluentAssertions;
using Krutaka.Core;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Telegram.Bot;
using Telegram.Bot.Types;
using Telegram.Bot.Types.Enums;

namespace Krutaka.Telegram.Tests;

[Collection("PollingLockFileTests")]  // Share collection to prevent lock conflicts
public class TelegramBotServiceTests
{
    private readonly TelegramSecurityConfig _config;
    private readonly ITelegramAuthGuard _authGuard;
    private readonly ITelegramCommandRouter _router;
    private readonly ITelegramSessionBridge _sessionBridge;
    private readonly ITelegramResponseStreamer _streamer;
    private readonly ISessionManager _sessionManager;
    private readonly IHostApplicationLifetime _hostLifetime;
    private readonly ISecretsProvider _secretsProvider;
    private readonly ILogger<TelegramBotService> _logger;

    public TelegramBotServiceTests()
    {
        _config = new TelegramSecurityConfig(
            AllowedUsers:
            [
                new TelegramUserConfig(UserId: 12345678, Role: TelegramUserRole.Admin)
            ],
            Mode: TelegramTransportMode.LongPolling,
            PollingTimeoutSeconds: 30);

        _authGuard = Substitute.For<ITelegramAuthGuard>();
        _router = Substitute.For<ITelegramCommandRouter>();
        _sessionBridge = Substitute.For<ITelegramSessionBridge>();
        _streamer = Substitute.For<ITelegramResponseStreamer>();
        _sessionManager = Substitute.For<ISessionManager>();
        _hostLifetime = Substitute.For<IHostApplicationLifetime>();
        _secretsProvider = Substitute.For<ISecretsProvider>();
        _logger = Substitute.For<ILogger<TelegramBotService>>();

        // Default: bot token available (format: bot<token>, e.g., "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11")
        _secretsProvider.GetSecret("KRUTAKA_TELEGRAM_BOT_TOKEN").Returns("123456789:ABCdefGHIjklMNOpqrsTUVwxyz123456789");
    }

    [Fact]
    public void Constructor_Should_ThrowException_WhenBotTokenNotFound()
    {
        // Arrange
        _secretsProvider.GetSecret(Arg.Any<string>()).Returns((string?)null);
        Environment.SetEnvironmentVariable("KRUTAKA_TELEGRAM_BOT_TOKEN", null);

        // Act & Assert
        var act = () => new TelegramBotService(
            _config,
            _authGuard,
            _router,
            _sessionBridge,
            _streamer,
            _sessionManager,
            _hostLifetime,
            _secretsProvider,
            _logger);

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*bot token not found*");
    }

    [Fact]
    public void Constructor_Should_LoadBotToken_FromSecretsProvider()
    {
        // Arrange
        _secretsProvider.GetSecret("KRUTAKA_TELEGRAM_BOT_TOKEN").Returns("111111111:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw");

        // Act
        using var service = CreateService();

        // Assert
        service.Should().NotBeNull();
        _secretsProvider.Received(1).GetSecret("KRUTAKA_TELEGRAM_BOT_TOKEN");
    }

    [Fact]
    public void Constructor_Should_LoadBotToken_FromEnvironmentVariable_WhenSecretsProviderReturnsNull()
    {
        // Arrange
        _secretsProvider.GetSecret(Arg.Any<string>()).Returns((string?)null);
        Environment.SetEnvironmentVariable("KRUTAKA_TELEGRAM_BOT_TOKEN", "222222222:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw");

        try
        {
            // Act
            using var service = CreateService();

            // Assert
            service.Should().NotBeNull();
        }
        finally
        {
            Environment.SetEnvironmentVariable("KRUTAKA_TELEGRAM_BOT_TOKEN", null);
        }
    }

    [Fact]
    public void Constructor_Should_ThrowException_WhenPollingLockCannotBeAcquired()
    {
        // Arrange - Create first instance to hold the lock
        var firstService = CreateService();

        try
        {
            // Act & Assert - Second instance should fail
            var act = () => CreateService();

            act.Should().Throw<InvalidOperationException>()
                .WithMessage("*Another instance*already running*polling*");
        }
        finally
        {
            firstService.Dispose();
        }
    }

    [Fact]
    public void Constructor_Should_NotAcquireLock_InWebhookMode()
    {
        // Arrange
        var webhookConfig = new TelegramSecurityConfig(
            AllowedUsers:
            [
                new TelegramUserConfig(UserId: 12345678, Role: TelegramUserRole.Admin)
            ],
            Mode: TelegramTransportMode.Webhook,
            WebhookUrl: "https://example.com/webhook");

        // Act - Should not throw even if another instance exists
        var service1 = new TelegramBotService(
            webhookConfig,
            _authGuard,
            _router,
            _sessionBridge,
            _streamer,
            _sessionManager,
            _hostLifetime,
            _secretsProvider,
            _logger);

        var service2 = new TelegramBotService(
            webhookConfig,
            _authGuard,
            _router,
            _sessionBridge,
            _streamer,
            _sessionManager,
            _hostLifetime,
            _secretsProvider,
            _logger);

        // Assert
        service1.Should().NotBeNull();
        service2.Should().NotBeNull();

        service1.Dispose();
        service2.Dispose();
    }

    [Fact]
    public void Dispose_Should_ReleaseLock()
    {
        // Arrange
        var firstService = CreateService();

        // Act
        firstService.Dispose();

        // Assert - Should be able to create second instance after first is disposed
        var secondService = CreateService();
        secondService.Should().NotBeNull();
        secondService.Dispose();
    }

    [Fact]
    public void Constructor_Should_ThrowArgumentNullException_WhenConfigIsNull()
    {
        // Act & Assert
        var act = () => new TelegramBotService(
            null!,
            _authGuard,
            _router,
            _sessionBridge,
            _streamer,
            _sessionManager,
            _hostLifetime,
            _secretsProvider,
            _logger);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_Should_ThrowArgumentNullException_WhenAuthGuardIsNull()
    {
        // Act & Assert
        var act = () => new TelegramBotService(
            _config,
            null!,
            _router,
            _sessionBridge,
            _streamer,
            _sessionManager,
            _hostLifetime,
            _secretsProvider,
            _logger);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_Should_ThrowArgumentNullException_WhenRouterIsNull()
    {
        // Act & Assert
        var act = () => new TelegramBotService(
            _config,
            _authGuard,
            null!,
            _sessionBridge,
            _streamer,
            _sessionManager,
            _hostLifetime,
            _secretsProvider,
            _logger);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_Should_ThrowArgumentNullException_WhenSessionBridgeIsNull()
    {
        // Act & Assert
        var act = () => new TelegramBotService(
            _config,
            _authGuard,
            _router,
            null!,
            _streamer,
            _sessionManager,
            _hostLifetime,
            _secretsProvider,
            _logger);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_Should_ThrowArgumentNullException_WhenStreamerIsNull()
    {
        // Act & Assert
        var act = () => new TelegramBotService(
            _config,
            _authGuard,
            _router,
            _sessionBridge,
            null!,
            _sessionManager,
            _hostLifetime,
            _secretsProvider,
            _logger);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_Should_ThrowArgumentNullException_WhenSessionManagerIsNull()
    {
        // Act & Assert
        var act = () => new TelegramBotService(
            _config,
            _authGuard,
            _router,
            _sessionBridge,
            _streamer,
            null!,
            _hostLifetime,
            _secretsProvider,
            _logger);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_Should_ThrowArgumentNullException_WhenHostLifetimeIsNull()
    {
        // Act & Assert
        var act = () => new TelegramBotService(
            _config,
            _authGuard,
            _router,
            _sessionBridge,
            _streamer,
            _sessionManager,
            null!,
            _secretsProvider,
            _logger);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_Should_ThrowArgumentNullException_WhenSecretsProviderIsNull()
    {
        // Act & Assert
        var act = () => new TelegramBotService(
            _config,
            _authGuard,
            _router,
            _sessionBridge,
            _streamer,
            _sessionManager,
            _hostLifetime,
            null!,
            _logger);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_Should_ThrowArgumentNullException_WhenLoggerIsNull()
    {
        // Act & Assert
        var act = () => new TelegramBotService(
            _config,
            _authGuard,
            _router,
            _sessionBridge,
            _streamer,
            _sessionManager,
            _hostLifetime,
            _secretsProvider,
            null!);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_Should_NotLogBotToken()
    {
        // Arrange
        var loggerMock = Substitute.For<ILogger<TelegramBotService>>();
        _secretsProvider.GetSecret("KRUTAKA_TELEGRAM_BOT_TOKEN").Returns("333333333:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw");

        // Act
        using var service = new TelegramBotService(
            _config,
            _authGuard,
            _router,
            _sessionBridge,
            _streamer,
            _sessionManager,
            _hostLifetime,
            _secretsProvider,
            loggerMock);

        // Assert - Verify no log message contains the actual token
#pragma warning disable CA1873 // Avoid evaluating arguments when logging is disabled - acceptable in tests
        loggerMock.DidNotReceive().Log(
            Arg.Any<LogLevel>(),
            Arg.Any<EventId>(),
            Arg.Is<object>(o => o.ToString()!.Contains("333333333:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw")),
            Arg.Any<Exception>(),
            Arg.Any<Func<object, Exception?, string>>());
#pragma warning restore CA1873
    }

    private TelegramBotService CreateService()
    {
        return new TelegramBotService(
            _config,
            _authGuard,
            _router,
            _sessionBridge,
            _streamer,
            _sessionManager,
            _hostLifetime,
            _secretsProvider,
            _logger);
    }
}
