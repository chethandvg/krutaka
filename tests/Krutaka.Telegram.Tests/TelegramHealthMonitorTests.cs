using FluentAssertions;
using Krutaka.Core;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Telegram.Bot;

namespace Krutaka.Telegram.Tests;

public class TelegramHealthMonitorTests
{
    private readonly ITelegramBotClient _botClient;
    private readonly TelegramSecurityConfig _config;
    private readonly ISessionManager _sessionManager;
    private readonly ILogger<TelegramHealthMonitor> _logger;
    private readonly TelegramHealthMonitor _monitor;

    public TelegramHealthMonitorTests()
    {
        _botClient = Substitute.For<ITelegramBotClient>();
        _config = new TelegramSecurityConfig(
            AllowedUsers:
            [
                new TelegramUserConfig(UserId: 12345678, Role: TelegramUserRole.Admin),
                new TelegramUserConfig(UserId: 87654321, Role: TelegramUserRole.User),
                new TelegramUserConfig(UserId: 11111111, Role: TelegramUserRole.Admin)
            ],
            MaxCommandsPerMinute: 10
        );
        _sessionManager = Substitute.For<ISessionManager>();
        _logger = Substitute.For<ILogger<TelegramHealthMonitor>>();

        // Setup mock to return a valid Message object for any SendRequest call
        _botClient.SendRequest<global::Telegram.Bot.Types.Message>(default!, default)
            .ReturnsForAnyArgs(Task.FromResult(new global::Telegram.Bot.Types.Message()));

        _monitor = new TelegramHealthMonitor(_botClient, _config, _sessionManager, _logger);
    }

    [Fact]
    public async Task NotifyStartupAsync_Should_SendMessageToAllAdminUsers()
    {
        // Act
        await _monitor.NotifyStartupAsync(CancellationToken.None);

        // Assert - should send to both admin users (12345678 and 11111111)
        await _botClient.Received(2).SendRequest<global::Telegram.Bot.Types.Message>(
            Arg.Is<global::Telegram.Bot.Requests.SendMessageRequest>(r =>
                r.Text == "🟢 Krutaka bot is online"),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task NotifyShutdownAsync_Should_SendMessageToAllAdminUsers()
    {
        // Act
        await _monitor.NotifyShutdownAsync(CancellationToken.None);

        // Assert - should send to both admin users (12345678 and 11111111)
        await _botClient.Received(2).SendRequest<global::Telegram.Bot.Types.Message>(
            Arg.Is<global::Telegram.Bot.Requests.SendMessageRequest>(r =>
                r.Text == "🔴 Krutaka bot is shutting down"),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task NotifyErrorAsync_Should_SendSanitizedErrorToAdminUsers()
    {
        // Arrange
        var errorWithStackTrace = """
            Error occurred
            at System.IO.File.ReadAllText(String path)
            at MyApp.ReadFile(String path) in C:\Projects\MyApp\MyClass.cs:line 42
            """;

        // Act
        await _monitor.NotifyErrorAsync(errorWithStackTrace, CancellationToken.None);

        // Assert - should send sanitized error (without stack traces or file paths)
        await _botClient.Received().SendRequest<global::Telegram.Bot.Types.Message>(
            Arg.Is<global::Telegram.Bot.Requests.SendMessageRequest>(r =>
                r.Text.Contains("⚠️ Error alert:") &&
                !r.Text.Contains("at System.IO") &&
                !r.Text.Contains("C:\\Projects")),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task NotifyErrorAsync_Should_RemoveStackTracesFromErrorMessage()
    {
        // Arrange
        var errorWithStackTrace = """
            NullReferenceException occurred
            at Krutaka.Core.MyClass.DoSomething()
            at Krutaka.AI.AgentOrchestrator.RunAsync()
            """;

        // Act
        await _monitor.NotifyErrorAsync(errorWithStackTrace, CancellationToken.None);

        // Assert
        await _botClient.Received().SendRequest<global::Telegram.Bot.Types.Message>(
            Arg.Is<global::Telegram.Bot.Requests.SendMessageRequest>(r =>
                !r.Text.Contains("at Krutaka")),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task NotifyErrorAsync_Should_RemoveFilePathsFromErrorMessage()
    {
        // Arrange
        var errorWithFilePath = "Error reading file: C:\\Projects\\MyApp\\data.txt";

        // Act
        await _monitor.NotifyErrorAsync(errorWithFilePath, CancellationToken.None);

        // Assert
        await _botClient.Received().SendRequest<global::Telegram.Bot.Types.Message>(
            Arg.Is<global::Telegram.Bot.Requests.SendMessageRequest>(r =>
                !r.Text.Contains("C:\\Projects")),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task NotifyErrorAsync_Should_RemoveTokenLikeStringsFromErrorMessage()
    {
        // Arrange
        var errorWithToken = "API error: token sk_test_51234567890abcdefghijklmnopqrstuvwxyz123456 is invalid";

        // Act
        await _monitor.NotifyErrorAsync(errorWithToken, CancellationToken.None);

        // Assert
        await _botClient.Received().SendRequest<global::Telegram.Bot.Types.Message>(
            Arg.Is<global::Telegram.Bot.Requests.SendMessageRequest>(r =>
                !r.Text.Contains("sk_test_")),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task NotifyTaskCompletedAsync_Should_SendMessageToSpecificChat()
    {
        // Arrange
        const long chatId = 12345678;
        const string taskSummary = "File analysis completed";

        // Act
        await _monitor.NotifyTaskCompletedAsync(chatId, taskSummary, CancellationToken.None);

        // Assert
        await _botClient.Received(1).SendRequest<global::Telegram.Bot.Types.Message>(
            Arg.Is<global::Telegram.Bot.Requests.SendMessageRequest>(r =>
                r.ChatId.Identifier == chatId &&
                r.Text == $"✅ Task completed: {taskSummary}"),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task NotifyBudgetWarningAsync_Should_SendWarningWithUsagePercentage()
    {
        // Arrange
        const long chatId = 12345678;
        var budget = new SessionBudget(maxTokens: 100_000, maxToolCalls: 100);
        budget.AddTokens(85_000); // 85% usage

        // Act
        await _monitor.NotifyBudgetWarningAsync(chatId, budget, CancellationToken.None);

        // Assert
        await _botClient.Received(1).SendRequest<global::Telegram.Bot.Types.Message>(
            Arg.Is<global::Telegram.Bot.Requests.SendMessageRequest>(r =>
                r.ChatId.Identifier == chatId &&
                r.Text.Contains("💰 Budget warning") &&
                r.Text.Contains("85.0%") &&
                r.Text.Contains("85,000") &&
                r.Text.Contains("100,000")),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task NotifyBudgetWarningAsync_Should_SendWarningAt80PercentThreshold()
    {
        // Arrange
        const long chatId = 12345678;
        var budget = new SessionBudget(maxTokens: 100_000, maxToolCalls: 100);
        budget.AddTokens(80_000); // Exactly 80% usage

        // Act
        await _monitor.NotifyBudgetWarningAsync(chatId, budget, CancellationToken.None);

        // Assert
        await _botClient.Received(1).SendRequest<global::Telegram.Bot.Types.Message>(
            Arg.Is<global::Telegram.Bot.Requests.SendMessageRequest>(r =>
                r.ChatId.Identifier == chatId &&
                r.Text.Contains("💰 Budget warning") &&
                r.Text.Contains("80.0%")),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task NotifyBudgetWarningAsync_Should_SendWarningAbove80PercentThreshold()
    {
        // Arrange
        const long chatId = 12345678;
        var budget = new SessionBudget(maxTokens: 100_000, maxToolCalls: 100);
        budget.AddTokens(92_000); // 92% usage - well above threshold

        // Act
        await _monitor.NotifyBudgetWarningAsync(chatId, budget, CancellationToken.None);

        // Assert
        await _botClient.Received(1).SendRequest<global::Telegram.Bot.Types.Message>(
            Arg.Is<global::Telegram.Bot.Requests.SendMessageRequest>(r =>
                r.ChatId.Identifier == chatId &&
                r.Text.Contains("💰 Budget warning") &&
                r.Text.Contains("92.0%")),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CheckBudgetThresholdsAsync_Should_SkipSession_WhenExternalKeyIsNotTelegram()
    {
        // Arrange
        _sessionManager.ListActiveSessions().Returns(
        [
            new SessionSummary(
                Guid.NewGuid(),
                SessionState.Active,
                "/test/path",
                "console", // Non-Telegram external key
                null,
                DateTimeOffset.UtcNow,
                DateTimeOffset.UtcNow,
                90_000, // 90% of 100K
                0)
        ]);

        // Act
        await _monitor.CheckBudgetThresholdsAsync(CancellationToken.None);

        // Assert - should not send any warnings for non-Telegram sessions
        await _botClient.DidNotReceive().SendRequest<global::Telegram.Bot.Types.Message>(
            Arg.Any<global::Telegram.Bot.Requests.SendMessageRequest>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CheckBudgetThresholdsAsync_Should_HandleNullSession()
    {
        // Arrange
        var sessionId = Guid.NewGuid();
        _sessionManager.ListActiveSessions().Returns(
        [
            new SessionSummary(
                sessionId,
                SessionState.Active,
                "/test/path",
                "telegram:12345678",
                null,
                DateTimeOffset.UtcNow,
                DateTimeOffset.UtcNow,
                90_000,
                0)
        ]);
        _sessionManager.GetSession(sessionId).Returns((ManagedSession?)null); // Session terminated

        // Act
        await _monitor.CheckBudgetThresholdsAsync(CancellationToken.None);

        // Assert - should not throw and not send any warnings
        await _botClient.DidNotReceive().SendRequest<global::Telegram.Bot.Types.Message>(
            Arg.Any<global::Telegram.Bot.Requests.SendMessageRequest>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RateLimit_Should_SuppressDuplicateNotifications_WithinOneMinute()
    {
        // Arrange - send two error notifications within a short time

        // Act
        await _monitor.NotifyErrorAsync("First error", CancellationToken.None);
        await _monitor.NotifyErrorAsync("Second error", CancellationToken.None);

        // Assert - should only send the first notification due to rate limiting
        // Each admin user should receive only 1 message (not 2)
        await _botClient.Received(2).SendRequest<global::Telegram.Bot.Types.Message>( // 2 admin users, 1 message each
            Arg.Is<global::Telegram.Bot.Requests.SendMessageRequest>(r =>
                r.Text.Contains("⚠️ Error alert:")),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RateLimit_Should_AllowNotification_ForDifferentEventTypes()
    {
        // Arrange & Act - send startup notification (which has its own event type)
        await _monitor.NotifyStartupAsync(CancellationToken.None);
        
        // Send error notification (different event type, should not be rate-limited)
        await _monitor.NotifyErrorAsync("Test error", CancellationToken.None);

        // Assert - both should be sent because they're different event types
        // Startup: 2 admins * 1 message = 2 calls
        // Error: 2 admins * 1 message = 2 calls
        // Total: 4 calls
        await _botClient.Received(4).SendRequest<global::Telegram.Bot.Types.Message>(
            Arg.Any<global::Telegram.Bot.Requests.SendMessageRequest>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task NotifyStartupAsync_Should_NotSendToNonAdminUsers()
    {
        // Act
        await _monitor.NotifyStartupAsync(CancellationToken.None);

        // Assert - should NOT send to non-admin user (87654321)
        await _botClient.DidNotReceive().SendRequest<global::Telegram.Bot.Types.Message>(
            Arg.Is<global::Telegram.Bot.Requests.SendMessageRequest>(r =>
                r.ChatId.Identifier == 87654321),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task NotifyShutdownAsync_Should_NotSendToNonAdminUsers()
    {
        // Act
        await _monitor.NotifyShutdownAsync(CancellationToken.None);

        // Assert - should NOT send to non-admin user (87654321)
        await _botClient.DidNotReceive().SendRequest<global::Telegram.Bot.Types.Message>(
            Arg.Is<global::Telegram.Bot.Requests.SendMessageRequest>(r =>
                r.ChatId.Identifier == 87654321),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task NotifyErrorAsync_Should_ContinueOnFailure_ForIndividualAdmins()
    {
        // Arrange - make SendRequest throw for first admin
        _botClient.SendRequest<global::Telegram.Bot.Types.Message>(
            Arg.Is<global::Telegram.Bot.Requests.SendMessageRequest>(r => r.ChatId.Identifier == 12345678),
            Arg.Any<CancellationToken>())
            .Returns(_ => Task.FromException<global::Telegram.Bot.Types.Message>(new InvalidOperationException("Network error")));

        // Reset the default mock to allow other calls
        _botClient.SendRequest<global::Telegram.Bot.Types.Message>(
            Arg.Is<global::Telegram.Bot.Requests.SendMessageRequest>(r => r.ChatId.Identifier != 12345678),
            Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new global::Telegram.Bot.Types.Message()));

        // Act
        await _monitor.NotifyErrorAsync("Test error", CancellationToken.None);

        // Assert - should still try to send to second admin (11111111)
        await _botClient.Received(1).SendRequest<global::Telegram.Bot.Types.Message>(
            Arg.Is<global::Telegram.Bot.Requests.SendMessageRequest>(r =>
                r.ChatId.Identifier == 11111111 &&
                r.Text.Contains("⚠️ Error alert:")),
            Arg.Any<CancellationToken>());
    }
}
