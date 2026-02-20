using FluentAssertions;
using Krutaka.Core;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Telegram.Bot.Types.Enums;

#pragma warning disable CA2000 // Mock sessions in tests do not need disposal  
#pragma warning disable CA2213 // Mock ISessionManager in tests does not need disposal
#pragma warning disable CA1031 // Tests catching general exceptions for isolation

namespace Krutaka.Telegram.Tests;

public sealed class TelegramSessionBridgeTests : IDisposable
{
    private readonly ISessionManager _sessionManager;
    private readonly ISessionFactory _sessionFactory;
    private readonly TelegramSecurityConfig _config;
    private readonly ILogger<TelegramSessionBridge> _logger;
    private readonly TelegramSessionBridge _bridge;
    private readonly string _tempStorageRoot;

    public TelegramSessionBridgeTests()
    {
        // Use temporary storage root for test isolation
        _tempStorageRoot = Path.Combine(Path.GetTempPath(), $"krutaka-test-{Guid.NewGuid()}");
        Directory.CreateDirectory(_tempStorageRoot);

        _sessionManager = Substitute.For<ISessionManager>();
        _sessionFactory = Substitute.For<ISessionFactory>();
        _config = new TelegramSecurityConfig(
            AllowedUsers:
            [
                new TelegramUserConfig(UserId: 123456789, Role: TelegramUserRole.User, ProjectPath: Path.Combine(_tempStorageRoot, "user1")),
                new TelegramUserConfig(UserId: 987654321, Role: TelegramUserRole.User) // No ProjectPath configured
            ],
            MaxCommandsPerMinute: 10,
            MaxTokensPerHour: 100_000,
            MaxFailedAuthAttempts: 3,
            LockoutDuration: TimeSpan.FromMinutes(5)
        );
        _logger = Substitute.For<ILogger<TelegramSessionBridge>>();

        _bridge = new TelegramSessionBridge(_sessionManager, _sessionFactory, _config, _logger);
    }

    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }

    private void Dispose(bool disposing)
    {
        if (disposing)
        {
            // Clean up temporary storage
            if (Directory.Exists(_tempStorageRoot))
            {
                Directory.Delete(_tempStorageRoot, recursive: true);
            }
        }
    }

    [Fact]
    public async Task GetOrCreateSessionAsync_Should_UseCorrectExternalKey_ForDmChat()
    {
        // Arrange
        var userId = 123456789L;
        var chatId = 123456789L;
        var chatType = ChatType.Private;
        var expectedExternalKey = $"telegram:dm:{userId}";

        // Act
        try
        {
            await _bridge.GetOrCreateSessionAsync(chatId, userId, chatType, CancellationToken.None);
        }
        catch
        {
            // Ignore exceptions from SessionStore.FindMostRecentSession
        }

        // Assert
        await _sessionManager.Received(1).GetOrCreateByKeyAsync(
            expectedExternalKey,
            Arg.Is<SessionRequest>(r => r.ExternalKey == expectedExternalKey),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task GetOrCreateSessionAsync_Should_UseCorrectExternalKey_ForGroupChat()
    {
        // Arrange
        var userId = 987654321L;
        var chatId = -1001234567890L;
        var chatType = ChatType.Group;
        var expectedExternalKey = $"telegram:group:{chatId}";

        // Act
        try
        {
            await _bridge.GetOrCreateSessionAsync(chatId, userId, chatType, CancellationToken.None);
        }
        catch
        {
            // Ignore exceptions
        }

        // Assert
        await _sessionManager.Received(1).GetOrCreateByKeyAsync(
            expectedExternalKey,
            Arg.Is<SessionRequest>(r => r.ExternalKey == expectedExternalKey),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task GetOrCreateSessionAsync_Should_UseCorrectExternalKey_ForSupergroupChat()
    {
        // Arrange
        var userId = 987654321L;
        var chatId = -1001234567890L;
        var chatType = ChatType.Supergroup;
        var expectedExternalKey = $"telegram:group:{chatId}";

        // Act
        try
        {
            await _bridge.GetOrCreateSessionAsync(chatId, userId, chatType, CancellationToken.None);
        }
        catch
        {
            // Ignore exceptions
        }

        // Assert
        await _sessionManager.Received(1).GetOrCreateByKeyAsync(
            expectedExternalKey,
            Arg.Is<SessionRequest>(r => r.ExternalKey == expectedExternalKey),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task GetOrCreateSessionAsync_Should_UseConfiguredProjectPath_WhenAvailable()
    {
        // Arrange
        var userId = 123456789L; // User with configured ProjectPath
        var chatId = 123456789L;
        var chatType = ChatType.Private;
        var expectedProjectPath = Path.Combine(_tempStorageRoot, "user1");

        // Act
        try
        {
            await _bridge.GetOrCreateSessionAsync(chatId, userId, chatType, CancellationToken.None);
        }
        catch
        {
            // Ignore exceptions
        }

        // Assert
        await _sessionManager.Received(1).GetOrCreateByKeyAsync(
            Arg.Any<string>(),
            Arg.Is<SessionRequest>(r => r.ProjectPath == expectedProjectPath),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task GetOrCreateSessionAsync_Should_UseDefaultProjectPath_WhenNotConfigured()
    {
        // Arrange
        var userId = 987654321L; // User without configured ProjectPath
        var chatId = 987654321L;
        var chatType = ChatType.Private;
        var externalKey = $"telegram:dm:{userId}";
        var sanitizedKey = externalKey.Replace(":", "-", StringComparison.Ordinal); // telegram-dm-987654321
        var expectedProjectPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "KrutakaProjects", sanitizedKey);

        // Act
        try
        {
            await _bridge.GetOrCreateSessionAsync(chatId, userId, chatType, CancellationToken.None);
        }
        catch
        {
            // Ignore exceptions
        }

        // Assert
        await _sessionManager.Received(1).GetOrCreateByKeyAsync(
            Arg.Any<string>(),
            Arg.Is<SessionRequest>(r => r.ProjectPath == expectedProjectPath),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CreateNewSessionAsync_Should_TerminateExistingSession_BeforeCreatingNew()
    {
        // Arrange
        var userId = 123456789L;
        var chatId = 123456789L;
        var chatType = ChatType.Private;
        var externalKey = $"telegram:dm:{userId}";
        var existingSessionId = Guid.NewGuid();

        var existingSessionSummary = new SessionSummary(
            SessionId: existingSessionId,
            State: SessionState.Active,
            ProjectPath: "/tmp/test",
            ExternalKey: externalKey,
            UserId: userId.ToString(System.Globalization.CultureInfo.InvariantCulture),
            CreatedAt: DateTimeOffset.UtcNow,
            LastActivity: DateTimeOffset.UtcNow,
            TokensUsed: 100,
            TurnsUsed: 5);

        _sessionManager.ListActiveSessions().Returns([existingSessionSummary]);

        // CreateSessionAsync will throw ArgumentNullException due to null return,
        // but we're only verifying the TerminateSessionAsync call happened first
        try
        {
            await _bridge.CreateNewSessionAsync(chatId, userId, chatType, CancellationToken.None);
        }
        catch (NullReferenceException)
        {
            // Expected - CreateSessionAsync mock returns null
        }

        // Assert
        await _sessionManager.Received(1).TerminateSessionAsync(existingSessionId, Arg.Any<CancellationToken>());
        await _sessionManager.Received(1).CreateSessionAsync(Arg.Any<SessionRequest>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ListSessionsAsync_Should_FilterSessionsByUserId()
    {
        // Arrange
        var userId = 123456789L;
        var otherUserId = 987654321L;

        var userSession1 = new SessionSummary(
            SessionId: Guid.NewGuid(),
            State: SessionState.Active,
            ProjectPath: "/tmp/test1",
            ExternalKey: $"telegram:dm:{userId}",
            UserId: userId.ToString(System.Globalization.CultureInfo.InvariantCulture),
            CreatedAt: DateTimeOffset.UtcNow,
            LastActivity: DateTimeOffset.UtcNow,
            TokensUsed: 100,
            TurnsUsed: 5);

        var userSession2 = new SessionSummary(
            SessionId: Guid.NewGuid(),
            State: SessionState.Active,
            ProjectPath: "/tmp/test2",
            ExternalKey: $"telegram:group:-123",
            UserId: userId.ToString(System.Globalization.CultureInfo.InvariantCulture),
            CreatedAt: DateTimeOffset.UtcNow,
            LastActivity: DateTimeOffset.UtcNow,
            TokensUsed: 200,
            TurnsUsed: 10);

        var otherUserSession = new SessionSummary(
            SessionId: Guid.NewGuid(),
            State: SessionState.Active,
            ProjectPath: "/tmp/test3",
            ExternalKey: $"telegram:dm:{otherUserId}",
            UserId: otherUserId.ToString(System.Globalization.CultureInfo.InvariantCulture),
            CreatedAt: DateTimeOffset.UtcNow,
            LastActivity: DateTimeOffset.UtcNow,
            TokensUsed: 50,
            TurnsUsed: 2);

        _sessionManager.ListActiveSessions().Returns([userSession1, userSession2, otherUserSession]);

        // Act
        var result = await _bridge.ListSessionsAsync(userId, CancellationToken.None);

        // Assert
        result.Should().HaveCount(2);
        result.Should().Contain(s => s.SessionId == userSession1.SessionId);
        result.Should().Contain(s => s.SessionId == userSession2.SessionId);
        result.Should().NotContain(s => s.SessionId == otherUserSession.SessionId);
    }

    [Fact]
    public async Task ListSessionsAsync_Should_ReturnEmptyList_WhenUserHasNoSessions()
    {
        // Arrange
        var userId = 123456789L;
        _sessionManager.ListActiveSessions().Returns([]);

        // Act
        var result = await _bridge.ListSessionsAsync(userId, CancellationToken.None);

        // Assert
        result.Should().BeEmpty();
    }

    [Fact]
    public async Task SwitchSessionAsync_Should_ReturnNull_WhenSessionDoesNotExist()
    {
        // Arrange
        var userId = 123456789L;
        var chatId = 123456789L;
        var sessionId = Guid.NewGuid();

        _sessionManager.ListActiveSessions().Returns([]);

        // Act
        var result = await _bridge.SwitchSessionAsync(chatId, userId, sessionId, CancellationToken.None);

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public async Task SwitchSessionAsync_Should_ReturnNull_WhenSessionBelongsToOtherUser()
    {
        // Arrange
        var userId = 123456789L;
        var otherUserId = 987654321L;
        var chatId = 123456789L;
        var sessionId = Guid.NewGuid();

        var sessionSummary = new SessionSummary(
            SessionId: sessionId,
            State: SessionState.Active,
            ProjectPath: "/tmp/test",
            ExternalKey: $"telegram:dm:{otherUserId}",
            UserId: otherUserId.ToString(System.Globalization.CultureInfo.InvariantCulture),
            CreatedAt: DateTimeOffset.UtcNow,
            LastActivity: DateTimeOffset.UtcNow,
            TokensUsed: 100,
            TurnsUsed: 5);

        _sessionManager.ListActiveSessions().Returns([sessionSummary]);

        // Act
        var result = await _bridge.SwitchSessionAsync(chatId, userId, sessionId, CancellationToken.None);

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public async Task GetOrCreateSessionAsync_Should_ThrowArgumentException_ForUnsupportedChatType()
    {
        // Arrange
        var userId = 123456789L;
        var chatId = 123456789L;
        var chatType = ChatType.Channel; // Unsupported

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await _bridge.GetOrCreateSessionAsync(chatId, userId, chatType, CancellationToken.None));
    }
}
