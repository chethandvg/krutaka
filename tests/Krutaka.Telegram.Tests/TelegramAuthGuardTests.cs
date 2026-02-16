using FluentAssertions;
using Krutaka.Core;
using NSubstitute;
using Telegram.Bot.Types;

namespace Krutaka.Telegram.Tests;

public class TelegramAuthGuardTests
{
    private readonly TelegramSecurityConfig _config;
    private readonly IAuditLogger _auditLogger;
    private readonly ICorrelationContextAccessor _correlationAccessor;
    private readonly TelegramAuthGuard _authGuard;
    private readonly CorrelationContext _correlationContext;

    public TelegramAuthGuardTests()
    {
        // Create a valid configuration with 2 users (1 admin, 1 regular user)
        _config = new TelegramSecurityConfig(
            AllowedUsers:
            [
                new TelegramUserConfig(UserId: 12345678, Role: TelegramUserRole.Admin),
                new TelegramUserConfig(UserId: 87654321, Role: TelegramUserRole.User)
            ],
            MaxCommandsPerMinute: 10,
            MaxFailedAuthAttempts: 3,
            LockoutDuration: TimeSpan.FromSeconds(5), // Short lockout for testing
            MaxInputMessageLength: 4000
        );

        _auditLogger = Substitute.For<IAuditLogger>();
        _correlationContext = new CorrelationContext();
        _correlationAccessor = Substitute.For<ICorrelationContextAccessor>();
        _correlationAccessor.Current.Returns(_correlationContext);

        _authGuard = new TelegramAuthGuard(_config, _auditLogger, _correlationAccessor);
    }

    [Fact]
    public async Task ValidateAsync_Should_ReturnValid_WhenUserIsInAllowlist()
    {
        // Arrange
        var update = CreateUpdate(userId: 12345678, chatId: 111, updateId: 1, messageText: "test");

        // Act
        var result = await _authGuard.ValidateAsync(update, CancellationToken.None);

        // Assert
        result.IsValid.Should().BeTrue();
        result.DeniedReason.Should().BeNull();
        result.UserId.Should().Be(12345678);
        result.ChatId.Should().Be(111);
        result.UserRole.Should().Be(TelegramUserRole.Admin);

        // Verify audit logging
        _auditLogger.Received(1).LogTelegramAuth(
            Arg.Any<CorrelationContext>(),
            Arg.Is<TelegramAuthEvent>(e => e.Outcome == AuthOutcome.Allowed && e.TelegramUserId == 12345678));
    }

    [Fact]
    public async Task ValidateAsync_Should_ReturnInvalid_WhenUserIsNotInAllowlist()
    {
        // Arrange
        var update = CreateUpdate(userId: 99999999, chatId: 111, updateId: 1, messageText: "test");

        // Act
        var result = await _authGuard.ValidateAsync(update, CancellationToken.None);

        // Assert
        result.IsValid.Should().BeFalse();
        result.DeniedReason.Should().Be("User not in allowlist");
        result.UserId.Should().Be(99999999);
        result.ChatId.Should().Be(111);

        // Verify security incident logging for unknown user
        _auditLogger.Received(1).LogTelegramSecurityIncident(
            Arg.Any<CorrelationContext>(),
            Arg.Is<TelegramSecurityIncidentEvent>(e => 
                e.Type == IncidentType.UnknownUserAttempt && 
                e.TelegramUserId == 99999999));
    }

    [Fact]
    public async Task ValidateAsync_Should_ReturnCorrectRole_ForAdminUser()
    {
        // Arrange
        var update = CreateUpdate(userId: 12345678, chatId: 111, updateId: 1, messageText: "test");

        // Act
        var result = await _authGuard.ValidateAsync(update, CancellationToken.None);

        // Assert
        result.UserRole.Should().Be(TelegramUserRole.Admin);
    }

    [Fact]
    public async Task ValidateAsync_Should_ReturnCorrectRole_ForRegularUser()
    {
        // Arrange
        var update = CreateUpdate(userId: 87654321, chatId: 222, updateId: 1, messageText: "test");

        // Act
        var result = await _authGuard.ValidateAsync(update, CancellationToken.None);

        // Assert
        result.UserRole.Should().Be(TelegramUserRole.User);
    }

    [Fact]
    public async Task ValidateAsync_Should_DenyRequest_WhenRateLimitExceeded()
    {
        // Arrange
        var userId = 12345678L;
        var chatId = 111L;

        // Act - Send MaxCommandsPerMinute + 1 requests rapidly
        AuthResult? lastResult = null;
        for (int i = 1; i <= _config.MaxCommandsPerMinute + 1; i++)
        {
            var update = CreateUpdate(userId, chatId, i, "test");
            lastResult = await _authGuard.ValidateAsync(update, CancellationToken.None);
        }

        // Assert - Last request should be rate-limited
        lastResult.Should().NotBeNull();
        lastResult!.IsValid.Should().BeFalse();
        lastResult.DeniedReason.Should().Be("Rate limit exceeded");

        // Verify rate limit event was logged
        _auditLogger.Received(1).LogTelegramRateLimit(
            Arg.Any<CorrelationContext>(),
            Arg.Is<TelegramRateLimitEvent>(e => 
                e.TelegramUserId == userId && 
                e.CommandCount > _config.MaxCommandsPerMinute));

        // Verify authentication denial was logged
        _auditLogger.Received(1).LogTelegramAuth(
            Arg.Any<CorrelationContext>(),
            Arg.Is<TelegramAuthEvent>(e => 
                e.Outcome == AuthOutcome.RateLimited && 
                e.TelegramUserId == userId));
    }

    [Fact]
    public async Task ValidateAsync_Should_AllowRequests_AfterRateLimitWindowExpires()
    {
        // Arrange
        var userId = 12345678L;
        var chatId = 111L;

        // Send MaxCommandsPerMinute requests
        for (int i = 1; i <= _config.MaxCommandsPerMinute; i++)
        {
            var update = CreateUpdate(userId, chatId, i, "test");
            await _authGuard.ValidateAsync(update, CancellationToken.None);
        }

        // Wait for sliding window to expire (1 minute + buffer)
        await Task.Delay(TimeSpan.FromSeconds(61));

        // Act - Send another request after window expires
        var finalUpdate = CreateUpdate(userId, chatId, _config.MaxCommandsPerMinute + 1, "test");
        var result = await _authGuard.ValidateAsync(finalUpdate, CancellationToken.None);

        // Assert
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public async Task ValidateAsync_Should_TriggerLockout_AfterMaxFailedAuthAttempts()
    {
        // Arrange
        var userId = 12345678L;
        var chatId = 111L;

        // Trigger rate limit MaxFailedAuthAttempts times
        for (int i = 1; i <= _config.MaxFailedAuthAttempts; i++)
        {
            // Exhaust rate limit to trigger failure
            for (int j = 1; j <= _config.MaxCommandsPerMinute + 1; j++)
            {
                var update = CreateUpdate(userId, chatId, i * 100 + j, "test");
                await _authGuard.ValidateAsync(update, CancellationToken.None);
            }
        }

        // Act - Next request should be locked out
        var lockedOutUpdate = CreateUpdate(userId, chatId, 9999, "test");
        var result = await _authGuard.ValidateAsync(lockedOutUpdate, CancellationToken.None);

        // Assert
        result.IsValid.Should().BeFalse();
        result.DeniedReason.Should().Be("User locked out");

        // Verify lockout security incident was logged
        _auditLogger.Received().LogTelegramSecurityIncident(
            Arg.Any<CorrelationContext>(),
            Arg.Is<TelegramSecurityIncidentEvent>(e => 
                e.Type == IncidentType.LockoutTriggered && 
                e.TelegramUserId == userId));
    }

    [Fact]
    public async Task ValidateAsync_Should_AllowRequests_AfterLockoutExpires()
    {
        // Arrange - Create a guard with very short lockout duration
        var shortLockoutConfig = new TelegramSecurityConfig(
            AllowedUsers: _config.AllowedUsers,
            MaxCommandsPerMinute: _config.MaxCommandsPerMinute,
            MaxFailedAuthAttempts: _config.MaxFailedAuthAttempts,
            LockoutDuration: TimeSpan.FromSeconds(2), // Very short for testing
            MaxInputMessageLength: _config.MaxInputMessageLength
        );

        var guard = new TelegramAuthGuard(shortLockoutConfig, _auditLogger, _correlationAccessor);

        var userId = 12345678L;
        var chatId = 111L;

        // Trigger lockout
        for (int i = 1; i <= shortLockoutConfig.MaxFailedAuthAttempts; i++)
        {
            for (int j = 1; j <= shortLockoutConfig.MaxCommandsPerMinute + 1; j++)
            {
                var update = CreateUpdate(userId, chatId, i * 100 + j, "test");
                await guard.ValidateAsync(update, CancellationToken.None);
            }
        }

        // Verify lockout
        var lockedUpdate = CreateUpdate(userId, chatId, 8888, "test");
        var lockedResult = await guard.ValidateAsync(lockedUpdate, CancellationToken.None);
        lockedResult.IsValid.Should().BeFalse();
        lockedResult.DeniedReason.Should().Be("User locked out");

        // Wait for BOTH lockout AND rate limit window to expire
        await Task.Delay(shortLockoutConfig.LockoutDurationValue + TimeSpan.FromMinutes(1) + TimeSpan.FromSeconds(2));

        // Act - Request after both lockout and rate limit window expired
        var unlockedUpdate = CreateUpdate(userId, chatId, 9999, "test");
        var result = await guard.ValidateAsync(unlockedUpdate, CancellationToken.None);

        // Assert
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public async Task ValidateAsync_Should_RejectReplayAttempt_WithDuplicateUpdateId()
    {
        // Arrange
        var userId = 12345678L;
        var chatId = 111L;
        var updateId = 100;

        // First request
        var firstUpdate = CreateUpdate(userId, chatId, updateId, "test");
        var firstResult = await _authGuard.ValidateAsync(firstUpdate, CancellationToken.None);
        firstResult.IsValid.Should().BeTrue();

        // Act - Replay with same update ID
        var replayUpdate = CreateUpdate(userId, chatId, updateId, "test");
        var replayResult = await _authGuard.ValidateAsync(replayUpdate, CancellationToken.None);

        // Assert
        replayResult.IsValid.Should().BeFalse();
        replayResult.DeniedReason.Should().Be("Replay attempt detected");

        // Verify security incident
        _auditLogger.Received().LogTelegramSecurityIncident(
            Arg.Any<CorrelationContext>(),
            Arg.Is<TelegramSecurityIncidentEvent>(e => 
                e.Type == IncidentType.ReplayAttempt));
    }

    [Fact]
    public async Task ValidateAsync_Should_RejectReplayAttempt_WithOlderUpdateId()
    {
        // Arrange
        var userId = 12345678L;
        var chatId = 111L;

        // First request with update ID 100
        var firstUpdate = CreateUpdate(userId, chatId, 100, "test");
        await _authGuard.ValidateAsync(firstUpdate, CancellationToken.None);

        // Act - Try older update ID
        var olderUpdate = CreateUpdate(userId, chatId, 50, "test");
        var result = await _authGuard.ValidateAsync(olderUpdate, CancellationToken.None);

        // Assert
        result.IsValid.Should().BeFalse();
        result.DeniedReason.Should().Be("Replay attempt detected");
    }

    [Fact]
    public async Task ValidateAsync_Should_AcceptRequest_WithNewerUpdateId()
    {
        // Arrange
        var userId = 12345678L;
        var chatId = 111L;

        // First request with update ID 100
        var firstUpdate = CreateUpdate(userId, chatId, 100, "test");
        await _authGuard.ValidateAsync(firstUpdate, CancellationToken.None);

        // Act - Try newer update ID
        var newerUpdate = CreateUpdate(userId, chatId, 200, "test");
        var result = await _authGuard.ValidateAsync(newerUpdate, CancellationToken.None);

        // Assert
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public async Task ValidateAsync_Should_RejectMessage_WhenTooLong()
    {
        // Arrange
        var longMessage = new string('a', _config.MaxInputMessageLength + 1);
        var update = CreateUpdate(userId: 12345678, chatId: 111, updateId: 1, messageText: longMessage);

        // Act
        var result = await _authGuard.ValidateAsync(update, CancellationToken.None);

        // Assert
        result.IsValid.Should().BeFalse();
        result.DeniedReason.Should().Contain("Message too long");
    }

    [Fact]
    public async Task ValidateAsync_Should_AcceptMessage_AtExactMaxLength()
    {
        // Arrange
        var maxLengthMessage = new string('a', _config.MaxInputMessageLength);
        var update = CreateUpdate(userId: 12345678, chatId: 111, updateId: 1, messageText: maxLengthMessage);

        // Act
        var result = await _authGuard.ValidateAsync(update, CancellationToken.None);

        // Assert
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public async Task ValidateAsync_Should_HandleNullMessage_Gracefully()
    {
        // Arrange
        var update = new Update
        {
            Id = 1,
            Message = new Message
            {
                Date = DateTime.UtcNow,
                From = new User { Id = 12345678 },
                Chat = new Chat { Id = 111 },
                Text = null // Null text
            }
        };

        // Act
        var result = await _authGuard.ValidateAsync(update, CancellationToken.None);

        // Assert - Should not throw, treats null as empty string
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public async Task ValidateAsync_Should_RejectUpdate_WithNoUser()
    {
        // Arrange
        var update = new Update
        {
            Id = 1,
            Message = new Message
            {
                Date = DateTime.UtcNow,
                From = null, // No user
                Chat = new Chat { Id = 111 },
                Text = "test"
            }
        };

        // Act
        var result = await _authGuard.ValidateAsync(update, CancellationToken.None);

        // Assert
        result.IsValid.Should().BeFalse();
        result.UserId.Should().Be(0); // Extracted as 0
    }

    [Fact]
    public async Task ValidateAsync_Should_HandleConcurrentRequests_ForSameUser()
    {
        // Arrange
        var userId = 12345678L;
        var tasks = new List<Task<AuthResult>>();

        // Act - Submit 10 concurrent requests for the same user
        for (int i = 0; i < 10; i++)
        {
            var updateId = i + 1;
            var update = CreateUpdate(userId, 111, updateId, "test");
            tasks.Add(_authGuard.ValidateAsync(update, CancellationToken.None));
        }

        var results = await Task.WhenAll(tasks);

        // Assert - All should complete without exception
        // Some may be rate-limited, but no exceptions should occur
        results.Should().HaveCount(10);
        results.Should().OnlyContain(r => r != null);
    }

    [Fact]
    public async Task ValidateAsync_Should_HandleConcurrentRequests_ForDifferentUsers()
    {
        // Arrange
        var tasks = new List<Task<AuthResult>>();

        // Act - Submit concurrent requests for 2 different users
        for (int i = 0; i < 5; i++)
        {
            var update1 = CreateUpdate(12345678, 111, i * 2 + 1, "test");
            var update2 = CreateUpdate(87654321, 222, i * 2 + 2, "test");
            tasks.Add(_authGuard.ValidateAsync(update1, CancellationToken.None));
            tasks.Add(_authGuard.ValidateAsync(update2, CancellationToken.None));
        }

        var results = await Task.WhenAll(tasks);

        // Assert - All should complete successfully (within rate limits)
        results.Should().HaveCount(10);
        results.Should().OnlyContain(r => r.IsValid);
    }

    [Fact]
    public void Constructor_Should_ThrowArgumentNullException_WhenConfigIsNull()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            new TelegramAuthGuard(null!, _auditLogger, _correlationAccessor));
    }

    [Fact]
    public void Constructor_Should_ThrowArgumentNullException_WhenAuditLoggerIsNull()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            new TelegramAuthGuard(_config, null!, _correlationAccessor));
    }

    [Fact]
    public void Constructor_Should_ThrowArgumentNullException_WhenCorrelationAccessorIsNull()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            new TelegramAuthGuard(_config, _auditLogger, null!));
    }

    [Fact]
    public async Task ValidateAsync_Should_ThrowArgumentNullException_WhenUpdateIsNull()
    {
        // Act & Assert
        await Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await _authGuard.ValidateAsync(null!, CancellationToken.None));
    }

    private static Update CreateUpdate(long userId, long chatId, int updateId, string messageText)
    {
        return new Update
        {
            Id = updateId,
            Message = new Message
            {
                Date = DateTime.UtcNow,
                From = new User { Id = userId },
                Chat = new Chat { Id = chatId },
                Text = messageText
            }
        };
    }
}
