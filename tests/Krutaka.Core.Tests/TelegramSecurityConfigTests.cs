using FluentAssertions;

namespace Krutaka.Core.Tests;

public class TelegramSecurityConfigTests
{
    [Fact]
    public void Constructor_Should_UseDefaultValues()
    {
        // Arrange
        var users = new[] { new TelegramUserConfig(12345678) };

        // Act
        var config = new TelegramSecurityConfig(users);

        // Assert
        config.AllowedUsers.Should().BeEquivalentTo(users);
        config.RequireConfirmationForElevated.Should().BeTrue();
        config.MaxCommandsPerMinute.Should().Be(10);
        config.MaxTokensPerHour.Should().Be(100_000);
        config.MaxFailedAuthAttempts.Should().Be(3);
        config.LockoutDurationValue.Should().Be(TimeSpan.FromHours(1));
        config.PanicCommand.Should().Be("/killswitch");
        config.MaxInputMessageLength.Should().Be(4_000);
        config.Mode.Should().Be(TelegramTransportMode.LongPolling);
        config.WebhookUrl.Should().BeNull();
        config.PollingTimeoutSeconds.Should().Be(30);
    }

    [Fact]
    public void Constructor_Should_ThrowInvalidOperationException_WhenAllowedUsersIsNull()
    {
        // Act & Assert
        var exception = Assert.Throws<InvalidOperationException>(() =>
            new TelegramSecurityConfig(null!));
        
        exception.Message.Should().Contain("AllowedUsers cannot be null or empty");
    }

    [Fact]
    public void Constructor_Should_ThrowInvalidOperationException_WhenAllowedUsersIsEmpty()
    {
        // Act & Assert
        var exception = Assert.Throws<InvalidOperationException>(() =>
            new TelegramSecurityConfig([]));
        
        exception.Message.Should().Contain("AllowedUsers cannot be null or empty");
    }

    [Fact]
    public void Constructor_Should_ThrowInvalidOperationException_WhenMaxCommandsPerMinuteIsZero()
    {
        // Arrange
        var users = new[] { new TelegramUserConfig(12345678) };

        // Act & Assert
        var exception = Assert.Throws<InvalidOperationException>(() =>
            new TelegramSecurityConfig(users, MaxCommandsPerMinute: 0));
        
        exception.Message.Should().Contain("MaxCommandsPerMinute must be greater than 0");
    }

    [Fact]
    public void Constructor_Should_ThrowInvalidOperationException_WhenMaxCommandsPerMinuteIsNegative()
    {
        // Arrange
        var users = new[] { new TelegramUserConfig(12345678) };

        // Act & Assert
        var exception = Assert.Throws<InvalidOperationException>(() =>
            new TelegramSecurityConfig(users, MaxCommandsPerMinute: -1));
        
        exception.Message.Should().Contain("MaxCommandsPerMinute must be greater than 0");
    }

    [Fact]
    public void Constructor_Should_ThrowInvalidOperationException_WhenMaxTokensPerHourIsZero()
    {
        // Arrange
        var users = new[] { new TelegramUserConfig(12345678) };

        // Act & Assert
        var exception = Assert.Throws<InvalidOperationException>(() =>
            new TelegramSecurityConfig(users, MaxTokensPerHour: 0));
        
        exception.Message.Should().Contain("MaxTokensPerHour must be greater than 0");
    }

    [Fact]
    public void Constructor_Should_ThrowInvalidOperationException_WhenMaxTokensPerHourIsNegative()
    {
        // Arrange
        var users = new[] { new TelegramUserConfig(12345678) };

        // Act & Assert
        var exception = Assert.Throws<InvalidOperationException>(() =>
            new TelegramSecurityConfig(users, MaxTokensPerHour: -1));
        
        exception.Message.Should().Contain("MaxTokensPerHour must be greater than 0");
    }

    [Fact]
    public void Constructor_Should_ThrowInvalidOperationException_WhenMaxFailedAuthAttemptsIsZero()
    {
        // Arrange
        var users = new[] { new TelegramUserConfig(12345678) };

        // Act & Assert
        var exception = Assert.Throws<InvalidOperationException>(() =>
            new TelegramSecurityConfig(users, MaxFailedAuthAttempts: 0));
        
        exception.Message.Should().Contain("MaxFailedAuthAttempts must be greater than 0");
    }

    [Fact]
    public void Constructor_Should_ThrowInvalidOperationException_WhenMaxFailedAuthAttemptsIsNegative()
    {
        // Arrange
        var users = new[] { new TelegramUserConfig(12345678) };

        // Act & Assert
        var exception = Assert.Throws<InvalidOperationException>(() =>
            new TelegramSecurityConfig(users, MaxFailedAuthAttempts: -1));
        
        exception.Message.Should().Contain("MaxFailedAuthAttempts must be greater than 0");
    }

    [Fact]
    public void Constructor_Should_ThrowInvalidOperationException_WhenLockoutDurationIsZero()
    {
        // Arrange
        var users = new[] { new TelegramUserConfig(12345678) };

        // Act & Assert
        var exception = Assert.Throws<InvalidOperationException>(() =>
            new TelegramSecurityConfig(users, LockoutDuration: TimeSpan.Zero));
        
        exception.Message.Should().Contain("LockoutDuration must be greater than TimeSpan.Zero");
    }

    [Fact]
    public void Constructor_Should_ThrowInvalidOperationException_WhenLockoutDurationIsNegative()
    {
        // Arrange
        var users = new[] { new TelegramUserConfig(12345678) };

        // Act & Assert
        var exception = Assert.Throws<InvalidOperationException>(() =>
            new TelegramSecurityConfig(users, LockoutDuration: TimeSpan.FromMinutes(-1)));
        
        exception.Message.Should().Contain("LockoutDuration must be greater than TimeSpan.Zero");
    }

    [Fact]
    public void Constructor_Should_ThrowInvalidOperationException_WhenMaxInputMessageLengthIsZero()
    {
        // Arrange
        var users = new[] { new TelegramUserConfig(12345678) };

        // Act & Assert
        var exception = Assert.Throws<InvalidOperationException>(() =>
            new TelegramSecurityConfig(users, MaxInputMessageLength: 0));
        
        exception.Message.Should().Contain("MaxInputMessageLength must be greater than 0");
    }

    [Fact]
    public void Constructor_Should_ThrowInvalidOperationException_WhenMaxInputMessageLengthIsNegative()
    {
        // Arrange
        var users = new[] { new TelegramUserConfig(12345678) };

        // Act & Assert
        var exception = Assert.Throws<InvalidOperationException>(() =>
            new TelegramSecurityConfig(users, MaxInputMessageLength: -1));
        
        exception.Message.Should().Contain("MaxInputMessageLength must be greater than 0");
    }

    [Fact]
    public void Constructor_Should_ThrowInvalidOperationException_WhenPollingTimeoutSecondsIsZero()
    {
        // Arrange
        var users = new[] { new TelegramUserConfig(12345678) };

        // Act & Assert
        var exception = Assert.Throws<InvalidOperationException>(() =>
            new TelegramSecurityConfig(users, PollingTimeoutSeconds: 0));
        
        exception.Message.Should().Contain("PollingTimeoutSeconds must be greater than 0");
    }

    [Fact]
    public void Constructor_Should_ThrowInvalidOperationException_WhenPollingTimeoutSecondsIsNegative()
    {
        // Arrange
        var users = new[] { new TelegramUserConfig(12345678) };

        // Act & Assert
        var exception = Assert.Throws<InvalidOperationException>(() =>
            new TelegramSecurityConfig(users, PollingTimeoutSeconds: -1));
        
        exception.Message.Should().Contain("PollingTimeoutSeconds must be greater than 0");
    }

    [Fact]
    public void Constructor_Should_ThrowInvalidOperationException_WhenWebhookModeWithNullUrl()
    {
        // Arrange
        var users = new[] { new TelegramUserConfig(12345678) };

        // Act & Assert
        var exception = Assert.Throws<InvalidOperationException>(() =>
            new TelegramSecurityConfig(users, Mode: TelegramTransportMode.Webhook, WebhookUrl: null));
        
        exception.Message.Should().Contain("WebhookUrl is required when Mode is set to Webhook");
    }

    [Fact]
    public void Constructor_Should_ThrowInvalidOperationException_WhenWebhookModeWithEmptyUrl()
    {
        // Arrange
        var users = new[] { new TelegramUserConfig(12345678) };

        // Act & Assert
        var exception = Assert.Throws<InvalidOperationException>(() =>
            new TelegramSecurityConfig(users, Mode: TelegramTransportMode.Webhook, WebhookUrl: ""));
        
        exception.Message.Should().Contain("WebhookUrl is required when Mode is set to Webhook");
    }

    [Fact]
    public void Constructor_Should_ThrowInvalidOperationException_WhenWebhookModeWithWhitespaceUrl()
    {
        // Arrange
        var users = new[] { new TelegramUserConfig(12345678) };

        // Act & Assert
        var exception = Assert.Throws<InvalidOperationException>(() =>
            new TelegramSecurityConfig(users, Mode: TelegramTransportMode.Webhook, WebhookUrl: "   "));
        
        exception.Message.Should().Contain("WebhookUrl is required when Mode is set to Webhook");
    }

    [Fact]
    public void Constructor_Should_AllowLongPollingModeWithNullWebhookUrl()
    {
        // Arrange
        var users = new[] { new TelegramUserConfig(12345678) };

        // Act
        var config = new TelegramSecurityConfig(users, Mode: TelegramTransportMode.LongPolling, WebhookUrl: null);

        // Assert
        config.Mode.Should().Be(TelegramTransportMode.LongPolling);
        config.WebhookUrl.Should().BeNull();
    }

    [Fact]
    public void Constructor_Should_AllowWebhookModeWithValidUrl()
    {
        // Arrange
        var users = new[] { new TelegramUserConfig(12345678) };
        var webhookUrl = "https://example.com/webhook";

        // Act
        var config = new TelegramSecurityConfig(users, Mode: TelegramTransportMode.Webhook, WebhookUrl: webhookUrl);

        // Assert
        config.Mode.Should().Be(TelegramTransportMode.Webhook);
        config.WebhookUrl.Should().Be(webhookUrl);
    }

    [Fact]
    public void Constructor_Should_ThrowInvalidOperationException_WhenDuplicateUserIds()
    {
        // Arrange
        var users = new[]
        {
            new TelegramUserConfig(12345678, TelegramUserRole.Admin),
            new TelegramUserConfig(87654321, TelegramUserRole.User),
            new TelegramUserConfig(12345678, TelegramUserRole.User) // Duplicate
        };

        // Act & Assert
        var exception = Assert.Throws<InvalidOperationException>(() =>
            new TelegramSecurityConfig(users));
        
        exception.Message.Should().Contain("Duplicate UserId values found");
        exception.Message.Should().Contain("12345678");
    }

    [Fact]
    public void Constructor_Should_AcceptCustomValues()
    {
        // Arrange
        var users = new[]
        {
            new TelegramUserConfig(12345678, TelegramUserRole.Admin, "C:\\Projects\\Admin"),
            new TelegramUserConfig(87654321, TelegramUserRole.User)
        };
        var customLockout = TimeSpan.FromMinutes(30);

        // Act
        var config = new TelegramSecurityConfig(
            users,
            RequireConfirmationForElevated: false,
            MaxCommandsPerMinute: 20,
            MaxTokensPerHour: 200_000,
            MaxFailedAuthAttempts: 5,
            LockoutDuration: customLockout,
            PanicCommand: "/emergency",
            MaxInputMessageLength: 8_000,
            Mode: TelegramTransportMode.Webhook,
            WebhookUrl: "https://example.com/bot",
            PollingTimeoutSeconds: 60);

        // Assert
        config.AllowedUsers.Should().BeEquivalentTo(users);
        config.RequireConfirmationForElevated.Should().BeFalse();
        config.MaxCommandsPerMinute.Should().Be(20);
        config.MaxTokensPerHour.Should().Be(200_000);
        config.MaxFailedAuthAttempts.Should().Be(5);
        config.LockoutDurationValue.Should().Be(customLockout);
        config.PanicCommand.Should().Be("/emergency");
        config.MaxInputMessageLength.Should().Be(8_000);
        config.Mode.Should().Be(TelegramTransportMode.Webhook);
        config.WebhookUrl.Should().Be("https://example.com/bot");
        config.PollingTimeoutSeconds.Should().Be(60);
    }

    [Fact]
    public void LockoutDurationValue_Should_UseDefaultWhenNull()
    {
        // Arrange
        var users = new[] { new TelegramUserConfig(12345678) };

        // Act
        var config = new TelegramSecurityConfig(users, LockoutDuration: null);

        // Assert
        config.LockoutDurationValue.Should().Be(TimeSpan.FromHours(1));
    }

    [Fact]
    public void Config_Should_NotHaveBotTokenProperty()
    {
        // This test ensures the security requirement that BotToken is NOT part of the config
        // Act
        var properties = typeof(TelegramSecurityConfig).GetProperties();
        var hasBotToken = properties.Any(p => 
            p.Name.Equals("BotToken", StringComparison.OrdinalIgnoreCase) || 
            p.Name.Equals("Token", StringComparison.OrdinalIgnoreCase) ||
            p.Name.Equals("ApiToken", StringComparison.OrdinalIgnoreCase));

        // Assert
        hasBotToken.Should().BeFalse("BotToken must NOT be part of TelegramSecurityConfig for security reasons");
    }
}
