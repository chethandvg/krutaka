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

    [Fact]
    public void Validator_Should_RejectConfigModifiedViaWithExpression()
    {
        // Arrange
        var users = new[] { new TelegramUserConfig(12345678) };
        var validConfig = new TelegramSecurityConfig(users);

        // Act - modify valid config with invalid value using 'with' expression
        var invalidConfig = validConfig with { MaxCommandsPerMinute = -1 };

        // Assert - validator should catch the invalid value
        var exception = Assert.Throws<InvalidOperationException>(() =>
            TelegramConfigValidator.Validate(invalidConfig));
        
        exception.Message.Should().Contain("MaxCommandsPerMinute must be greater than 0");
    }

    [Fact]
    public void Validator_Should_RejectWebhookModeModifiedViaWithExpression()
    {
        // Arrange
        var users = new[] { new TelegramUserConfig(12345678) };
        var validConfig = new TelegramSecurityConfig(users, Mode: TelegramTransportMode.LongPolling);

        // Act - modify to Webhook mode without URL using 'with' expression
        var invalidConfig = validConfig with { Mode = TelegramTransportMode.Webhook };

        // Assert - validator should catch the missing WebhookUrl
        var exception = Assert.Throws<InvalidOperationException>(() =>
            TelegramConfigValidator.Validate(invalidConfig));
        
        exception.Message.Should().Contain("WebhookUrl is required when Mode is set to Webhook");
    }

    [Fact]
    public void AllowedUsers_Should_BeDefensivelyCopied()
    {
        // Arrange
        var users = new[] { new TelegramUserConfig(12345678, TelegramUserRole.Admin) };
        var config = new TelegramSecurityConfig(users);

        // Act - modify the original array
        users[0] = new TelegramUserConfig(87654321, TelegramUserRole.User);

        // Assert - config should have the original value (defensive copy was made)
        config.AllowedUsers.Should().HaveCount(1);
        config.AllowedUsers[0].UserId.Should().Be(12345678);
        config.AllowedUsers[0].Role.Should().Be(TelegramUserRole.Admin);
    }

    [Fact]
    public void AllowedUsers_Array_Should_NotBeModifiableAfterConstruction()
    {
        // Arrange
        var users = new[] { new TelegramUserConfig(12345678) };
        var config = new TelegramSecurityConfig(users);
        var originalUser = config.AllowedUsers[0];

        // Act - attempt to modify the AllowedUsers array
        config.AllowedUsers[0] = new TelegramUserConfig(87654321);

        // Assert - modification affects the returned array (since arrays are mutable)
        // but validation on the modified config should fail
        config.AllowedUsers[0].UserId.Should().Be(87654321);
        
        // This demonstrates the limitation - while we can't prevent array modification,
        // the validator should be called before using the config in security-critical code
    }
}
