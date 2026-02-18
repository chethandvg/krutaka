using FluentAssertions;
using Krutaka.Console;
using Krutaka.Core;

namespace Krutaka.Console.Tests;

/// <summary>
/// Tests for WindowsSecretsProvider.
/// Note: These tests validate the ISecretsProvider interface implementation,
/// but do not test actual Windows Credential Manager operations (requires Windows OS).
/// The SetSecret method will throw if the underlying SecretsProvider validation fails.
/// </summary>
public class WindowsSecretsProviderTests
{
    private readonly WindowsSecretsProvider _secretsProvider;

    public WindowsSecretsProviderTests()
    {
        _secretsProvider = new WindowsSecretsProvider();
    }

    [Fact]
    public void SetSecret_Should_ThrowArgumentException_WhenKeyIsUnsupported()
    {
        // Arrange
        var unsupportedKey = "UnsupportedKey";
        var value = "some-value";

        // Act
        var action = () => _secretsProvider.SetSecret(unsupportedKey, value);

        // Assert
        action.Should().Throw<ArgumentException>()
            .WithParameterName("key")
            .WithMessage("*Unsupported secret key*");
    }

    [Theory]
    [InlineData("Claude:ApiKey")]
    [InlineData("Krutaka_ApiKey")]
    public void SetSecret_Should_ThrowArgumentException_WhenClaudeApiKeyIsInvalid(string key)
    {
        // Arrange - Invalid API key (doesn't start with sk-ant-)
        var invalidApiKey = "invalid-key";

        // Act
        var action = () => _secretsProvider.SetSecret(key, invalidApiKey);

        // Assert
        action.Should().Throw<ArgumentException>()
            .WithMessage("*must start with 'sk-ant-'*");
    }

    [Fact]
    public void SetSecret_Should_ThrowArgumentException_WhenTelegramBotTokenIsInvalid()
    {
        // Arrange - Invalid bot token (doesn't match digits:alphanumeric pattern)
        var invalidBotToken = "invalid-token";

        // Act
        var action = () => _secretsProvider.SetSecret("KRUTAKA_TELEGRAM_BOT_TOKEN", invalidBotToken);

        // Assert
        action.Should().Throw<ArgumentException>()
            .WithMessage("*must match the format 'digits:alphanumeric'*");
    }

    [Theory]
    [InlineData("Claude:ApiKey")]
    [InlineData("Krutaka_ApiKey")]
    public void GetSecret_Should_ReturnNull_WhenClaudeApiKeyDoesNotExist(string key)
    {
        // Act - No credential is actually stored in this test environment
        var result = _secretsProvider.GetSecret(key);

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public void GetSecret_Should_ReturnNull_WhenTelegramBotTokenDoesNotExist()
    {
        // Act - No credential is actually stored in this test environment
        var result = _secretsProvider.GetSecret("KRUTAKA_TELEGRAM_BOT_TOKEN");

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public void GetSecret_Should_ReturnNull_WhenKeyIsUnsupported()
    {
        // Act
        var result = _secretsProvider.GetSecret("UnsupportedKey");

        // Assert
        result.Should().BeNull();
    }

    [Theory]
    [InlineData("Claude:ApiKey")]
    [InlineData("Krutaka_ApiKey")]
    public void HasSecret_Should_ReturnFalse_WhenClaudeApiKeyDoesNotExist(string key)
    {
        // Act - No credential is actually stored in this test environment
        var result = _secretsProvider.HasSecret(key);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void HasSecret_Should_ReturnFalse_WhenTelegramBotTokenDoesNotExist()
    {
        // Act - No credential is actually stored in this test environment
        var result = _secretsProvider.HasSecret("KRUTAKA_TELEGRAM_BOT_TOKEN");

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void HasSecret_Should_ReturnFalse_WhenKeyIsUnsupported()
    {
        // Act
        var result = _secretsProvider.HasSecret("UnsupportedKey");

        // Assert
        result.Should().BeFalse();
    }
}
