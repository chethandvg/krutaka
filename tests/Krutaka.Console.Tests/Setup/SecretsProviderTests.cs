using FluentAssertions;
using Krutaka.Console;

namespace Krutaka.Console.Tests;

/// <summary>
/// Tests for SecretsProvider validation logic.
/// Note: Actual Windows Credential Manager operations are not tested here
/// as they require Windows OS and admin privileges.
/// </summary>
public class SecretsProviderTests
{
    [Theory]
    [InlineData("sk-ant-api03-1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")]
    [InlineData("sk-ant-1234")]
    [InlineData("sk-ant-")]
    public void IsValidApiKey_Should_ReturnTrue_WhenApiKeyStartsWithPrefix(string apiKey)
    {
        // Act
        var result = SecretsProvider.IsValidApiKey(apiKey);

        // Assert
        result.Should().BeTrue();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("invalid-key")]
    [InlineData("sk-api-1234")]
    [InlineData("api-key-1234")]
    public void IsValidApiKey_Should_ReturnFalse_WhenApiKeyIsInvalid(string? apiKey)
    {
        // Act
        var result = SecretsProvider.IsValidApiKey(apiKey);

        // Assert
        result.Should().BeFalse();
    }

    [Theory]
    [InlineData("123456789:ABCdefGHIjklMNOpqrsTUVwxyz1234567890")]
    [InlineData("1:a")]
    [InlineData("999999999:Token_With-Underscores")]
    [InlineData("12345:abcdefghijklmnopqrstuvwxyz0123456789")]
    public void IsValidBotToken_Should_ReturnTrue_WhenBotTokenMatchesPattern(string botToken)
    {
        // Act
        var result = SecretsProvider.IsValidBotToken(botToken);

        // Assert
        result.Should().BeTrue();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("no-colon-separator")]
    [InlineData("abc:123")] // First part not all digits
    [InlineData("123:")] // Second part empty
    [InlineData(":abc")] // First part empty
    [InlineData("123:abc@def")] // Invalid character in token (@)
    [InlineData("123:abc def")] // Space in token
    [InlineData("123:abc!def")] // Invalid character in token (!)
    [InlineData("123:αβγ")] // Unicode letters (not ASCII)
    [InlineData("①②③:abc")] // Unicode digits (not ASCII)
    [InlineData("123:café")] // Unicode character (é)
    public void IsValidBotToken_Should_ReturnFalse_WhenBotTokenIsInvalid(string? botToken)
    {
        // Act
        var result = SecretsProvider.IsValidBotToken(botToken);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void WriteCredential_Should_ThrowArgumentNullException_WhenApiKeyIsNull()
    {
        // Act
        var action = () => SecretsProvider.WriteCredential(null!);

        // Assert
        action.Should().Throw<ArgumentNullException>();
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void WriteCredential_Should_ThrowArgumentException_WhenApiKeyIsEmptyOrWhitespace(string apiKey)
    {
        // Act
        var action = () => SecretsProvider.WriteCredential(apiKey);

        // Assert
        action.Should().Throw<ArgumentException>();
    }

    [Theory]
    [InlineData("invalid-key")]
    [InlineData("sk-api-1234")]
    public void WriteCredential_Should_ThrowArgumentException_WhenApiKeyIsInvalidFormat(string apiKey)
    {
        // Act
        var action = () => SecretsProvider.WriteCredential(apiKey);

        // Assert
        action.Should().Throw<ArgumentException>()
            .WithMessage("*must start with 'sk-ant-'*");
    }

    [Fact]
    public void WriteBotToken_Should_ThrowArgumentNullException_WhenBotTokenIsNull()
    {
        // Act
        var action = () => SecretsProvider.WriteBotToken(null!);

        // Assert
        action.Should().Throw<ArgumentNullException>();
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void WriteBotToken_Should_ThrowArgumentException_WhenBotTokenIsEmptyOrWhitespace(string botToken)
    {
        // Act
        var action = () => SecretsProvider.WriteBotToken(botToken);

        // Assert
        action.Should().Throw<ArgumentException>();
    }

    [Theory]
    [InlineData("invalid-token")]
    [InlineData("abc:123")]
    [InlineData("123:abc@def")]
    public void WriteBotToken_Should_ThrowArgumentException_WhenBotTokenIsInvalidFormat(string botToken)
    {
        // Act
        var action = () => SecretsProvider.WriteBotToken(botToken);

        // Assert
        action.Should().Throw<ArgumentException>()
            .WithMessage("*must match the format 'digits:letters/digits/underscore/hyphen'*");
    }
}
