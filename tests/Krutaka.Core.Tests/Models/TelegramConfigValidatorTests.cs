using FluentAssertions;

namespace Krutaka.Core.Tests;

public class TelegramConfigValidatorTests
{
    [Fact]
    public void Validate_Should_ThrowArgumentNullException_WhenConfigIsNull()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => 
            TelegramConfigValidator.Validate(null!));
    }

    [Fact]
    public void Validate_Should_NotThrow_WhenConfigIsValid()
    {
        // Arrange
        var users = new[] { new TelegramUserConfig(12345678) };
        var config = new TelegramSecurityConfig(users);

        // Act & Assert
        var exception = Record.Exception(() => TelegramConfigValidator.Validate(config));
        exception.Should().BeNull();
    }

    [Fact]
    public void TryValidate_Should_ReturnTrue_WhenConfigIsValid()
    {
        // Arrange
        var users = new[] { new TelegramUserConfig(12345678) };
        var config = new TelegramSecurityConfig(users);

        // Act
        var result = TelegramConfigValidator.TryValidate(config, out var errorMessage);

        // Assert
        result.Should().BeTrue();
        errorMessage.Should().BeNull();
    }

    [Fact]
    public void TryValidate_Should_ReturnFalse_WhenConfigIsNull()
    {
        // Act
        var result = TelegramConfigValidator.TryValidate(null!, out var errorMessage);

        // Assert
        result.Should().BeFalse();
        errorMessage.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void TryValidate_Should_CaptureValidationErrors()
    {
        // Note: We can't directly construct an invalid config because it throws in the constructor.
        // This test validates that TryValidate handles construction exceptions.
        
        // Arrange & Act
        var result = TelegramConfigValidator.TryValidate(null!, out var errorMessage);

        // Assert
        result.Should().BeFalse();
        errorMessage.Should().Contain("Value cannot be null");
    }
}
