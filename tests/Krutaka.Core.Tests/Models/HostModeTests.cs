using FluentAssertions;
using Krutaka.Core;
using Xunit;

namespace Krutaka.Core.Tests;

/// <summary>
/// Unit tests for HostMode enum.
/// </summary>
public class HostModeTests
{
    [Fact]
    public void HostMode_ShouldHaveConsoleValue()
    {
        // Arrange & Act
        var consoleMode = HostMode.Console;

        // Assert
        consoleMode.Should().Be(HostMode.Console);
        ((int)consoleMode).Should().Be(0);
    }

    [Fact]
    public void HostMode_ShouldHaveTelegramValue()
    {
        // Arrange & Act
        var telegramMode = HostMode.Telegram;

        // Assert
        telegramMode.Should().Be(HostMode.Telegram);
        ((int)telegramMode).Should().Be(1);
    }

    [Fact]
    public void HostMode_ShouldHaveBothValue()
    {
        // Arrange & Act
        var bothMode = HostMode.Both;

        // Assert
        bothMode.Should().Be(HostMode.Both);
        ((int)bothMode).Should().Be(2);
    }

    [Fact]
    public void HostMode_ShouldHaveExactlyThreeValues()
    {
        // Arrange & Act
        var values = Enum.GetValues<HostMode>();

        // Assert
        values.Should().HaveCount(3);
        values.Should().Contain([HostMode.Console, HostMode.Telegram, HostMode.Both]);
    }

    [Fact]
    public void HostMode_ShouldParseFromString_Console()
    {
        // Arrange & Act
        var parsed = Enum.Parse<HostMode>("Console", ignoreCase: true);

        // Assert
        parsed.Should().Be(HostMode.Console);
    }

    [Fact]
    public void HostMode_ShouldParseFromString_Telegram()
    {
        // Arrange & Act
        var parsed = Enum.Parse<HostMode>("Telegram", ignoreCase: true);

        // Assert
        parsed.Should().Be(HostMode.Telegram);
    }

    [Fact]
    public void HostMode_ShouldParseFromString_Both()
    {
        // Arrange & Act
        var parsed = Enum.Parse<HostMode>("Both", ignoreCase: true);

        // Assert
        parsed.Should().Be(HostMode.Both);
    }

    [Fact]
    public void HostMode_ShouldThrowOnInvalidString()
    {
        // Arrange, Act & Assert
        var act = () => Enum.Parse<HostMode>("InvalidMode", ignoreCase: true);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void HostMode_ShouldSupportToString()
    {
        // Arrange & Act
        var consoleStr = HostMode.Console.ToString();
        var telegramStr = HostMode.Telegram.ToString();
        var bothStr = HostMode.Both.ToString();

        // Assert
        consoleStr.Should().Be("Console");
        telegramStr.Should().Be("Telegram");
        bothStr.Should().Be("Both");
    }
}
