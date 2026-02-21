using FluentAssertions;

namespace Krutaka.Telegram.Tests;

public class TelegramCommandParserTests
{
    [Fact]
    public void Parse_Should_ReturnAsk_ForPlainText()
    {
        // Arrange
        var messageText = "how does authentication work?";

        // Act
        var (command, arguments) = TelegramCommandParser.Parse(messageText);

        // Assert
        command.Should().Be(TelegramCommand.Ask);
        arguments.Should().Be("how does authentication work?");
    }

    [Fact]
    public void Parse_Should_ReturnAsk_ForAskCommand()
    {
        // Arrange
        var messageText = "/ask how does authentication work?";

        // Act
        var (command, arguments) = TelegramCommandParser.Parse(messageText);

        // Assert
        command.Should().Be(TelegramCommand.Ask);
        arguments.Should().Be("how does authentication work?");
    }

    [Fact]
    public void Parse_Should_ReturnTask_ForTaskCommand()
    {
        // Arrange
        var messageText = "/task refactor the session manager";

        // Act
        var (command, arguments) = TelegramCommandParser.Parse(messageText);

        // Assert
        command.Should().Be(TelegramCommand.Task);
        arguments.Should().Be("refactor the session manager");
    }

    [Fact]
    public void Parse_Should_ReturnStatus_ForStatusCommand()
    {
        // Arrange
        var messageText = "/status";

        // Act
        var (command, arguments) = TelegramCommandParser.Parse(messageText);

        // Assert
        command.Should().Be(TelegramCommand.Status);
        arguments.Should().BeNull();
    }

    [Fact]
    public void Parse_Should_ReturnAbort_ForAbortCommand()
    {
        // Arrange
        var messageText = "/abort";

        // Act
        var (command, arguments) = TelegramCommandParser.Parse(messageText);

        // Assert
        command.Should().Be(TelegramCommand.Abort);
        arguments.Should().BeNull();
    }

    [Fact]
    public void Parse_Should_ReturnKillSwitch_ForKillSwitchCommand()
    {
        // Arrange
        var messageText = "/killswitch";

        // Act
        var (command, arguments) = TelegramCommandParser.Parse(messageText);

        // Assert
        command.Should().Be(TelegramCommand.KillSwitch);
        arguments.Should().BeNull();
    }

    [Fact]
    public void Parse_Should_ReturnSessions_ForSessionsCommand()
    {
        // Arrange
        var messageText = "/sessions";

        // Act
        var (command, arguments) = TelegramCommandParser.Parse(messageText);

        // Assert
        command.Should().Be(TelegramCommand.Sessions);
        arguments.Should().BeNull();
    }

    [Fact]
    public void Parse_Should_ReturnSwitchSession_ForSessionCommand()
    {
        // Arrange
        var messageText = "/session abc123";

        // Act
        var (command, arguments) = TelegramCommandParser.Parse(messageText);

        // Assert
        command.Should().Be(TelegramCommand.SwitchSession);
        arguments.Should().Be("abc123");
    }

    [Fact]
    public void Parse_Should_ReturnHelp_ForHelpCommand()
    {
        // Arrange
        var messageText = "/help";

        // Act
        var (command, arguments) = TelegramCommandParser.Parse(messageText);

        // Assert
        command.Should().Be(TelegramCommand.Help);
        arguments.Should().BeNull();
    }

    [Fact]
    public void Parse_Should_ReturnConfig_ForConfigCommand()
    {
        // Arrange
        var messageText = "/config";

        // Act
        var (command, arguments) = TelegramCommandParser.Parse(messageText);

        // Assert
        command.Should().Be(TelegramCommand.Config);
        arguments.Should().BeNull();
    }

    [Fact]
    public void Parse_Should_ReturnAudit_ForAuditCommand()
    {
        // Arrange
        var messageText = "/audit 20";

        // Act
        var (command, arguments) = TelegramCommandParser.Parse(messageText);

        // Assert
        command.Should().Be(TelegramCommand.Audit);
        arguments.Should().Be("20");
    }

    [Fact]
    public void Parse_Should_ReturnBudget_ForBudgetCommand()
    {
        // Arrange
        var messageText = "/budget";

        // Act
        var (command, arguments) = TelegramCommandParser.Parse(messageText);

        // Assert
        command.Should().Be(TelegramCommand.Budget);
        arguments.Should().BeNull();
    }

    [Fact]
    public void Parse_Should_ReturnNew_ForNewCommand()
    {
        // Arrange
        var messageText = "/new";

        // Act
        var (command, arguments) = TelegramCommandParser.Parse(messageText);

        // Assert
        command.Should().Be(TelegramCommand.New);
        arguments.Should().BeNull();
    }

    [Fact]
    public void Parse_Should_ReturnUnknown_ForUnrecognizedCommand()
    {
        // Arrange
        var messageText = "/unknowncommand";

        // Act
        var (command, arguments) = TelegramCommandParser.Parse(messageText);

        // Assert
        command.Should().Be(TelegramCommand.Unknown);
        arguments.Should().BeNull();
    }

    [Fact]
    public void Parse_Should_StripBotMention_FromCommand()
    {
        // Arrange
        var messageText = "/ask@krutaka_bot test message";

        // Act
        var (command, arguments) = TelegramCommandParser.Parse(messageText);

        // Assert
        command.Should().Be(TelegramCommand.Ask);
        arguments.Should().Be("test message");
    }

    [Fact]
    public void Parse_Should_BeCaseInsensitive()
    {
        // Arrange
        var messageText = "/ASK test message";

        // Act
        var (command, arguments) = TelegramCommandParser.Parse(messageText);

        // Assert
        command.Should().Be(TelegramCommand.Ask);
        arguments.Should().Be("test message");
    }

    [Fact]
    public void Parse_Should_ReturnUnknown_ForEmptyMessage()
    {
        // Arrange
        string? messageText = null;

        // Act
        var (command, arguments) = TelegramCommandParser.Parse(messageText);

        // Assert
        command.Should().Be(TelegramCommand.Unknown);
        arguments.Should().BeNull();
    }

    [Fact]
    public void Parse_Should_ReturnUnknown_ForWhitespaceMessage()
    {
        // Arrange
        var messageText = "   ";

        // Act
        var (command, arguments) = TelegramCommandParser.Parse(messageText);

        // Assert
        command.Should().Be(TelegramCommand.Unknown);
        arguments.Should().BeNull();
    }

    [Fact]
    public void Parse_Should_HandleMultilineArguments()
    {
        // Arrange
        var messageText = "/task refactor the session manager\nand add new tests";

        // Act
        var (command, arguments) = TelegramCommandParser.Parse(messageText);

        // Assert
        command.Should().Be(TelegramCommand.Task);
        arguments.Should().Be("refactor the session manager\nand add new tests");
    }

    [Fact]
    public void Parse_Should_ReturnAutonomy_ForAutonomyCommand()
    {
        // Arrange
        var messageText = "/autonomy";

        // Act
        var (command, arguments) = TelegramCommandParser.Parse(messageText);

        // Assert
        command.Should().Be(TelegramCommand.Autonomy);
        arguments.Should().BeNull();
    }

    [Fact]
    public void Parse_Should_ReturnAutonomy_ForAutonomyCommandWithBotMention()
    {
        // Arrange
        var messageText = "/autonomy@krutaka_bot";

        // Act
        var (command, arguments) = TelegramCommandParser.Parse(messageText);

        // Assert
        command.Should().Be(TelegramCommand.Autonomy);
        arguments.Should().BeNull();
    }
}
