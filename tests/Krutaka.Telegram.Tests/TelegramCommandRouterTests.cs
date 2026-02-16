using FluentAssertions;
using Krutaka.Core;
using Telegram.Bot.Types;

namespace Krutaka.Telegram.Tests;

public class TelegramCommandRouterTests
{
    private readonly TelegramCommandRouter _router;

    public TelegramCommandRouterTests()
    {
        _router = new TelegramCommandRouter();
    }

    [Fact]
    public async Task RouteAsync_Should_RouteAskCommand_WithSanitizedInput()
    {
        // Arrange
        var update = CreateUpdate(messageText: "/ask how does auth work?");
        var authResult = AuthResult.Valid(userId: 12345678, chatId: 111, role: TelegramUserRole.User);

        // Act
        var result = await _router.RouteAsync(update, authResult, CancellationToken.None);

        // Assert
        result.Command.Should().Be(TelegramCommand.Ask);
        result.Arguments.Should().Be("how does auth work?");
        result.SanitizedInput.Should().Be("<untrusted_content source=\"telegram:user:12345678\">how does auth work?</untrusted_content>");
        result.IsAdminOnly.Should().BeFalse();
        result.Routed.Should().BeTrue();
    }

    [Fact]
    public async Task RouteAsync_Should_RoutePlainText_AsAskCommand()
    {
        // Arrange
        var update = CreateUpdate(messageText: "how does auth work?");
        var authResult = AuthResult.Valid(userId: 12345678, chatId: 111, role: TelegramUserRole.User);

        // Act
        var result = await _router.RouteAsync(update, authResult, CancellationToken.None);

        // Assert
        result.Command.Should().Be(TelegramCommand.Ask);
        result.Arguments.Should().Be("how does auth work?");
        result.SanitizedInput.Should().Be("<untrusted_content source=\"telegram:user:12345678\">how does auth work?</untrusted_content>");
        result.IsAdminOnly.Should().BeFalse();
        result.Routed.Should().BeTrue();
    }

    [Fact]
    public async Task RouteAsync_Should_RouteTaskCommand_WithSanitizedInput()
    {
        // Arrange
        var update = CreateUpdate(messageText: "/task refactor the session manager");
        var authResult = AuthResult.Valid(userId: 12345678, chatId: 111, role: TelegramUserRole.User);

        // Act
        var result = await _router.RouteAsync(update, authResult, CancellationToken.None);

        // Assert
        result.Command.Should().Be(TelegramCommand.Task);
        result.Arguments.Should().Be("refactor the session manager");
        result.SanitizedInput.Should().Be("<untrusted_content source=\"telegram:user:12345678\">refactor the session manager</untrusted_content>");
        result.IsAdminOnly.Should().BeFalse();
        result.Routed.Should().BeTrue();
    }

    [Fact]
    public async Task RouteAsync_Should_RouteStatusCommand_WithoutSanitization()
    {
        // Arrange
        var update = CreateUpdate(messageText: "/status");
        var authResult = AuthResult.Valid(userId: 12345678, chatId: 111, role: TelegramUserRole.User);

        // Act
        var result = await _router.RouteAsync(update, authResult, CancellationToken.None);

        // Assert
        result.Command.Should().Be(TelegramCommand.Status);
        result.Arguments.Should().BeNull();
        result.SanitizedInput.Should().BeNull();
        result.IsAdminOnly.Should().BeFalse();
        result.Routed.Should().BeTrue();
    }

    [Fact]
    public async Task RouteAsync_Should_RouteAbortCommand()
    {
        // Arrange
        var update = CreateUpdate(messageText: "/abort");
        var authResult = AuthResult.Valid(userId: 12345678, chatId: 111, role: TelegramUserRole.User);

        // Act
        var result = await _router.RouteAsync(update, authResult, CancellationToken.None);

        // Assert
        result.Command.Should().Be(TelegramCommand.Abort);
        result.IsAdminOnly.Should().BeFalse();
        result.Routed.Should().BeTrue();
    }

    [Fact]
    public async Task RouteAsync_Should_RouteKillSwitchCommand_AsAdminOnly()
    {
        // Arrange
        var update = CreateUpdate(messageText: "/killswitch");
        var authResult = AuthResult.Valid(userId: 12345678, chatId: 111, role: TelegramUserRole.Admin);

        // Act
        var result = await _router.RouteAsync(update, authResult, CancellationToken.None);

        // Assert
        result.Command.Should().Be(TelegramCommand.KillSwitch);
        result.IsAdminOnly.Should().BeTrue();
        result.Routed.Should().BeTrue();
    }

    [Fact]
    public async Task RouteAsync_Should_DenyKillSwitch_ForNonAdminUser()
    {
        // Arrange
        var update = CreateUpdate(messageText: "/killswitch");
        var authResult = AuthResult.Valid(userId: 12345678, chatId: 111, role: TelegramUserRole.User);

        // Act
        var result = await _router.RouteAsync(update, authResult, CancellationToken.None);

        // Assert
        result.Command.Should().Be(TelegramCommand.KillSwitch);
        result.IsAdminOnly.Should().BeTrue();
        result.Routed.Should().BeFalse();
    }

    [Fact]
    public async Task RouteAsync_Should_RouteSessionsCommand()
    {
        // Arrange
        var update = CreateUpdate(messageText: "/sessions");
        var authResult = AuthResult.Valid(userId: 12345678, chatId: 111, role: TelegramUserRole.User);

        // Act
        var result = await _router.RouteAsync(update, authResult, CancellationToken.None);

        // Assert
        result.Command.Should().Be(TelegramCommand.Sessions);
        result.IsAdminOnly.Should().BeFalse();
        result.Routed.Should().BeTrue();
    }

    [Fact]
    public async Task RouteAsync_Should_RouteSwitchSessionCommand_WithSanitizedArgument()
    {
        // Arrange
        var update = CreateUpdate(messageText: "/session abc123");
        var authResult = AuthResult.Valid(userId: 12345678, chatId: 111, role: TelegramUserRole.User);

        // Act
        var result = await _router.RouteAsync(update, authResult, CancellationToken.None);

        // Assert
        result.Command.Should().Be(TelegramCommand.SwitchSession);
        result.Arguments.Should().Be("abc123");
        result.SanitizedInput.Should().Be("<untrusted_content source=\"telegram:user:12345678\">abc123</untrusted_content>");
        result.IsAdminOnly.Should().BeFalse();
        result.Routed.Should().BeTrue();
    }

    [Fact]
    public async Task RouteAsync_Should_RouteHelpCommand()
    {
        // Arrange
        var update = CreateUpdate(messageText: "/help");
        var authResult = AuthResult.Valid(userId: 12345678, chatId: 111, role: TelegramUserRole.User);

        // Act
        var result = await _router.RouteAsync(update, authResult, CancellationToken.None);

        // Assert
        result.Command.Should().Be(TelegramCommand.Help);
        result.IsAdminOnly.Should().BeFalse();
        result.Routed.Should().BeTrue();
    }

    [Fact]
    public async Task RouteAsync_Should_RouteConfigCommand_ForAdminUser()
    {
        // Arrange
        var update = CreateUpdate(messageText: "/config");
        var authResult = AuthResult.Valid(userId: 12345678, chatId: 111, role: TelegramUserRole.Admin);

        // Act
        var result = await _router.RouteAsync(update, authResult, CancellationToken.None);

        // Assert
        result.Command.Should().Be(TelegramCommand.Config);
        result.IsAdminOnly.Should().BeTrue();
        result.Routed.Should().BeTrue();
    }

    [Fact]
    public async Task RouteAsync_Should_DenyConfigCommand_ForNonAdminUser()
    {
        // Arrange
        var update = CreateUpdate(messageText: "/config");
        var authResult = AuthResult.Valid(userId: 12345678, chatId: 111, role: TelegramUserRole.User);

        // Act
        var result = await _router.RouteAsync(update, authResult, CancellationToken.None);

        // Assert
        result.Command.Should().Be(TelegramCommand.Config);
        result.IsAdminOnly.Should().BeTrue();
        result.Routed.Should().BeFalse();
    }

    [Fact]
    public async Task RouteAsync_Should_RouteAuditCommand_WithSanitizedArgument_ForAdminUser()
    {
        // Arrange
        var update = CreateUpdate(messageText: "/audit 20");
        var authResult = AuthResult.Valid(userId: 12345678, chatId: 111, role: TelegramUserRole.Admin);

        // Act
        var result = await _router.RouteAsync(update, authResult, CancellationToken.None);

        // Assert
        result.Command.Should().Be(TelegramCommand.Audit);
        result.Arguments.Should().Be("20");
        result.SanitizedInput.Should().Be("<untrusted_content source=\"telegram:user:12345678\">20</untrusted_content>");
        result.IsAdminOnly.Should().BeTrue();
        result.Routed.Should().BeTrue();
    }

    [Fact]
    public async Task RouteAsync_Should_DenyAuditCommand_ForNonAdminUser()
    {
        // Arrange
        var update = CreateUpdate(messageText: "/audit 10");
        var authResult = AuthResult.Valid(userId: 12345678, chatId: 111, role: TelegramUserRole.User);

        // Act
        var result = await _router.RouteAsync(update, authResult, CancellationToken.None);

        // Assert
        result.Command.Should().Be(TelegramCommand.Audit);
        result.IsAdminOnly.Should().BeTrue();
        result.Routed.Should().BeFalse();
    }

    [Fact]
    public async Task RouteAsync_Should_RouteBudgetCommand()
    {
        // Arrange
        var update = CreateUpdate(messageText: "/budget");
        var authResult = AuthResult.Valid(userId: 12345678, chatId: 111, role: TelegramUserRole.User);

        // Act
        var result = await _router.RouteAsync(update, authResult, CancellationToken.None);

        // Assert
        result.Command.Should().Be(TelegramCommand.Budget);
        result.IsAdminOnly.Should().BeFalse();
        result.Routed.Should().BeTrue();
    }

    [Fact]
    public async Task RouteAsync_Should_RouteNewCommand()
    {
        // Arrange
        var update = CreateUpdate(messageText: "/new");
        var authResult = AuthResult.Valid(userId: 12345678, chatId: 111, role: TelegramUserRole.User);

        // Act
        var result = await _router.RouteAsync(update, authResult, CancellationToken.None);

        // Assert
        result.Command.Should().Be(TelegramCommand.New);
        result.IsAdminOnly.Should().BeFalse();
        result.Routed.Should().BeTrue();
    }

    [Fact]
    public async Task RouteAsync_Should_ReturnUnrouted_ForUnknownCommand()
    {
        // Arrange
        var update = CreateUpdate(messageText: "/unknowncommand");
        var authResult = AuthResult.Valid(userId: 12345678, chatId: 111, role: TelegramUserRole.User);

        // Act
        var result = await _router.RouteAsync(update, authResult, CancellationToken.None);

        // Assert
        result.Command.Should().Be(TelegramCommand.Unknown);
        result.Routed.Should().BeFalse();
    }

    [Fact]
    public async Task RouteAsync_Should_ThrowArgumentNullException_WhenUpdateIsNull()
    {
        // Arrange
        Update? update = null;
        var authResult = AuthResult.Valid(userId: 12345678, chatId: 111, role: TelegramUserRole.User);

        // Act
        var act = async () => await _router.RouteAsync(update!, authResult, CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task RouteAsync_Should_ThrowArgumentNullException_WhenAuthResultIsNull()
    {
        // Arrange
        var update = CreateUpdate(messageText: "/status");
        AuthResult? authResult = null;

        // Act
        var act = async () => await _router.RouteAsync(update, authResult!, CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    private static Update CreateUpdate(string? messageText)
    {
        return new Update
        {
            Message = messageText != null ? new Message
            {
                Text = messageText,
                From = new User { Id = 12345678 },
                Chat = new Chat { Id = 111 }
            } : null
        };
    }
}
