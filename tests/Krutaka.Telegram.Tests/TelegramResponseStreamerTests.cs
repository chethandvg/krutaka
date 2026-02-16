using FluentAssertions;
using Krutaka.Core;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Telegram.Bot;
using Telegram.Bot.Types;
using Telegram.Bot.Types.Enums;
using Telegram.Bot.Types.ReplyMarkups;

namespace Krutaka.Telegram.Tests;

public class TelegramResponseStreamerTests
{
    private readonly ITelegramBotClient _botClient;
    private readonly ILogger<TelegramResponseStreamer> _logger;
    private readonly TelegramResponseStreamer _streamer;

    public TelegramResponseStreamerTests()
    {
        _botClient = Substitute.For<ITelegramBotClient>();
        _logger = Substitute.For<ILogger<TelegramResponseStreamer>>();
        _streamer = new TelegramResponseStreamer(_botClient, _logger);

        // Setup default bot client responses - match any overload
        _botClient.SendMessage(default!, default!, default, default, default, default, default, default, default, default, default, default, default)
            .ReturnsForAnyArgs(Task.FromResult(new Message()));

        _botClient.EditMessageText(default!, default, default!, default, default, default, default, default, default)
            .ReturnsForAnyArgs(Task.FromResult(new Message()));
    }

    [Fact]
    public async Task StreamResponseAsync_Should_BufferRapidTextDeltas()
    {
        // Arrange
        var chatId = 12345L;
        var events = CreateTextDeltaEvents(10, "Token ");

        // Act
        await _streamer.StreamResponseAsync(chatId, events, null, CancellationToken.None);

        // Assert - Should have fewer message sends than TextDelta events due to buffering
        await _botClient.Received(1).SendMessage(
            (ChatId)chatId,
            Arg.Is<string>(text => text.Contains("Token", StringComparison.Ordinal) && text.Contains("Token Token", StringComparison.Ordinal)),
            parseMode: ParseMode.MarkdownV2,
            cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task StreamResponseAsync_Should_FlushBufferOnThreshold()
    {
        // Arrange
        var chatId = 12345L;
        var longText = new string('a', 250); // Exceeds 200 char threshold
        var events = CreateSingleEventStream(new TextDelta(longText));

        // Act
        await _streamer.StreamResponseAsync(chatId, events, null, CancellationToken.None);

        // Assert - Should send the message
        await _botClient.Received(1).SendMessage(
            (ChatId)chatId,
            Arg.Any<string>(),
            parseMode: ParseMode.MarkdownV2,
            cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task StreamResponseAsync_Should_SendToolCallStartedMessage()
    {
        // Arrange
        var chatId = 12345L;
        var events = CreateSingleEventStream(new ToolCallStarted("TestTool", "tool-123", "{}"));

        // Act
        await _streamer.StreamResponseAsync(chatId, events, null, CancellationToken.None);

        // Assert
        await _botClient.Received(1).SendMessage(
            (ChatId)chatId,
            Arg.Is<string>(text => text.Contains('⚙') && text.Contains("TestTool", StringComparison.Ordinal)),
            parseMode: ParseMode.MarkdownV2,
            cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task StreamResponseAsync_Should_EditMessageOnToolCallCompleted()
    {
        // Arrange
        var chatId = 12345L;
        var events = CreateEventStream(
            new ToolCallStarted("TestTool", "tool-123", "{}"),
            new ToolCallCompleted("TestTool", "tool-123", "Success"));

        // Act
        await _streamer.StreamResponseAsync(chatId, events, null, CancellationToken.None);

        // Assert
        await _botClient.Received(1).EditMessageText(
            (ChatId)chatId,
            123,
            Arg.Is<string>(text => text.Contains('✅') && text.Contains("TestTool") && text.Contains("complete")),
            parseMode: ParseMode.MarkdownV2,
            cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task StreamResponseAsync_Should_EditMessageOnToolCallFailed()
    {
        // Arrange
        var chatId = 12345L;
        var events = CreateEventStream(
            new ToolCallStarted("TestTool", "tool-123", "{}"),
            new ToolCallFailed("TestTool", "tool-123", "Error occurred"));

        // Act
        await _streamer.StreamResponseAsync(chatId, events, null, CancellationToken.None);

        // Assert
        await _botClient.Received(1).EditMessageText(
            (ChatId)chatId,
            123,
            Arg.Is<string>(text => text.Contains('❌') && text.Contains("TestTool") && text.Contains("failed")),
            parseMode: ParseMode.MarkdownV2,
            cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task StreamResponseAsync_Should_SendFinalResponse()
    {
        // Arrange
        var chatId = 12345L;
        var events = CreateSingleEventStream(new FinalResponse("Final answer here", "end_turn"));

        // Act
        await _streamer.StreamResponseAsync(chatId, events, null, CancellationToken.None);

        // Assert
        await _botClient.Received(1).SendMessage(
            (ChatId)chatId,
            Arg.Is<string>(text => text.Contains("Final answer here")),
            parseMode: ParseMode.MarkdownV2,
            cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task StreamResponseAsync_Should_ChunkLongMessages()
    {
        // Arrange
        var chatId = 12345L;
        var longContent = new string('a', 5000); // Exceeds 4096 limit
        var events = CreateSingleEventStream(new FinalResponse(longContent, "end_turn"));

        // Act
        await _streamer.StreamResponseAsync(chatId, events, null, CancellationToken.None);

        // Assert - Should send multiple messages
        await _botClient.Received(Arg.Is<int>(count => count >= 2)).SendMessage(
            (ChatId)chatId,
            Arg.Any<string>(),
            parseMode: ParseMode.MarkdownV2,
            cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task StreamResponseAsync_Should_NotSendMessageForEmptyFinalResponse()
    {
        // Arrange
        var chatId = 12345L;
        var events = CreateSingleEventStream(new FinalResponse("", "end_turn"));

        // Act
        await _streamer.StreamResponseAsync(chatId, events, null, CancellationToken.None);

        // Assert - Should not send any message
        await _botClient.DidNotReceive().SendMessage(
            (ChatId)12345L,
            Arg.Any<string>(),
            cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task StreamResponseAsync_Should_InvokeCallbackForHumanApprovalRequired()
    {
        // Arrange
        var chatId = 12345L;
        var approvalEvent = new HumanApprovalRequired("TestTool", "tool-123", "{}");
        var events = CreateSingleEventStream(approvalEvent);
        AgentEvent? capturedEvent = null;
        Func<AgentEvent, Task> callback = evt =>
        {
            capturedEvent = evt;
            return Task.CompletedTask;
        };

        // Act
        await _streamer.StreamResponseAsync(chatId, events, callback, CancellationToken.None);

        // Assert
        capturedEvent.Should().NotBeNull();
        capturedEvent.Should().BeOfType<HumanApprovalRequired>();
        (capturedEvent as HumanApprovalRequired)?.ToolName.Should().Be("TestTool");
    }

    [Fact]
    public async Task StreamResponseAsync_Should_InvokeCallbackForDirectoryAccessRequested()
    {
        // Arrange
        var chatId = 12345L;
        var dirAccessEvent = new DirectoryAccessRequested("/path/to/dir", AccessLevel.ReadOnly, "Need to read files");
        var events = CreateSingleEventStream(dirAccessEvent);
        AgentEvent? capturedEvent = null;
        Func<AgentEvent, Task> callback = evt =>
        {
            capturedEvent = evt;
            return Task.CompletedTask;
        };

        // Act
        await _streamer.StreamResponseAsync(chatId, events, callback, CancellationToken.None);

        // Assert
        capturedEvent.Should().NotBeNull();
        capturedEvent.Should().BeOfType<DirectoryAccessRequested>();
    }

    [Fact]
    public async Task StreamResponseAsync_Should_InvokeCallbackForCommandApprovalRequested()
    {
        // Arrange
        var chatId = 12345L;
        var request = new CommandExecutionRequest("git", ["status"], "/path/to/work", "Need to check status");
        var decision = CommandDecision.Approve(CommandRiskTier.Safe, "Safe command");
        var cmdApprovalEvent = new CommandApprovalRequested(request, decision);
        var events = CreateSingleEventStream(cmdApprovalEvent);
        AgentEvent? capturedEvent = null;
        Func<AgentEvent, Task> callback = evt =>
        {
            capturedEvent = evt;
            return Task.CompletedTask;
        };

        // Act
        await _streamer.StreamResponseAsync(chatId, events, callback, CancellationToken.None);

        // Assert
        capturedEvent.Should().NotBeNull();
        capturedEvent.Should().BeOfType<CommandApprovalRequested>();
    }

    [Fact]
    public async Task StreamResponseAsync_Should_SilentlyConsumeRequestIdCaptured()
    {
        // Arrange
        var chatId = 12345L;
        var events = CreateSingleEventStream(new RequestIdCaptured("req-123"));

        // Act
        await _streamer.StreamResponseAsync(chatId, events, null, CancellationToken.None);

        // Assert - Should not send any message
        await _botClient.DidNotReceive().SendMessage(
            (ChatId)12345L,
            Arg.Any<string>(),
            cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task StreamResponseAsync_Should_ContinueStreamingAfterEditFailure()
    {
        // Arrange
        var chatId = 12345L;
        _botClient.EditMessageText(
                Arg.Any<ChatId>(),
                Arg.Any<int>(),
                Arg.Any<string>(),
                parseMode: Arg.Any<ParseMode>(),
                cancellationToken: Arg.Any<CancellationToken>())
            .Returns<Task<Message>>(_ => throw new InvalidOperationException("Edit failed"));

        var events = CreateEventStream(
            new ToolCallStarted("TestTool", "tool-123", "{}"),
            new ToolCallCompleted("TestTool", "tool-123", "Success"),
            new FinalResponse("Final", "end_turn"));

        // Act
        var act = async () => await _streamer.StreamResponseAsync(chatId, events, null, CancellationToken.None);

        // Assert - Should not throw, should continue streaming
        await act.Should().NotThrowAsync();
        await _botClient.Received(1).SendMessage(
            (ChatId)chatId,
            Arg.Is<string>(text => text.Contains("Final")),
            parseMode: ParseMode.MarkdownV2,
            cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task StreamResponseAsync_Should_EscapeMarkdownSpecialCharacters()
    {
        // Arrange
        var chatId = 12345L;
        var textWithSpecialChars = "Hello_world *bold* [link]";
        var events = CreateSingleEventStream(new TextDelta(textWithSpecialChars));

        // Act
        await _streamer.StreamResponseAsync(chatId, events, null, CancellationToken.None);

        // Assert - Special characters should be escaped
        await _botClient.Received(1).SendMessage(
            (ChatId)chatId,
            Arg.Is<string>(text => text.Contains("\\_") && text.Contains("\\*") && text.Contains("\\[")),
            parseMode: ParseMode.MarkdownV2,
            cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task StreamResponseAsync_Should_NotEscapeCharactersInCodeBlocks()
    {
        // Arrange
        var chatId = 12345L;
        var textWithCodeBlock = "Text ```code_with_*special*``` end";
        var events = CreateSingleEventStream(new FinalResponse(textWithCodeBlock, "end_turn"));

        // Act
        await _streamer.StreamResponseAsync(chatId, events, null, CancellationToken.None);

        // Assert - Code block contents should not be escaped
        await _botClient.Received(1).SendMessage(
            (ChatId)chatId,
            Arg.Is<string>(text => text.Contains("```code_with_*special*```")),
            parseMode: ParseMode.MarkdownV2,
            cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task StreamResponseAsync_Should_HandleMixedTextDeltaAndToolCalls()
    {
        // Arrange
        var chatId = 12345L;
        var events = CreateEventStream(
            new TextDelta("Thinking..."),
            new ToolCallStarted("TestTool", "tool-123", "{}"),
            new ToolCallCompleted("TestTool", "tool-123", "Success"),
            new TextDelta("Done"),
            new FinalResponse("Complete", "end_turn"));

        // Act
        await _streamer.StreamResponseAsync(chatId, events, null, CancellationToken.None);

        // Assert - Should handle all events
        await _botClient.Received().SendMessage(
            (ChatId)chatId,
            Arg.Is<string>(text => text.Contains("Thinking")),
            parseMode: ParseMode.MarkdownV2,
            cancellationToken: Arg.Any<CancellationToken>());

        await _botClient.Received().SendMessage(
            (ChatId)chatId,
            Arg.Is<string>(text => text.Contains("TestTool")),
            parseMode: ParseMode.MarkdownV2,
            cancellationToken: Arg.Any<CancellationToken>());
    }

    // Helper methods

    private static async IAsyncEnumerable<AgentEvent> CreateSingleEventStream(AgentEvent evt)
    {
        await Task.CompletedTask;
        yield return evt;
    }

    private static async IAsyncEnumerable<AgentEvent> CreateEventStream(params AgentEvent[] events)
    {
        await Task.CompletedTask;
        foreach (var evt in events)
        {
            yield return evt;
        }
    }

    private static async IAsyncEnumerable<AgentEvent> CreateTextDeltaEvents(int count, string text)
    {
        await Task.CompletedTask;
        for (int i = 0; i < count; i++)
        {
            yield return new TextDelta(text);
        }
    }
}
