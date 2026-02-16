using FluentAssertions;
using Krutaka.Core;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Telegram.Bot;

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
        
        // Setup mock to return a valid Message object for any SendRequest call
        // Using ReturnsForAnyArgs to handle generic method mocking
        _botClient.SendRequest<global::Telegram.Bot.Types.Message>(default!, default)
            .ReturnsForAnyArgs(Task.FromResult(new global::Telegram.Bot.Types.Message()));
        
        _streamer = new TelegramResponseStreamer(_botClient, _logger);
    }

    [Fact]
    public async Task StreamResponseAsync_Should_ProcessTextDeltaEvents()
    {
        // Arrange
        var chatId = 12345L;
        var events = CreateEventStream(
            new TextDelta("Hello"),
            new TextDelta(" World"));

        // Act
        var act = async () => await _streamer.StreamResponseAsync(chatId, events, null, CancellationToken.None);

        // Assert - Should not throw
        await act.Should().NotThrowAsync();
        
        // Verify SendRequest was called (this is the underlying method that extension methods use)
        await _botClient.Received().SendRequest<global::Telegram.Bot.Types.Message>(
            Arg.Any<global::Telegram.Bot.Requests.SendMessageRequest>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task StreamResponseAsync_Should_ProcessToolCallStartedEvent()
    {
        // Arrange
        var chatId = 12345L;
        var events = CreateSingleEventStream(new ToolCallStarted("TestTool", "tool-123", "{}"));

        // Act
        var act = async () => await _streamer.StreamResponseAsync(chatId, events, null, CancellationToken.None);

        // Assert - Should not throw
        await act.Should().NotThrowAsync();
        
        // Verify a message was sent
        await _botClient.Received().SendRequest<global::Telegram.Bot.Types.Message>(
            Arg.Any<global::Telegram.Bot.Requests.SendMessageRequest>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task StreamResponseAsync_Should_ProcessToolCallCompletedEvent()
    {
        // Arrange
        var chatId = 12345L;
        var events = CreateEventStream(
            new ToolCallStarted("TestTool", "tool-123", "{}"),
            new ToolCallCompleted("TestTool", "tool-123", "Success"));

        // Act
        var act = async () => await _streamer.StreamResponseAsync(chatId, events, null, CancellationToken.None);

        // Assert - Should not throw
        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task StreamResponseAsync_Should_ProcessToolCallFailedEvent()
    {
        // Arrange
        var chatId = 12345L;
        var events = CreateEventStream(
            new ToolCallStarted("TestTool", "tool-123", "{}"),
            new ToolCallFailed("TestTool", "tool-123", "Error occurred"));

        // Act
        var act = async () => await _streamer.StreamResponseAsync(chatId, events, null, CancellationToken.None);

        // Assert - Should not throw
        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task StreamResponseAsync_Should_ProcessFinalResponseEvent()
    {
        // Arrange
        var chatId = 12345L;
        var events = CreateSingleEventStream(new FinalResponse("Final answer here", "end_turn"));

        // Act
        var act = async () => await _streamer.StreamResponseAsync(chatId, events, null, CancellationToken.None);

        // Assert - Should not throw
        await act.Should().NotThrowAsync();
        
        // Verify a message was sent
        await _botClient.Received().SendRequest<global::Telegram.Bot.Types.Message>(
            Arg.Any<global::Telegram.Bot.Requests.SendMessageRequest>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task StreamResponseAsync_Should_NotThrowForEmptyFinalResponse()
    {
        // Arrange
        var chatId = 12345L;
        var events = CreateSingleEventStream(new FinalResponse("", "end_turn"));

        // Act
        var act = async () => await _streamer.StreamResponseAsync(chatId, events, null, CancellationToken.None);

        // Assert - Should not throw
        await act.Should().NotThrowAsync();
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
        (capturedEvent as DirectoryAccessRequested)?.Path.Should().Be("/path/to/dir");
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
        var act = async () => await _streamer.StreamResponseAsync(chatId, events, null, CancellationToken.None);

        // Assert - Should not throw and should not send any messages
        await act.Should().NotThrowAsync();
        
        // Verify no messages were sent
        await _botClient.DidNotReceive().SendRequest<global::Telegram.Bot.Types.Message>(
            Arg.Any<global::Telegram.Bot.Requests.SendMessageRequest>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task StreamResponseAsync_Should_HandleMixedEvents()
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
        var act = async () => await _streamer.StreamResponseAsync(chatId, events, null, CancellationToken.None);

        // Assert - Should not throw
        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task StreamResponseAsync_Should_ThrowWhenCancellationTokenIsAlreadyCancelled()
    {
        // Arrange
        var chatId = 12345L;
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        var events = CreateSingleEventStream(new TextDelta("Test"));

        // Act & Assert - Should throw immediately when cancellation token is already cancelled
        await Assert.ThrowsAsync<OperationCanceledException>(
            () => _streamer.StreamResponseAsync(chatId, events, null, cts.Token));
    }

    [Fact]
    public async Task Constructor_Should_ThrowWhenBotClientIsNull()
    {
        // Act
        var act = () => new TelegramResponseStreamer(null!, _logger);

        // Assert
        act.Should().Throw<ArgumentNullException>().WithParameterName("botClient");
    }

    [Fact]
    public async Task Constructor_Should_ThrowWhenLoggerIsNull()
    {
        // Act
        var act = () => new TelegramResponseStreamer(_botClient, null!);

        // Assert
        act.Should().Throw<ArgumentNullException>().WithParameterName("logger");
    }

    [Fact]
    public async Task StreamResponseAsync_Should_ThrowWhenEventsIsNull()
    {
        // Arrange
        var chatId = 12345L;

        // Act
        var act = async () => await _streamer.StreamResponseAsync(chatId, null!, null, CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<ArgumentNullException>().WithParameterName("events");
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
}
