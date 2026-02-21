using FluentAssertions;
using Krutaka.Core;

namespace Krutaka.Telegram.Tests;

/// <summary>
/// Unit tests for TelegramBotService.FormatBudgetMessage() static helper.
/// </summary>
public class TelegramBudgetFormatterTests
{
    [Fact]
    public void FormatBudgetMessage_WithNullTracker_ReturnsGracefulMessage()
    {
        // Act
        var message = TelegramBotService.FormatBudgetMessage(null);

        // Assert
        message.Should().Contain("Budget tracking not enabled");
        message.Should().Contain("📊");
    }

    [Fact]
    public void FormatBudgetMessage_WithFreshTracker_ContainsCheckEmoji()
    {
        // Arrange — all dimensions at 0% (fresh session)
        var tracker = new TaskBudgetTracker(new TaskBudget(
            MaxClaudeTokens: 200_000,
            MaxToolCalls: 100,
            MaxFilesModified: 20,
            MaxProcessesSpawned: 10));

        // Act
        var message = TelegramBotService.FormatBudgetMessage(tracker);

        // Assert — all at 0% should show ✅ for all dimensions
        message.Should().Contain("✅");
        message.Should().NotContain("⚠️");
        message.Should().NotContain("🛑");
    }

    [Fact]
    public void FormatBudgetMessage_WithWarningLevelTokens_ContainsWarningEmoji()
    {
        // Arrange — tokens at 85%, others at 0%
        var tracker = new TaskBudgetTracker(new TaskBudget(
            MaxClaudeTokens: 100,
            MaxToolCalls: 100,
            MaxFilesModified: 20,
            MaxProcessesSpawned: 10));
        tracker.TryConsume(BudgetDimension.Tokens, 85);

        // Act
        var message = TelegramBotService.FormatBudgetMessage(tracker);

        // Assert — 85% tokens should show ⚠️
        message.Should().Contain("⚠️");
    }

    [Fact]
    public void FormatBudgetMessage_WithExhaustedToolCalls_ContainsStopEmoji()
    {
        // Arrange — tool calls at 100%
        var tracker = new TaskBudgetTracker(new TaskBudget(
            MaxClaudeTokens: 200_000,
            MaxToolCalls: 10,
            MaxFilesModified: 20,
            MaxProcessesSpawned: 10));
        tracker.TryConsume(BudgetDimension.ToolCalls, 10);

        // Act
        var message = TelegramBotService.FormatBudgetMessage(tracker);

        // Assert — 100% tool calls should show 🛑
        message.Should().Contain("🛑");
    }

    [Fact]
    public void FormatBudgetMessage_ContainsBudgetCannotBeExtendedNote()
    {
        // Arrange
        var tracker = new TaskBudgetTracker(new TaskBudget());

        // Act
        var message = TelegramBotService.FormatBudgetMessage(tracker);

        // Assert — S10 note must be present
        message.Should().Contain("Budget cannot be extended by the agent");
    }

    [Fact]
    public void FormatBudgetMessage_ContainsCorrectNumberFormat()
    {
        // Arrange — verify 45230 formats as "45,230"
        var tracker = new TaskBudgetTracker(new TaskBudget(MaxClaudeTokens: 200_000));
        tracker.TryConsume(BudgetDimension.Tokens, 45_230);

        // Act
        var message = TelegramBotService.FormatBudgetMessage(tracker);

        // Assert — number formatted with thousands separator
        message.Should().Contain("45,230");
    }

    [Fact]
    public void FormatBudgetMessage_HasNoUnclosedBackticks()
    {
        // Arrange
        var tracker = new TaskBudgetTracker(new TaskBudget(
            MaxClaudeTokens: 200_000,
            MaxToolCalls: 100,
            MaxFilesModified: 20,
            MaxProcessesSpawned: 10));
        tracker.TryConsume(BudgetDimension.Tokens, 50_000);

        // Act
        var message = TelegramBotService.FormatBudgetMessage(tracker);

        // Assert — backtick pairs must be even (valid MarkdownV2)
        var backtickCount = message.Count(c => c == '`');
        (backtickCount % 2).Should().Be(0, "backticks must be paired in MarkdownV2");
    }

    [Fact]
    public void FormatBudgetMessage_ContainsAllFourDimensions()
    {
        // Arrange
        var tracker = new TaskBudgetTracker(new TaskBudget());

        // Act
        var message = TelegramBotService.FormatBudgetMessage(tracker);

        // Assert — all four dimension labels must appear
        message.Should().Contain("Tokens");
        message.Should().Contain("Tool Calls");
        message.Should().Contain("Files");
        message.Should().Contain("Processes");
    }
}
