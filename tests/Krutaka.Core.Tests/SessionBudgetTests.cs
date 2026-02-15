using FluentAssertions;

namespace Krutaka.Core.Tests;

public class SessionBudgetTests
{
    [Fact]
    public void Constructor_Should_SetMaxValues()
    {
        // Act
        var budget = new SessionBudget(100_000, 50);

        // Assert
        budget.MaxTokens.Should().Be(100_000);
        budget.MaxToolCalls.Should().Be(50);
    }

    [Fact]
    public void InitialState_Should_HaveZeroUsage()
    {
        // Act
        var budget = new SessionBudget(100_000, 50);

        // Assert
        budget.TokensUsed.Should().Be(0);
        budget.ToolCallsUsed.Should().Be(0);
        budget.TurnsUsed.Should().Be(0);
    }

    [Fact]
    public void IsExhausted_Should_ReturnFalse_WhenUnderBothLimits()
    {
        // Arrange
        var budget = new SessionBudget(100_000, 50);
        budget.AddTokens(50_000);
        budget.IncrementToolCall();

        // Assert
        budget.IsExhausted.Should().BeFalse();
    }

    [Fact]
    public void IsExhausted_Should_ReturnTrue_WhenTokensReachLimit()
    {
        // Arrange
        var budget = new SessionBudget(100_000, 50);
        budget.AddTokens(100_000);

        // Assert
        budget.IsExhausted.Should().BeTrue();
    }

    [Fact]
    public void IsExhausted_Should_ReturnTrue_WhenTokensExceedLimit()
    {
        // Arrange
        var budget = new SessionBudget(100_000, 50);
        budget.AddTokens(150_000);

        // Assert
        budget.IsExhausted.Should().BeTrue();
    }

    [Fact]
    public void IsExhausted_Should_ReturnTrue_WhenToolCallsReachLimit()
    {
        // Arrange
        var budget = new SessionBudget(100_000, 50);
        for (int i = 0; i < 50; i++)
        {
            budget.IncrementToolCall();
        }

        // Assert
        budget.IsExhausted.Should().BeTrue();
    }

    [Fact]
    public void IsExhausted_Should_ReturnTrue_WhenToolCallsExceedLimit()
    {
        // Arrange
        var budget = new SessionBudget(100_000, 50);
        for (int i = 0; i < 60; i++)
        {
            budget.IncrementToolCall();
        }

        // Assert
        budget.IsExhausted.Should().BeTrue();
    }

    [Fact]
    public void IncrementTurn_Should_IncrementCorrectly()
    {
        // Arrange
        var budget = new SessionBudget(100_000, 50);

        // Act
        budget.IncrementTurn();
        budget.IncrementTurn();
        budget.IncrementTurn();

        // Assert
        budget.TurnsUsed.Should().Be(3);
    }

    [Fact]
    public void IncrementToolCall_Should_IncrementCorrectly()
    {
        // Arrange
        var budget = new SessionBudget(100_000, 50);

        // Act
        budget.IncrementToolCall();
        budget.IncrementToolCall();

        // Assert
        budget.ToolCallsUsed.Should().Be(2);
    }

    [Fact]
    public void AddTokens_Should_AddCorrectly()
    {
        // Arrange
        var budget = new SessionBudget(100_000, 50);

        // Act
        budget.AddTokens(1000);
        budget.AddTokens(2000);
        budget.AddTokens(500);

        // Assert
        budget.TokensUsed.Should().Be(3500);
    }

    [Fact]
    public async Task AddTokens_Should_BeThreadSafe()
    {
        // Arrange
        var budget = new SessionBudget(1_000_000, 1000);
        const int taskCount = 10;
        const int additionsPerTask = 1000;
        const int tokensPerAddition = 100;

        // Act - Run 10 tasks in parallel, each adding tokens 1000 times
        var tasks = Enumerable.Range(0, taskCount)
            .Select(_ => Task.Run(() =>
            {
                for (int i = 0; i < additionsPerTask; i++)
                {
                    budget.AddTokens(tokensPerAddition);
                }
            }))
            .ToArray();

        await Task.WhenAll(tasks);

        // Assert - Total should be taskCount * additionsPerTask * tokensPerAddition
        var expectedTotal = taskCount * additionsPerTask * tokensPerAddition;
        budget.TokensUsed.Should().Be(expectedTotal);
    }
}
