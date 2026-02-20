using FluentAssertions;

namespace Krutaka.Core.Tests;

public class TaskBudgetTests
{
    [Fact]
    public void TaskBudget_Should_HaveCorrectDefaults()
    {
        // Act
        var budget = new TaskBudget();

        // Assert
        budget.MaxClaudeTokens.Should().Be(200_000);
        budget.MaxToolCalls.Should().Be(100);
        budget.MaxFilesModified.Should().Be(20);
        budget.MaxProcessesSpawned.Should().Be(10);
    }

    [Fact]
    public void TaskBudget_Should_AcceptCustomValues()
    {
        // Act
        var budget = new TaskBudget(MaxClaudeTokens: 500_000, MaxToolCalls: 200, MaxFilesModified: 50, MaxProcessesSpawned: 25);

        // Assert
        budget.MaxClaudeTokens.Should().Be(500_000);
        budget.MaxToolCalls.Should().Be(200);
        budget.MaxFilesModified.Should().Be(50);
        budget.MaxProcessesSpawned.Should().Be(25);
    }

    [Fact]
    public void TaskBudget_Should_SupportValueEquality()
    {
        // Arrange
        var budget1 = new TaskBudget(MaxClaudeTokens: 100_000, MaxToolCalls: 50, MaxFilesModified: 10, MaxProcessesSpawned: 5);
        var budget2 = new TaskBudget(MaxClaudeTokens: 100_000, MaxToolCalls: 50, MaxFilesModified: 10, MaxProcessesSpawned: 5);

        // Assert
        budget1.Should().Be(budget2);
        (budget1 == budget2).Should().BeTrue();
    }

    [Fact]
    public void TaskBudget_Should_NotBeEqual_WhenValuesDiffer()
    {
        // Arrange
        var budget1 = new TaskBudget();
        var budget2 = new TaskBudget(MaxClaudeTokens: 100_000);

        // Assert
        budget1.Should().NotBe(budget2);
    }

    [Fact]
    public void TaskBudget_Should_SupportWith_Expression()
    {
        // Arrange
        var original = new TaskBudget();

        // Act
        var modified = original with { MaxToolCalls = 50 };

        // Assert
        modified.MaxClaudeTokens.Should().Be(200_000);
        modified.MaxToolCalls.Should().Be(50);
        modified.MaxFilesModified.Should().Be(20);
        modified.MaxProcessesSpawned.Should().Be(10);
    }
}
