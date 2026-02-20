using FluentAssertions;

namespace Krutaka.Core.Tests;

public class ITaskBudgetTrackerTests
{
    private sealed class StubTracker : ITaskBudgetTracker
    {
        private readonly TaskBudget _budget;
        private int _tokens;
        private int _toolCalls;
        private int _filesModified;
        private int _processesSpawned;

        public StubTracker(TaskBudget? budget = null)
        {
            _budget = budget ?? new TaskBudget();
        }

        public bool IsExhausted
        {
            get
            {
                return _tokens >= _budget.MaxClaudeTokens
                    || _toolCalls >= _budget.MaxToolCalls
                    || _filesModified >= _budget.MaxFilesModified
                    || _processesSpawned >= _budget.MaxProcessesSpawned;
            }
        }

        public bool TryConsume(BudgetDimension dimension, int amount)
        {
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(amount);

            switch (dimension)
            {
                case BudgetDimension.Tokens when (long)_tokens + amount <= _budget.MaxClaudeTokens:
                    _tokens += amount;
                    return true;
                case BudgetDimension.ToolCalls when (long)_toolCalls + amount <= _budget.MaxToolCalls:
                    _toolCalls += amount;
                    return true;
                case BudgetDimension.FilesModified when (long)_filesModified + amount <= _budget.MaxFilesModified:
                    _filesModified += amount;
                    return true;
                case BudgetDimension.ProcessesSpawned when (long)_processesSpawned + amount <= _budget.MaxProcessesSpawned:
                    _processesSpawned += amount;
                    return true;
                default:
                    return false;
            }
        }

        public TaskBudgetSnapshot GetSnapshot() => new(
            TokensConsumed: _tokens,
            ToolCallsConsumed: _toolCalls,
            FilesModified: _filesModified,
            ProcessesSpawned: _processesSpawned,
            TokensPercentage: _budget.MaxClaudeTokens > 0 ? (double)_tokens / _budget.MaxClaudeTokens : 0.0,
            ToolCallsPercentage: _budget.MaxToolCalls > 0 ? (double)_toolCalls / _budget.MaxToolCalls : 0.0,
            FilesModifiedPercentage: _budget.MaxFilesModified > 0 ? (double)_filesModified / _budget.MaxFilesModified : 0.0,
            ProcessesSpawnedPercentage: _budget.MaxProcessesSpawned > 0 ? (double)_processesSpawned / _budget.MaxProcessesSpawned : 0.0
        );
    }

    [Fact]
    public void ITaskBudgetTracker_Should_BeAssignableFromStubImplementation()
    {
        // Act
        ITaskBudgetTracker tracker = new StubTracker();

        // Assert
        tracker.Should().NotBeNull();
        tracker.Should().BeAssignableTo<ITaskBudgetTracker>();
    }

    [Fact]
    public void TryConsume_Should_ReturnTrue_WhenWithinBudget()
    {
        // Arrange
        ITaskBudgetTracker tracker = new StubTracker(new TaskBudget(MaxClaudeTokens: 1000));

        // Act
        bool result = tracker.TryConsume(BudgetDimension.Tokens, 500);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public void TryConsume_Should_ReturnFalse_WhenBudgetExceeded()
    {
        // Arrange
        ITaskBudgetTracker tracker = new StubTracker(new TaskBudget(MaxClaudeTokens: 100));

        // Act
        bool result = tracker.TryConsume(BudgetDimension.Tokens, 200);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void IsExhausted_Should_BeFalse_Initially()
    {
        // Arrange
        ITaskBudgetTracker tracker = new StubTracker();

        // Assert
        tracker.IsExhausted.Should().BeFalse();
    }

    [Fact]
    public void IsExhausted_Should_BeTrue_AfterTokenBudgetReached()
    {
        // Arrange
        ITaskBudgetTracker tracker = new StubTracker(new TaskBudget(MaxClaudeTokens: 100));
        tracker.TryConsume(BudgetDimension.Tokens, 100);

        // Assert
        tracker.IsExhausted.Should().BeTrue();
    }

    [Fact]
    public void GetSnapshot_Should_ReflectCurrentConsumption()
    {
        // Arrange
        ITaskBudgetTracker tracker = new StubTracker(new TaskBudget(MaxClaudeTokens: 1000, MaxToolCalls: 10));
        tracker.TryConsume(BudgetDimension.Tokens, 500);
        tracker.TryConsume(BudgetDimension.ToolCalls, 3);

        // Act
        TaskBudgetSnapshot snapshot = tracker.GetSnapshot();

        // Assert
        snapshot.TokensConsumed.Should().Be(500);
        snapshot.ToolCallsConsumed.Should().Be(3);
        snapshot.TokensPercentage.Should().BeApproximately(0.5, 1e-9);
        snapshot.ToolCallsPercentage.Should().BeApproximately(0.3, 1e-9);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public void TryConsume_Should_Throw_WhenAmountIsNotPositive(int invalidAmount)
    {
        // Arrange
        ITaskBudgetTracker tracker = new StubTracker();

        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() => tracker.TryConsume(BudgetDimension.Tokens, invalidAmount));
    }

    [Fact]
    public void TryConsume_Should_ReturnFalse_WhenAmountWouldCauseOverflow()
    {
        // Arrange — budget is large enough that int overflow would previously make the sum negative
        ITaskBudgetTracker tracker = new StubTracker(new TaskBudget(MaxClaudeTokens: int.MaxValue));
        tracker.TryConsume(BudgetDimension.Tokens, int.MaxValue);

        // Act — attempt to consume 1 more; counter is already at MaxValue so this should return false
        bool result = tracker.TryConsume(BudgetDimension.Tokens, 1);

        // Assert
        result.Should().BeFalse();
    }
}
