namespace Krutaka.Core;

/// <summary>
/// Thread-safe implementation of <see cref="ITaskBudgetTracker"/> using atomic compare-and-swap
/// operations to track resource consumption across multiple dimensions.
/// </summary>
public sealed class TaskBudgetTracker : ITaskBudgetTracker
{
    private readonly TaskBudget _budget;

    // Counters for each dimension — accessed only via Interlocked / Volatile
    private int _tokens;
    private int _toolCalls;
    private int _filesModified;
    private int _processesSpawned;

    /// <summary>
    /// Initializes a new instance of the <see cref="TaskBudgetTracker"/> class.
    /// </summary>
    /// <param name="budget">The budget limits for this task.</param>
    public TaskBudgetTracker(TaskBudget budget)
    {
        ArgumentNullException.ThrowIfNull(budget);
        _budget = budget;
    }

    /// <inheritdoc/>
    public bool IsExhausted
    {
        get
        {
            return Volatile.Read(ref _tokens) >= _budget.MaxClaudeTokens ||
                   Volatile.Read(ref _toolCalls) >= _budget.MaxToolCalls ||
                   Volatile.Read(ref _filesModified) >= _budget.MaxFilesModified ||
                   Volatile.Read(ref _processesSpawned) >= _budget.MaxProcessesSpawned;
        }
    }

    /// <inheritdoc/>
    public TaskBudget GetBudget() => _budget;

    /// <inheritdoc/>
    public bool TryConsume(BudgetDimension dimension, int amount)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(amount);

        return dimension switch
        {
            BudgetDimension.Tokens => TryConsumeInternal(ref _tokens, _budget.MaxClaudeTokens, amount),
            BudgetDimension.ToolCalls => TryConsumeInternal(ref _toolCalls, _budget.MaxToolCalls, amount),
            BudgetDimension.FilesModified => TryConsumeInternal(ref _filesModified, _budget.MaxFilesModified, amount),
            BudgetDimension.ProcessesSpawned => TryConsumeInternal(ref _processesSpawned, _budget.MaxProcessesSpawned, amount),
            _ => false
        };
    }

    /// <inheritdoc/>
    public TaskBudgetSnapshot GetSnapshot()
    {
        int tokens = Volatile.Read(ref _tokens);
        int toolCalls = Volatile.Read(ref _toolCalls);
        int filesModified = Volatile.Read(ref _filesModified);
        int processesSpawned = Volatile.Read(ref _processesSpawned);

        return new TaskBudgetSnapshot(
            TokensConsumed: tokens,
            ToolCallsConsumed: toolCalls,
            FilesModified: filesModified,
            ProcessesSpawned: processesSpawned,
            TokensPercentage: _budget.MaxClaudeTokens > 0 ? (double)tokens / _budget.MaxClaudeTokens : 0.0,
            ToolCallsPercentage: _budget.MaxToolCalls > 0 ? (double)toolCalls / _budget.MaxToolCalls : 0.0,
            FilesModifiedPercentage: _budget.MaxFilesModified > 0 ? (double)filesModified / _budget.MaxFilesModified : 0.0,
            ProcessesSpawnedPercentage: _budget.MaxProcessesSpawned > 0 ? (double)processesSpawned / _budget.MaxProcessesSpawned : 0.0
        );
    }

    /// <summary>
    /// Returns the current percentage consumed for the given dimension.
    /// </summary>
    public double GetPercentage(BudgetDimension dimension)
    {
        return dimension switch
        {
            BudgetDimension.Tokens => _budget.MaxClaudeTokens > 0
                ? (double)Volatile.Read(ref _tokens) / _budget.MaxClaudeTokens : 0.0,
            BudgetDimension.ToolCalls => _budget.MaxToolCalls > 0
                ? (double)Volatile.Read(ref _toolCalls) / _budget.MaxToolCalls : 0.0,
            BudgetDimension.FilesModified => _budget.MaxFilesModified > 0
                ? (double)Volatile.Read(ref _filesModified) / _budget.MaxFilesModified : 0.0,
            BudgetDimension.ProcessesSpawned => _budget.MaxProcessesSpawned > 0
                ? (double)Volatile.Read(ref _processesSpawned) / _budget.MaxProcessesSpawned : 0.0,
            _ => 0.0
        };
    }

    /// <summary>
    /// Atomically attempts to consume <paramref name="amount"/> from the counter, respecting
    /// the given <paramref name="limit"/>. Returns <see langword="false"/> if consuming would
    /// exceed the limit. Uses a CAS loop so the operation is lock-free and thread-safe.
    /// </summary>
    private static bool TryConsumeInternal(ref int counter, int limit, int amount)
    {
        while (true)
        {
            int current = Volatile.Read(ref counter);

            // Reject if adding amount would exceed the limit.
            // Use long arithmetic to avoid integer overflow when current is near int.MaxValue.
            if ((long)current + amount > limit)
            {
                return false;
            }

            int next = current + amount;

            // Atomically update the counter only if it hasn't changed since we read it.
            if (Interlocked.CompareExchange(ref counter, next, current) == current)
            {
                return true;
            }

            // Another thread modified the counter — retry from the beginning.
        }
    }
}
