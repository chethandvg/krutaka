namespace Krutaka.Core;

/// <summary>
/// Tracks resource consumption for a session with thread-safe counters.
/// Monitors token usage, tool call count, and turn count against configured limits.
/// </summary>
public sealed class SessionBudget
{
    private int _tokensUsed;
    private int _toolCallsUsed;
    private int _turnsUsed;

    /// <summary>
    /// Gets the number of tokens consumed by this session.
    /// </summary>
    public int TokensUsed => _tokensUsed;

    /// <summary>
    /// Gets the number of tool calls executed by this session.
    /// </summary>
    public int ToolCallsUsed => _toolCallsUsed;

    /// <summary>
    /// Gets the number of turns (user interactions) processed by this session.
    /// </summary>
    public int TurnsUsed => _turnsUsed;

    /// <summary>
    /// Gets the maximum number of tokens this session is allowed to consume.
    /// </summary>
    public int MaxTokens { get; }

    /// <summary>
    /// Gets the maximum number of tool calls this session is allowed to execute.
    /// </summary>
    public int MaxToolCalls { get; }

    /// <summary>
    /// Gets a value indicating whether the session has exhausted its token or tool call budget.
    /// </summary>
    public bool IsExhausted => _tokensUsed >= MaxTokens || _toolCallsUsed >= MaxToolCalls;

    /// <summary>
    /// Initializes a new instance of the <see cref="SessionBudget"/> class.
    /// </summary>
    /// <param name="maxTokens">Maximum tokens allowed for the session.</param>
    /// <param name="maxToolCalls">Maximum tool calls allowed for the session.</param>
    public SessionBudget(int maxTokens, int maxToolCalls)
    {
        MaxTokens = maxTokens;
        MaxToolCalls = maxToolCalls;
    }

    /// <summary>
    /// Increments the turn counter using atomic operations.
    /// </summary>
    public void IncrementTurn()
    {
        Interlocked.Increment(ref _turnsUsed);
    }

    /// <summary>
    /// Adds the specified number of tokens to the usage counter using atomic operations.
    /// </summary>
    /// <param name="count">Number of tokens to add.</param>
    public void AddTokens(int count)
    {
        Interlocked.Add(ref _tokensUsed, count);
    }

    /// <summary>
    /// Increments the tool call counter using atomic operations.
    /// </summary>
    public void IncrementToolCall()
    {
        Interlocked.Increment(ref _toolCallsUsed);
    }
}
