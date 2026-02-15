namespace Krutaka.Core;

/// <summary>
/// Request parameters for creating a new session.
/// </summary>
/// <param name="ProjectPath">The absolute path to the project directory for this session.</param>
/// <param name="ExternalKey">Optional external identifier (e.g., Telegram chatId) for session lookup.</param>
/// <param name="UserId">Optional user identifier for per-user session limits.</param>
/// <param name="MaxTokenBudget">Maximum tokens this session can consume. Default is 200,000.</param>
/// <param name="MaxToolCallBudget">Maximum tool calls this session can execute. Default is 100.</param>
/// <param name="MaxDuration">Maximum session duration. If null, no time-based limit is enforced.</param>
public record SessionRequest(
    string ProjectPath,
    string? ExternalKey = null,
    string? UserId = null,
    int MaxTokenBudget = 200_000,
    int MaxToolCallBudget = 100,
    TimeSpan? MaxDuration = null)
{
    /// <summary>
    /// Gets the validated project path.
    /// </summary>
    /// <exception cref="ArgumentException">Thrown when ProjectPath is null or whitespace during construction.</exception>
    public string ProjectPath { get; init; } = ValidateProjectPath(ProjectPath);

    private static string ValidateProjectPath(string projectPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(projectPath);
        return projectPath;
    }
}
