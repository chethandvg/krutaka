using Krutaka.Core;
using Krutaka.Tools;

namespace Krutaka.Console;

/// <summary>
/// Interface for console UI operations, enabling testability.
/// </summary>
internal interface IConsoleUI : IDisposable
{
    /// <summary>
    /// Gets a cancellation token that is triggered when the user requests shutdown (e.g., Ctrl+C).
    /// </summary>
    CancellationToken ShutdownToken { get; }

    /// <summary>
    /// Displays the startup banner.
    /// </summary>
    void DisplayBanner();

    /// <summary>
    /// Gets user input from the console.
    /// </summary>
    /// <returns>The user input string, or null if cancelled.</returns>
    string? GetUserInput();

    /// <summary>
    /// Displays streaming response from the agent.
    /// </summary>
    Task DisplayStreamingResponseAsync(
        IAsyncEnumerable<AgentEvent> events,
        Action<string, bool, bool>? onApprovalDecision = null,
        Action<bool, AccessLevel?, bool>? onDirectoryAccessDecision = null,
        Action<bool, bool>? onCommandApprovalDecision = null,
        CancellationToken cancellationToken = default);
}
