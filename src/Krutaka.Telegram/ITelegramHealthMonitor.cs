using Krutaka.Core;

namespace Krutaka.Telegram;

/// <summary>
/// Interface for Telegram health monitoring and proactive notifications.
/// Sends notifications for system events, error alerts, task completion, and budget warnings.
/// </summary>
public interface ITelegramHealthMonitor
{
    /// <summary>
    /// Sends a startup notification to all admin users indicating the bot is online.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token to cancel the operation.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    Task NotifyStartupAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Sends a shutdown notification to all admin users indicating the bot is shutting down.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token to cancel the operation.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    Task NotifyShutdownAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Sends an error alert to all admin users.
    /// The provided error summary is sanitized before sending and alerts NEVER contain stack traces,
    /// file paths, tokens, or other sensitive data.
    /// </summary>
    /// <param name="errorSummary">
    /// A raw, human-readable error summary that may contain sensitive details; it will be sanitized before sending.
    /// </param>
    /// <param name="cancellationToken">Cancellation token to cancel the operation.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    Task NotifyErrorAsync(string errorSummary, CancellationToken cancellationToken);

    /// <summary>
    /// Sends a task completion notification to a specific chat.
    /// </summary>
    /// <param name="chatId">The chat ID to send the notification to.</param>
    /// <param name="taskSummary">A summary of the completed task.</param>
    /// <param name="cancellationToken">Cancellation token to cancel the operation.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    Task NotifyTaskCompletedAsync(long chatId, string taskSummary, CancellationToken cancellationToken);

    /// <summary>
    /// Sends a budget warning notification to a specific chat when budget usage exceeds 80%.
    /// </summary>
    /// <param name="chatId">The chat ID to send the notification to.</param>
    /// <param name="budget">The session budget with current usage information.</param>
    /// <param name="cancellationToken">Cancellation token to cancel the operation.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    Task NotifyBudgetWarningAsync(long chatId, SessionBudget budget, CancellationToken cancellationToken);

    /// <summary>
    /// Checks all active sessions for budget threshold violations (80% usage).
    /// Sends warnings to chats for sessions that have crossed the threshold.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token to cancel the operation.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    Task CheckBudgetThresholdsAsync(CancellationToken cancellationToken);
}
