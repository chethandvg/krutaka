namespace Krutaka.Telegram;

/// <summary>
/// Telegram bot commands that can be issued by users.
/// </summary>
public enum TelegramCommand
{
    /// <summary>
    /// Send a prompt to the agent. Triggered by /ask or plain text.
    /// </summary>
    Ask,

    /// <summary>
    /// Send a task with tracking metadata. Triggered by /task.
    /// </summary>
    Task,

    /// <summary>
    /// Show the current session status. Triggered by /status.
    /// </summary>
    Status,

    /// <summary>
    /// Cancel the current operation. Triggered by /abort.
    /// </summary>
    Abort,

    /// <summary>
    /// Emergency shutdown: terminate all sessions and stop the bot. Triggered by /killswitch. Admin only.
    /// </summary>
    KillSwitch,

    /// <summary>
    /// List all active sessions. Triggered by /sessions.
    /// </summary>
    Sessions,

    /// <summary>
    /// Switch to or resume a specific session. Triggered by /session.
    /// </summary>
    SwitchSession,

    /// <summary>
    /// Display help message listing available commands. Triggered by /help.
    /// </summary>
    Help,

    /// <summary>
    /// Show or modify configuration. Triggered by /config. Admin only.
    /// </summary>
    Config,

    /// <summary>
    /// Show recent audit events. Triggered by /audit. Admin only.
    /// </summary>
    Audit,

    /// <summary>
    /// Show token budget usage. Triggered by /budget.
    /// </summary>
    Budget,

    /// <summary>
    /// Start a fresh session. Triggered by /new.
    /// </summary>
    New,

    /// <summary>
    /// Unrecognized command.
    /// </summary>
    Unknown
}
