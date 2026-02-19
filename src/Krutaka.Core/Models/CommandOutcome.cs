namespace Krutaka.Core;

/// <summary>
/// Defines the outcome of evaluating a command execution request.
/// </summary>
public enum CommandOutcome
{
    /// <summary>
    /// Command is approved for immediate execution without human approval.
    /// Used for Safe tier commands and Moderate tier commands in trusted directories.
    /// </summary>
    Approved = 0,

    /// <summary>
    /// Command requires interactive human approval before execution.
    /// Used for Moderate tier commands in untrusted directories and Elevated tier commands.
    /// </summary>
    RequiresApproval = 1,

    /// <summary>
    /// Command is denied and will not execute.
    /// Used for Dangerous tier commands and unknown executables (fail-closed).
    /// </summary>
    Denied = 2
}
