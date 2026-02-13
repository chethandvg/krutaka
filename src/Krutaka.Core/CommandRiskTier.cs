namespace Krutaka.Core;

/// <summary>
/// Defines the risk tier for command execution, which determines approval requirements.
/// Commands are classified into one of four tiers based on their potential impact.
/// </summary>
public enum CommandRiskTier
{
    /// <summary>
    /// Safe commands that are always auto-approved.
    /// Examples: git status, cat, echo, version checks.
    /// These are read-only operations with no side effects.
    /// </summary>
    Safe = 0,

    /// <summary>
    /// Moderate risk commands that are context-dependent.
    /// Auto-approved in trusted directories, require approval elsewhere.
    /// Examples: git commit, dotnet build, npm run.
    /// </summary>
    Moderate = 1,

    /// <summary>
    /// Elevated risk commands that always require human approval.
    /// No "Always allow" option available.
    /// Examples: git push, npm install, dotnet publish.
    /// </summary>
    Elevated = 2,

    /// <summary>
    /// Dangerous commands that are always blocked and never executed.
    /// These cannot be overridden via configuration.
    /// Examples: powershell, cmd, format, diskpart.
    /// </summary>
    Dangerous = 3
}
