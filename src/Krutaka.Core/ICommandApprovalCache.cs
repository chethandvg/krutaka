namespace Krutaka.Core;

/// <summary>
/// Cache for tracking command approvals within a session.
/// Used by RunCommandTool to check if a command execution was recently approved by the user,
/// allowing approved commands to bypass the policy check on retry.
/// This is a short-lived cache scoped to the AgentOrchestrator instance.
/// </summary>
public interface ICommandApprovalCache
{
    /// <summary>
    /// Checks if a command with the given signature was recently approved.
    /// </summary>
    /// <param name="commandSignature">
    /// The command signature (format: "executable arg1 arg2...").
    /// </param>
    /// <returns>True if the command was approved and the approval is still valid.</returns>
    bool IsApproved(string commandSignature);

    /// <summary>
    /// Adds a command approval to the cache with a short TTL.
    /// </summary>
    /// <param name="commandSignature">
    /// The command signature (format: "executable arg1 arg2...").
    /// </param>
    /// <param name="ttl">Time-to-live for the approval. After this duration, the approval expires.</param>
    void AddApproval(string commandSignature, TimeSpan ttl);

    /// <summary>
    /// Removes an approval from the cache after command execution completes.
    /// </summary>
    /// <param name="commandSignature">The command signature to remove.</param>
    void RemoveApproval(string commandSignature);
}
