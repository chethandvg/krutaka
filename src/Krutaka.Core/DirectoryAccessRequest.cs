namespace Krutaka.Core;

/// <summary>
/// Represents a request from an agent to access a directory at a specific access level.
/// This request is evaluated by the access policy engine to determine if access should be granted.
/// </summary>
/// <param name="Path">The directory path being requested (can be relative or absolute).</param>
/// <param name="Level">The level of access being requested (ReadOnly, ReadWrite, or Execute).</param>
/// <param name="Justification">Agent-provided reason for requesting access (shown to user during approval prompts).</param>
public sealed record DirectoryAccessRequest(
    string Path,
    AccessLevel Level,
    string Justification
);
