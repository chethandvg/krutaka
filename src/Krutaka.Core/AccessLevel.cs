namespace Krutaka.Core;

/// <summary>
/// Defines the level of access requested for directory operations.
/// Each level implies specific permissions that must be validated by the access policy engine.
/// </summary>
public enum AccessLevel
{
    /// <summary>
    /// Read-only access to directory contents (list files, read file contents, search).
    /// Does not permit write, delete, or execute operations.
    /// </summary>
    ReadOnly = 0,

    /// <summary>
    /// Read and write access to directory contents (create, update, delete files).
    /// Does not permit command execution within the directory.
    /// </summary>
    ReadWrite = 1,

    /// <summary>
    /// Execute access for running commands with the directory as working directory.
    /// Implies ReadOnly access but not ReadWrite (commands may read but not modify files unless separately granted).
    /// </summary>
    Execute = 2
}
