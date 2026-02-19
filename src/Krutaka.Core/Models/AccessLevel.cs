namespace Krutaka.Core;

/// <summary>
/// Defines the level of access requested for directory operations.
/// These are distinct permission types, not a hierarchy. A request for one level does not imply another.
/// Use explicit permission checking logic rather than numeric comparisons.
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
    /// Does not imply ReadWrite access (commands can read but cannot modify files unless ReadWrite is also granted).
    /// </summary>
    Execute = 2
}
