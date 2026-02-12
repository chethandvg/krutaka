namespace Krutaka.Core;

/// <summary>
/// Specifies who or what granted directory access for auditing purposes.
/// </summary>
public enum GrantSource
{
    /// <summary>
    /// Access was granted by explicit user approval (human-in-the-loop).
    /// </summary>
    User = 0,

    /// <summary>
    /// Access was automatically granted by matching an auto-grant pattern (Layer 2).
    /// </summary>
    AutoGrant = 1,

    /// <summary>
    /// Access was granted by policy evaluation (e.g., Layer 2 pattern match recorded in session).
    /// </summary>
    Policy = 2
}

/// <summary>
/// Represents a session-scoped directory access grant with time-to-live enforcement.
/// Immutable record tracking approved directory access for the duration of a session.
/// </summary>
/// <param name="Path">The canonical, fully-resolved directory path that was granted access.</param>
/// <param name="AccessLevel">The level of access that was granted (ReadOnly, ReadWrite, or Execute).</param>
/// <param name="GrantedAt">The UTC timestamp when access was granted.</param>
/// <param name="ExpiresAt">The UTC timestamp when the grant expires; null means session lifetime (no expiry).</param>
/// <param name="Justification">The reason why access was requested (shown to user, stored for audit).</param>
/// <param name="GrantedBy">The source that granted the access (User, AutoGrant, or Policy).</param>
public sealed record SessionAccessGrant(
    string Path,
    AccessLevel AccessLevel,
    DateTimeOffset GrantedAt,
    DateTimeOffset? ExpiresAt,
    string Justification,
    GrantSource GrantedBy
)
{
    /// <summary>
    /// Checks if this grant has expired based on the current UTC time.
    /// </summary>
    /// <param name="utcNow">The current UTC time to compare against.</param>
    /// <returns>True if the grant has expired; false if still active or has no expiry.</returns>
    public bool IsExpired(DateTimeOffset utcNow)
    {
        return ExpiresAt.HasValue && utcNow >= ExpiresAt.Value;
    }

    /// <summary>
    /// Checks if this grant satisfies a requested access level.
    /// Access levels are NOT hierarchical - each must match exactly or be explicitly allowed.
    /// </summary>
    /// <param name="requestedLevel">The access level being requested.</param>
    /// <returns>True if this grant covers the requested access level.</returns>
    public bool CoversAccessLevel(AccessLevel requestedLevel)
    {
        // Exact match is always allowed
        if (AccessLevel == requestedLevel)
        {
            return true;
        }

        // ReadWrite grant covers ReadOnly requests
        if (AccessLevel == AccessLevel.ReadWrite && requestedLevel == AccessLevel.ReadOnly)
        {
            return true;
        }

        // No other cross-level permissions
        return false;
    }
}
