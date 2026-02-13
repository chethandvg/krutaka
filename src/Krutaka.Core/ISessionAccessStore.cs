namespace Krutaka.Core;

/// <summary>
/// Manages session-scoped directory access grants with time-to-live (TTL) enforcement.
/// Grants are stored in memory for the lifetime of the session with optional expiry.
/// Thread-safe for concurrent access across multiple tool executions.
/// </summary>
public interface ISessionAccessStore
{
    /// <summary>
    /// Checks if access has been previously granted for a specific path and access level.
    /// Automatically prunes expired grants before checking.
    /// </summary>
    /// <param name="path">The canonical directory path to check (must be fully resolved).</param>
    /// <param name="requestedLevel">The access level being requested.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if an active (not expired) grant exists with sufficient access level; otherwise false.</returns>
    Task<bool> IsGrantedAsync(string path, AccessLevel requestedLevel, CancellationToken cancellationToken);

    /// <summary>
    /// Grants access to a directory at a specific access level with an optional TTL.
    /// If the maximum number of concurrent grants has been reached, this method will throw an exception.
    /// </summary>
    /// <param name="path">The canonical directory path (must be fully resolved).</param>
    /// <param name="grantedLevel">The access level being granted.</param>
    /// <param name="expiresAfter">Optional time-to-live for the grant; null means session lifetime.</param>
    /// <param name="justification">The reason for granting access.</param>
    /// <param name="grantedBy">The source that granted the access (User, AutoGrant, or Policy).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <exception cref="InvalidOperationException">Thrown when the maximum number of concurrent grants has been reached.</exception>
    Task GrantAccessAsync(
        string path,
        AccessLevel grantedLevel,
        TimeSpan? expiresAfter,
        string justification,
        GrantSource grantedBy,
        CancellationToken cancellationToken);

    /// <summary>
    /// Revokes access to a specific directory path.
    /// If no grant exists for the path, this method does nothing.
    /// </summary>
    /// <param name="path">The canonical directory path to revoke access for.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task RevokeAccessAsync(string path, CancellationToken cancellationToken);

    /// <summary>
    /// Gets all active (non-expired) grants in the session.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A read-only collection of all active session grants.</returns>
    Task<IReadOnlyList<SessionAccessGrant>> GetActiveGrantsAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Removes all expired grants from the store.
    /// This is called automatically before each IsGrantedAsync check.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The number of grants that were removed.</returns>
    Task<int> PruneExpiredAsync(CancellationToken cancellationToken);
}
