namespace Krutaka.Core;

/// <summary>
/// Manages session-scoped directory access grants with time-to-live (TTL) enforcement.
/// Placeholder interface for v0.2.0 Issue 5. Full implementation coming in Issue 6.
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
    /// </summary>
    /// <param name="path">The canonical directory path (must be fully resolved).</param>
    /// <param name="grantedLevel">The access level being granted.</param>
    /// <param name="expiresAfter">Optional time-to-live for the grant; null means session lifetime.</param>
    /// <param name="justification">The reason for granting access.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task GrantAccessAsync(string path, AccessLevel grantedLevel, TimeSpan? expiresAfter, string justification, CancellationToken cancellationToken);
}
