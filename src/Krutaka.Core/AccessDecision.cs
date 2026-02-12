namespace Krutaka.Core;

/// <summary>
/// Represents the result of evaluating a directory access request through the access policy engine.
/// Contains the decision (granted/denied), the canonical scoped path if granted, and metadata about the decision.
/// </summary>
/// <param name="Granted">True if access was granted, false if denied.</param>
/// <param name="ScopedPath">The canonicalized, validated absolute path if granted; null if denied.</param>
/// <param name="GrantedLevel">The access level that was actually granted (may be downgraded from requested level); null if denied.</param>
/// <param name="ExpiresAfter">Optional time-to-live for the grant; null means session lifetime or permanent based on policy.</param>
/// <param name="DeniedReasons">List of reasons why access was denied; empty if granted.</param>
public sealed record AccessDecision(
    bool Granted,
    string? ScopedPath,
    AccessLevel? GrantedLevel,
    TimeSpan? ExpiresAfter,
    IReadOnlyList<string> DeniedReasons
)
{
    /// <summary>
    /// Creates a successful access decision with granted access.
    /// </summary>
    /// <param name="scopedPath">The canonicalized, validated absolute path.</param>
    /// <param name="grantedLevel">The access level being granted.</param>
    /// <param name="expiresAfter">Optional TTL for the grant.</param>
    /// <returns>An AccessDecision indicating granted access.</returns>
    public static AccessDecision Grant(string scopedPath, AccessLevel grantedLevel, TimeSpan? expiresAfter = null)
    {
        return new AccessDecision(
            Granted: true,
            ScopedPath: scopedPath,
            GrantedLevel: grantedLevel,
            ExpiresAfter: expiresAfter,
            DeniedReasons: Array.Empty<string>()
        );
    }

    /// <summary>
    /// Creates a failed access decision with one or more denial reasons.
    /// </summary>
    /// <param name="reasons">The reasons why access was denied.</param>
    /// <returns>An AccessDecision indicating denied access.</returns>
    public static AccessDecision Deny(params string[] reasons)
    {
        return new AccessDecision(
            Granted: false,
            ScopedPath: null,
            GrantedLevel: null,
            ExpiresAfter: null,
            DeniedReasons: reasons.ToList()
        );
    }
}
