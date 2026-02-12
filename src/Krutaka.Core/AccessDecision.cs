namespace Krutaka.Core;

/// <summary>
/// Defines the outcome of evaluating a directory access request.
/// </summary>
public enum AccessOutcome
{
    /// <summary>
    /// Access was granted. The request passed all policy layers.
    /// </summary>
    Granted = 0,

    /// <summary>
    /// Access was denied. One or more policy layers rejected the request.
    /// </summary>
    Denied = 1,

    /// <summary>
    /// Access requires interactive human approval. The request did not match auto-grant patterns or existing session grants.
    /// </summary>
    RequiresApproval = 2
}

/// <summary>
/// Represents the result of evaluating a directory access request through the access policy engine.
/// Contains the decision outcome, the canonical scoped path if granted, and metadata about the decision.
/// </summary>
/// <param name="Outcome">The decision outcome: Granted, Denied, or RequiresApproval.</param>
/// <param name="ScopedPath">The canonicalized, validated absolute path if granted; null if denied or requires approval.</param>
/// <param name="GrantedLevel">The access level that was actually granted (may be downgraded from requested level); null if denied or requires approval.</param>
/// <param name="ExpiresAfter">Optional time-to-live for the grant; null means session lifetime or permanent based on policy.</param>
/// <param name="DeniedReasons">List of reasons why access was denied; empty if granted or requires approval.</param>
public sealed record AccessDecision(
    AccessOutcome Outcome,
    string? ScopedPath,
    AccessLevel? GrantedLevel,
    TimeSpan? ExpiresAfter,
    IReadOnlyList<string> DeniedReasons
)
{
    /// <summary>
    /// Gets a value indicating whether access was granted.
    /// </summary>
    public bool Granted => Outcome == AccessOutcome.Granted;

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
            Outcome: AccessOutcome.Granted,
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
            Outcome: AccessOutcome.Denied,
            ScopedPath: null,
            GrantedLevel: null,
            ExpiresAfter: null,
            DeniedReasons: Array.AsReadOnly(reasons)
        );
    }

    /// <summary>
    /// Creates an access decision indicating human approval is required.
    /// </summary>
    /// <param name="requestedPath">The path that requires approval (not yet canonicalized).</param>
    /// <returns>An AccessDecision indicating approval is required.</returns>
    public static AccessDecision RequireApproval(string requestedPath)
    {
        return new AccessDecision(
            Outcome: AccessOutcome.RequiresApproval,
            ScopedPath: requestedPath,
            GrantedLevel: null,
            ExpiresAfter: null,
            DeniedReasons: Array.Empty<string>()
        );
    }
}
