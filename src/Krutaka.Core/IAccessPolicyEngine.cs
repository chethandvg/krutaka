namespace Krutaka.Core;

/// <summary>
/// Evaluates directory access requests through a multi-layered security policy engine.
/// Validates requests against hard deny lists, auto-grant patterns, session grants, and heuristics.
/// This is the core abstraction for v0.2.0's dynamic directory scoping model.
/// </summary>
public interface IAccessPolicyEngine
{
    /// <summary>
    /// Evaluates a directory access request and returns a decision indicating whether access is granted or denied.
    /// The evaluation proceeds through multiple policy layers (hard deny list, auto-grant patterns, session grants, heuristics).
    /// A denial at any layer is final and cannot be overridden by subsequent layers.
    /// </summary>
    /// <param name="request">The directory access request to evaluate.</param>
    /// <param name="cancellationToken">Cancellation token to cancel the operation.</param>
    /// <returns>An AccessDecision indicating whether access is granted, the scoped path if granted, and reasons if denied.</returns>
    /// <remarks>
    /// The policy engine evaluates requests through four ordered layers:
    /// 1. Hard Deny List - System directories, UNC paths, paths above ceiling (immutable, never changes)
    /// 2. Configurable Allow List - Glob patterns from configuration for auto-approved directories
    /// 3. Session Grants - Previously approved directory access within the current session (TTL-bounded)
    /// 4. Heuristic Checks - Cross-volume detection, path depth analysis, suspicious patterns
    /// 
    /// A denial at Layer 1 cannot be overridden by auto-grant or session approval.
    /// The decision may indicate that human approval is required (needs interactive prompt).
    /// </remarks>
    Task<AccessDecision> EvaluateAsync(DirectoryAccessRequest request, CancellationToken cancellationToken);
}
