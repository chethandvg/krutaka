namespace Krutaka.Core;

/// <summary>
/// Provides access to the current <see cref="CorrelationContext"/> for the ongoing operation.
/// This is a scoped service that is set by the orchestrator at the start of each turn
/// and can be accessed by tools and policies that need correlation IDs for audit logging.
/// </summary>
public interface ICorrelationContextAccessor
{
    /// <summary>
    /// Gets or sets the current correlation context.
    /// </summary>
    /// <value>
    /// The current correlation context, or null if not set.
    /// </value>
    CorrelationContext? Current { get; set; }
}
