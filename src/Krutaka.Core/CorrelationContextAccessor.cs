namespace Krutaka.Core;

/// <summary>
/// Default implementation of <see cref="ICorrelationContextAccessor"/> that stores
/// the correlation context in a thread-safe manner using AsyncLocal to flow across async boundaries.
/// Registered as a singleton in DI, with instance-scoped AsyncLocal storage.
/// </summary>
public sealed class CorrelationContextAccessor : ICorrelationContextAccessor
{
    private readonly AsyncLocal<CorrelationContext?> _current = new();

    /// <inheritdoc/>
    public CorrelationContext? Current
    {
        get => _current.Value;
        set => _current.Value = value;
    }
}
