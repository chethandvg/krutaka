namespace Krutaka.Core;

/// <summary>
/// Default implementation of <see cref="ICorrelationContextAccessor"/> that stores
/// the correlation context in a thread-safe manner.
/// </summary>
public sealed class CorrelationContextAccessor : ICorrelationContextAccessor
{
    private static readonly AsyncLocal<CorrelationContext?> _current = new();

    /// <inheritdoc/>
    public CorrelationContext? Current
    {
        get => _current.Value;
        set => _current.Value = value;
    }
}
