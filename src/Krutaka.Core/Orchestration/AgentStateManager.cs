namespace Krutaka.Core;

/// <summary>
/// Thread-safe implementation of <see cref="IAgentStateManager"/>.
/// Enforces valid state transitions and a 1-second debounce to prevent rapid cycling (AT10 mitigation).
/// </summary>
public sealed class AgentStateManager : IAgentStateManager
{
    private readonly object _lock = new();
    private AgentState _currentState = AgentState.Running;
    private string? _pauseReason;
    private DateTimeOffset _lastTransitionTime = DateTimeOffset.MinValue;

    private static readonly TimeSpan DebounceInterval = TimeSpan.FromSeconds(1);

    /// <inheritdoc/>
    public AgentState CurrentState
    {
        get
        {
            lock (_lock)
            {
                return _currentState;
            }
        }
    }

    /// <inheritdoc/>
    public string? PauseReason
    {
        get
        {
            lock (_lock)
            {
                return _pauseReason;
            }
        }
    }

    /// <inheritdoc/>
    public event EventHandler<AgentStateChangedEventArgs>? StateChanged;

    /// <inheritdoc/>
    public bool TryTransition(AgentState target)
    {
        AgentStateChangedEventArgs? args = null;

        lock (_lock)
        {
            if (!IsValidTransition(_currentState, target))
            {
                return false;
            }

            if (!IsDebounceSatisfied())
            {
                return false;
            }

            args = new AgentStateChangedEventArgs(_currentState, target, $"Transitioned to {target}");
            _currentState = target;
            if (target != AgentState.Paused)
            {
                _pauseReason = null;
            }

            _lastTransitionTime = DateTimeOffset.UtcNow;
        }

        StateChanged?.Invoke(this, args);
        return true;
    }

    /// <inheritdoc/>
    public void RequestPause(string reason)
    {
        ArgumentNullException.ThrowIfNull(reason);

        AgentStateChangedEventArgs? args = null;

        lock (_lock)
        {
            if (_currentState != AgentState.Running)
            {
                return;
            }

            if (!IsDebounceSatisfied())
            {
                return;
            }

            args = new AgentStateChangedEventArgs(AgentState.Running, AgentState.Paused, reason);
            _currentState = AgentState.Paused;
            _pauseReason = reason;
            _lastTransitionTime = DateTimeOffset.UtcNow;
        }

        StateChanged?.Invoke(this, args);
    }

    /// <inheritdoc/>
    public void RequestAbort(string reason)
    {
        ArgumentNullException.ThrowIfNull(reason);

        AgentStateChangedEventArgs? args = null;

        lock (_lock)
        {
            if (_currentState == AgentState.Aborted)
            {
                return;
            }

            var oldState = _currentState;
            _currentState = AgentState.Aborted;
            _pauseReason = null;
            _lastTransitionTime = DateTimeOffset.UtcNow;
            args = new AgentStateChangedEventArgs(oldState, AgentState.Aborted, reason);
        }

        StateChanged?.Invoke(this, args);
    }

    /// <inheritdoc/>
    public void ResumeAgent()
    {
        AgentStateChangedEventArgs? args = null;

        lock (_lock)
        {
            if (_currentState != AgentState.Paused)
            {
                return;
            }

            if (!IsDebounceSatisfied())
            {
                return;
            }

            args = new AgentStateChangedEventArgs(AgentState.Paused, AgentState.Running, "Resumed by user");
            _currentState = AgentState.Running;
            _pauseReason = null;
            _lastTransitionTime = DateTimeOffset.UtcNow;
        }

        StateChanged?.Invoke(this, args);
    }

    /// <summary>
    /// Returns <see langword="true"/> if the transition from <paramref name="from"/> to <paramref name="to"/> is valid.
    /// </summary>
    private static bool IsValidTransition(AgentState from, AgentState to)
    {
        return (from, to) switch
        {
            (AgentState.Running, AgentState.Paused) => true,
            (AgentState.Running, AgentState.Aborted) => true,
            (AgentState.Paused, AgentState.Running) => true,
            (AgentState.Paused, AgentState.Aborted) => true,
            _ => false,
        };
    }

    /// <summary>
    /// Returns <see langword="true"/> if the debounce interval has elapsed since the last transition.
    /// Must be called while holding <see cref="_lock"/>.
    /// </summary>
    private bool IsDebounceSatisfied()
    {
        return DateTimeOffset.UtcNow - _lastTransitionTime >= DebounceInterval;
    }
}
