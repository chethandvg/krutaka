using Krutaka.Core;

namespace Krutaka.Tools;

/// <summary>
/// Timer-based deadman's switch that monitors user interaction for a single session.
/// Runs entirely in <see cref="SessionManager"/> scope — inaccessible to the agent (security invariant S12).
/// </summary>
/// <remarks>
/// Behavior:
/// <list type="bullet">
///   <item>At <c>MaxUnattendedDuration</c>: calls <see cref="IAgentStateManager.RequestPause"/> with a diagnostic reason.</item>
///   <item>At <c>2× MaxUnattendedDuration</c>: calls <see cref="IAgentStateManager.RequestAbort"/> (terminal).</item>
///   <item><see cref="ResetTimer"/> must only be called for genuine user input — never for agent-generated events (S12).</item>
/// </list>
/// Thread-safe. Disposal is idempotent.
/// </remarks>
public sealed class DeadmanSwitch : IDisposable
{
    private readonly IAgentStateManager _stateManager;
    private readonly TimeSpan _maxUnattendedDuration;
    private readonly Timer _timer;
    private readonly object _lock = new();
    private bool _pauseFired;
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="DeadmanSwitch"/> class and starts the timer.
    /// </summary>
    /// <param name="stateManager">The per-session agent state manager to pause/abort.</param>
    /// <param name="maxUnattendedDuration">The duration of inactivity before the agent is paused.</param>
    public DeadmanSwitch(IAgentStateManager stateManager, TimeSpan maxUnattendedDuration)
    {
        ArgumentNullException.ThrowIfNull(stateManager);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(maxUnattendedDuration, TimeSpan.Zero);

        _stateManager = stateManager;
        _maxUnattendedDuration = maxUnattendedDuration;
        _timer = new Timer(OnTimerFired, null, maxUnattendedDuration, Timeout.InfiniteTimeSpan);
    }

    private void OnTimerFired(object? state)
    {
        lock (_lock)
        {
            if (_disposed)
            {
                return;
            }

            if (!_pauseFired)
            {
                // First expiry: pause the agent and re-arm for abort
                _pauseFired = true;
                _stateManager.RequestPause("Deadman switch: no user interaction");
                _timer.Change(_maxUnattendedDuration, Timeout.InfiniteTimeSpan);
            }
            else
            {
                // Second expiry: abort the agent (terminal)
                _stateManager.RequestAbort("Deadman switch: auto-abort");
            }
        }
    }

    /// <summary>
    /// Resets the timer on genuine user input, cancelling any pending pause/abort escalation.
    /// Must only be called for genuine user interactions (messages, commands, approval decisions).
    /// Never call this for agent-generated events (security invariant S12).
    /// </summary>
    public void ResetTimer()
    {
        lock (_lock)
        {
            if (_disposed)
            {
                return;
            }

            _pauseFired = false;
            _timer.Change(_maxUnattendedDuration, Timeout.InfiniteTimeSpan);
        }
    }

    /// <summary>
    /// Disposes the deadman switch, stopping the timer and releasing all resources.
    /// Safe to call multiple times (idempotent).
    /// </summary>
    public void Dispose()
    {
        bool shouldDispose;
        lock (_lock)
        {
            shouldDispose = !_disposed;
            _disposed = true;
        }

        if (shouldDispose)
        {
            _timer.Dispose();
        }
    }
}
