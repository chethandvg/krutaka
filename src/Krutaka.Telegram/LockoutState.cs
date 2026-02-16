namespace Krutaka.Telegram;

/// <summary>
/// Thread-safe lockout state for a user.
/// Tracks failed authentication attempts and lockout expiration using monotonic clock.
/// </summary>
internal sealed class LockoutState
{
    private int _failedAttempts;
    private long _lockoutExpiresAtTicks;

    /// <summary>
    /// Gets the number of failed authentication attempts.
    /// </summary>
    public int FailedAttempts => _failedAttempts;

    /// <summary>
    /// Gets the tick count when the lockout expires (0 if not locked out).
    /// </summary>
    public long LockoutExpiresAtTicks => _lockoutExpiresAtTicks;

    /// <summary>
    /// Checks if the user is currently locked out.
    /// </summary>
    /// <param name="currentTicks">The current tick count (from Environment.TickCount64).</param>
    /// <returns>True if locked out and lockout has not expired; otherwise, false.</returns>
    public bool IsLockedOut(long currentTicks)
    {
        var expiresAt = Interlocked.Read(ref _lockoutExpiresAtTicks);
        return expiresAt > 0 && currentTicks < expiresAt;
    }

    /// <summary>
    /// Increments the failed attempt counter.
    /// </summary>
    /// <returns>The new failed attempt count.</returns>
    public int IncrementFailedAttempts()
    {
        return Interlocked.Increment(ref _failedAttempts);
    }

    /// <summary>
    /// Triggers a lockout with the specified duration.
    /// </summary>
    /// <param name="currentTicks">The current tick count (from Environment.TickCount64).</param>
    /// <param name="durationTicks">The lockout duration in ticks.</param>
    public void TriggerLockout(long currentTicks, long durationTicks)
    {
        var expiresAt = currentTicks + durationTicks;
        Interlocked.Exchange(ref _lockoutExpiresAtTicks, expiresAt);
    }

    /// <summary>
    /// Clears the lockout and resets the failed attempt counter.
    /// </summary>
    public void ClearLockout()
    {
        Interlocked.Exchange(ref _failedAttempts, 0);
        Interlocked.Exchange(ref _lockoutExpiresAtTicks, 0);
    }
}
