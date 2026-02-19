namespace Krutaka.Core;

/// <summary>
/// Configuration options for the session manager.
/// </summary>
/// <param name="MaxActiveSessions">Maximum number of active sessions allowed concurrently. Default is 10.</param>
/// <param name="IdleTimeout">Duration before an active session transitions to idle. Default is 15 minutes.</param>
/// <param name="SuspendedTtl">Time-to-live for suspended sessions before they are removed. Default is 24 hours.</param>
/// <param name="GlobalMaxTokensPerHour">Global token budget per hour across all sessions. Default is 1,000,000.</param>
/// <param name="MaxSessionsPerUser">Maximum sessions per user (identified by UserId). Default is 3.</param>
/// <param name="EvictionStrategy">Strategy for evicting sessions when limits are reached. Default is SuspendOldestIdle.</param>
public record SessionManagerOptions(
    int MaxActiveSessions = 10,
    TimeSpan? IdleTimeout = null,
    TimeSpan? SuspendedTtl = null,
    int GlobalMaxTokensPerHour = 1_000_000,
    int MaxSessionsPerUser = 3,
    EvictionStrategy EvictionStrategy = EvictionStrategy.SuspendOldestIdle)
{
    /// <summary>
    /// Gets the validated maximum active sessions count.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when MaxActiveSessions is negative during construction.</exception>
    public int MaxActiveSessions { get; init; } = ValidateMaxActiveSessions(MaxActiveSessions);

    /// <summary>
    /// Gets the validated maximum sessions per user count.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when MaxSessionsPerUser is negative during construction.</exception>
    public int MaxSessionsPerUser { get; init; } = ValidateMaxSessionsPerUser(MaxSessionsPerUser);

    /// <summary>
    /// Gets the validated idle timeout. Stored as validated value for eager validation.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when IdleTimeout is negative during construction.</exception>
    public TimeSpan? IdleTimeout { get; init; } = ValidateTimeSpan(IdleTimeout, nameof(IdleTimeout));

    /// <summary>
    /// Gets the validated suspended session TTL. Stored as validated value for eager validation.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when SuspendedTtl is negative during construction.</exception>
    public TimeSpan? SuspendedTtl { get; init; } = ValidateTimeSpan(SuspendedTtl, nameof(SuspendedTtl));

    /// <summary>
    /// Gets the idle timeout duration. Defaults to 15 minutes if not specified.
    /// </summary>
    public TimeSpan IdleTimeoutValue => IdleTimeout ?? TimeSpan.FromMinutes(15);

    /// <summary>
    /// Gets the suspended session TTL. Defaults to 24 hours if not specified.
    /// </summary>
    public TimeSpan SuspendedTtlValue => SuspendedTtl ?? TimeSpan.FromHours(24);

    private static int ValidateMaxActiveSessions(int maxActiveSessions)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(maxActiveSessions);
        return maxActiveSessions;
    }

    private static int ValidateMaxSessionsPerUser(int maxSessionsPerUser)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(maxSessionsPerUser);
        return maxSessionsPerUser;
    }

    private static TimeSpan? ValidateTimeSpan(TimeSpan? value, string paramName)
    {
        if (value.HasValue)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value.Value, TimeSpan.Zero, paramName);
        }

        return value;
    }
}
